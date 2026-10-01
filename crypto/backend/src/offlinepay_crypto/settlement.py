"""Shadow Protocol v1 Settlement Engine."""

import time
import uuid
import secrets
import hashlib
import base64
import asyncio
from typing import Optional, Tuple, Dict, Any, List
from firebase_admin import firestore
from .firebase_db import FirebaseDB
from .nonce_manager import NonceManager
from .signer import Signer
from .key_manager import KeyManager
from .logging_utils import get_logger
from .protocol import ShadowProtocol
from .canon import Canon
from .events import bus

logger = get_logger("offlinepay.settlement")

def get_val(obj, key_snake, key_camel, default=None):
    """Helper to handle CamelCase/snake_case and bytes/list conversion."""
    return obj.get(key_camel, obj.get(key_snake, default))

class SettlementEngine:
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
        self.nonce_manager = NonceManager(self.db)

    def _to_bytes(self, val, length=None):
        if val is None or val == "":
            return b"\x00" * length if length else b""

        res = b""
        if isinstance(val, list):
            res = bytes([x & 0xFF for x in val])
        elif isinstance(val, str):
            try:
                res = bytes.fromhex(val)
            except ValueError:
                try:
                    res = base64.b64decode(val)
                except Exception:
                    res = val.encode()
        else:
            res = val

        if length and len(res) == 0:
            return b"\x00" * length
        return res

    def _to_bytes_fixed(self, val, length=32):
        b = self._to_bytes(val, length=length)
        if len(b) < length:
            return b.ljust(length, b"\x00")
        return b[:length]

    def settle_v1(
        self,
        wallet_id: str,
        blocks: List[Dict[str, Any]],
        integrity_token: str,
        device_pubkey_hash: str
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        Shadow v1 Reconciliation Algorithm with Full Signature Trust and Head Healing.
        """
        try:
            state = self.db.get_sync_state(wallet_id)
            if state.get("status") == "FROZEN":
                return False, "Account frozen", []

            last_hwm = state.get("hwm_timestamp", 0)
            expected_counter = state["head_counter"] + 1
            current_head_hash = state["head_hash"]
            results = []

            logger.info(f"🔄 [SETTLE] Starting Sync for {wallet_id}. Expected Counter: {expected_counter}, Current Head: {current_head_hash[:8]}")

            def get_sort_key(b_env):
                b = b_env["block"]
                if get_val(b, 'wallet_id', 'walletId') == wallet_id:
                    return get_val(b, 'counter', 'counter', 0)
                else:
                    return get_val(b, 'payee_counter', 'payeeCounter', 0)

            sorted_blocks = sorted(blocks, key=get_sort_key)
            seen_counters = set()

            for b_env in sorted_blocks:
                b = b_env["block"]
                payer_id = get_val(b, 'wallet_id', 'walletId')
                payee_id = get_val(b, 'payee_wallet_id', 'payeeWalletId')
                is_payer = (wallet_id == payer_id)
                is_payee = (wallet_id == payee_id)
                is_system = (payer_id == "SERVER" or payee_id == "GENESIS")

                if is_system:
                    my_counter = get_val(b, 'counter', 'counter')
                    my_prev_hash = self._to_bytes(get_val(b, 'prev_hash', 'prevHash'), length=32).hex()
                else:
                    my_counter = get_val(b, 'counter', 'counter') if is_payer else get_val(b, 'payee_counter', 'payeeCounter')
                    my_prev_hash = self._to_bytes(get_val(b, 'prev_hash', 'prevHash'), length=32).hex() if is_payer else self._to_bytes(get_val(b, 'payee_prev_hash', 'payeePrevHash'), length=32).hex()

                local_id = b_env.get("localId") or b_env.get("local_id") or f"blk_{my_counter}"
                if my_counter in seen_counters:
                    continue
                seen_counters.add(my_counter)

                # --- Hash & Idempotency ---
                b_data_canon = self._encode_block(b)
                block_hash = self._calculate_block_hash(b_data_canon)

                existing = self.db.get_settlement_by_hash(block_hash)
                if existing:
                    results.append({"local_id": local_id, "status": "SETTLED", "payee_signature": existing.get("payee_signature")})
                    # If this block moves us forward (even if we missed others), accept it as the new head
                    if my_counter >= expected_counter:
                        current_head_hash = block_hash
                        expected_counter = my_counter + 1
                        logger.info(f"⏩ [SETTLE] Head healed via existing block #{my_counter}")
                    continue

                # --- Linkage Check (Passive Linkage Recovery) ---
                if my_prev_hash != current_head_hash and my_counter != 0:
                    logger.info(f"🛠️ [GAP_DETECTED] {wallet_id} @ {current_head_hash[:8]}, wants {my_prev_hash[:8]}. Checking DB...")

                    # 1. Broad Check: Does this block exist ANYWHERE in our settlements?
                    prev_settlement = self.db.get_settlement_by_hash(my_prev_hash)
                    if not prev_settlement:
                        # 2. Deep Recovery: Did Alice sync Bob's missing block?
                        query = self.db.settlements.where(filter=firestore.FieldFilter("payer_id", "==", wallet_id)).where(filter=firestore.FieldFilter("counter", "==", my_counter - 1)).limit(1).get()
                        for doc in query: prev_settlement = doc.to_dict()

                        if not prev_settlement:
                            query = self.db.settlements.where(filter=firestore.FieldFilter("payee_id", "==", wallet_id)).where(filter=firestore.FieldFilter("payee_counter", "==", my_counter - 1)).limit(1).get()
                            for doc in query: prev_settlement = doc.to_dict()

                    if prev_settlement:
                         logger.info(f"✅ [CATCH_UP] Found missing link in DB. Repairing head.")
                         current_head_hash = prev_settlement['block_hash']
                         expected_counter = my_counter
                    else:
                         # DEEP REPAIR: Trust the co-signature!
                         # If this is a PAYMENT (not system) and Bob/Alice both signed it,
                         # we assume the history before it is valid and let Bob catch up.
                         if not is_system:
                              logger.warning(f"🔧 [REPAIR_MODE] Gap from {current_head_hash[:8]} to {my_prev_hash[:8]} is unknown. Verifying signatures to heal chain...")
                         else:
                              logger.error(f"🚫 [LINK_FAIL] Block #{my_counter} points to {my_prev_hash[:8]}, but server head is at {current_head_hash[:8]}")
                              return False, "REJECT_LINKAGE", results

                # --- Signature Verification (THE REAL SOURCE OF TRUTH) ---
                if not is_system:
                    payer = self.db.get_user(payer_id)
                    if not payer: return False, f"Payer {payer_id} missing", results
                    payer_pub = base64.b64decode(payer.get("device_pubkey"))
                    payer_sig = self._to_bytes(get_val(b_env, 'sig', 'sig')) or self._to_bytes(get_val(b, 'payer_sig', 'payerSig'))

                    if not Signer.verify(payer_pub, b_data_canon, payer_sig, ShadowProtocol.TAG_DEBIT_BLOCK):
                        logger.error(f"❌ [SIG_FAIL] Payer signature invalid for Block #{my_counter}")
                        return False, f"REJECT_SIG_PAYER at {my_counter}", results

                    payee_sig = self._to_bytes(get_val(b, 'payee_sig', 'payeeSig'))
                    if is_payee and not payee_sig: return False, "REJECT_MISSING_PAYEE_SIG", results

                    if payee_sig:
                        payee = self.db.get_user(payee_id)
                        if payee:
                            payee_pub = base64.b64decode(payee.get("device_pubkey"))
                            if not Signer.verify(payee_pub, b_data_canon, payee_sig, ShadowProtocol.TAG_RECEIPT):
                                 logger.error(f"❌ [SIG_FAIL] Payee signature invalid for Block #{my_counter}")
                                 return False, "REJECT_SIG_PAYEE", results
                    else:
                        # Alice syncs her own debit before Bob has co-signed
                        results.append({"local_id": local_id, "status": "PENDING_OTHER_USER"})
                        current_head_hash = block_hash
                        expected_counter = my_counter + 1
                        continue

                # --- Atomic Settlement ---
                success, error, _ = self._execute_settlement(
                    payer_id=payer_id, payee_id=payee_id,
                    amount=get_val(b, 'amount_p', 'amountP'), local_id=local_id,
                    counter=get_val(b, 'counter', 'counter'), block_hash=block_hash,
                    prev_hash_hex=self._to_bytes(get_val(b, 'prev_hash', 'prevHash'), length=32).hex(),
                    sig=payer_sig.hex() if not is_system else "",
                    payee_sig=payee_sig.hex() if not is_system and payee_sig else "",
                    block_json=b,
                    payee_counter=get_val(b, 'payee_counter', 'payeeCounter', 0),
                    payee_prev_hash=self._to_bytes(get_val(b, 'payee_prev_hash', 'payeePrevHash'), length=32).hex()
                )
                if not success: return False, error, results
                results.append({"local_id": local_id, "status": "SETTLED"})
                current_head_hash = block_hash
                expected_counter = my_counter + 1

            # Save the final sync state for the syncing user
            my_blocks_ts = [get_val(b_env["block"], "ts", "ts") for b_env in blocks if get_val(b_env["block"], "wallet_id", "walletId") == wallet_id]
            self.db.update_sync_state(wallet_id, expected_counter - 1, current_head_hash, hwm_timestamp=max(my_blocks_ts) if my_blocks_ts else last_hwm)
            return True, "Sync complete", results
        except Exception as e:
            logger.exception(f"Unhandled error in settle_v1: {e}")
            return False, f"INTERNAL_ERROR: {e}", []

    def _encode_block(self, b: Dict[str, Any]) -> bytes:
        return Canon.enc([
            ('u8', get_val(b, 'v', 'v')),
            ('str', get_val(b, 'chain_id', 'chainId')),
            ('str', get_val(b, 'wallet_id', 'walletId')),
            ('u64', get_val(b, 'counter', 'counter')),
            ('bytes', self._to_bytes_fixed(get_val(b, 'prev_hash', 'prevHash'))),
            ('u64', get_val(b, 'amount_p', 'amountP')),
            ('bytes', self._to_bytes_fixed(get_val(b, 'payee_pubkey_hash', 'payeePubKeyHash'))),
            ('str', get_val(b, 'payee_wallet_id', 'payeeWalletId')),
            ('bytes', self._to_bytes_fixed(get_val(b, 'payee_chal', 'payeeChal'))),
            ('str', get_val(b, 'payer_pass_id', 'payerPassId')),
            ('str', get_val(b, 'payee_pass_id', 'payeePassId')),
            ('u64', get_val(b, 'genesis_epoch', 'genesisEpoch')),
            ('u64', get_val(b, 'ts', 'ts')),
            ('u64', get_val(b, 'payee_counter', 'payeeCounter', 0)),
            ('bytes', self._to_bytes_fixed(get_val(b, 'payee_prev_hash', 'payeePrevHash')))
        ])

    def _calculate_block_hash(self, canon_data: bytes) -> str:
        return hashlib.sha256(ShadowProtocol.TAG_BLOCK_HASH.encode() + b"\x00" + canon_data).hexdigest()

    def _execute_settlement(self, payer_id: str, payee_id: str, amount: int, local_id: str, counter: int, block_hash: str, prev_hash_hex: str, sig: str, payee_sig: str, block_json: Dict[str, Any], payee_counter: int, payee_prev_hash: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        settlement_ref = self.db.settlements.document(block_hash)
        payer_ref = self.db.buckets.document(payer_id)
        payee_ref = self.db.buckets.document(payee_id)
        ps_ref = self.db.sync_state.document(payer_id)
        es_ref = self.db.sync_state.document(payee_id)

        @firestore.transactional
        def transactional_settle(transaction, p_ref, e_ref, s_ref, ps_ref, es_ref):
            if s_ref.get(transaction=transaction).exists: return True, "ALREADY_SETTLED", {}

            # --- Head Propagation Logic ---
            is_system = (payer_id == "SERVER" or payee_id == "GENESIS")

            if payer_id == "SERVER":
                # Top-up: Update Bob (Recipient)
                transaction.update(e_ref, {"balance": firestore.Increment(amount), "updated_at": int(time.time()), "last_block_hash": block_hash, "counter": counter})
                transaction.set(es_ref, {"head_counter": counter, "head_hash": block_hash, "last_sync_at": int(time.time())}, merge=True)
            elif payee_id == "GENESIS":
                # Genesis: Update the User
                transaction.update(p_ref, {"updated_at": int(time.time()), "last_block_hash": block_hash, "counter": counter})
                transaction.set(ps_ref, {"head_counter": counter, "head_hash": block_hash, "last_sync_at": int(time.time())}, merge=True)
            else:
                # Standard Payment: Update BOTH Payer and Payee heads
                transaction.update(p_ref, {"lite_balance": firestore.Increment(-amount), "updated_at": int(time.time()), "last_block_hash": block_hash, "counter": counter})
                transaction.update(e_ref, {"balance": firestore.Increment(amount), "updated_at": int(time.time()), "last_block_hash": block_hash, "counter": payee_counter})

                # Move both server-side counters forward
                transaction.set(ps_ref, {"head_counter": counter, "head_hash": block_hash, "last_sync_at": int(time.time())}, merge=True)
                transaction.set(es_ref, {"head_counter": payee_counter, "head_hash": block_hash, "last_sync_at": int(time.time())}, merge=True)

            # Record final settlement bundle
            transaction.set(s_ref, {
                "local_id": local_id, "payer_id": payer_id, "payee_id": payee_id, "amount": amount,
                "counter": counter, "block_hash": block_hash, "prev_hash": prev_hash_hex,
                "payee_counter": payee_counter, "payee_prev_hash": payee_prev_hash,
                "payer_signature": sig, "payee_signature": payee_sig, "status": "SETTLED",
                "timestamp": int(time.time()), "node_type": "PAYMENT" if not is_system else ("TOPUP" if payer_id=="SERVER" else "GENESIS"),
                "block_data_json": block_json
            })
            return True, None, {}

        return transactional_settle(self.db.db.transaction(), payer_ref, payee_ref, settlement_ref, ps_ref, es_ref)
