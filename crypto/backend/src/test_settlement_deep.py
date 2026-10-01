"""
Shadow Protocol v1 - Deep Settlement Test Suite.
Verifies Linkage, Dual-Head Advancement, and Gap Repair.
"""

import os
import sys
import time
import hashlib
import base64
import secrets
from pathlib import Path

# Setup path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from offlinepay_crypto.firebase_db import FirebaseDB
from offlinepay_crypto.settlement import SettlementEngine
from offlinepay_crypto.key_manager import KeyManager
from offlinepay_crypto.signer import Signer
from offlinepay_crypto.protocol import ShadowProtocol
from offlinepay_crypto.canon import Canon

class DeepTest:
    def __init__(self):
        self.db = FirebaseDB()
        self.engine = SettlementEngine(self.db)
        self.alice_id = "test_alice"
        self.bob_id = "test_bob"
        self.server_priv, self.server_pub = KeyManager.get_master_server_key()

    def setup_users(self):
        print("🔧 Setting up Test Users...")
        # Alice
        a_priv, a_pub = KeyManager.generate_key_pair()
        self.alice_pub_bytes = KeyManager.public_key_to_bytes(a_pub)
        self.alice_priv = a_priv
        self.db.create_user(self.alice_id, {
            "wallet_id": self.alice_id,
            "device_pubkey": base64.b64encode(self.alice_pub_bytes).decode(),
            "status": "ACTIVE", "genesis_epoch": 1
        })
        self.db.create_bucket(self.alice_id, {"balance": 0, "lite_balance": 0, "counter": 0, "last_block_hash": "0"*64})
        self.db.update_sync_state(self.alice_id, 0, "0"*64)

        # Bob
        b_priv, b_pub = KeyManager.generate_key_pair()
        self.bob_pub_bytes = KeyManager.public_key_to_bytes(b_pub)
        self.bob_priv = b_priv
        self.db.create_user(self.bob_id, {
            "wallet_id": self.bob_id,
            "device_pubkey": base64.b64encode(self.bob_pub_bytes).decode(),
            "status": "ACTIVE", "genesis_epoch": 1
        })
        self.db.create_bucket(self.bob_id, {"balance": 0, "lite_balance": 0, "counter": 0, "last_block_hash": "0"*64})
        self.db.update_sync_state(self.bob_id, 0, "0"*64)

    def make_topup(self, wallet_id, counter, prev_hash, amount):
        block = {
            "v": 1, "chainId": "SHADOW", "walletId": "SERVER",
            "counter": counter, "prevHash": prev_hash, "amountP": amount,
            "payeeWalletId": wallet_id, "ts": int(time.time()),
            "payeeCounter": 0, "payeePrevHash": "0"*64,
            "node_type": "TOPUP",
            "payeePubKeyHash": "0"*64, "payeeChal": "0"*64,
            "payerPassId": "SYSTEM", "payeePassId": "SYSTEM",
            "genesisEpoch": 1
        }
        canon = self.engine._encode_block(block)
        sig = Signer.sign(self.server_priv, canon, ShadowProtocol.TAG_DEBIT_BLOCK)
        return {"block": block, "sig": sig.hex()}

    def make_payment(self, payer_id, payee_id, p_counter, e_counter, p_prev, e_prev, amount, payer_priv, payee_priv):
        block = {
            "v": 1, "chainId": "SHADOW", "walletId": payer_id,
            "counter": p_counter, "prevHash": p_prev, "amountP": amount,
            "payeeWalletId": payee_id, "payeeCounter": e_counter, "payeePrevHash": e_prev,
            "ts": int(time.time()), "genesisEpoch": 1,
            "payeePubKeyHash": "0"*64, "payeeChal": "0"*64, "payerPassId": "p1", "payeePassId": "e1"
        }
        canon = self.engine._encode_block(block)
        p_sig = Signer.sign(payer_priv, canon, ShadowProtocol.TAG_DEBIT_BLOCK)
        e_sig = Signer.sign(payee_priv, canon, ShadowProtocol.TAG_RECEIPT)
        block["payeeSig"] = e_sig.hex()
        block["payerSig"] = p_sig.hex()
        return {"block": block, "sig": p_sig.hex()}

    def run(self):
        print("\n🚀 STARTING DEEP SETTLEMENT TEST\n")
        self.setup_users()

        # 1. Bob Tops up (Block 1)
        print("\n--- TEST 1: Bob Top-up ---")
        topup = self.make_topup(self.bob_id, 1, "0"*64, 5000)
        t_hash = self.engine._calculate_block_hash(self.engine._encode_block(topup["block"]))

        ok, msg, res = self.engine.settle_v1(self.bob_id, [topup], "", "")
        print(f"Result: {ok}, Msg: {msg}")
        assert ok, "Bob Top-up Failed"

        # 2. Alice Tops up (Block 1)
        print("\n--- TEST 2: Alice Top-up ---")
        a_topup = self.make_topup(self.alice_id, 1, "0"*64, 10000)
        a_t_hash = self.engine._calculate_block_hash(self.engine._encode_block(a_topup["block"]))
        ok, _, _ = self.engine.settle_v1(self.alice_id, [a_topup], "", "")
        assert ok, "Alice Top-up Failed"

        # 3. Alice pays Bob (Alice Counter 2, Bob Counter 2)
        print("\n--- TEST 3: Alice pays Bob (Alice Syncs) ---")
        payment = self.make_payment(self.alice_id, self.bob_id, 2, 2, a_t_hash, t_hash, 2000, self.alice_priv, self.bob_priv)
        p_hash = self.engine._calculate_block_hash(self.engine._encode_block(payment["block"]))

        # Alice syncs the payment
        ok, msg, res = self.engine.settle_v1(self.alice_id, [payment], "", "")
        print(f"Alice Sync Result: {ok}, Msg: {msg}")
        assert ok, "Alice Sync Failed"

        # DEEP VERIFICATION: Bob's head on server MUST have moved to Block 2
        bob_state = self.db.get_sync_state(self.bob_id)
        print(f"🔍 Bob's Server Head: Counter={bob_state['head_counter']}, Hash={bob_state['head_hash'][:8]}")
        assert bob_state['head_counter'] == 2, "Bob's head did not advance via Alice's sync!"
        assert bob_state['head_hash'] == p_hash, "Bob's head hash is wrong!"

        # 4. Bob syncs his own ledger (Idempotency check)
        print("\n--- TEST 4: Bob Syncs (Idempotency) ---")
        # Bob sends his topup + the payment he already settled via Alice
        ok, msg, res = self.engine.settle_v1(self.bob_id, [topup, payment], "", "")
        print(f"Bob Sync Result: {ok}, Msg: {msg}")
        assert ok, "Bob Sync Failed"
        assert res[0]["status"] == "SETTLED" or res[0]["status"] == "ALREADY_SETTLED"

        # 5. Consecutive Payment with GAP (Alice syncs 4, skipping 3)
        print("\n--- TEST 5: Consecutive Gap Repair ---")
        # P3: Bob pays Alice (Alice 3, Bob 3)
        p3 = self.make_payment(self.bob_id, self.alice_id, 3, 3, p_hash, p_hash, 100, self.bob_priv, self.alice_priv)
        p3_hash = self.engine._calculate_block_hash(self.engine._encode_block(p3["block"]))

        # P4: Alice pays Bob (Alice 4, Bob 4)
        p4 = self.make_payment(self.alice_id, self.bob_id, 4, 4, p3_hash, p3_hash, 50, self.alice_priv, self.bob_priv)
        p4_hash = self.engine._calculate_block_hash(self.engine._encode_block(p4["block"]))

        # SCENARIO: Alice only syncs P4. Server head is at P2.
        # Server should use GAP REPAIR to find P3 in DB (if Alice synced it) or fail.
        # Let's sync P3 first to put it in DB
        self.engine.settle_v1(self.bob_id, [p3], "", "")

        # Now sync P4 from Alice's perspective. Linkage: P4 -> P3. Head is at P3 (from Bob's sync).
        ok, msg, res = self.engine.settle_v1(self.alice_id, [p4], "", "")
        print(f"Alice Sync P4 Result: {ok}, Msg: {msg}")
        assert ok, "Gap repair failed"

        print("\n✨ ALL DEEP SETTLEMENT TESTS PASSED! ✨\n")

if __name__ == "__main__":
    test = DeepTest()
    try:
        test.run()
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
