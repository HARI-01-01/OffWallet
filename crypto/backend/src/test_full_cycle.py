"""
Shadow Protocol v1 - Full Lifecycle Integration Test.
Simulates Registration -> Top-up -> Offline Payment -> Sync -> Head Propagation.
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

class FullCycleTest:
    def __init__(self):
        self.db = FirebaseDB()
        self.engine = SettlementEngine(self.db)
        self.server_priv, self.server_pub = KeyManager.get_master_server_key()
        self.users = {}

    def register_user(self, name):
        print(f"👤 Registering user: {name}...")
        wallet_id = f"user_{name}_{secrets.token_hex(4)}"
        priv, pub = KeyManager.generate_key_pair()
        pub_bytes = KeyManager.public_key_to_bytes(pub)
        pub_hash = hashlib.sha256(pub_bytes).hexdigest()

        # 1. Create User
        self.db.create_user(wallet_id, {
            "wallet_id": wallet_id,
            "device_pubkey": base64.b64encode(pub_bytes).decode(),
            "device_pubkey_hash": pub_hash,
            "status": "ACTIVE",
            "genesis_epoch": 1,
            "display_name": name
        })

        # 2. Generate Genesis Block
        genesis_block = {
            "v": 1, "chainId": "SHADOW", "walletId": wallet_id,
            "counter": 0, "prevHash": "0"*64, "amountP": 0,
            "payeeWalletId": "GENESIS", "ts": int(time.time()),
            "payeeCounter": 0, "payeePrevHash": "0"*64,
            "node_type": "GENESIS", "payeePubKeyHash": "0"*64, "payeeChal": "0"*64,
            "payerPassId": "SYSTEM", "payeePassId": "SYSTEM", "genesisEpoch": 1
        }
        canon = self.engine._encode_block(genesis_block)
        g_hash = self.engine._calculate_block_hash(canon)
        g_sig = Signer.sign(self.server_priv, canon, ShadowProtocol.TAG_DEBIT_BLOCK)

        # 3. Initialize States
        self.db.create_bucket(wallet_id, {
            "wallet_id": wallet_id, "balance": 0, "lite_balance": 0,
            "counter": 0, "last_block_hash": g_hash, "status": "ACTIVE"
        })
        self.db.update_sync_state(wallet_id, 0, g_hash)

        # Save settlement record for genesis
        self.db.settlements.document(g_hash).set({
            "block_hash": g_hash, "payer_id": "SYSTEM", "payee_id": wallet_id,
            "amount": 0, "counter": 0, "status": "SETTLED", "node_type": "GENESIS",
            "timestamp": int(time.time()), "block_data_json": genesis_block
        })

        self.users[name] = {
            "id": wallet_id, "priv": priv, "pub": pub,
            "pub_bytes": pub_bytes, "head": g_hash, "counter": 0
        }
        print(f"✅ User {name} registered at head {g_hash[:8]}")

    def topup_user(self, name, amount):
        user = self.users[name]
        print(f"💰 Topping up {name} by ₹{amount/100}...")

        new_counter = user["counter"] + 1
        topup_block = {
            "v": 1, "chainId": "SHADOW", "walletId": "SERVER",
            "counter": new_counter, "prevHash": user["head"], "amountP": amount,
            "payeeWalletId": user["id"], "ts": int(time.time()),
            "payeeCounter": 0, "payeePrevHash": "0"*64,
            "node_type": "TOPUP", "payeePubKeyHash": "0"*64, "payeeChal": "0"*64,
            "payerPassId": "SYSTEM", "payeePassId": "SYSTEM", "genesisEpoch": 1
        }

        canon = self.engine._encode_block(topup_block)
        t_hash = self.engine._calculate_block_hash(canon)
        t_sig = Signer.sign(self.server_priv, canon, ShadowProtocol.TAG_DEBIT_BLOCK)

        # Sync the topup block
        ok, msg, _ = self.engine.settle_v1(user["id"], [{"block": topup_block, "sig": t_sig.hex()}], "", "")
        if not ok: raise Exception(f"Topup failed: {msg}")

        user["head"] = t_hash
        user["counter"] = new_counter
        print(f"✅ {name} Top-up successful. New head: {t_hash[:8]}, Balance: ₹{amount/100}")

    def perform_payment(self, payer_name, payee_name, amount):
        payer = self.users[payer_name]
        payee = self.users[payee_name]
        print(f"💸 {payer_name} paying {payee_name} ₹{amount/100} (OFFLINE)...")

        p_counter = payer["counter"] + 1
        e_counter = payee["counter"] + 1

        payment_block = {
            "v": 1, "chainId": "SHADOW", "walletId": payer["id"],
            "counter": p_counter, "prevHash": payer["head"], "amountP": amount,
            "payeeWalletId": payee["id"], "payeeCounter": e_counter, "payeePrevHash": payee["head"],
            "ts": int(time.time()), "genesisEpoch": 1,
            "payeePubKeyHash": "0"*64, "payeeChal": "0"*64, "payerPassId": "p_id", "payeePassId": "e_id"
        }

        canon = self.engine._encode_block(payment_block)
        p_sig = Signer.sign(payer["priv"], canon, ShadowProtocol.TAG_DEBIT_BLOCK)
        e_sig = Signer.sign(payee["priv"], canon, ShadowProtocol.TAG_RECEIPT)

        payment_block["payeeSig"] = e_sig.hex()
        payment_block["payerSig"] = p_sig.hex()

        p_hash = self.engine._calculate_block_hash(canon)

        # We'll return the bundle that would be synced
        return {"block": payment_block, "sig": p_sig.hex(), "hash": p_hash}

    def run(self):
        print("\n🚀 STARTING FULL INTEGRATION TEST\n")

        # 1. Setup
        self.register_user("Alice")
        self.register_user("Bob")

        # 2. Money
        self.topup_user("Alice", 5000) # ₹50
        self.topup_user("Bob", 2000)   # ₹20

        # 3. Transaction
        bundle = self.perform_payment("Alice", "Bob", 1500) # Alice pays Bob ₹15

        # 4. ALICE SYNCS
        print("\n--- TEST: Alice Syncing Payment ---")
        ok, msg, res = self.engine.settle_v1(self.users["Alice"]["id"], [bundle], "", "")
        print(f"Alice Sync Result: {ok}, Msg: {msg}")
        assert ok, "Alice sync failed"

        # 5. DUAL PROPAGATION VERIFICATION
        print("\n--- TEST: Verifying Head Propagation ---")
        alice_state = self.db.get_sync_state(self.users["Alice"]["id"])
        bob_state = self.db.get_sync_state(self.users["Bob"]["id"])

        print(f"🔍 Alice's Server Head: Counter={alice_state['head_counter']}, Hash={alice_state['head_hash'][:8]}")
        print(f"🔍 Bob's Server Head:   Counter={bob_state['head_counter']}, Hash={bob_state['head_hash'][:8]}")

        assert alice_state['head_counter'] == 2, "Alice head did not move to 2"
        assert bob_state['head_counter'] == 2, "Bob head did not propagate to 2"
        assert alice_state['head_hash'] == bundle['hash'], "Alice head hash mismatch"
        assert bob_state['head_hash'] == bundle['hash'], "Bob head hash mismatch"
        print("✅ Dual-Head Propagation Verified!")

        # 6. IDEMPOTENCY TEST (Bob syncs the same block)
        print("\n--- TEST: Bob Syncing (Already Settled) ---")
        ok, msg, res = self.engine.settle_v1(self.users["Bob"]["id"], [bundle], "", "")
        print(f"Bob Sync Result: {ok}, Msg: {msg}")
        assert ok, "Bob sync should be OK even if already settled"
        assert res[0]["status"] == "SETTLED", "Bob sync should report SETTLED for existing block"
        print("✅ Bob's Idempotent Sync Verified!")

        print("\n✨ FULL INTEGRATION TEST PASSED! ✨\n")

if __name__ == "__main__":
    # Reset first to ensure clean state
    os.environ["ENV"] = "development"
    test = FullCycleTest()
    try:
        test.run()
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
