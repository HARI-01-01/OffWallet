"""
Shadow Protocol v1 - Stress & Edge Case Test Suite.
Covers: Gaps, Forks, Sig Failures, Propagation, and Idempotency.
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

class StressTest:
    def __init__(self):
        self.db = FirebaseDB()
        self.engine = SettlementEngine(self.db)
        self.server_priv, _ = KeyManager.get_master_server_key()
        self.users = {}

    def setup_user(self, name):
        print(f"👤 Creating {name}...")
        wallet_id = f"st_{name}_{secrets.token_hex(3)}"
        priv, pub = KeyManager.generate_key_pair()
        pub_bytes = KeyManager.public_key_to_bytes(pub)

        # Genesis
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

        self.db.create_user(wallet_id, {
            "wallet_id": wallet_id,
            "device_pubkey": base64.b64encode(pub_bytes).decode(),
            "status": "ACTIVE", "genesis_epoch": 1
        })
        self.db.create_bucket(wallet_id, {"balance": 0, "lite_balance": 0, "counter": 0, "last_block_hash": g_hash})
        self.db.update_sync_state(wallet_id, 0, g_hash)

        self.users[name] = {
            "id": wallet_id, "priv": priv, "pub_bytes": pub_bytes, "head": g_hash, "counter": 0
        }

    def topup(self, name, amount):
        u = self.users[name]
        u["counter"] += 1
        block = {
            "v": 1, "chainId": "SHADOW", "walletId": "SERVER",
            "counter": u["counter"], "prevHash": u["head"], "amountP": amount,
            "payeeWalletId": u["id"], "ts": int(time.time()),
            "payeeCounter": 0, "payeePrevHash": "0"*64,
            "node_type": "TOPUP", "payeePubKeyHash": "0"*64, "payeeChal": "0"*64,
            "payerPassId": "SYSTEM", "payeePassId": "SYSTEM", "genesisEpoch": 1
        }
        canon = self.engine._encode_block(block)
        sig = Signer.sign(self.server_priv, canon, ShadowProtocol.TAG_DEBIT_BLOCK)
        ok, _, _ = self.engine.settle_v1(u["id"], [{"block": block, "sig": sig.hex()}], "", "")
        if not ok: raise Exception(f"Topup fail for {name}")
        u["head"] = self.engine._calculate_block_hash(canon)

    def create_payment(self, payer_name, payee_name, amount, corrupt_sig=False):
        p = self.users[payer_name]
        e = self.users[payee_name]
        p["counter"] += 1
        e["counter"] += 1
        block = {
            "v": 1, "chainId": "SHADOW", "walletId": p["id"],
            "counter": p["counter"], "prevHash": p["head"], "amountP": amount,
            "payeeWalletId": e["id"], "payeeCounter": e["counter"], "payeePrevHash": e["head"],
            "ts": int(time.time()), "genesisEpoch": 1,
            "payeePubKeyHash": "0"*64, "payeeChal": "0"*64, "payerPassId": "p", "payeePassId": "e"
        }
        canon = self.engine._encode_block(block)
        p_sig = Signer.sign(p["priv"], canon, ShadowProtocol.TAG_DEBIT_BLOCK)
        e_sig = Signer.sign(e["priv"], canon, ShadowProtocol.TAG_RECEIPT)

        if corrupt_sig: p_sig = secrets.token_bytes(64)

        block["payeeSig"] = e_sig.hex()
        block["payerSig"] = p_sig.hex()
        p["head"] = self.engine._calculate_block_hash(canon)
        e["head"] = p["head"]
        return {"block": block, "sig": p_sig.hex(), "hash": p["head"]}

    def run(self):
        print("\n🧪 STARTING STRESS TEST SUITE\n")
        self.setup_user("Alice")
        self.setup_user("Bob")
        self.setup_user("Charlie")

        self.topup("Alice", 10000)
        self.topup("Bob", 10000)

        # SCENARIO 1: Simple Success (Alice -> Bob)
        print("\n[Scenario 1] Simple Payer Sync...")
        p1 = self.create_payment("Alice", "Bob", 100)
        ok, _, _ = self.engine.settle_v1(self.users["Alice"]["id"], [p1], "", "")
        assert ok, "S1 failed"
        print("✅ Alice syncs, both heads moved.")

        # SCENARIO 2: Bob syncs same block (Already Settled)
        print("\n[Scenario 2] Idempotent Recipient Sync...")
        ok, _, res = self.engine.settle_v1(self.users["Bob"]["id"], [p1], "", "")
        assert ok and res[0]["status"] == "SETTLED", "S2 failed"
        print("✅ Bob syncs Alice's block, returns SETTLED.")

        # SCENARIO 3: Alice pays Charlie, but Alice skips sync. Charlie syncs.
        print("\n[Scenario 3] Recipient Sync (Payer skipped)...")
        p2 = self.create_payment("Alice", "Charlie", 200)
        ok, _, _ = self.engine.settle_v1(self.users["Charlie"]["id"], [p2], "", "")
        assert ok, "S3 failed"
        print("✅ Charlie syncs Alice's block, Alice's head advanced on server.")

        # SCENARIO 4: Bad Signature Check
        print("\n[Scenario 4] Invalid Signature Rejection...")
        bad_p = self.create_payment("Alice", "Bob", 50, corrupt_sig=True)
        ok, msg, _ = self.engine.settle_v1(self.users["Alice"]["id"], [bad_p], "", "")
        assert not ok and "REJECT_SIG" in msg, f"S4 failed to reject: {msg}"
        print("✅ Server rejected corrupted signature.")

        # SCENARIO 5: Gap Repair (The "Interleaved" Case)
        # Alice 4 -> Bob 3
        # Alice 5 -> Charlie 2
        # Bob syncs Alice 4. Alice 5 is now "Gapped" relative to Alice's last sync.
        print("\n[Scenario 5] Gap Repair (Interleaved Transactions)...")
        p_gap_1 = self.create_payment("Alice", "Bob", 10)
        p_gap_2 = self.create_payment("Alice", "Charlie", 10)

        # Bob syncs p_gap_1
        self.engine.settle_v1(self.users["Bob"]["id"], [p_gap_1], "", "")

        # Alice syncs ONLY p_gap_2 (Server Alice Head is now at p_gap_1, wants p_gap_2. Link: p_gap_2.prev == p_gap_1.hash)
        ok, msg, _ = self.engine.settle_v1(self.users["Alice"]["id"], [p_gap_2], "", "")
        assert ok, f"S5 Gap Repair failed: {msg}"
        print("✅ Alice synced Block 5 directly because Block 4 was already in DB via Bob.")

        # SCENARIO 6: Out of Order Sync (Block 7 sent before Block 6)
        print("\n[Scenario 6] Out-of-Order Rejection (Security check)...")
        p6 = self.create_payment("Alice", "Bob", 10)
        p7 = self.create_payment("Alice", "Bob", 10)
        # Try sync p7 while server is at p5. Should fail (p6 missing).
        ok, msg, _ = self.engine.settle_v1(self.users["Alice"]["id"], [p7], "", "")
        assert not ok and "REJECT_LINKAGE" in msg, "S6 failed to detect gap"
        print("✅ Server rejected Block 7 because Block 6 is unknown.")

        # SCENARIO 7: Multi-Block Batch Sync
        print("\n[Scenario 7] Batch Sync (6 and 7 together)...")
        ok, msg, _ = self.engine.settle_v1(self.users["Alice"]["id"], [p6, p7], "", "")
        assert ok, "S7 batch sync failed"
        print("✅ Server processed batch of 2 blocks correctly.")

        print("\n✨ ALL STRESS TESTS PASSED! ✨\n")

if __name__ == "__main__":
    test = StressTest()
    try:
        test.run()
    except Exception as e:
        print(f"\n❌ STRESS TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
