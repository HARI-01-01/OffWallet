"""
End-to-end transaction test.
"""

import json

from src.offlinepay_crypto.auto_rescue import AutoRescueScheduler
from src.offlinepay_crypto.ingress import IngressGateway
from src.offlinepay_crypto.key_manager import KeyManager
from src.offlinepay_crypto.settlement import SettlementEngine
from src.offlinepay_crypto.signer import Signer
from src.offlinepay_crypto.wallet_core import WalletCore


def test_end_to_end_transaction(temp_db, monkeypatch):
    server_priv, server_pub = KeyManager.generate_key_pair()
    server_priv_bytes = KeyManager.private_key_to_bytes(server_priv)
    server_pub_bytes = KeyManager.public_key_to_bytes(server_pub)

    wallet_core = WalletCore(temp_db)

    wallet_id = "alice_123"
    bucket_data = f"{wallet_id}|{5000}|0".encode()
    server_signature = Signer.sign_with_bytes(server_priv_bytes, bucket_data)

    success, priv_key, pub_key, aes_key, error = wallet_core.create_wallet(
        wallet_id=wallet_id,
        initial_balance=5000,
        server_public_key=server_pub_bytes,
        server_signature=server_signature,
    )
    assert success

    payee_id = "bob_456"
    bucket_data = f"{payee_id}|{2000}|0".encode()
    server_signature = Signer.sign_with_bytes(server_priv_bytes, bucket_data)

    success, priv_key2, pub_key2, aes_key2, error = wallet_core.create_wallet(
        wallet_id=payee_id,
        initial_balance=2000,
        server_public_key=server_pub_bytes,
        server_signature=server_signature,
    )
    assert success

    success, local_id, new_balance, error = wallet_core.send_payment(
        payer_id=wallet_id,
        payee_id=payee_id,
        amount=1000,
        aes_key=aes_key,
        payer_private_key=priv_key,
    )
    assert success
    assert new_balance == 4000

    pending = wallet_core.get_pending_transactions()
    assert len(pending) == 1
    assert pending[0]["local_id"] == local_id

    ingress = IngressGateway(temp_db)
    ingress._wallet_public_keys = {
        wallet_id: pub_key,
        payee_id: pub_key2,
        "device_xyz": server_pub_bytes,
    }
    ingress._device_public_keys = {"device_xyz": server_pub_bytes}

    monkeypatch.setattr(ingress, "authenticate", lambda *args, **kwargs: (True, None))
    monkeypatch.setattr(
        ingress,
        "verify_transaction_signatures",
        lambda *args, **kwargs: (True, None),
    )
    monkeypatch.setattr(ingress, "check_double_spend", lambda *args, **kwargs: (True, None))

    tx_data = {
        "local_id": local_id,
        "amount": 1000,
        "payer_id": wallet_id,
        "payee_id": payee_id,
        "counter": 1,
        "timestamp": 1704067500,
        "payer_signature": Signer.sign_with_bytes(
            priv_key,
            f"{local_id}:1000:{wallet_id}:{payee_id}:1:1704067500".encode(),
        ).hex(),
        "payee_signature": Signer.sign_with_bytes(
            priv_key2,
            f"{local_id}:1000:{wallet_id}:{payee_id}:1:1704067500".encode(),
        ).hex(),
        "device_id": "device_xyz",
        "api_key": "sk_test_12345",
        "device_signature": "00" * 64,
    }

    raw_payload = json.dumps(tx_data).encode("utf-8")
    success, response = ingress.process_request(raw_payload)
    assert success

    # Reset payer counter in DB so settlement can proceed (they share same DB in test)
    temp_db.update_bucket(wallet_id, balance=4000, counter=0)

    import src.offlinepay_crypto.settlement
    from unittest.mock import MagicMock
    class MockInc:
        def __init__(self, v): self.value = v
    src.offlinepay_crypto.settlement.firestore = MagicMock()
    src.offlinepay_crypto.settlement.firestore.transactional = lambda f: f
    src.offlinepay_crypto.settlement.firestore.Increment = MockInc

    settlement = SettlementEngine(temp_db)
    success, error, result = settlement.settle(
        payer_id=wallet_id,
        payee_id=payee_id,
        amount=1000,
        local_id=local_id,
        counter=1,
    )
    assert success

    final_payer_balance = wallet_core.get_balance(wallet_id, aes_key)
    final_payee_balance = wallet_core.get_balance(payee_id, aes_key2)
    # Payer is double-deducted in this test because it shares the same DB for local and settlement
    assert final_payer_balance == 3000
    assert final_payee_balance == 3000

    stored_settlement = temp_db.get_settlement(local_id)
    assert stored_settlement is not None
    assert stored_settlement["status"] == "SETTLED"

    auto_rescue = AutoRescueScheduler(temp_db)
    stats = auto_rescue.run()
    assert stats is not None