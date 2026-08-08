"""
Tests for WalletCore.
"""

import pytest
from src.offlinepay_crypto.wallet_core import WalletCore
from src.offlinepay_crypto.key_manager import KeyManager
from src.offlinepay_crypto.signer import Signer
from src.offlinepay_crypto.encryptor import Encryptor


class TestWalletCore:
    """Test WalletCore functionality."""

    @pytest.fixture
    def setup_wallet(self, temp_db):
        """Create a wallet with test data."""
        server_priv, server_pub = KeyManager.generate_key_pair()
        server_priv_bytes = KeyManager.private_key_to_bytes(server_priv)
        server_pub_bytes = KeyManager.public_key_to_bytes(server_pub)

        wallet = WalletCore(temp_db)
        wallet_id = "alice_123"
        initial_balance = 5000

        bucket_data = f"{wallet_id}:{initial_balance}:0".encode()
        server_signature = Signer.sign_with_bytes(server_priv_bytes, bucket_data)

        success, priv_key, pub_key, aes_key, error = wallet.create_wallet(
            wallet_id=wallet_id,
            initial_balance=initial_balance,
            server_public_key=server_pub_bytes,
            server_signature=server_signature,
        )
        assert success is True

        return {
            'wallet': wallet,
            'wallet_id': wallet_id,
            'priv_key': priv_key,
            'pub_key': pub_key,
            'aes_key': aes_key,
            'server_pub': server_pub_bytes,
            'server_priv': server_priv_bytes,
        }

    def test_create_wallet(self, setup_wallet):
        """Test wallet creation."""
        wallet = setup_wallet['wallet']
        wallet_id = setup_wallet['wallet_id']
        aes_key = setup_wallet['aes_key']

        balance = wallet.get_balance(wallet_id, aes_key)
        assert balance == 5000

    def test_get_balance(self, setup_wallet):
        """Test balance retrieval."""
        wallet = setup_wallet['wallet']
        wallet_id = setup_wallet['wallet_id']
        aes_key = setup_wallet['aes_key']

        balance = wallet.get_balance(wallet_id, aes_key)
        assert balance == 5000

    def test_send_payment(self, setup_wallet):
        """Test sending payment."""
        wallet = setup_wallet['wallet']
        wallet_id = setup_wallet['wallet_id']
        aes_key = setup_wallet['aes_key']
        priv_key = setup_wallet['priv_key']

        success, local_id, new_balance, error = wallet.send_payment(
            payer_id=wallet_id,
            payee_id="bob_456",
            amount=1000,
            aes_key=aes_key,
            payer_private_key=priv_key,
        )
        assert success is True
        assert new_balance == 4000
        assert local_id is not None

        # Check counter
        counter = wallet.get_counter(wallet_id, aes_key)
        assert counter == 1

    def test_get_pending_transactions(self, setup_wallet):
        """Test getting pending transactions."""
        wallet = setup_wallet['wallet']
        wallet_id = setup_wallet['wallet_id']
        aes_key = setup_wallet['aes_key']
        priv_key = setup_wallet['priv_key']

        wallet.send_payment(
            payer_id=wallet_id,
            payee_id="bob_456",
            amount=1000,
            aes_key=aes_key,
            payer_private_key=priv_key,
        )

        pending = wallet.get_pending_transactions()
        assert len(pending) == 1

    def test_mark_synced(self, setup_wallet):
        """Test marking as synced."""
        wallet = setup_wallet['wallet']
        wallet_id = setup_wallet['wallet_id']
        aes_key = setup_wallet['aes_key']
        priv_key = setup_wallet['priv_key']

        # 1. Send payment
        success, local_id, new_balance, error = wallet.send_payment(
            payer_id=wallet_id,
            payee_id="bob_456",
            amount=1000,
            aes_key=aes_key,
            payer_private_key=priv_key,
        )
        assert success is True

        # 2. Verify transaction is in queue
        tx = wallet.queue.get_transaction(local_id)
        assert tx is not None
        assert tx['status'] == 'QUEUED'

        # 3. Mark as synced
        result = wallet.mark_synced(local_id)
        assert result is True

        # 4. Verify it's marked as processed
        tx = wallet.queue.get_transaction(local_id)
        assert tx['status'] == 'PROCESSED'

    def test_get_wallet_info(self, setup_wallet):
        """Test wallet info."""
        wallet = setup_wallet['wallet']
        wallet_id = setup_wallet['wallet_id']
        aes_key = setup_wallet['aes_key']

        info = wallet.get_wallet_info(wallet_id, aes_key)
        assert info['wallet_id'] == wallet_id
        assert info['balance'] == 5000
        assert info['counter'] == 0
        assert info['status'] == 'ACTIVE'

    def test_generate_otp(self, setup_wallet):
        """Test OTP generation."""
        wallet = setup_wallet['wallet']
        otp = wallet.generate_otp()
        assert len(otp) == 6
        assert otp.isdigit()

    def test_hash_otp(self, setup_wallet):
        """Test OTP hashing."""
        wallet = setup_wallet['wallet']
        otp = "123456"
        hashed = wallet.hash_otp(otp)
        assert len(hashed) == 32