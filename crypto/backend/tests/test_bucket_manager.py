"""
Tests for BucketManager.
"""

import pytest
import time
from src.offlinepay_crypto.bucket_manager import BucketManager
from src.offlinepay_crypto.key_manager import KeyManager
from src.offlinepay_crypto.signer import Signer
from src.offlinepay_crypto.encryptor import Encryptor
from src.offlinepay_crypto.database import Database


class TestBucketManager:
    """Test BucketManager functionality."""

    @pytest.fixture
    def setup_bucket(self, temp_db):
        """Create a bucket with test data."""
        # Generate keys
        server_priv, server_pub = KeyManager.generate_key_pair()
        server_priv_bytes = KeyManager.private_key_to_bytes(server_priv)
        server_pub_bytes = KeyManager.public_key_to_bytes(server_pub)

        aes_key = Encryptor.generate_key()
        wallet_id = "alice_123"
        initial_balance = 5000

        # Sign bucket
        bucket_data = f"{wallet_id}|{initial_balance}|0".encode()
        server_signature = Signer.sign_with_bytes(server_priv_bytes, bucket_data)

        manager = BucketManager(temp_db)
        manager.create_bucket(
            wallet_id=wallet_id,
            initial_balance=initial_balance,
            aes_key=aes_key,
            server_public_key=server_pub_bytes,
            server_signature=server_signature,
        )

        return {
            'manager': manager,
            'wallet_id': wallet_id,
            'aes_key': aes_key,
            'server_priv': server_priv_bytes,
            'server_pub': server_pub_bytes,
            'balance': initial_balance,
        }

    def test_create_bucket(self, setup_bucket):
        """Test bucket creation."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']
        aes_key = setup_bucket['aes_key']

        bucket = manager.get_bucket(wallet_id, aes_key)
        assert bucket is not None
        assert bucket['balance'] == 5000
        assert bucket['counter'] == 0

    def test_deduct_funds(self, setup_bucket):
        """Test fund deduction."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']
        aes_key = setup_bucket['aes_key']

        success, new_balance, new_counter, error = manager.deduct_funds(
            wallet_id=wallet_id,
            amount=1000,
            aes_key=aes_key,
        )
        assert success is True
        assert new_balance == 4000
        assert new_counter == 1
        assert error is None

    def test_deduct_insufficient_funds(self, setup_bucket):
        """Test deduction with insufficient funds."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']
        aes_key = setup_bucket['aes_key']

        success, new_balance, new_counter, error = manager.deduct_funds(
            wallet_id=wallet_id,
            amount=10000,
            aes_key=aes_key,
        )
        assert success is False
        assert error == "Insufficient balance"

    def test_add_funds(self, setup_bucket):
        """Test fund addition."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']
        aes_key = setup_bucket['aes_key']
        server_priv = setup_bucket['server_priv']
        server_pub = setup_bucket['server_pub']

        # Add $20
        new_balance = 7000  # 5000 + 2000
        bucket_data = f"{wallet_id}|{new_balance}|{setup_bucket['manager'].get_counter(wallet_id, aes_key)}".encode()
        server_signature = Signer.sign_with_bytes(server_priv, bucket_data)

        success, balance, error = manager.add_funds(
            wallet_id=wallet_id,
            amount=2000,
            aes_key=aes_key,
            server_public_key=server_pub,
            server_signature=server_signature,
        )
        assert success is True
        assert balance == 7000

    def test_check_balance(self, setup_bucket):
        """Test balance check."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']
        aes_key = setup_bucket['aes_key']

        balance = manager.check_balance(wallet_id, aes_key)
        assert balance == 5000

    def test_get_counter(self, setup_bucket):
        """Test counter retrieval."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']
        aes_key = setup_bucket['aes_key']

        counter = manager.get_counter(wallet_id, aes_key)
        assert counter == 0

    def test_is_expired(self, setup_bucket):
        """Test expiry check."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']

        # Should not be expired (fresh bucket)
        assert manager.is_expired(wallet_id) is False

    def test_freeze_bucket(self, setup_bucket):
        """Test bucket freeze."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']

        result = manager.freeze_bucket(wallet_id)
        assert result is True

        status = manager.get_bucket_status(wallet_id)
        assert status == 'FROZEN'

    def test_activate_bucket(self, setup_bucket):
        """Test bucket activation."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']

        manager.freeze_bucket(wallet_id)
        result = manager.activate_bucket(wallet_id)
        assert result is True

        status = manager.get_bucket_status(wallet_id)
        assert status == 'ACTIVE'

    def test_deduct_funds_from_frozen_bucket(self, setup_bucket):
        """Test deduction from frozen bucket."""
        manager = setup_bucket['manager']
        wallet_id = setup_bucket['wallet_id']
        aes_key = setup_bucket['aes_key']

        manager.freeze_bucket(wallet_id)

        success, new_balance, new_counter, error = manager.deduct_funds(
            wallet_id=wallet_id,
            amount=1000,
            aes_key=aes_key,
        )
        assert success is False
        assert "FROZEN" in error