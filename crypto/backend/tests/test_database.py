"""
Tests for Database.
"""

import pytest
import uuid
from src.offlinepay_crypto.database import Database


class TestDatabase:
    """Test Database functionality."""

    def test_init_db(self, temp_db):
        """Test database initialization."""
        assert temp_db is not None

    def test_create_bucket(self, temp_db):
        """Test bucket creation."""
        wallet_id = "test_123"
        result = temp_db.create_bucket(
            wallet_id=wallet_id,
            balance=5000,
            counter=0,
            encrypted_balance=b"test",
            encrypted_counter=b"test",
            server_signature=b"sig",
            expires_at=9999999999,
        )
        assert result is True

    def test_get_bucket(self, temp_db):
        """Test bucket retrieval."""
        wallet_id = "test_123"
        temp_db.create_bucket(wallet_id, balance=5000, counter=0)
        bucket = temp_db.get_bucket(wallet_id)
        assert bucket is not None
        assert bucket['wallet_id'] == wallet_id
        assert bucket['balance'] == 5000

    def test_update_bucket(self, temp_db):
        """Test bucket update."""
        wallet_id = "test_123"
        temp_db.create_bucket(wallet_id, balance=5000, counter=0)
        temp_db.update_bucket(wallet_id, balance=4000, counter=1)
        bucket = temp_db.get_bucket(wallet_id)
        assert bucket['balance'] == 4000
        assert bucket['counter'] == 1

    def test_update_bucket_counter(self, temp_db):
        """Test optimistic locking counter update."""
        wallet_id = "test_123"
        temp_db.create_bucket(wallet_id, balance=5000, counter=0)

        # First update should succeed
        result = temp_db.update_bucket_counter(wallet_id, 1)
        assert result is True
        bucket = temp_db.get_bucket(wallet_id)
        assert bucket['counter'] == 1

        # Second update with same counter should fail (optimistic locking)
        result = temp_db.update_bucket_counter(wallet_id, 1)
        assert result is False

    def test_add_to_queue(self, temp_db):
        """Test adding to queue."""
        local_id = str(uuid.uuid4())
        transaction = {
            'local_id': local_id,
            'amount': 1000,
            'payer_id': 'alice',
            'payee_id': 'bob',
            'counter': 1,
            'timestamp': 1234567890,
            'payer_signature': b'a' * 64,
            'payee_signature': b'b' * 64,
            'status': 'QUEUED',
            'retry_count': 0,
        }
        result = temp_db.add_to_queue(transaction)
        assert result is True

    def test_get_pending_transactions(self, temp_db):
        """Test getting pending transactions."""
        local_id = str(uuid.uuid4())
        transaction = {
            'local_id': local_id,
            'amount': 1000,
            'payer_id': 'alice',
            'payee_id': 'bob',
            'counter': 1,
            'timestamp': 1234567890,
            'payer_signature': b'a' * 64,
            'payee_signature': b'b' * 64,
            'status': 'QUEUED',
            'retry_count': 0,
        }
        temp_db.add_to_queue(transaction)
        pending = temp_db.get_pending_transactions(status='QUEUED')
        assert len(pending) == 1
        assert pending[0]['local_id'] == local_id

    def test_update_queue_status(self, temp_db):
        """Test queue status update."""
        local_id = str(uuid.uuid4())
        transaction = {
            'local_id': local_id,
            'amount': 1000,
            'payer_id': 'alice',
            'payee_id': 'bob',
            'counter': 1,
            'timestamp': 1234567890,
            'payer_signature': b'a' * 64,
            'payee_signature': b'b' * 64,
            'status': 'QUEUED',
            'retry_count': 0,
        }
        temp_db.add_to_queue(transaction)
        result = temp_db.update_queue_status(local_id, 'PROCESSED')
        assert result is True
        pending = temp_db.get_pending_transactions(status='PROCESSED')
        assert len(pending) == 1

    def test_delete_from_queue(self, temp_db):
        """Test deleting from queue."""
        local_id = str(uuid.uuid4())
        transaction = {
            'local_id': local_id,
            'amount': 1000,
            'payer_id': 'alice',
            'payee_id': 'bob',
            'counter': 1,
            'timestamp': 1234567890,
            'payer_signature': b'a' * 64,
            'payee_signature': b'b' * 64,
            'status': 'QUEUED',
            'retry_count': 0,
        }
        temp_db.add_to_queue(transaction)
        result = temp_db.delete_from_queue(local_id)
        assert result is True
        pending = temp_db.get_pending_transactions()
        assert len(pending) == 0

    def test_get_queue_count(self, temp_db):
        """Test queue count."""
        local_id = str(uuid.uuid4())
        transaction = {
            'local_id': local_id,
            'amount': 1000,
            'payer_id': 'alice',
            'payee_id': 'bob',
            'counter': 1,
            'timestamp': 1234567890,
            'payer_signature': b'a' * 64,
            'payee_signature': b'b' * 64,
            'status': 'QUEUED',
            'retry_count': 0,
        }
        temp_db.add_to_queue(transaction)
        count = temp_db.get_queue_count()
        assert count == 1
        count = temp_db.get_queue_count('QUEUED')
        assert count == 1

    def test_ledger_entries(self, temp_db):
        """Test ledger entries."""
        result = temp_db.create_ledger_entry(
            transaction_id="txn_123",
            wallet_id="alice",
            amount=-1000,
            entry_type="DEBIT",
            balance_before=5000,
            balance_after=4000,
            timestamp=1234567890,
            description="Payment to bob",
        )
        assert result is True
        ledger = temp_db.get_ledger("alice")
        assert len(ledger) == 1
        assert ledger[0]['amount'] == -1000

    def test_create_user(self, temp_db):
        """Test user creation and retrieval."""
        result = temp_db.create_user(
            wallet_id="user_123",
            email="alice@example.com",
            phone="+1234567890",
            password_hash="hash123",
            public_key=b"public-key",
        )
        assert result is True

        user = temp_db.get_user("user_123")
        assert user is not None
        assert user["email"] == "alice@example.com"

    def test_create_pending_transaction(self, temp_db):
        """Test pending transaction creation wrapper."""
        result = temp_db.create_pending_transaction(
            local_id="tx_123",
            amount=1000,
            payer_id="alice",
            payee_id="bob",
            counter=1,
            timestamp=1234567890,
            payer_signature=b"a" * 64,
            payee_signature=b"b" * 64,
        )
        assert result is True

        tx = temp_db.get_transaction_by_id("tx_123")
        assert tx is not None
        assert tx["status"] == "QUEUED"

    def test_create_settlement(self, temp_db):
        """Test settlement persistence."""
        result = temp_db.create_settlement(
            local_id="tx_123",
            transaction_id="txn_123",
            payer_id="alice",
            payee_id="bob",
            amount=1000,
            counter=1,
        )
        assert result is True

        settlement = temp_db.get_settlement("tx_123")
        assert settlement is not None
        assert settlement["status"] == "SETTLED"

    def test_create_device(self, temp_db):
        """Test device auth persistence."""
        result = temp_db.create_device("device_123", b"public-key")
        assert result is True

        device = temp_db.get_device("device_123")
        assert device is not None
        assert device["device_id"] == "device_123"

    def test_api_key_lifecycle(self, temp_db):
        """Test secure API key storage and revocation."""
        result = temp_db.create_api_key(
            key_id="key_123",
            api_key="secret-key",
            merchant_id="merchant_123",
            expires_at=9999999999,
        )
        assert result is True

        api_key = temp_db.get_api_key("secret-key")
        assert api_key is not None
        assert api_key["merchant_id"] == "merchant_123"

        revoked = temp_db.revoke_api_key("secret-key")
        assert revoked is True

        api_key = temp_db.get_api_key("secret-key")
        assert api_key is not None
        assert api_key["revoked"] == 1