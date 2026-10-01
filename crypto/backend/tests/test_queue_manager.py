"""
Tests for QueueManager.
"""

import pytest
import uuid
from src.offlinepay_crypto.queue_manager import QueueManager
from src.offlinepay_crypto.database import Database


class TestQueueManager:
    """Test QueueManager functionality."""

    @pytest.fixture
    def queue_manager(self, temp_db):
        """Create queue manager."""
        return QueueManager(temp_db)

    @pytest.fixture
    def test_transaction(self):
        """Create test transaction."""
        return {
            'amount': 1000,
            'payer_id': 'alice_123',
            'payee_id': 'bob_456',
            'counter': 1,
            'payer_signature': b'a' * 64,
            'payee_signature': b'b' * 64,
        }

    def test_add_transaction(self, queue_manager, test_transaction):
        """Test adding transaction."""
        local_id = queue_manager.add_transaction(**test_transaction)
        assert local_id is not None
        assert isinstance(local_id, str)

    def test_get_pending_transactions(self, queue_manager, test_transaction):
        """Test getting pending transactions."""
        local_id = queue_manager.add_transaction(**test_transaction)
        pending = queue_manager.get_pending_transactions()
        assert len(pending) == 1
        assert pending[0]['local_id'] == local_id

    def test_get_transaction(self, queue_manager, test_transaction):
        """Test getting specific transaction."""
        local_id = queue_manager.add_transaction(**test_transaction)
        tx = queue_manager.get_transaction(local_id)
        assert tx is not None
        assert tx['local_id'] == local_id
        assert tx['amount'] == 1000

    def test_mark_as_processed(self, queue_manager, test_transaction):
        """Test marking as processed."""
        local_id = queue_manager.add_transaction(**test_transaction)
        result = queue_manager.mark_as_processed(local_id)
        assert result is True

        tx = queue_manager.get_transaction(local_id)
        assert tx['status'] == 'PROCESSED'

    def test_mark_as_failed(self, queue_manager, test_transaction):
        """Test marking as failed."""
        local_id = queue_manager.add_transaction(**test_transaction)
        result = queue_manager.mark_as_failed(local_id)
        assert result is True

        tx = queue_manager.get_transaction(local_id)
        assert tx['status'] == 'FAILED_TO_PROCESS'

    def test_increment_retry(self, queue_manager, test_transaction):
        """Test incrementing retry count."""
        local_id = queue_manager.add_transaction(**test_transaction)
        queue_manager.mark_as_failed(local_id)
        result = queue_manager.increment_retry(local_id)
        assert result is True

        tx = queue_manager.get_transaction(local_id)
        assert tx['retry_count'] == 1

    def test_should_retry(self, queue_manager, test_transaction):
        """Test retry eligibility."""
        local_id = queue_manager.add_transaction(**test_transaction)
        queue_manager.mark_as_failed(local_id)

        should, reason = queue_manager.should_retry(local_id)
        assert should is True

    def test_should_not_retry_after_max(self, queue_manager, test_transaction):
        """Test retry after max retries."""
        local_id = queue_manager.add_transaction(**test_transaction)
        queue_manager.mark_as_failed(local_id)

        # Increment retry 3 times
        for _ in range(3):
            queue_manager.increment_retry(local_id)

        should, reason = queue_manager.should_retry(local_id)
        assert should is False
        assert "Max retries" in reason

    def test_get_queue_count(self, queue_manager, test_transaction):
        """Test queue count."""
        queue_manager.add_transaction(**test_transaction)
        count = queue_manager.get_queue_count()
        assert count == 1
        count = queue_manager.get_queue_count('QUEUED')
        assert count == 1

    def test_has_pending(self, queue_manager, test_transaction):
        """Test pending check."""
        assert queue_manager.has_pending() is False
        queue_manager.add_transaction(**test_transaction)
        assert queue_manager.has_pending() is True