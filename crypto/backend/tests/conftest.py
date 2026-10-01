"""
Shared fixtures for all tests.
"""

import os
import pytest
import tempfile

from src.offlinepay_crypto.database import Database
from src.offlinepay_crypto.key_manager import KeyManager
from src.offlinepay_crypto.encryptor import Encryptor
from src.offlinepay_crypto.signer import Signer

# Monkeypatch firestore for tests
import sys
from unittest.mock import MagicMock

class MockFirestore:
    def transactional(self, func):
        def wrapper(transaction, *args, **kwargs):
            print(f"DEBUG: Executing transactional function {func.__name__}")
            return func(transaction, *args, **kwargs)
        return wrapper

    class Increment:
        def __init__(self, value):
            self.value = value

mock_firestore = MagicMock()
mock_firestore.transactional = MockFirestore().transactional
mock_firestore.Increment = MockFirestore.Increment

# Monkeypatch asyncio for tests
import asyncio
asyncio.create_task = lambda coro: None


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    fd,path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db = Database(path)
    yield db
    db.clear_all_data()
    os.unlink(path)


@pytest.fixture
def test_keys():
    """Generate test keys."""
    priv, pub = KeyManager.generate_key_pair()
    return {
        'private': KeyManager.private_key_to_bytes(priv),
        'public': KeyManager.public_key_to_bytes(pub),
        'private_obj': priv,
        'public_obj': pub,
    }


@pytest.fixture
def server_keys():
    """Generate server keys for signing buckets."""
    priv, pub = KeyManager.generate_key_pair()
    return {
        'private': KeyManager.private_key_to_bytes(priv),
        'public': KeyManager.public_key_to_bytes(pub),
        'private_obj': priv,
        'public_obj': pub,
    }


@pytest.fixture
def aes_key():
    """Generate an AES key for testing."""
    return Encryptor.generate_key()


@pytest.fixture
def test_wallet_id():
    """Return a test wallet ID."""
    return "test_wallet_123"


@pytest.fixture
def test_bucket_data(test_wallet_id, server_keys):
    """Create test bucket data."""
    bucket_data = f"{test_wallet_id}:5000:0".encode()
    signature = Signer.sign_with_bytes(server_keys['private'], bucket_data)
    return {
        'wallet_id': test_wallet_id,
        'balance': 5000,
        'counter': 0,
        'signature': signature,
    }