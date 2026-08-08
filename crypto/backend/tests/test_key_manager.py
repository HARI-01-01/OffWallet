"""
Tests for KeyManager.
"""

import pytest
from src.offlinepay_crypto.key_manager import KeyManager


class TestKeyManager:
    """Test KeyManager functionality."""

    def test_generate_key_pair(self):
        """Test key pair generation."""
        priv, pub = KeyManager.generate_key_pair()
        assert priv is not None
        assert pub is not None

    def test_private_key_bytes(self):
        """Test private key to bytes conversion."""
        priv, _ = KeyManager.generate_key_pair()
        bytes_data = KeyManager.private_key_to_bytes(priv)
        assert len(bytes_data) == 32
        assert isinstance(bytes_data, bytes)

    def test_public_key_bytes(self):
        """Test public key to bytes conversion."""
        _, pub = KeyManager.generate_key_pair()
        bytes_data = KeyManager.public_key_to_bytes(pub)
        assert len(bytes_data) == 32
        assert isinstance(bytes_data, bytes)

    def test_bytes_to_private_key(self):
        """Test bytes to private key conversion."""
        priv_original, _ = KeyManager.generate_key_pair()
        bytes_data = KeyManager.private_key_to_bytes(priv_original)
        priv_reconstructed = KeyManager.bytes_to_private_key(bytes_data)
        assert priv_reconstructed is not None

    def test_bytes_to_public_key(self):
        """Test bytes to public key conversion."""
        _, pub_original = KeyManager.generate_key_pair()
        bytes_data = KeyManager.public_key_to_bytes(pub_original)
        pub_reconstructed = KeyManager.bytes_to_public_key(bytes_data)
        assert pub_reconstructed is not None

    def test_private_key_size_validation(self):
        """Test private key size validation."""
        with pytest.raises(ValueError):
            KeyManager.bytes_to_private_key(b"too short")

    def test_public_key_size_validation(self):
        """Test public key size validation."""
        with pytest.raises(ValueError):
            KeyManager.bytes_to_public_key(b"too short")

