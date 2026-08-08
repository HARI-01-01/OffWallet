"""
Tests for Signer.
"""

import pytest
from src.offlinepay_crypto.signer import Signer
from src.offlinepay_crypto.key_manager import KeyManager


class TestSigner:
    """Test Signer functionality."""

    def test_sign_and_verify(self):
        """Test signing and verification."""
        priv, pub = KeyManager.generate_key_pair()
        message = b"Hello, World!"
        signature = Signer.sign(priv, message)
        assert len(signature) == 64
        assert Signer.verify(pub, message, signature) is True

    def test_verify_wrong_message(self):
        """Test verification with wrong message."""
        priv, pub = KeyManager.generate_key_pair()
        message = b"Hello, World!"
        wrong_message = b"Goodbye, World!"
        signature = Signer.sign(priv, message)
        assert Signer.verify(pub, wrong_message, signature) is False

    def test_sign_with_bytes(self):
        """Test signing with raw key bytes."""
        priv, _ = KeyManager.generate_key_pair()
        priv_bytes = KeyManager.private_key_to_bytes(priv)
        message = b"Hello, World!"
        signature = Signer.sign_with_bytes(priv_bytes, message)
        assert len(signature) == 64

    def test_verify_with_bytes(self):
        """Test verification with raw key bytes."""
        priv, pub = KeyManager.generate_key_pair()
        priv_bytes = KeyManager.private_key_to_bytes(priv)
        pub_bytes = KeyManager.public_key_to_bytes(pub)
        message = b"Hello, World!"
        signature = Signer.sign_with_bytes(priv_bytes, message)
        assert Signer.verify_with_bytes(pub_bytes, message, signature) is True

    def test_verify_with_bytes_wrong_key(self):
        """Test verification with wrong public key."""
        priv, _ = KeyManager.generate_key_pair()
        _, wrong_pub = KeyManager.generate_key_pair()
        priv_bytes = KeyManager.private_key_to_bytes(priv)
        wrong_pub_bytes = KeyManager.public_key_to_bytes(wrong_pub)
        message = b"Hello, World!"
        signature = Signer.sign_with_bytes(priv_bytes, message)
        assert Signer.verify_with_bytes(wrong_pub_bytes, message, signature) is False

    def test_verify_with_bytes_invalid_signature(self):
        """Test verification with invalid signature."""
        priv, pub = KeyManager.generate_key_pair()
        pub_bytes = KeyManager.public_key_to_bytes(pub)
        message = b"Hello, World!"
        invalid_signature = b"x" * 64
        assert Signer.verify_with_bytes(pub_bytes, message, invalid_signature) is False

    def test_sign_with_bytes_validation(self):
        """Test private key validation in sign_with_bytes."""
        with pytest.raises(ValueError):
            Signer.sign_with_bytes(b"too short", b"message")