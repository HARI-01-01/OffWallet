"""
Tests for Encryptor.
"""

import pytest
from src.offlinepay_crypto.encryptor import Encryptor
from cryptography.exceptions import InvalidTag


class TestEncryptor:
    """Test Encryptor functionality."""

    def test_generate_key(self):
        """Test key generation."""
        key = Encryptor.generate_key()
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_iv(self):
        """Test IV generation."""
        iv = Encryptor.generate_iv()
        assert len(iv) == 12
        assert isinstance(iv, bytes)

    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        key = Encryptor.generate_key()
        plaintext = b"Hello, World!"
        ciphertext, iv, tag = Encryptor.encrypt(key, plaintext)
        decrypted = Encryptor.decrypt(key, ciphertext, iv, tag)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Test encryption with AAD."""
        key = Encryptor.generate_key()
        plaintext = b"Hello, World!"
        aad = b"metadata"
        ciphertext, iv, tag = Encryptor.encrypt(key, plaintext, aad)
        decrypted = Encryptor.decrypt(key, ciphertext, iv, tag, aad)
        assert decrypted == plaintext

    def test_decrypt_wrong_key(self):
        """Test decryption with wrong key."""
        key1 = Encryptor.generate_key()
        key2 = Encryptor.generate_key()
        plaintext = b"Hello, World!"
        ciphertext, iv, tag = Encryptor.encrypt(key1, plaintext)
        with pytest.raises(InvalidTag):
            Encryptor.decrypt(key2, ciphertext, iv, tag)

    def test_decrypt_tampered(self):
        """Test decryption with tampered ciphertext."""
        key = Encryptor.generate_key()
        plaintext = b"Hello, World!"
        ciphertext, iv, tag = Encryptor.encrypt(key, plaintext)
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            Encryptor.decrypt(key, bytes(tampered), iv, tag)

    def test_encrypt_different_ciphertext(self):
        """Test that same plaintext produces different ciphertext."""
        key = Encryptor.generate_key()
        plaintext = b"Hello, World!"
        ciphertext1, iv1, tag1 = Encryptor.encrypt(key, plaintext)
        ciphertext2, iv2, tag2 = Encryptor.encrypt(key, plaintext)
        assert ciphertext1 != ciphertext2
        assert iv1 != iv2