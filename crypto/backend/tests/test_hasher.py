"""
Tests for Hasher.
"""

import pytest
from src.offlinepay_crypto.hasher import Hasher


class TestHasher:
    """Test Hasher functionality."""

    def test_sha256(self):
        """Test SHA-256 hashing."""
        data = b"Hello, World!"
        digest = Hasher.sha256(data)
        assert len(digest) == 32
        assert isinstance(digest, bytes)

    def test_sha256_hex(self):
        """Test SHA-256 hex output."""
        data = b"Hello, World!"
        hex_digest = Hasher.sha256_hex(data)
        assert len(hex_digest) == 64
        assert isinstance(hex_digest, str)

    def test_hash_otp(self):
        """Test OTP hashing."""
        otp = "123456"
        digest = Hasher.hash_otp(otp)
        assert len(digest) == 32

    def test_hash_otp_hex(self):
        """Test OTP hex hashing."""
        otp = "123456"
        hex_digest = Hasher.hash_otp_hex(otp)
        assert len(hex_digest) == 64

    def test_verify_otp(self):
        """Test OTP verification."""
        otp = "123456"
        digest = Hasher.hash_otp(otp)
        assert Hasher.verify_otp(otp, digest) is True
        assert Hasher.verify_otp("999999", digest) is False

    def test_generate_challenge(self):
        """Test challenge generation."""
        challenge = Hasher.generate_challenge()
        assert len(challenge) == 32
        assert isinstance(challenge, bytes)

    def test_double_hash(self):
        """Test double hashing."""
        data = b"Hello, World!"
        digest = Hasher.double_hash(data)
        assert len(digest) == 32

    def test_deterministic(self):
        """Test that hashing is deterministic."""
        data = b"test"
        digest1 = Hasher.sha256(data)
        digest2 = Hasher.sha256(data)
        assert digest1 == digest2