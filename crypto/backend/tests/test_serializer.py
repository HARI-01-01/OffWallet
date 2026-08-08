"""
Tests for Serializer.
"""

import pytest
from src.offlinepay_crypto.serializer import Serializer


class TestSerializer:
    """Test Serializer functionality."""

    def test_encode_decode(self):
        """Test CBOR encode/decode."""
        data = {"key": "value", "number": 123}
        encoded = Serializer.encode(data)
        decoded = Serializer.decode(encoded)
        assert decoded == data

    def test_encode_payment_token(self):
        """Test payment token encoding."""
        token = Serializer.encode_payment_token(
            local_id="uuid-123",
            amount=1000,
            counter=5,
            payer_id="alice",
            payee_id="bob",
            timestamp=1234567890,
            payer_signature=b"a" * 64,
        )
        assert isinstance(token, bytes)
        assert len(token) > 0

    def test_decode_payment_token(self):
        """Test payment token decoding."""
        token = Serializer.encode_payment_token(
            local_id="uuid-123",
            amount=1000,
            counter=5,
            payer_id="alice",
            payee_id="bob",
            timestamp=1234567890,
            payer_signature=b"a" * 64,
        )
        decoded = Serializer.decode_payment_token(token)
        assert decoded['localId'] == "uuid-123"
        assert decoded['amount'] == 1000
        assert decoded['counter'] == 5

    def test_decode_invalid_payment_token(self):
        """Test decoding invalid payment token."""
        import cbor2
        with pytest.raises((ValueError, cbor2.CBORDecodeEOF, cbor2.CBORDecodeError)):
            Serializer.decode_payment_token(b"invalid")

    def test_encode_challenge(self):
        """Test challenge encoding."""
        challenge = Serializer.encode_challenge(
            otp_hash=b"a" * 32,
            public_key=b"b" * 32,
            timestamp=1234567890,
            nonce=b"c" * 32,
            signature=b"d" * 64,
        )
        assert isinstance(challenge, bytes)

    def test_decode_challenge(self):
        """Test challenge decoding."""
        challenge = Serializer.encode_challenge(
            otp_hash=b"a" * 32,
            public_key=b"b" * 32,
            timestamp=1234567890,
            nonce=b"c" * 32,
            signature=b"d" * 64,
        )
        decoded = Serializer.decode_challenge(challenge)
        assert decoded['otpHash'] == b"a" * 32
        assert decoded['publicKey'] == b"b" * 32

    def test_size_of(self):
        """Test size calculation."""
        data = {"a": 1, "b": 2, "c": 3}
        size = Serializer.size_of(data)
        assert size > 0
        assert size == len(Serializer.encode(data))

    def test_hex_dump(self):
        """Test hex dump."""
        data = b"Hello, World!"
        dump = Serializer.hex_dump(data)
        assert isinstance(dump, str)