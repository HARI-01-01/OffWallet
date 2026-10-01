"""Shadow Protocol v1 - Backend Utilities."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib
import struct

class ShadowProtocol:
    # Domain Separation Tags
    TAG_ATTEST_CHALLENGE = "shadow/v1/attest-challenge"
    TAG_GENESIS = "shadow/v1/genesis"
    TAG_PASS = "shadow/v1/pass"
    TAG_SESSION_AUTH = "shadow/v1/session-auth"
    TAG_DEBIT_BLOCK = "shadow/v1/debit-block"
    TAG_RECEIPT = "shadow/v1/receipt"
    TAG_ACK = "shadow/v1/ack"
    TAG_BLOCK_HASH = "shadow/v1/block-hash"
    TAG_SAS = "shadow/v1/sas"
    TAG_TOPUP = "shadow/v1/topup"
    TAG_KEY_A2B = "shadow/v1/key/a2b"
    TAG_KEY_B2A = "shadow/v1/key/b2a"

    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def hkdf(ikm: bytes, salt: bytes, info: str, length: int) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info.encode(),
        ).derive(ikm)

    @staticmethod
    def encrypt(key: bytes, nonce: int, aad: bytes, plaintext: bytes) -> bytes:
        chacha = ChaCha20Poly1305(key)
        nonce_bytes = struct.pack('<Q', nonce).ljust(12, b'\x00')
        return chacha.encrypt(nonce_bytes, plaintext, aad)

    @staticmethod
    def decrypt(key: bytes, nonce: int, aad: bytes, ciphertext: bytes) -> bytes:
        chacha = ChaCha20Poly1305(key)
        nonce_bytes = struct.pack('<Q', nonce).ljust(12, b'\x00')
        return chacha.decrypt(nonce_bytes, ciphertext, aad)
