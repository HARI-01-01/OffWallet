import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

class Encryptor:
    KEY_SIZE = 32
    IV_SIZE = 12
    TAG_SIZE = 16
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a random AES-256 key."""
        return os.urandom(Encryptor.KEY_SIZE)

    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random 12 bytes initialization vector (IV)."""
        return os.urandom(Encryptor.IV_SIZE)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
        """Encrypt plaintext using AES-256-GCM."""
        iv = Encryptor.generate_iv()
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, aad)
        ciphertext = ciphertext_with_tag[:-Encryptor.TAG_SIZE]
        tag = ciphertext_with_tag[-Encryptor.TAG_SIZE:]
        return ciphertext, iv, tag
    
    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """Decrypt ciphertext using AES-256-GCM."""
        ciphertext_with_tag = ciphertext + tag
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext_with_tag, aad)

    @staticmethod
    def decrypt_aes_key_with_ephemeral(ephemeral_priv, client_pub_bytes, iv, ciphertext, tag) -> bytes:
        """Issue 2: Decrypt AES key using EKE (X25519 + HKDF + AES-GCM)."""
        from .key_manager import KeyManager
        client_pub = KeyManager.bytes_to_public_key(client_pub_bytes, "X25519")

        # 1. Compute shared secret (ECDH)
        shared_secret = ephemeral_priv.exchange(client_pub)
        
        # 2. Derive wrap key (HKDF)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"shadow/v1/aes-key-wrap",
        ).derive(shared_secret)

        # 3. Decrypt the actual DBK
        return Encryptor.decrypt(derived_key, ciphertext, iv, tag)
    
    