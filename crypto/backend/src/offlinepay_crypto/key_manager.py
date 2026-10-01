#  handles ed25519 key generation and serialization
#  use the cryptogrphy library for all cryptographic operation

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization


class KeyManager:
    PRIVATE_KEY_SIZE = 32
    PUBLIC_KEY_SIZE = 32
    
    @staticmethod
    def generate_key_pair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        """Generate a new Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_ephemeral_key_pair() -> tuple[X25519PrivateKey, X25519PublicKey]:
        """Generate a new X25519 key pair for EKE."""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def private_key_to_bytes(private_key: Ed25519PrivateKey | X25519PrivateKey) -> bytes:
        """Convert private key to 32 bytes for storage/transmission."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def public_key_to_bytes(public_key: Ed25519PublicKey | X25519PublicKey) -> bytes:
        """Convert public key to 32 bytes for storage/transmission."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    
    @staticmethod
    def bytes_to_private_key(data: bytes, alg: str = "Ed25519") -> Ed25519PrivateKey | X25519PrivateKey:
        if len(data) != KeyManager.PRIVATE_KEY_SIZE:
            raise ValueError(f"private key must be {KeyManager.PRIVATE_KEY_SIZE} bytes")
        if alg == "X25519":
            return X25519PrivateKey.from_private_bytes(data)
        return Ed25519PrivateKey.from_private_bytes(data)
    
    @staticmethod
    def bytes_to_public_key(data: bytes, alg: str = "Ed25519") -> Ed25519PublicKey | X25519PublicKey:
        if len(data) != KeyManager.PUBLIC_KEY_SIZE:
            raise ValueError(f"public key must be {KeyManager.PUBLIC_KEY_SIZE} bytes")
        if alg == "X25519":
            return X25519PublicKey.from_public_bytes(data)
        return Ed25519PublicKey.from_public_bytes(data)

    @staticmethod
    def get_master_server_key() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        """Load the persistent master server key from file or generate a new one."""
        key_file = Path("server_master.key")
        if key_file.exists():
            with open(key_file, "rb") as f:
                private_bytes = f.read()
                private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
                return private_key, private_key.public_key()
        else:
            private_key, public_key = KeyManager.generate_key_pair()
            with open(key_file, "wb") as f:
                f.write(KeyManager.private_key_to_bytes(private_key))
            return private_key, public_key
