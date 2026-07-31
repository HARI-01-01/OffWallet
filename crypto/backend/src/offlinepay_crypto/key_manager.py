#  handles ed25519 key generation and serialization
#  use the cryptogrphy library for all cryptographic operation

import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization


class KeyManager:
    PRIVATE_KEY_SIZE = 32
    PUBLIC_KEY_SIZE = 32
    
    @staticmethod
    def generate_key_pair()->tuple[Ed25519PrivateKey,Ed25519PublicKey]:
        # generate a new ed25519 key pair
       
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key,public_key
    @staticmethod
    def private_key_to_bytes(private_key:Ed25519PrivateKey)->bytes:
        # convert private key to 32 bytes for storage/transmission
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    @staticmethod
    def public_key_to_bytes(public_key:Ed25519PublicKey)->bytes:
        # convert public key to 32 bytes for storage/transmission
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    
    @staticmethod
    def bytes_to_private_key(data:bytes)->Ed25519PrivateKey:
        if len(data)!=KeyManager.PRIVATE_KEY_SIZE:
            raise ValueError(f"private key must be {KeyManager.PRIVATE_KEY_SIZE} bytes")
        return Ed25519PrivateKey.from_private_bytes(data)
    
    @staticmethod
    def bytes_to_public_key(data:bytes)->Ed25519PublicKey:
        if len(data)!=KeyManager.PUBLIC_KEY_SIZE:
            raise ValueError(f"public key must be {KeyManager.PUBLIC_KEY_SIZE} bytes")
        return Ed25519PublicKey.from_public_bytes(data)