# handles ed25519 signing and verification
# use the cryptgraphy library for all cryptographuc operation

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,Ed25519PrivateKey
)

class Signer:
    SIGNATURE_SIZE = 64
    
    @staticmethod
    def sign(private_key:Ed25519PrivateKey,message:bytes)->bytes:
        # sign a message using ed25519 private key
        return private_key.sign(message)
    @staticmethod
    def verify(public_key:Ed25519PublicKey,message:bytes,signature:bytes)->bool:
        # verify a message signature
        try:
            if isinstance(public_key, Ed25519PublicKey):
                public_key.verify(signature, message)
                return True
            # Handle bytes
            elif isinstance(public_key, bytes):
                if len(public_key) != 32:
                    return False
                pub_key_obj = Ed25519PublicKey.from_public_bytes(public_key)
                pub_key_obj.verify(signature, message)
                return True
            else:
                return False
        except Exception:
            return False
    
    @staticmethod
    def sign_with_bytes(private_key_bytes:bytes,message:bytes)->bytes:
        # sign message using raw private key bytes
        if len(private_key_bytes)!=32:
            raise ValueError("Private key must be 32 bytes")
        
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return private_key.sign(message)
    
    @staticmethod
    def verify_with_bytes(public_key_bytes:bytes,message:bytes,signature:bytes)->bool:
        # verify signature using raw publickey bytes
        if not isinstance(public_key_bytes, bytes):
        # If it's an Ed25519PublicKey object, extract raw bytes
            if hasattr(public_key_bytes, 'public_bytes'):
                from cryptography.hazmat.primitives import serialization
                public_key_bytes = public_key_bytes.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                raise TypeError("Public key must be bytes")
        if len(public_key_bytes)!=32:
            raise ValueError("Public key must be 32 bytes")
        if len(signature)!=64:
            raise ValueError("Signature must be 64 bytes")
        
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature,message)
            return True
        except Exception:
            return False
    