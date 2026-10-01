# handles ed25519 and ecdsa signing and verification
# use the cryptgraphy library for all cryptographuc operation

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

CURVE_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
N_HALF = CURVE_N // 2

class Signer:
    SIGNATURE_SIZE = 64
    
    @staticmethod
    def sign(private_key, message: bytes, tag: str = "") -> bytes:
        # sign_input(tag, payload) = tag || 0x00 || payload
        # If tag is empty, sign the raw message for compatibility
        if not tag:
            tagged_message = message
        else:
            tagged_message = tag.encode() + b'\x00' + message

        if isinstance(private_key, Ed25519PrivateKey):
            return private_key.sign(tagged_message)
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            der = private_key.sign(tagged_message, ec.ECDSA(hashes.SHA256()))
            return Signer.normalize(der)
        raise TypeError("Unsupported private key type")

    @staticmethod
    def verify(public_key, message: bytes, signature: bytes, tag: str = "") -> bool:
        if len(signature) != Signer.SIGNATURE_SIZE:
            return False

        if not tag:
            tagged_message = message
        else:
            tagged_message = tag.encode() + b'\x00' + message

        try:
            if isinstance(public_key, Ed25519PublicKey):
                public_key.verify(signature, tagged_message)
                return True
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # Enforce Low-S
                r_val, s_val = utils.decode_dss_signature(Signer.denormalize(signature))
                if s_val > N_HALF:
                    return False

                der = Signer.denormalize(signature)
                public_key.verify(der, tagged_message, ec.ECDSA(hashes.SHA256()))
                return True
            # Handle bytes (assumes Ed25519 if 32 bytes)
            elif isinstance(public_key, bytes):
                if len(public_key) == 32:
                    pub_key_obj = Ed25519PublicKey.from_public_bytes(public_key)
                    pub_key_obj.verify(signature, tagged_message)
                    return True
                else:
                    # Try parsing as SPKI (for ECDSA)
                    pub_key_obj = serialization.load_der_public_key(public_key)
                    return Signer.verify(pub_key_obj, message, signature, tag)
            else:
                return False
        except Exception:
            return False
    
    @staticmethod
    def normalize(der: bytes) -> bytes:
        r_val, s_val = utils.decode_dss_signature(der)
        if s_val > N_HALF:
            s_val = CURVE_N - s_val
        return r_val.to_bytes(32, 'big') + s_val.to_bytes(32, 'big')

    @staticmethod
    def denormalize(sig64: bytes) -> bytes:
        r_val = int.from_bytes(sig64[:32], 'big')
        s_val = int.from_bytes(sig64[32:], 'big')
        return utils.encode_dss_signature(r_val, s_val)

    @staticmethod
    def sign_with_bytes(private_key_bytes: bytes, message: bytes, tag: str = "") -> bytes:
        if len(private_key_bytes) != 32:
            raise ValueError("Private key must be 32 bytes")
        
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return Signer.sign(private_key, message, tag)
    
    @staticmethod
    def verify_with_bytes(public_key_bytes: bytes, message: bytes, signature: bytes, tag: str = "") -> bool:
        return Signer.verify(public_key_bytes, message, signature, tag)
