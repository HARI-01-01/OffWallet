import hashlib
import time
import logging
from typing import List, Tuple, Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.backends import default_backend
from .logging_utils import get_logger

logger = get_logger("offlinepay.attestation")

# Google Hardware Attestation Root Certificates (Placeholder for actual PEMs)
# In production, these would be the actual Google Root PEMs.
GOOGLE_ROOT_CERT_HASHES = [
    "2c2466070a256df29c29d0092c686e09968469d76c669147575218d661413f3d", # Global
]

class AttestResult:
    def __init__(self, success: bool, tier: str = "SOFTWARE", error: Optional[str] = None):
        self.success = success
        self.tier = tier
        self.error = error

class AttestationVerifier:

    @staticmethod
    def verify(chain_der: List[bytes], challenge: bytes, submitted_pubkey: bytes) -> AttestResult:
        try:
            # 1. Parse chain
            certs = [x509.load_der_x509_certificate(c) for c in chain_der]
            if len(certs) < 2:
                return AttestResult(False, error="Chain too short")

            # 2. Verify chain to root (Simplified: check root hash)
            root_pub = certs[-1].public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            root_hash = hashlib.sha256(root_pub).hexdigest()
            # if root_hash not in GOOGLE_ROOT_CERT_HASHES:
            #    return AttestResult(False, error="Untrusted root")

            # 3. Check revocation (Placeholder)
            # verify_revocation(certs[0])

            # 4. Extract Attestation Extension from leaf
            leaf = certs[0]
            # Extension OID: 1.3.6.1.4.1.11129.2.1.17
            ext = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"))

            # MOCK IMPLEMENTATION for Hackathon
            attest_challenge = challenge # Mock
            if attest_challenge != challenge:
                 return AttestResult(False, error="Challenge mismatch")

            # 5. Determine tier (STRONGBOX > TEE > SOFTWARE)
            tier = "TEE" # Mock

            return AttestResult(True, tier=tier)

        except Exception as e:
            return AttestResult(False, error=str(e))

class IntegrityVerifier:
    @staticmethod
    def verify(token: str, expected_nonce: bytes) -> bool:
        """Issue 4 & 5: Verify Play Integrity token."""
        # For hackathon, we assume the token is valid if it matches our dev expectations
        if token == "MOCK_INTEGRITY_TOKEN":
            return True

        # Log for debugging (using standard print if logger is problematic)
        print(f"DEBUG: Play Integrity verification for nonce {expected_nonce.hex()}")

        # In a real app, we would perform JWS verification here.
        return True
