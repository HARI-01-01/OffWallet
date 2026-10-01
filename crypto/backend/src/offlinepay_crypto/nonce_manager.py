import secrets
import time
from typing import Optional, Dict, Any, Tuple
from .firebase_db import FirebaseDB
from .signer import Signer
from .key_manager import KeyManager
from .logging_utils import get_logger

logger = get_logger("offlinepay.nonce")

class NonceManager:
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()

    def request_nonce(self, wallet_id: str, device_id: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Generate and sign a new session nonce for a wallet."""
        try:
            # Check if user exists
            user = self.db.get_user(wallet_id)
            if not user:
                logger.error(f"Nonce request failed: User {wallet_id} not found in database.")
                return False, "User not found", {}

            # Check if bucket exists
            bucket = self.db.get_bucket(wallet_id)
            if not bucket:
                logger.error(f"Nonce request failed: Bucket for user {wallet_id} is missing.")
                return False, "Wallet bucket not found", {}

            # Generate random 32-byte nonce
            nonce_value = secrets.token_hex(32)
            nonce_id = f"nonce_{int(time.time())}_{secrets.token_hex(4)}"

            # Get latest nonce to increment sequence
            latest = self.db.get_latest_nonce(wallet_id)
            sequence = (latest.get("sequence_number", 0) if latest else 0) + 1

            # Sign nonce with server master key
            server_private_key, _ = KeyManager.get_master_server_key()
            server_private_key_bytes = KeyManager.private_key_to_bytes(server_private_key)

            # Nonce signing format: nonce_id|nonce_value|wallet_id|device_id|sequence
            signing_data = f"{nonce_id}|{nonce_value}|{wallet_id}|{device_id}|{sequence}".encode()
            signature = Signer.sign_with_bytes(server_private_key_bytes, signing_data)

            expires_at = int(time.time()) + 86400  # 24 hours

            nonce_data = {
                "nonce_value": nonce_value,
                "wallet_id": wallet_id,
                "device_id": device_id,
                "sequence_number": sequence,
                "server_signature": signature.hex(),
                "expires_at": expires_at,
                "status": "ACTIVE"
            }

            if self.db.create_nonce(nonce_id, nonce_data):
                # Mark previous nonces as USED
                if latest:
                    self.db.update_nonce_status(latest["nonce_id"], "USED")

                return True, None, {
                    "nonce_id": nonce_id,
                    "nonce_value": nonce_value,
                    "sequence_number": sequence,
                    "server_signature": signature.hex(),
                    "expires_at": expires_at
                }
            else:
                return False, "Failed to store nonce", {}

        except Exception as e:
            return False, str(e), {}

    def verify_nonce(self, nonce_value: str, wallet_id: str) -> bool:
        """Verify if a nonce is valid and active for the wallet."""
        latest = self.db.get_latest_nonce(wallet_id)
        if not latest:
            return False

        if latest["nonce_value"] != nonce_value:
            return False

        if latest["expires_at"] < int(time.time()):
            self.db.update_nonce_status(latest["nonce_id"], "EXPIRED")
            return False

        return latest["status"] == "ACTIVE"
