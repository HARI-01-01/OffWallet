"""User Manager with Firebase Auth and Firestore."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Optional, Tuple, Dict, Any, List

from firebase_admin import auth as firebase_auth

from .firebase_db import FirebaseDB
from .bucket_manager import BucketManager
from .key_manager import KeyManager
from .signer import Signer
from .encryptor import Encryptor
from .logging_utils import get_logger

logger = get_logger("offlinepay.user")

class UserManagerFirebase:
    """User manager with Firebase integration."""
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
        self.bucket = BucketManager(self.db)
        self._otp_cache = {}
    
    def register_user_with_firebase(
        self,
        email: str,
        phone: str,
        password: str,
        full_name: str,
        date_of_birth: str,
        country: str,
        public_key: bytes,
        device_id: str,
        initial_balance: int = 0,
        wallet_name: str = "My Wallet",
        currency: str = "USD",
        device_name: Optional[str] = None,
        os_version: Optional[str] = None,
        app_version: Optional[str] = None,
        push_token: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Register a new user with Firebase Auth and Firestore.
        """
        try:
            # 1. Create Firebase Auth user
            try:
                firebase_user = firebase_auth.create_user(
                    email=email,
                    password=password,
                    phone_number=phone,
                    display_name=full_name,
                    disabled=False,
                )
                wallet_id = f"user_{firebase_user.uid}"
            except firebase_auth.EmailAlreadyExistsError:
                return False, "Email already registered", {}
            except Exception as e:
                logger.error(f"Firebase auth error: {e}")
                return False, f"Auth error: {str(e)}", {}
            
            # 2. Get Master Server Key
            server_private_key, server_public_key = KeyManager.get_master_server_key()
            server_private_key_bytes = KeyManager.private_key_to_bytes(server_private_key)
            server_public_key_bytes = KeyManager.public_key_to_bytes(server_public_key)
            
            # 3. Create wallet with server signature
            # ✅ Standardized format: wallet_id|balance|counter
            bucket_data = f"{wallet_id}|{initial_balance}|0".encode()
            server_signature = Signer.sign_with_bytes(server_private_key_bytes, bucket_data)
            
            # 4. Generate wallet keys
            aes_key = Encryptor.generate_key()
            
            # 5. Create bucket
            bucket_success = self.bucket.create_bucket(
                wallet_id=wallet_id,
                initial_balance=initial_balance,
                aes_key=aes_key,
                server_public_key=server_public_key_bytes,
                server_signature=server_signature,
            )
            
            if not bucket_success:
                # Rollback Firebase user
                firebase_auth.delete_user(firebase_user.uid)
                return False, "Failed to create bucket", {}
            
            # 6. Save user in Firestore
            user_data = {
                "email": email,
                "phone": phone,
                "full_name": full_name,
                "firebase_uid": firebase_user.uid,
                "public_key": public_key.hex(),
                "aes_key": aes_key.hex(),
                "server_public_key": server_public_key_bytes.hex(),
                "server_signature": server_signature.hex(),
                "status": "ACTIVE",
                "email_verified": False,
                "phone_verified": False,
                "created_at": int(time.time()),
                "updated_at": int(time.time()),
            }
            self.db.create_user(wallet_id, user_data)
            
            # 7. Save user metadata
            meta_data = {
                "full_name": full_name,
                "date_of_birth": date_of_birth,
                "country": country,
                "wallet_name": wallet_name,
                "currency": currency,
                "device_id": device_id,
                "device_name": device_name,
                "os_version": os_version,
                "app_version": app_version,
                "push_token": push_token,
            }
            self.db.create_user_meta(wallet_id, meta_data)

            return True, None, {
                "wallet_id": wallet_id,
                "firebase_uid": firebase_user.uid,
                "public_key": public_key.hex(),
                "aes_key": aes_key.hex(),
                "server_public_key": server_public_key_bytes.hex(),
                "server_signature": server_signature.hex(),
                "message": "User registered successfully.",
            }
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False, str(e), {}

    def get_user_info(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        """Get user information."""
        user = self.db.get_user(wallet_id)
        meta = self.db.get_user_meta(wallet_id)
        
        if not user:
            return None
        
        return {
            "wallet_id": wallet_id,
            "email": user.get("email"),
            "phone": user.get("phone"),
            "full_name": user.get("full_name"),
            "status": user.get("status"),
            ** (meta if meta else {}),
        }
