"""Lite Wallet Manager for offline spending - Firebase Implementation."""

from __future__ import annotations

import time
from typing import Optional, Tuple, Dict, Any

from .firebase_db import FirebaseDB
from .key_manager import KeyManager
from .signer import Signer
from .encryptor import Encryptor
from .protocol import ShadowProtocol
from .logging_utils import get_logger

logger = get_logger("offlinepay.lite")

class LiteWalletManager:
    """Manage Lite Wallet (offline bucket) operations with Firebase."""
    
    LITE_EXPIRY_SECONDS = 604800  # 7 days
    MAX_LITE_BALANCE = 200000     # Strictly ₹2,000 (200,000 paisa) to match App
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
        
    def topup_lite(
        self,
        wallet_id: str,
        amount: int,
        aes_key: bytes,
        server_private_key: bytes,
        server_public_key: bytes,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Top up the lite wallet from the main balance."""
        
        # 1. Validate amount
        if amount <= 0:
            return False, "Amount must be positive", {}
        if amount > self.MAX_LITE_BALANCE:
            return False, f"Amount exceeds max lite balance of ${self.MAX_LITE_BALANCE/100:.2f}", {}
        
        # 2. Get main bucket and check balance
        main_bucket = self.db.get_bucket(wallet_id)
        if not main_bucket:
            return False, "Wallet not found", {}
        
        main_balance = main_bucket.get("balance", 0)
        if main_balance < amount:
            return False, f"Insufficient main balance: {main_balance} < {amount}", {}
        
        # 3. Get lite bucket current state
        lite_data = self.db.get_lite_bucket(wallet_id)
        current_lite_balance = lite_data.get("lite_balance", 0) if lite_data else 0
        current_lite_counter = lite_data.get("lite_counter", 0) if lite_data else 0
        
        # 4. Calculate new lite state
        new_lite_balance = current_lite_balance + amount
        new_lite_counter = current_lite_counter + 1
        
        # 5. Create server signature for the lite bucket
        now = int(time.time())
        expiry = now + self.LITE_EXPIRY_SECONDS
        # Standardized format: wallet_id|balance|counter|expiry
        bucket_data = f"{wallet_id}|{new_lite_balance}|{new_lite_counter}|{expiry}".encode()
        # Secure Tagged signing for production
        server_signature = Signer.sign_with_bytes(server_private_key, bucket_data, ShadowProtocol.TAG_TOPUP)
        
        # 6. Encrypt lite balance and counter
        balance_data = str(new_lite_balance).encode()
        counter_data = str(new_lite_counter).encode()
        
        encrypted_balance, iv_balance, tag_balance = Encryptor.encrypt(aes_key, balance_data)
        encrypted_counter, iv_counter, tag_counter = Encryptor.encrypt(aes_key, counter_data)
        
        encrypted_balance_with_iv = iv_balance + tag_balance + encrypted_balance
        encrypted_counter_with_iv = iv_counter + tag_counter + encrypted_counter
        
        # 7. Update main balance (deduct)
        new_main_balance = main_balance - amount
        main_update = {
            "balance": new_main_balance,
            "updated_at": now
        }
        
        if not self.db.update_bucket(wallet_id, main_update):
            return False, "Failed to update main balance", {}
        
        # 8. Update lite bucket (add)
        lite_update = {
            "lite_balance": new_lite_balance,
            "lite_counter": new_lite_counter,
            "lite_encrypted_balance": encrypted_balance_with_iv,
            "lite_encrypted_counter": encrypted_counter_with_iv,
            "lite_server_signature": server_signature,
            "lite_expires_at": expiry,
            "lite_last_synced": now,
            "updated_at": now
        }
        
        if not self.db.update_lite_bucket(wallet_id, lite_update):
            # Rollback main balance
            rollback = {"balance": main_balance}
            self.db.update_bucket(wallet_id, rollback)
            return False, "Failed to update lite bucket", {}
        
        return True, None, {
            "wallet_id": wallet_id,
            "main_balance_after": new_main_balance,
            "lite_balance_after": new_lite_balance,
            "lite_counter": new_lite_counter,
            "lite_server_signature": server_signature.hex(),
            "expires_at": expiry,
            "issued_at": now,
            "encrypted_balance": encrypted_balance_with_iv.hex(),
            "encrypted_counter": encrypted_counter_with_iv.hex(),
        }
    
    def get_lite_balance(
        self,
        wallet_id: str,
        aes_key: bytes,
    ) -> Optional[Dict[str, Any]]:
        """Get lite wallet balance and state."""
        
        lite_data = self.db.get_lite_bucket(wallet_id)
        if not lite_data:
            return {
                "lite_balance": 0,
                "lite_counter": 0,
                "expires_at": 0,
                "is_active": False,
                "last_synced": 0,
            }
        
        # Check expiry
        expires_at = lite_data.get("lite_expires_at", 0)
        is_expired = expires_at < int(time.time())
        
        # Decrypt balance if encrypted
        encrypted_balance_with_iv = lite_data.get("lite_encrypted_balance")
        balance = lite_data.get("lite_balance", 0)
        
        if encrypted_balance_with_iv and isinstance(encrypted_balance_with_iv, bytes) and len(encrypted_balance_with_iv) > 28:
            try:
                iv_balance = encrypted_balance_with_iv[:12]
                tag_balance = encrypted_balance_with_iv[12:28]
                encrypted_balance = encrypted_balance_with_iv[28:]
                balance_bytes = Encryptor.decrypt(aes_key, encrypted_balance, iv_balance, tag_balance)
                balance = int(balance_bytes.decode())
            except Exception as e:
                logger.warning(f"Failed to decrypt lite balance for {wallet_id}: {e}")
        
        return {
            "lite_balance": balance,
            "lite_counter": lite_data.get("lite_counter", 0),
            "expires_at": expires_at,
            "is_active": not is_expired,
            "last_synced": lite_data.get("lite_last_synced", 0),
        }
    
    def verify_lite_signature(
        self,
        wallet_id: str,
        lite_balance: int,
        lite_counter: int,
        expires_at: int,
        server_signature: bytes,
        server_public_key: bytes,
    ) -> bool:
        """Verify lite wallet server signature."""
        # Standardized format: wallet_id|balance|counter|expiry
        bucket_data = f"{wallet_id}|{lite_balance}|{lite_counter}|{expires_at}".encode()
        return Signer.verify_with_bytes(ShadowProtocol.TAG_TOPUP, server_public_key, bucket_data, server_signature)
