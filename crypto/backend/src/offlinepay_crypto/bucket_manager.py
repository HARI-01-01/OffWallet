# handle offline bucket business logic
# manages balance, counter and server signature verification
import time
from typing import Optional, Tuple, Any
from .firebase_db import FirebaseDB
from .encryptor import Encryptor
from .signer import Signer
from .logging_utils import get_logger

logger = get_logger("offlinepay.bucket")

class BucketManager:
    BUCKET_EXPIRY_SECONDS = 86400
    MAX_BALANCE = 1000000
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
    
    # Core operation
    
    def create_bucket(self,
                      wallet_id: str,
                      initial_balance: int,
                      aes_key: bytes,
                      server_public_key: bytes,
                      server_signature: bytes
                      ) -> bool:
        # create a new offline bucket with pre-loaded funds.
        # ✅ Standardized format: wallet_id|balance|counter
        bucket_data = f"{wallet_id}|{initial_balance}|0".encode()
        is_valid = Signer.verify_with_bytes(
            server_public_key,
            bucket_data,
            server_signature
        )
        if not is_valid:
            logger.error(f"Invalid server signature for {wallet_id}. Data: {bucket_data}")
            raise ValueError("Invalid server signature")
        
        balance_data = str(initial_balance).encode()
        counter_data = b"0"
        encrypted_balance, iv_balance, tag_balance = Encryptor.encrypt(
            aes_key, balance_data
        )
        encrypted_counter, iv_counter, tag_counter = Encryptor.encrypt(
            aes_key, counter_data
        )
        
        encrypted_balance_with_iv = iv_balance + tag_balance + encrypted_balance
        encrypted_counter_with_iv = iv_counter + tag_counter + encrypted_counter
        
        bucket_data_dict = {
            "wallet_id": wallet_id,
            "balance": initial_balance,
            "counter": 0,
            "encrypted_balance": encrypted_balance_with_iv,
            "encrypted_counter": encrypted_counter_with_iv,
            "server_signature": server_signature,
            "expires_at": int(time.time()) + self.BUCKET_EXPIRY_SECONDS,
            "status": "ACTIVE",
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "last_synced": int(time.time())
        }
        return self.db.create_bucket(wallet_id, bucket_data_dict)
        
    def get_bucket(self, wallet_id: str, aes_key: bytes) -> Optional[dict]:
        bucket = self.db.get_bucket(wallet_id)
        if not bucket:
            return None
        
        encrypted_balance_with_iv = bucket.get('encrypted_balance')
        encrypted_counter_with_iv = bucket.get('encrypted_counter')
        balance = bucket.get('balance', 0)
        counter = bucket.get('counter', 0)
        
        # Decrypt balance if encrypted and exists
        if encrypted_balance_with_iv and isinstance(encrypted_balance_with_iv, bytes) and len(encrypted_balance_with_iv) > 28:
            try:
                iv_balance = encrypted_balance_with_iv[:12]
                tag_balance = encrypted_balance_with_iv[12:28]
                encrypted_balance = encrypted_balance_with_iv[28:]
                balance_bytes = Encryptor.decrypt(
                    aes_key, encrypted_balance, iv_balance, tag_balance
                )
                balance = int(balance_bytes.decode())
            except Exception as e:
                logger.warning(f"Failed to decrypt balance for {wallet_id}: {e}")
                pass

        # Decrypt counter if encrypted and exists
        if encrypted_counter_with_iv and isinstance(encrypted_counter_with_iv, bytes) and len(encrypted_counter_with_iv) > 28:
            try:
                iv_counter = encrypted_counter_with_iv[:12]
                tag_counter = encrypted_counter_with_iv[12:28]
                encrypted_counter = encrypted_counter_with_iv[28:]
                counter_bytes = Encryptor.decrypt(
                    aes_key, encrypted_counter, iv_counter, tag_counter
                )
                counter = int(counter_bytes.decode())
            except Exception as e:
                pass

        return {
            'wallet_id': wallet_id,
            'balance': balance,
            'counter': counter,
            'status': bucket.get('status', 'ACTIVE'),
            'created_at': bucket.get('created_at', 0),
            'expires_at': bucket.get('expires_at', 0),
            'last_synced': bucket.get('last_synced', 0),
        }
        
    def deduct_funds(self, wallet_id: str, amount: int, aes_key: bytes) -> Tuple[bool, int, int, Optional[str]]:
        bucket = self.get_bucket(wallet_id, aes_key)
        if not bucket:
            return False, 0, 0, "Bucket not found"
        
        if bucket['status'] != 'ACTIVE':
            return False, 0, 0, f"Bucket is {bucket['status']}"
        
        if bucket['expires_at'] < int(time.time()):
            return False, 0, 0, "Bucket expired"
        
        if bucket['balance'] < amount:
            return False, 0, 0, "Insufficient balance"
        
        new_balance = bucket['balance'] - amount
        new_counter = bucket['counter'] + 1
        
        update_data = {
            "balance": new_balance,
            "counter": new_counter,
            "last_synced": int(time.time()),
            "updated_at": int(time.time())
        }
        success = self.db.update_bucket(wallet_id, update_data)
        if success:
            return True, new_balance, new_counter, None
        else:
            return False, 0, 0, "Failed to update bucket"

    def add_funds(
        self,
        wallet_id: str,
        amount: int,
        aes_key: bytes,
        server_public_key: bytes,
        server_signature: bytes,
    ) -> Tuple[bool, int, Optional[str]]:
        # add funds to bucket (online replenishment)
        bucket = self.get_bucket(wallet_id, aes_key)
        if not bucket:
            return False, 0, "Bucket not found"
        
        new_balance = bucket['balance'] + amount
        # ✅ Standardized format: wallet_id|balance|counter
        bucket_data = f"{wallet_id}|{new_balance}|{bucket['counter']}".encode()
        is_valid = Signer.verify_with_bytes(
            server_public_key,
            bucket_data,
            server_signature
        )
        if not is_valid:
            return False, 0, "Invalid server signature"
        
        balance_data = str(new_balance).encode()
        encrypted_balance, iv_balance, tag_balance = Encryptor.encrypt(
            aes_key, balance_data
        )
        encrypted_balance_with_iv = iv_balance + tag_balance + encrypted_balance

        update_data = {
            "balance": new_balance,
            "encrypted_balance": encrypted_balance_with_iv,
            "server_signature": server_signature,
            "expires_at": int(time.time()) + self.BUCKET_EXPIRY_SECONDS,
            "last_synced": int(time.time()),
            "status": "ACTIVE",
            "updated_at": int(time.time())
        }
        success = self.db.update_bucket(wallet_id, update_data)
        return (success, new_balance, None) if success else (False, 0, "Failed to update bucket")

    def check_balance(self, wallet_id: str, aes_key: bytes) -> Optional[int]:
        """Get current balance."""
        bucket = self.get_bucket(wallet_id, aes_key)
        return bucket['balance'] if bucket else None

    def get_counter(self, wallet_id: str, aes_key: bytes) -> Optional[int]:
        """Get current counter."""
        bucket = self.get_bucket(wallet_id, aes_key)
        return bucket['counter'] if bucket else None

    def freeze_bucket(self, wallet_id: str) -> bool:
        """Freeze bucket (fraud prevention)."""
        return self.db.update_bucket(wallet_id, {"status": "FROZEN"})

    def activate_bucket(self, wallet_id: str) -> bool:
        """Activate a frozen bucket."""
        return self.db.update_bucket(wallet_id, {"status": "ACTIVE"})

    def get_bucket_status(self, wallet_id: str) -> Optional[str]:
        """Get bucket status."""
        bucket = self.db.get_bucket(wallet_id)
        return bucket.get('status') if bucket else None

    def verify_server_signature(
        self,
        wallet_id: str,
        balance: int,
        counter: int,
        server_public_key: bytes,
        server_signature: bytes,
    ) -> bool:
        # ✅ Standardized format: wallet_id|balance|counter
        bucket_data = f"{wallet_id}|{balance}|{counter}".encode()
        return Signer.verify_with_bytes(
            server_public_key,
            bucket_data,
            server_signature
        )
