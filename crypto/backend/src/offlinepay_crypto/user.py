#  handles user onboarding and bucket funding
import time
import uuid
from typing import Optional, Tuple, Dict, Any, List
import hashlib
from .database import Database
from .bucket_manager import BucketManager
from .wallet_core import WalletCore
from .key_manager import KeyManager
from .signer import Signer
from .encryptor import Encryptor
from .hasher import Hasher


class UserManager:

    # 2FA: In production, use TOTP (Google Authenticator)
    DEFAULT_2FA_CODE = "123456"

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.wallet = WalletCore(self.db)
        self._users = {}
        self._otp_cache = {}

    def register_user(
        self,
        email: str,
        phone: str,
        password: str,
        initial_balance: int = 0,
        server_private_key: Optional[bytes] = None,
        server_public_key: Optional[bytes] = None,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        

        wallet_id = self._generate_wallet_id(email)
        if self._user_exists(wallet_id):
            return False, "User already exists", {}

        if server_private_key is None or server_public_key is None:
            server_priv, server_pub = KeyManager.generate_key_pair()
            server_private_key = KeyManager.private_key_to_bytes(server_priv)
            server_public_key = KeyManager.public_key_to_bytes(server_pub)

        bucket_data = f"{wallet_id}:{initial_balance}:0".encode()
        server_signature = Signer.sign_with_bytes(server_private_key, bucket_data)
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        success, priv_key, pub_key, aes_key, error = self.wallet.create_wallet(
            wallet_id=wallet_id,
            initial_balance=initial_balance,
            server_public_key=server_public_key,
            server_signature=server_signature,
        )

        if not success:
            return False, error, {}

        self.db.create_user(
            wallet_id=wallet_id,
            email=email,
            phone=phone,
            password_hash=password_hash,
            public_key=pub_key,
        )

        self._users[wallet_id] = {
            'wallet_id': wallet_id,
            'email': email,
            'phone': phone,
            'password_hash': password_hash,
            'private_key': priv_key.hex(),
            'public_key': pub_key.hex(),
            'aes_key': aes_key.hex(),
            'created_at': int(time.time()),
        }

        return True, None, {
            'wallet_id': wallet_id,
            'public_key': pub_key.hex(),
            'private_key': priv_key.hex(),
            'aes_key': aes_key.hex(),
        }

    def _generate_wallet_id(self, email: str) -> str:
        return f"user_{hashlib.sha256(email.encode()).hexdigest()[:8]}"

    def _user_exists(self, wallet_id: str) -> bool:
        return wallet_id in self._users or self.db.get_user(wallet_id) is not None


    def generate_2fa_code(self, wallet_id: str) -> str:
        import random
        otp = f"{random.randint(100000, 999999)}"
        self._otp_cache[wallet_id] = {
            'code': otp,
            'expires_at': int(time.time()) + 300,  # 5 minutes
        }
        return otp

    def verify_2fa_code(self, wallet_id: str, code: str) -> bool:
        cached = self._otp_cache.get(wallet_id)
        if not cached:
            return False
        if int(time.time()) > cached['expires_at']:
            return False
        return cached['code'] == code

    def add_funds(
        self,
        wallet_id: str,
        amount: int,
        aes_key: bytes,
        server_private_key: bytes,
        server_public_key: bytes,
        twofa_code: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:

        # 1. Verify 2FA (in production, use actual 2FA)
        if twofa_code and not self.verify_2fa_code(wallet_id, twofa_code):
            return False, "Invalid 2FA code", {}

        bucket = self.db.get_bucket(wallet_id)
        if not bucket:
            return False, "Wallet not found", {}

        current_balance = bucket.get('balance', 0)
        new_balance = current_balance + amount

        counter = bucket.get('counter', 0)
        bucket_data = f"{wallet_id}:{new_balance}:{counter}".encode()
        server_signature = Signer.sign_with_bytes(server_private_key, bucket_data)

        success, new_balance, error = self.wallet.bucket.add_funds(
            wallet_id=wallet_id,
            amount=amount,
            aes_key=aes_key,
            server_public_key=server_public_key,
            server_signature=server_signature,
        )

        if not success:
            return False, error, {}

        return True, None, {
            'wallet_id': wallet_id,
            'old_balance': current_balance,
            'added_amount': amount,
            'new_balance': new_balance,
        }


    def get_balance(self, wallet_id: str, aes_key: bytes) -> Optional[int]:
        return self.wallet.get_balance(wallet_id, aes_key)

    def get_user_info(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        user = self._users.get(wallet_id)
        if not user:
            bucket = self.db.get_bucket(wallet_id)
            if bucket:
                return {
                    'wallet_id': wallet_id,
                    'balance': bucket.get('balance', 0),
                    'counter': bucket.get('counter', 0),
                    'status': bucket.get('status', 'UNKNOWN'),
                }
            return None
        return user

    def freeze_account(self, wallet_id: str) -> bool:
        return self.db.update_bucket(
            wallet_id=wallet_id,
            status='FROZEN',
        )

    def unfreeze_account(self, wallet_id: str) -> bool:
        return self.db.update_bucket(
            wallet_id=wallet_id,
            status='ACTIVE',
        )

    def get_transaction_history(
        self,
        wallet_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        pending = self.db.get_pending_transactions(limit=limit)
        return [tx for tx in pending if tx.get('payer_id') == wallet_id or tx.get('payee_id') == wallet_id]

    def check_bucket_status(self, wallet_id: str) -> Optional[str]:
        bucket = self.db.get_bucket(wallet_id)
        return bucket.get('status') if bucket else None