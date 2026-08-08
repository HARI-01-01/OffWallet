# main orchestrator for offline payment wallet

import time
import uuid
from typing import Optional, List, Dict, Any, Tuple
from .firebase_db import FirebaseDB
from .bucket_manager import BucketManager
from .queue_manager import QueueManager
from .key_manager import KeyManager
from .signer import Signer
from .encryptor import Encryptor
from .hasher import Hasher

class WalletCore:
    
    # create wallet, add funds, send payment, syc
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
        self.bucket = BucketManager(self.db)
        self.queue = QueueManager(self.db)
        
    
    # wallet setup
    def create_wallet(
        self,
        wallet_id: str,
        initial_balance: int,
        server_public_key: bytes,
        server_signature: bytes,
    ) -> Tuple[bool, bytes, bytes, bytes, Optional[str]]:
        # create a new wallet with offline bucket
        private_key, public_key = KeyManager.generate_key_pair()
        private_key_bytes = KeyManager.private_key_to_bytes(private_key)
        public_key_bytes = KeyManager.public_key_to_bytes(public_key)
        
        aes_key = Encryptor.generate_key()
        
        try:
            self.bucket.create_bucket(
                wallet_id=wallet_id,
                initial_balance=initial_balance,
                aes_key=aes_key,
                server_public_key=server_public_key,
                server_signature=server_signature      
            )
        except ValueError as e:
            return False, b"", b"", b"", str(e)
        
        return True, private_key_bytes, public_key_bytes, aes_key, "no error"
    
    # balance management
    def add_funds(
        self,
        wallet_id: str,
        amount: int,
        aes_key: bytes,
        server_public_key: bytes,
        server_signature: bytes,
    ) -> Tuple[bool, int, Optional[str]]:
        # add funds to offline bucket (online replenishment)
        
        return self.bucket.add_funds(
            wallet_id,
            amount,
            aes_key,
            server_public_key,
            server_signature
        )

    def get_balance(self, wallet_id: str, aes_key: bytes) -> Optional[int]:
        return self.bucket.check_balance(wallet_id, aes_key)
    
    def get_counter(self, wallet_id: str, aes_key: bytes) -> Optional[int]:
        return self.bucket.get_counter(wallet_id, aes_key)
    
    # send payment
    def send_payment(
        self,
        payer_id: str,
        payee_id: str,
        amount: int,
        aes_key: bytes,
        payer_private_key: bytes,
    ) -> Tuple[bool, str, int, Optional[str]]:
        bucket = self.bucket.get_bucket(payer_id, aes_key)
        
        if not bucket:
            return False, "", 0, "Bucket not found"

        if bucket['status'] != 'ACTIVE':
            return False, "", 0, f"Bucket is {bucket['status']}"

        if bucket['expires_at'] < int(time.time()):
            return False, "", 0, "Bucket expired"

        if bucket['balance'] < amount:
            return False, "", 0, "Insufficient balance"

        new_counter = bucket['counter'] + 1
        local_id = str(uuid.uuid4())
        timestamp = int(time.time())
        
        # ✅ Standardized format: local_id|amount|payer_id|payee_id|counter|timestamp
        token_data = f"{local_id}|{amount}|{payer_id}|{payee_id}|{new_counter}|{timestamp}".encode()
        payer_signature = Signer.sign_with_bytes(payer_private_key, token_data)
        
        success, new_balance, counter, error = self.bucket.deduct_funds(
            wallet_id=payer_id,
            amount=amount,
            aes_key=aes_key
        )
        
        if not success:
            return False, "", 0, error
        
        self.queue.add_transaction(
            amount=amount,
            payer_id=payer_id,
            payee_id=payee_id,
            counter=new_counter,
            payer_signature=payer_signature,
            local_id=local_id
        )
        return True, local_id, new_balance, None
    
    # receiver payment
    def receive_payment(
        self,
        payer_id: str,
        payee_id: str,
        amount: int,
        local_id: str,
        payee_private_key: bytes,
    ) -> Tuple[bool, bytes, Optional[str]]:
        # receiver payment from another wallet (during nfc tap)
        
        # ✅ Standardized format: local_id|amount|payer_id|payee_id|timestamp
        timestamp = int(time.time())
        receipt_data = f"{local_id}|{amount}|{payer_id}|{payee_id}|{timestamp}".encode()
        
        receipt_signature = Signer.sign_with_bytes(payee_private_key, receipt_data)
        
        self.queue.add_transaction(
            amount,
            payer_id,
            payee_id,
            counter=0,
            payer_signature=b"",
            payee_signature=receipt_signature,
            local_id=local_id,  
        )
        
        return True, receipt_signature, None
    
    # sync (upload to server)
    def get_pending_transactions(self) -> List[Dict[str, Any]]:
        return self.queue.get_pending_transactions()
    
    def mark_synced(self, local_id: str) -> bool:
        return self.queue.mark_as_processed(local_id)
    
    def mark_sync_failed(self, local_id: str) -> bool:
        return self.queue.mark_as_failed(local_id)
    
    def has_pending(self) -> bool:
        return self.queue.has_pending()
    
    # Queue management
    def get_queue_count(self) -> int:
        return self.queue.get_queue_count()

    def get_pending_amount(self) -> int:
        return self.queue.get_total_pending_amount()

    def get_failed_transactions(self) -> List[Dict[str, Any]]:
        return self.queue.get_failed_transaction()

    def get_retryable_transactions(self) -> List[Dict[str, Any]]:
        return self.queue.get_retryable_transaction()
    
    # utility
    def get_wallet_info(self, wallet_id: str, aes_key: bytes) -> Dict[str, Any]:
        bucket = self.bucket.get_bucket(wallet_id, aes_key)
        
        if not bucket:
            return {'error': 'wallet not found'}
        
        pending_count = self.queue.get_queue_count('QUEUED')
        pending_amount = self.queue.get_total_pending_amount()
        
        return {
            'wallet_id': wallet_id,
            'balance': bucket['balance'],
            'counter': bucket['counter'],
            'status': bucket['status'],
            'expires_at': bucket['expires_at'],
            'pending_transactions': pending_count,
            'pending_amount': pending_amount
        }

    def generate_otp(self) -> str:
        import random
        return f"{random.randint(100000, 999999)}"
    
    def hash_otp(self, otp: str) -> bytes:
        return Hasher.hash_otp(otp)
