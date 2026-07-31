# handle offline bucket business logic
#  manages balance, counter and server signature verification
import time
from typing import Optional,Tuple
from datetime import datetime
from .database import Database
from .encryptor import Encryptor
from .key_manager import KeyManager
from .signer import Signer

class BucketManager:
    BUCKET_EXPIRY_SECONDS = 86400
    MAX_BALANCE=1000000
    
    def __init__(self,db:Optional[Database]=None):
        self.db = db  or Database()
    
    # Core operation
    
    def create_bucket(self,
                      wallet_id:str,
                      initial_balance:int,
                      aes_key:bytes,
                      server_public_key:bytes,
                      server_signature:bytes
                      )->bool:
        # create a new offline bucket with pre-loaded funds.
        bucket_data = f"{wallet_id}:{initial_balance}:0".encode()
        is_valid = Signer.verify(
            server_public_key,
            bucket_data,
            server_signature
        )
        if not is_valid:
            raise ValueError("Invalid server signature")
        
        balance_data = str(initial_balance).encode()
        counter_data = b"0"
        encrypted_balance,iv_balance,tag_balance = Encryptor.encrypt(
            aes_key,balance_data
        )
        encrypted_counter,iv_counter,tag_counter = Encryptor.encrypt(
            aes_key,counter_data
        )
        
        encrypted_balance_with_iv = iv_balance + tag_balance+encrypted_balance
        encrypted_counter_with_iv = iv_counter + tag_counter+encrypted_counter
        
        return self.db.create_bucket(
            wallet_id=wallet_id,
            balance=initial_balance,
            counter=0,
            encrypted_balance=encrypted_balance_with_iv,
            encrypted_counter=encrypted_counter_with_iv,
            server_signature=server_signature,
            expires_at=int(time.time())+self.BUCKET_EXPIRY_SECONDS,
        )
        
    def  get_bucket(self,wallet_id:str,aes_key:bytes)->Optional[dict]:
        bucket = self.db.get_bucket(wallet_id)
        if not bucket:
            return None
        
        encrypted_balance_with_iv = bucket['encrypted_balance']
        if encrypted_balance_with_iv:
            iv_balance = encrypted_balance_with_iv[:12]
            tag_balance = encrypted_balance_with_iv[12:28]
            encrypted_balance = encrypted_balance_with_iv[28:]
            balance_bytes = Encryptor.decrypt(
                aes_key, encrypted_balance, iv_balance, tag_balance
            )
            balance = int(balance_bytes.decode())
        else:
            balance = bucket['balance']

        # Decrypt counter
        encrypted_counter_with_iv = bucket['encrypted_counter']
        if encrypted_counter_with_iv:
            iv_counter = encrypted_counter_with_iv[:12]
            tag_counter = encrypted_counter_with_iv[12:28]
            encrypted_counter = encrypted_counter_with_iv[28:]
            counter_bytes = Encryptor.decrypt(
                aes_key, encrypted_counter, iv_counter, tag_counter
            )
            counter = int(counter_bytes.decode())
        else:
            counter = bucket['counter']

        return {
            'wallet_id': bucket['wallet_id'],
            'balance': balance,
            'counter': counter,
            'status': bucket['status'],
            'created_at': bucket['created_at'],
            'expires_at': bucket['expires_at'],
            'last_synced': bucket['last_synced'],
        }
        
    def deduct_funds(
        self,
        wallet_id:str,
        amount:int,
        aes_key:bytes,
    )->Tuple[bool,int,int,Optional[str]]:
        # dedct funds from bucket (during offline payment)
        
        bucket = self.get_bucket(wallet_id,aes_key)
        if not bucket:
            return False,0,0,"Bucket not found"
        
        if bucket['status']!='ACTIVE':
            return False,0,0,f"Bucket is {bucket['status']}"
        
        if bucket['expires_at']<int(time.time()):
            return False,0,0,f"Bucket expired (24h ttl)"
        
        if bucket['balance']<amount:
            return False,0,0,f"Insufficient balance"
        
        new_balance = bucket['balance'] - amount
        new_counter = bucket['counter'] + 1
        
        balance_data = str(new_balance).encode()
        counter_data = str(new_counter).encode()
        
        encrypted_balance,iv_balance,tag_balance = Encryptor.encrypt(
            aes_key,balance_data
        )
        encrypted_counter,iv_counter,tag_counter = Encryptor.encrypt(
            aes_key,counter_data
        )
        
        encrypted_balance_with_iv = iv_balance +tag_balance+encrypted_balance
        encrypted_counter_with_iv = iv_counter +tag_counter+encrypted_counter
        
        counter_updated  = self.db.update_bucket_counter(wallet_id,new_counter)
        
        if not counter_updated:
            return False,0,0,"Counter conflict (potential double-spend)"
        
        self.db.update_bucket(
            wallet_id=wallet_id,
            balance=new_balance,
            encrypted_balance=encrypted_balance_with_iv,
            encrypted_counter=encrypted_counter_with_iv,
            last_synced=int(time.time())
        )
        return True,new_balance,new_counter,None
    
    
    def add_funds(
        self,
        wallet_id:str,
        amount:int,
        aes_key:bytes,
        server_public_key:bytes,
        server_signature:bytes,
    )->Tuple[bool,int,Optional[str]]:
        # add funds to bucket (online replenshment)
        
        bucket=self.get_bucket(wallet_id,aes_key)
        if not bucket:
            return False,0,"Bucket not found"
        
        new_balance = bucket['balance'] + amount
        bucket_data = f"{wallet_id}:{new_balance}:{bucket['counter']}".encode()
        is_vaild = Signer.verify_with_bytes(
            server_public_key,bucket_data,
            server_signature
        )
        if not is_vaild:
            return False,0,"Invalid server signature"
        
        balance_data = str(new_balance).encode()
        encrypted_balance, iv_balance, tag_balance = Encryptor.encrypt(
            aes_key, balance_data
        )
        encrypted_balance_with_iv = iv_balance + tag_balance + encrypted_balance

        self.db.update_bucket(
            wallet_id=wallet_id,
            balance=new_balance,
            encrypted_balance=encrypted_balance_with_iv,
            server_signature=server_signature,
            expires_at=int(time.time()) + self.BUCKET_EXPIRY_SECONDS,
            last_synced=int(time.time()),
            status='ACTIVE',
        )

        return True, new_balance, None

    def check_balance(self, wallet_id: str, aes_key: bytes) -> Optional[int]:
        """Get current balance."""
        bucket = self.get_bucket(wallet_id, aes_key)
        return bucket['balance'] if bucket else None

    def get_counter(self, wallet_id: str, aes_key: bytes) -> Optional[int]:
        """Get current counter."""
        bucket = self.get_bucket(wallet_id, aes_key)
        return bucket['counter'] if bucket else None

    def is_expired(self, wallet_id: str) -> bool:
        """Check if bucket is expired."""
        bucket = self.db.get_bucket(wallet_id)
        if not bucket:
            return True
        return bucket['expires_at'] < int(time.time())

    def freeze_bucket(self, wallet_id: str) -> bool:
        """Freeze bucket (fraud prevention)."""
        return self.db.update_bucket(
            wallet_id=wallet_id,
            status='FROZEN'
        )

    def activate_bucket(self, wallet_id: str) -> bool:
        """Activate a frozen bucket."""
        return self.db.update_bucket(
            wallet_id=wallet_id,
            status='ACTIVE'
        )

    def get_bucket_status(self, wallet_id: str) -> Optional[str]:
        """Get bucket status."""
        bucket = self.db.get_bucket(wallet_id)
        return bucket['status'] if bucket else None

    def verify_server_signature(
        self,
        wallet_id: str,
        balance: int,
        counter: int,
        server_public_key: bytes,
        server_signature: bytes,
    ) -> bool:

        bucket_data = f"{wallet_id}:{balance}:{counter}".encode()
        return Signer.verify_with_bytes(
            server_public_key,
            bucket_data,
            server_signature
        )