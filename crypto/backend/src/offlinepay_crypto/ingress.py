# backend ingress gateway: receives offline transaction uploads

import json
import os
import time
from typing import Optional, Dict,Any,Tuple
from dataclasses import dataclass

from .database import Database
from .serializer import Serializer
from .rate_limiter import RateLimiter
from .signer import Signer
from .key_manager import KeyManager
from .firebase_db import FirebaseDB

def _decode_signature(value: str) -> bytes:
    if not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def _ensure_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    return value


@dataclass
class IngressRequest:
    local_id:str
    amount:int
    payer_id:str
    payee_id:str
    counter:int
    timestamp:int
    payer_signature:bytes
    payee_signature:bytes
    device_id:str
    api_str:str
    device_signature:bytes
    
class IngressGateway:
    RATE_LIMIT=100
    RATE_WINDOW = 60
    
    def __init__(self,db:Optional[Database]=None):
        if db is None:
            try:
                self.db = FirebaseDB(skip_initialization=False)
                self._is_firebase = True
            except Exception:
                self.db = Database()
                self._is_firebase = False
        self._rate_limiter = RateLimiter(os.getenv("REDIS_URL"))
        self._rate_limit = int(os.getenv("RATE_LIMIT", str(self.RATE_LIMIT)))
        self._rate_window = int(os.getenv("RATE_WINDOW", str(self.RATE_WINDOW)))
        
    def authenticate_device(
        self,
        device_id: str,
        signature: bytes,
        payload: bytes,
        timestamp: int,
    ) -> Tuple[bool, Optional[str]]:
        device = self.db.get_device(device_id)
        if not device:
            return False, "Device not registered"

        if abs(int(time.time()) - int(timestamp)) > 300:
            return False, "Timestamp too old"

        public_key_bytes = _ensure_bytes(device.get("public_key"))
        if not public_key_bytes:
            return False, "Device not registered"

        message = f"{timestamp}:{payload.hex()}".encode()
        if not Signer.verify_with_bytes(public_key_bytes, message, signature):
            return False, "Invalid signature"

        self.db.touch_device(device_id)
        return True, None

    def verify_api_key(self, api_key: str) -> Tuple[bool, Optional[str]]:
        key_data = self.db.get_api_key(api_key)
        if not key_data:
            return False, "Invalid API key"

        if key_data.get("revoked"):
            return False, "API key revoked"

        expires_at = key_data.get("expires_at")
        if expires_at is not None and expires_at < int(time.time()):
            return False, "API key expired"

        self.db.touch_api_key(api_key)
        return True, None

    def check_rate_limit(self, device_id: str) -> Tuple[bool, Optional[str]]:
        allowed, _ = self._rate_limiter.check_rate_limit(
            key=device_id,
            limit=self._rate_limit,
            window=self._rate_window,
        )
        if not allowed:
            return False, "Rate limit exceeded"
        return True, None

    def authenticate(
        self,
        api_key:str,
        device_id:str,
        device_signature:bytes,
        payload:bytes,
        timestamp:int
    )->Tuple[bool,Optional[str]]:
        valid, error = self.verify_api_key(api_key)
        if not valid:
            return False, error

        valid, error = self.authenticate_device(device_id, device_signature, payload, timestamp)
        if not valid:
            return False, error

        return True, None
        
    def _get_device_public_key(self,device_id:str)->Optional[bytes]:
        device = self.db.get_device(device_id)
        if not device:
            return None
        return _ensure_bytes(device.get("public_key"))
        
    def validate_payload(self,data:Dict[str,Any])->Tuple[bool,Optional[str]]:
        # validate incoming payload structure
        
        required = [
            'local_id', 'amount', 'payer_id', 'payee_id',
            'counter', 'timestamp', 'payer_signature',
            'payee_signature', 'device_id', 'api_key'
        ]
        
        for i in required:
            if i not in data:
                return False,f"Missing field: {i}"
        
        try:
            int(data['amount'])
            int(data['counter'])
            int(data['timestamp'])
        except (ValueError,TypeError):
            return False,"Invalid numeric field"
        
        return True,None
    
    def verify_transaction_signatures(
        self,
        data:Dict[str,Any],
        payer_public_key:bytes,
        payee_public_key:bytes,
    )->Tuple[bool,Optional[str]]:
        # verify payer and payee signature
        msg = (
            f"{data['local_id']}:{data['amount']}:"
            f"{data['payer_id']}:{data['payee_id']}:"
            f"{data['counter']}:{data['timestamp']}"
        ).encode()
        
        if not Signer.verify_with_bytes(
            payer_public_key,
            msg,
            _decode_signature(data.get('payer_signature', ''))
        ):
            return False,"Invalid payer signature"
        
        if not Signer.verify_with_bytes(
            payee_public_key,
            msg,
            _decode_signature(data.get('payee_signature', ''))
        ):
            return False,"Invalid payee signature"
        
        return True,None
    
    def check_double_spend(self,payer_id:str,counter:int)->Tuple[bool,Optional[str]]:
        # check if this transaction is a double -spend
        
        bucket = self.db.get_bucket(payer_id)
        if not bucket:
            return False,"Payer not found"
        
        last_counter = bucket.get('counter',0)
        if counter<= last_counter:
            return False,f"Double-spend detected: counter {counter}<= {last_counter}"
        
        if counter!= last_counter+1:
            return False,f"Counter gap: expected {last_counter+1}, got {counter}"
        return True,None
    
    def process_request(self,raw_data:bytes)->Tuple[bool,Dict[str,Any]]:
        # process an incoming request
        
        try:
            data=json.loads(raw_data.decode('utf-8'))
        except (json.JSONDecodeError,UnicodeDecodeError):
            return False,{"error":"Invalid JSON"}
        
        valid,error = self.validate_payload(data)
        if not valid:
            return False,{'error':error}
        
        api_key = data.get('api_key','')        
        device_id = data.get('device_id','')      
        device_signature = _decode_signature(data.get('device_signature', ''))
        payload_for_signature = dict(data)
        payload_for_signature.pop('device_signature', None)
        signed_payload = json.dumps(payload_for_signature, sort_keys=True, separators=(',', ':')).encode('utf-8')
        timestamp = int(data.get('timestamp', 0))
        
        valid,error =self.authenticate(
            api_key,
            device_id,
            device_signature,
            signed_payload,
            timestamp
        )
        
        if not valid: 
            return False,{'error':error,'reason':'auth'}
        
        valid,error = self.check_rate_limit(device_id)
        if not valid:
            return False,{'error':error,'reason':'rate_limit'}
        
        existing = self._get_transaction(data['local_id'])
        if existing:
            return True, {
                "status": "PROCESSED",
                "local_id": data['local_id'],
                "message": "Already processed"
            }
        payer_pub = self._get_public_key(data['payer_id'])
        payee_pub = self._get_public_key(data['payee_id'])
        
        if not payer_pub or not payee_pub:
            return False, {'error':"Invalid payer or payee"}
        
        vaild,error = self.verify_transaction_signatures(data,payer_pub,payee_pub)
        if not vaild:
            return False,{"error": error}
        
        valid,error = self.check_double_spend(data['payer_id'],data['counter'])
        if not valid:
            return False,{"error":error,"fraud":True}
        
        self._store_transaction(data)
        # in production :emit to message queue (rabbitMQ/Kafka)
        self.forward_to_detection(data)
        
        return True, {
            "status":"PENDING",
            "local_id":data['local_id'],
            "message":"Transaction received, processing..."
        }
        
    def _get_public_key(self, wallet_id: str) -> Optional[bytes]:
        """Get public key for a wallet."""
        if self._is_firebase:
            user = self.db.get_user(wallet_id)
        else:
            user = self.db.get_user(wallet_id)
        
        if user and user.get('public_key'):
            pub_key = user.get('public_key')
            if isinstance(pub_key, str):
                return bytes.fromhex(pub_key)
            return pub_key
        return None
    def _get_public_key(self,wallet_id:str)->Optional[bytes]:
        user = self.db.get_user(wallet_id)
        if user and user.get('public_key'):
            return user['public_key']
        return None
    
    def _store_transaction(self,data:Dict[str,Any])->None:
        self.db.create_pending_transaction(
            local_id=data['local_id'],
            amount=data['amount'],
            payer_id=data['payer_id'],
            payee_id=data['payee_id'],
            counter=data['counter'],
            timestamp=data['timestamp'],
            payer_signature=_decode_signature(data.get('payer_signature', '')),
            payee_signature=_decode_signature(data.get('payee_signature', '')),
            status='PENDING',
        )
    
    def forward_to_detection(self,data:Dict[str,Any])->None:
        # in production: publish to message queue
        pass