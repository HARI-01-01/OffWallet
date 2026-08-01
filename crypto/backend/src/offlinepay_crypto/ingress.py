# backend ingress gateway: receives offline transaction uploads

import time
import json
from typing import Optional, Dict,Any,Tuple
from dataclasses import dataclass

from .database import Database
from .serializer import Serializer
from .signer import Signer
from .key_manager import KeyManager

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
        self.db = db or Database()
        self._rate_cache = {}  # device_id
        
    def authenticate(
        self,
        api_key:str,
        device_id:str,
        device_signature:bytes,
        payload:bytes
    )->Tuple[bool,Optional[str]]:
        if not self._validate_api_key(api_key):
            return False,"Invalid API Key"
        
        pub_key = self._get_device_public_key(device_id)
        if not pub_key:
            return False, "Device not registered"
        
        if not Signer.verify_with_bytes(pub_key,payload,device_signature):
            return False,"Invalid device signature"
        
        return True,None
    
    def _validate_api_key(self,api_key:str)->bool:
        # in production :check against database
        
        return api_key.startswith("sk_")
        
    def _get_device_public_key(self,device_id:str)->Optional[bytes]:
        # in production : query database
        if hasattr(self, '_device_public_keys'):
            return self._wallet_public_keys.get(device_id)
        import os
        return os.urandom(32)
    
    def rate_limit(self,device_id:str)->Tuple[bool,Optional[str]]:
    # check rate limit for device
        now = int(time.time())
        if device_id not in self._rate_cache:
            self._rate_cache[device_id]=(now,1)
            return True,None
            
        last_time,count = self._rate_cache[device_id]
        if now - last_time>self.RATE_WINDOW:
            self._rate_cache[device_id] = (now,1)
            return True,None
            
        if count>=self.RATE_LIMIT:
            return False,"Rate limit exceeded"
        
        self._rate_cache[device_id] = (last_time,count+1)
        
        return True,None
        
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
            bytes.fromhex(data['payer_signature'])
        ):
            return False,"Invalid payer signature"
        
        if not Signer.verify_with_bytes(
            payee_public_key,
            msg,
            bytes.fromhex(data['payee_signature'])
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
        device_signature = bytes.fromhex(data.get('device_signature',''))
        
        valid,error =self.authenticate(
            api_key,
            device_id,
            device_signature,
            raw_data
        )
        
        if not valid: 
            return False,{'error':error}
        
        valid,error = self.rate_limit(device_id)
        if not valid:
            return False,{'error':error}
        
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
        if not valid:
            return False,{'error',error}
        
        valid,error = self.check_double_spend(data['payer_id'],data['counter'])
        if not valid:
            return False,{"error":error,"fraud":True}
        
        self._store_transaction(data)
        # in production :emit to message queue (rabbitMQ/Kafka)
        self._forward_to_detection(data)
        
        return True, {
            "status":"PENDING",
            "local_id":data['local_id'],
            "message":"Transaction received, processing..."
        }
        
    def _get_transaction(self,local_id:str)->Optional[Dict]:
        # in production : query database
        
        return None
    def _get_public_key(self,wallet_id:str)->Optional[bytes]:
        # in production : query from database
        if hasattr(self, '_wallet_public_keys'):
            return self._wallet_public_keys.get(wallet_id)
        import os
        return os.urandom(32)
    
    def _store_transaction(self,data:Dict[str,Any])->None:
        # in production :insert into pending_settlements
        pass
    
    def forward_to_detection(self,data:Dict[str,Any])->None:
        # in production: publish to message queue
        pass