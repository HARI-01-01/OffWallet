# nfc handshake engine :otp-based atomic swap protocol

import time
import random
from typing import Optional,Tuple,Dict,Any

from .hasher import Hasher
from .signer import Signer
from .serializer import Serializer
from .key_manager import KeyManager

class NFCHandshake:
    TIMEOUT_CHALLENGE = 150
    TIMEOUT_VERIFY = 300
    TIMEOUT_COMMIT = 150
    
    @staticmethod
    def generate_otp()->str:
        return f"{random.randint(100000,999999)}"
    
    @staticmethod
    def create_challenge(
        otp:str,
        private_key:bytes,
        public_key:bytes,
    )->Dict[str,Any]:
        otp_hash = Hasher.hash_otp(otp)
        timestamp = int(time.time())
        nonce = Hasher.generate_challenge()
        
        data = otp_hash + public_key + str(timestamp).encode() + nonce
        signature = Signer.sign_with_bytes(private_key,data)
        
        return {
            'otp_hash':otp_hash,
            'public_key':public_key,
            'timestamp':timestamp,
            'nonce':nonce,
            'signature':signature,
        }
    
    @staticmethod
    def verify_challenge(
        challenge:Dict[str,Any],
        peer_public_key:bytes,
    )->bool:
        
        try:
            required = ['otp_hash', 'public_key', 'timestamp', 'nonce', 'signature']
            for i in required:
                if i not in challenge:
                    return False
            
            if abs(int(time.time())-challenge['timestamp']) > 300:
                return False
            
            data = (   
                challenge['otp_hash'] + challenge['public_key'] + str(challenge['timestamp']).encode()+ challenge['nonce']
            )
            
            return Signer.verify_with_bytes(peer_public_key,data,challenge['signature'])
        
        except Exception:
            return False
        
    @staticmethod
    def verify_otp(otp:str,expected_hash:bytes)->bool:
        return Hasher.verify_otp(otp,expected_hash)

    @staticmethod
    def build_payment_token(
        local_id:str,
        amount:int,
        payer_id:str,
        payee_id:str,
        counter:int,
        private_key:bytes,
        challenge_a:bytes,
        challenge_b:bytes,
    )->Dict[str,Any]:
        timestamp = int(time.time())
        
        token = {
            'local_id':local_id,
            'amount':amount,
            'payer_id':payer_id,
            'payee_id':payee_id,
            'counter':counter,
            'timestamp':timestamp,
            'challenge_a':challenge_a,
            'challenge_b':challenge_b,
        }
        
        data = f"{local_id}:{amount}:{payer_id}:{payee_id}:{counter}:{timestamp}".encode()
        
        token['signature'] = Signer.sign_with_bytes(private_key,data)
        return token

    @staticmethod
    def verify_payment_token(
        token:Dict[str,Any],
        payer_public_key:bytes
    )->bool:
        try:
            required = ['local_id', 'amount', 'payer_id', 'payee_id',
                       'counter', 'timestamp', 'signature']
            
            for i in required:
                if i not in token:
                    return False
            
            if abs(int(time.time())-token['timestamp'])>300:
                return False
            
            data = (
                f"{token['local_id']}:{token['amount']}:"
                f"{token['payer_id']}:{token['payee_id']}:"
                f"{token['counter']}:{token['timestamp']}"
            ).encode()
            
            return Signer.verify_with_bytes(payer_public_key,data,token['signature'])
        except Exception:
            return False
        
    @staticmethod
    def build_receipt(
        local_id:str,
        amount:int,
        payer_id:str,
        payee_id:str,
        private_key:bytes
    )->Dict[str,Any]:
        timestamp = int(time.time())
        
        receipt = {
            'local_id':local_id,
            'amount':amount,
            'payer_id':payer_id,
            'payee_id':payee_id,
            'timestamp':timestamp,
        }
        
        data = f"{local_id}:{amount}:{payer_id}:{payee_id}:{timestamp}".encode()
        receipt['signature'] = Signer.sign_with_bytes(private_key,data)
        return receipt
    
    @staticmethod
    def verify_receipt(
        receipt:Dict[str,Any],
        payee_public_key:bytes
    )->bool:
        try:
            required = ['local_id', 'amount', 'payer_id', 'payee_id',
                       'timestamp', 'signature']
            for i in required:
                if i not in receipt:
                    return False
            if abs(int(time.time())-receipt['timestamp'])>300:
                return False
            
            data = (
                f"{receipt['local_id']}:{receipt['amount']}:"
                f"{receipt['payer_id']}:{receipt['payee_id']}:"
                f"{receipt['timestamp']}"
            ).encode()
            return Signer.verify_with_bytes(payee_public_key,data,receipt['signature'])
        except Exception:
            return False
        
    @staticmethod
    def create_atomic_swap_payload(
        payer_id:str,
        payee_id:str,
        amount:int,
        payer_private_key:bytes,
        payer_public_key:bytes,
        payee_private_key:bytes,
        payee_public_key:bytes,
        otp_a:str,
        otp_b:str
    )->Tuple[bytes,bytes,Dict,Dict]:
        import uuid
        local_id = str(uuid.uuid4())
        
        hash_a = Hasher.hash_otp(otp_a)
        hash_b = Hasher.hash_otp(otp_b)
        
        token = NFCHandshake.build_payment_token(
            local_id=local_id,
            amount=amount,
            payer_id=payer_id,
            payee_id=payee_id,
            counter=1,
            private_key=payer_private_key,
            challenge_a=hash_a,
            challenge_b=hash_b,
        )
        receipt = NFCHandshake.build_receipt(
            local_id=local_id,
            amount=amount,
            payer_id=payer_id,
            payee_id=payee_id,
            private_key=payee_private_key
        )
        return (
            Serializer.encode_payment_token(
                local_id=token['local_id'],
                amount=token['amount'],
                counter=token['counter'],
                payer_id=token['payer_id'],
                payee_id=token['payee_id'],
                timestamp=token['timestamp'],
                payer_signature=token['signature'],
                challenge_a=hash_a,
                challenge_b=hash_b,
            ),
            Serializer.encode_payment_token(
                local_id=receipt['local_id'],
                amount=receipt['amount'],
                counter=0,
                payer_id=receipt['payer_id'],
                payee_id=receipt['payee_id'],
                timestamp=receipt['timestamp'],
                payer_signature=receipt['signature'],
            ),
            token,
            receipt,
        )
        
    @staticmethod
    def verify_atomic_swap(
        token:Dict[str,Any],
        receipt:Dict[str,Any],
        payer_public_key:bytes,
        payee_public_key:bytes,
    )->bool:
        return (
            NFCHandshake.verify_payment_token(token,payer_public_key) and
            NFCHandshake.verify_receipt(receipt,payee_public_key) and
            token['local_id'] == receipt['local_id'] and
            token['amount'] == receipt['amount']
        )    