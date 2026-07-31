# handle CBOr encoding and decoding for NFC handshake payload
# use the cbor2 library for all serialization operation

import cbor2
from typing import Any,Dict,List,Union

class Serializer:
    
    
    @staticmethod
    def encode(data:Dict[str,Any])->bytes:
        return cbor2.dumps(data)
    
    @staticmethod
    def decode(data:bytes)->Dict[str,Any]:
        return cbor2.loads(data)
    @staticmethod
    def encode_payment_token(
        local_id:str,
        amount:int,
        counter:int,
        payer_id:str,
        payee_id:str,
        timestamp:int,
        payer_signature:bytes,
        payee_signature:bytes=b"",
        challenge_a:bytes=b"",
        challenge_b:bytes=b"",
    )->bytes:
        # encode a payment token to cbor
        data = {
            "type":"PAYMENT_TOKEN",
            "localId":local_id,
            "amount":amount,
            "counter":counter,
            "payerId":payer_id,
            "payeeId":payee_id,
            "timestamp":timestamp,
            "payerSignature":payer_signature,
        }
        if payee_signature:
            data["payeeSignature"] = payee_signature
        if challenge_a:
            data["challenge_A"]=challenge_a
        if challenge_b:
            data["challenge_b"]=challenge_b
            
        return cbor2.dumps(data)
    
    @staticmethod
    def decode_payment_token(data:bytes)->Dict[str,Any]:
        # decode a payment token from cbor
        decoded = cbor2.loads(data)
        
        if decoded.get("type")!="PAYMENT_TOKEN":
            raise ValueError("Invaild payment token:missing 'type' field")
        
        required_fields = ["localId","amount","counter","payerId","payeeId","timestamp","payerSignature"]
        for i in required_fields:
            if i not in decoded:
                raise ValueError(f"Invaild payment token: missing '{i}' filed")
            
        return decoded
    
    @staticmethod
    def encode_challenge(otp_hash:bytes,
                         public_key:bytes,
                         timestamp:int,
                         nonce:bytes,
                         signature:bytes
                         )->bytes:
        # encode an nfc challenge to CBOR
        data = {
            "type":"CHALLENGE",
            "otpHash":otp_hash,
            "publicKey":public_key,
            "timestamp":timestamp,
            "nonce":nonce,
            "signature":signature
        }
        return cbor2.dumps(data)
    
    @staticmethod
    def decode_challenge(data:bytes)->Dict[str,Any]:
        # decode an nfc challenge from cbor
        decoded = cbor2.loads(data)
        
        if decoded.get("type")!="CHALLENGE":
                raise ValueError("Invaild CHALLENGE token:missing 'type' field")
                
        required_fields = ["otpHash", "publicKey", "timestamp", "nonce", "signature"]
        for i in required_fields:
            if i not in decoded:
                raise ValueError(f"Invaild challenge token: missing '{i}' filed")
                    
        return decoded
    
    @staticmethod
    def size_of(data:Dict[str,Any])->int:
        # calculte the cbor encoded size of a dic in bytes
        return len(cbor2.dumps(data))
    
    @staticmethod
    def hex_dump(data:bytes)->str:
        # bytes to hex for debugging
        return data.hex()[:64]+"..."if len(data)>64 else data.hex()