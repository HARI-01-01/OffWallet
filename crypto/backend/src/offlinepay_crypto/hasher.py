# handles sha-256 hashing for otp, challenges, and digest

import hashlib
import hmac

class Hasher:
    # sha-256 produces 32-bytes (256 bit) output
    DIGEST_SIZE=32
    # hashing bytes data to bytes
    @staticmethod
    def sha256(data:bytes)->bytes:
        return hashlib.sha256(data).digest()
    # hashing bytes data to string
    @staticmethod
    def sha256_hex(data:bytes)->str:
        return hashlib.sha256(data).hexdigest()
    # hashing otp str to bytes
    @staticmethod
    def hash_otp(otp:str)->bytes:
        return hashlib.sha256(otp.encode('utf-8')).digest()
    # hashing otp str to str
    @staticmethod
    def hash_otp_hex(otp:str)->str:
        return Hasher.sha256_hex(otp.encode('utf-8'))
    
    # verify the expected hash to computed hash
    @staticmethod
    def verify_otp(otp:str,expected_hash:bytes)->bool:
        
        computed_hash = Hasher.hash_otp(otp)
        return hmac.compare_digest(computed_hash,expected_hash)
    
    # generate a random challenge for nfc handshake
    @staticmethod
    def generate_challenge()->bytes:
        import os
        return os.urandom(Hasher.DIGEST_SIZE)
    
    # compute sha-256 twice
    @staticmethod
    def double_hash(data:bytes)->bytes:
        first = Hasher.sha256(data)
        return Hasher.sha256(first)