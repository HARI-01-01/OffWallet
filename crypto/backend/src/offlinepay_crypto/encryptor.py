import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class Encryptor:
    KEY_SIZE=32
    IV_SIZE=12
    TAG_SIZE=16
    
    @staticmethod
    def generate_key()->bytes:
        # generate a random AES-256 key
        return os.urandom(Encryptor.KEY_SIZE)
    @staticmethod
    def generate_iv()->bytes:
        # generate a random 12 bytes initialization vector (IV)
        return os.urandom(Encryptor.IV_SIZE)
    

    @staticmethod
    def encrypt(key:bytes,plaintext:bytes,aad:bytes=b"")->tuple[bytes,bytes,bytes]:
        # encrypt plaintext using AES-256-GCM
        # args: key:32 bytes aes key, plaintext: data to encrypt (bytes), aad: additional authenticated data(optional , for integrity)
        # return (ciphertext, iv, tag)
        
        iv = Encryptor.generate_iv()
        aesgcm = AESGCM(key)
        
        # encrypt (return chiphertext + tag combined)
        #  aesgcm.encrypt() return (ciphertext+tag) concatenated
        ciphertext_with_tag = aesgcm.encrypt(iv,plaintext,aad)
        
        # split ciphertext and tag
        # the tag is the last 16 bytes
        ciphertext = ciphertext_with_tag[:-Encryptor.TAG_SIZE]
        tag = ciphertext_with_tag[-Encryptor.TAG_SIZE:]
        
        return ciphertext,iv,tag
    
    @staticmethod
    def decrypt(key:bytes,ciphertext:bytes,iv:bytes,tag:bytes,aad:bytes=b"")->bytes:
        # decrypt ciphertext using AES-256-GCM
        # args: key, ciphertext ,iv:initialization vector,tag:authentication tag,
        # return decrypt plaintext
        # raises invaild tag: if authentication fails (data tampered)
        
        ciphertext_with_tag = ciphertext+tag
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(iv,ciphertext_with_tag,aad)
        
        return plaintext   
    
    