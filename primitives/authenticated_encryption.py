import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key(self, key_length):
    if key_length not in [128, 192, 256]:
            raise ValueError("The key length must be 128, 192 or 256 bit")

    key = AESGCM.generate_key(bit_length=key_length)

    return _bytes_to_hex_string(key)

def AESGCM_encrypt(self, key, secret, unencrypted_data = None):
    if len(key) != 64:
        raise ValueError("The key must be 256 bit length")
    
    bkey = _hex_string_to_bytes(key)
    bsecret = _to_bytes_like(secret)
    bud = _to_bytes_like(unencrypted_data) if unencrypted_data else None
    
    aesgcm = AESGCM(bkey)
    nonce = os.urandom(12)
    bencrypted = aesgcm.encrypt(nonce, bsecret, bud)

    return _bytes_to_hex_string(bencrypted)

def AESGCM_decrypt(self, key):
    return "to do"


def _bytes_to_hex_string(byte_key):
    hex_string = byte_key.hex()
    return hex_string

def _hex_string_to_bytes(hex_string):
    byte_key = bytes.fromhex(hex_string)
    return byte_key

def _to_bytes_like(data):
    if isinstance(data, str):
        byte_data = data.encode()
    elif isinstance(data, (list, tuple)):
        byte_data = bytes(data)
    else:
        raise TypeError("The data type is not supported. Supported types are: string, list and tuple")
    
    return byte_data