import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key(self, key_length):
    if key_length not in [128, 192, 256]:
            raise ValueError("The key length must be 128, 192 or 256 bit")

    key = AESGCM.generate_key(bit_length=key_length)
    return _bytes_to_hex_string(key)


def _bytes_to_hex_string(byte_key):
    hex_string = byte_key.hex()
    return hex_string