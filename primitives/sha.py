from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def sha3_224(self, input):
    # it converts the string into bytes
    input_bytes = input.encode('utf-8')
        
    # Calculates the SHA-3 (SHA3-256) hash of the string in byte
    digest = hashes.Hash(hashes.SHA3_224(), backend=default_backend())
    digest.update(input_bytes)
    hashed_value = digest.finalize()
    
    # Converts the hash to hexadecimal format
    hashed_hex = hashed_value.hex()
    return hashed_hex

def sha3_256(self, input):
    # it converts the string into bytes
    input_bytes = input.encode('utf-8')
        
    # Calculates the SHA-3 (SHA3-256) hash of the string in byte
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(input_bytes)
    hashed_value = digest.finalize()
    
    # Converts the hash to hexadecimal format
    hashed_hex = hashed_value.hex()
    return hashed_hex

def sha3_512(self, input):
    # it converts the string into bytes
    input_bytes = input.encode('utf-8')
        
    # Calculates the SHA-3 (SHA3-256) hash of the string in byte
    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(input_bytes)
    hashed_value = digest.finalize()
    
    # Converts the hash to hexadecimal format
    hashed_hex = hashed_value.hex()
    return hashed_hex