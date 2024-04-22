"""Module providing sha-3 primitives."""

import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def sha3_224(self, input):
    '''
        This function is used to produce a SHA-3 hash of 224 bites length from the data passed in input.

        Parameters:
        input (string): The data to hash

        Returns:
        string: the hash as hexadecimal string  
    '''
    input_bytes = input.encode('utf-8')

    digest = hashes.Hash(hashes.SHA3_224(), backend=default_backend())
    digest.update(input_bytes)
    hashed_value = digest.finalize()
    hashed_hex = hashed_value.hex()
    
    json_data = json.dumps({ 'hash': hashed_hex })

    return json_data

def sha3_256(self, input):
    '''
        This function is used to produce a SHA-3 hash of 256 bites length from the data passed in input.

        Parameters:
        input (string): The data to hash

        Returns:
        string: the hash as hexadecimal string  
    '''
    input_bytes = input.encode('utf-8')

    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(input_bytes)
    hashed_value = digest.finalize()
    hashed_hex = hashed_value.hex()
    
    json_data = json.dumps({ 'hash': hashed_hex })

    return json_data

def sha3_512(self, input):
    '''
        This function is used to produce a SHA-3 hash of 512 bites length from the data passed in input.

        Parameters:
        input (string): The data to hash

        Returns:
        string: the hash as hexadecimal string  
    '''
    input_bytes = input.encode('utf-8')

    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(input_bytes)
    hashed_value = digest.finalize()
    hashed_hex = hashed_value.hex()
    
    json_data = json.dumps({ 'hash': hashed_hex })

    return json_data