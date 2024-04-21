"""Module providing authenticated encryption primitives."""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key(self, key_length):
    '''
        This function generate a private key of length equal to the value passed in input

        Parameters:
        key_length (number): accepted values are 128, 192, 256

        Returns:
        string: the private key as hexadecimal string  
    '''
    if key_length not in [128, 192, 256]:
        raise ValueError("The key length must be 128, 192 or 256 bit")

    key = AESGCM.generate_key(bit_length=key_length)

    return { 'key': _bytes_to_hex_string(key) }

def AESGCM_encrypt(self, key, secret, unencrypted_data = None):
    '''
        This function is used to encrypt a secret using the AES-GMC primitive

        Parameters:
        key (string): The private key of 256 bites length, in hexadecimal format
        secret (string): The secret to encrypt
        unencrypted_data (string) : unencrypted authenticated data to associate to the chiper. This parameter is optional

        Returns:
        string: the chiper as hexadecimal string  
    '''
    if len(key) != 64:
        raise ValueError("The key must be 256 bit length")

    bkey = _hex_string_to_bytes(key)
    bsecret = _to_bytes_like(secret)
    bud = _to_bytes_like(unencrypted_data) if unencrypted_data else None

    aesgcm = AESGCM(bkey)
    nonce = os.urandom(12)
    bencrypted = aesgcm.encrypt(nonce, bsecret, bud)
    return { 'chiper': _bytes_to_hex_string(bencrypted), 'nonce': _bytes_to_hex_string(nonce) }

def AESGCM_decrypt(self, key, chiper, nonce, unencrypted_data=None):
    '''
        This function is used to decrypt a chiper

        Parameters:
        key (hexadecimal): The private key used for the encryption, 256-bit length
        chiper (hexadecimal): the secret to decrypt, as hexadecimal string
        nonce (hexadecimal): the nonce used for the encryption, as hexadecimal
        unencrypted_data (string) : unencrypted authenticated data to associate to the chiper. This parameter is optional

        Returns:
        string: the hash as hexadecimal string  
    '''
    if len(key) != 64:
        raise ValueError("The key must be 256 bit length")

    bkey = _hex_string_to_bytes(key)
    aesgcm = AESGCM(bkey)
    bct = _hex_string_to_bytes(chiper)
    bnonce = _hex_string_to_bytes(nonce)
    aad = _to_bytes_like(unencrypted_data) if unencrypted_data else None

    return { 'message': aesgcm.decrypt(bnonce, bct, aad).decode('utf-8') }


def _bytes_to_hex_string(byte_string):
    '''
        This function converts a bytes data to hexadecimal string

        Parameters:
        byte_string (byte): The data to convert

        Returns:
        string: the data converted to hexadecimal string  
    '''
    hex_string = byte_string.hex()
    return hex_string

def _hex_string_to_bytes(hex_string):
    '''
        This function converts a hexadecimal string data to bytes

        Parameters:
        hex_string (string): The data to convert

        Returns:
        bytes: the data converted to bytes  
    '''
    byte_key = bytes.fromhex(hex_string)
    return byte_key

def _to_bytes_like(data):
    '''
        This function converts a string, a list or a tuple in bytes-like data

        Parameters:
        data (string|list|tuple): The data to convert

        Returns:
        bytes: the data converted to bytes  
    '''
    if isinstance(data, str):
        byte_data = data.encode()
    elif isinstance(data, (list, tuple)):
        byte_data = bytes(data)
    else:
        raise TypeError("The data type is not supported. Supported types are: string, list and tuple")

    return byte_data