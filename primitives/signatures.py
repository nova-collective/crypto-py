"""Module providing digital signatures primitives."""

import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

def generates_key_pair(self):
    '''
        This function is used to generate a private and public key pair.
        The keys are serialized as hexadecimal strings

        Returns:
        json: the pair of private and public key  
    '''
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )


    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    json_data = json.dumps({ 'privateKey': private_bytes.hex(), 'publicKey': public_bytes.hex() })

    return json_data

def sign(self, private_key, message):
    '''
        This function is used to sign a message using a private key.
        
        Parameters:
        private_key (string): The private key in hexadecimal string
        message (string): the message to sign

        Returns:
        json: the signed message  
    '''
    if private_key is None:
        raise ValueError("Private key has not been furnished.")
    if message is None or message == "":
        raise ValueError("Message has not been furnished or it's empty.")

    private_bytes = bytes.fromhex(private_key)

    p_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    byte_data = message.encode('utf-8')


    signed_message = p_key.sign(byte_data)

    json_data = json.dumps({ 'signature': signed_message.hex() })
    return json_data

def verify(self, public_key, signature, message):
    '''
        This function is used to verify a signature.
        
        Parameters:
        public_key (string): The public key in hexadecimal string
        signature (string): the signature in hexadecimal string
        message (string): the message signed to verify

        Returns:
        json: the signed message  
    '''
    if public_key is None:
        raise ValueError("Public key has not been furnished.")
    if signature is None:
        raise ValueError("Signature has not been furnished or it's empty.")
    if message is None or message == "":
        raise ValueError("Message has not been furnished or it's empty.")

    public_bytes = bytes.fromhex(public_key)
    p_key = Ed25519PublicKey.from_public_bytes(public_bytes)
    signature_bytes = bytes.fromhex(signature)
    byte_data = message.encode('utf-8')

    try:
        p_key.verify(signature_bytes, byte_data)
        json_data = json.dumps({ 'result': 'success' })
        return json_data
    except InvalidSignature:
        json_data = json.dumps({ 'result': 'invalid signature' })
        return json_data
