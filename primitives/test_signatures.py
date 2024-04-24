import json
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from signatures import generates_key_pair, sign, verify

def test_generates_key_pair():
    keys = generates_key_pair("")
    keys_dict = json.loads(keys)
    assert 'privateKey' in keys_dict
    assert 'publicKey' in keys_dict

def test_sign_and_verify():
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_hex = private_bytes.hex()
    
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_key_hex = public_bytes.hex()
    message = "Test message"

    signature_response = sign("", private_key_hex, message)
    signature_json = json.loads(signature_response)

    result = verify("", public_key_hex, signature_json['signature'], message)

    result_dict = json.loads(result)
    assert result_dict['result'] == 'success'

def test_verify_invalid_signature():
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_hex = private_bytes.hex()

    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_key_hex = public_bytes.hex()
    message = "Test message"

    signature_response = sign("", private_key_hex, message)
    signature_json = json.loads(signature_response)
    signature = signature_json['signature']

    altered_signature = signature[:-2] + "11"

    response = verify("", public_key_hex, altered_signature, message)
    response_json =  json.loads(response)

    assert response_json['result'] ==  "invalid signature"
