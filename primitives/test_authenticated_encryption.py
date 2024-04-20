import pytest
from authenticated_encryption import generate_key, AESGCM_encrypt, _bytes_to_hex_string

def test_generate_key_valid_lengths():
    for key_length in [128, 192, 256]:
        key = generate_key("", key_length)
        assert len(key['key']) == key_length / 4 

def test_generate_key_invalid_length():
    with pytest.raises(ValueError):
        generate_key("", 100)

def test_AESGCM_encrypt_key_length():
    key = '000102030405060708090a0b0c0d0e0f'
    secret = 'my_secret_data'
    
    with pytest.raises(ValueError):
        AESGCM_encrypt("", key, secret)
    
def test_AESGCM_encrypt():
    key = '941e058419564953ec4292aab10728b0f2c03eae5b89dc29abf77406ee051d29'
    secret = 'my_secret_data'
    encrypted_data = AESGCM_encrypt("", key, secret)
    assert encrypted_data

"""
def test_AESGCM_decrypt():
    key = '000102030405060708090a0b0c0d0e0f'
    secret = 'my_secret_data'
    unencrypted_data = 'unencrypted_data'
    encrypted_data = AESGCM_encrypt("", key, secret)

    decrypted_data = AESGCM_decrypt("", key, encrypted_data)
    assert decrypted_data == secret
"""

def test_bytes_to_hex_string():
    byte_key = b'\x00\x01\x02\x03\x04\x05'
    expected_hex_string = '000102030405'
    hex_string = _bytes_to_hex_string(byte_key)
    assert hex_string == expected_hex_string