"""Module providing authenticated encryption primitives unit tests."""

import pytest
from authenticated_encryption import (
    generate_key, AESGCM_encrypt,
    _bytes_to_hex_string,
    AESGCM_decrypt,
    _hex_string_to_bytes,
    _to_bytes_like
)

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
    nonce = encrypted_data['nonce']
    decrypted = AESGCM_decrypt("", key, encrypted_data['chiper'], nonce)
    assert encrypted_data
    assert decrypted['message'] == secret

def test_bytes_to_hex_string():
    byte_key = b'\x00\x01\x02\x03\x04\x05'
    expected_hex_string = '000102030405'
    hex_string = _bytes_to_hex_string(byte_key)
    assert hex_string == expected_hex_string

def test_hex_string_to_bytes():
    hex_string = '48656c6c6f20776f726c64'
    expected_bytes = b'Hello world'
    assert _hex_string_to_bytes(hex_string) == expected_bytes

    hex_string = ''
    expected_bytes = b''
    assert _hex_string_to_bytes(hex_string) == expected_bytes

    hex_string = 'zzzz'
    with pytest.raises(ValueError):
        _hex_string_to_bytes(hex_string)

def test_to_bytes_like():
    string_data = 'Hello world'
    expected_bytes = b'Hello world'
    assert _to_bytes_like(string_data) == expected_bytes

    list_data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]
    expected_bytes = b'Hello world'
    assert _to_bytes_like(list_data) == expected_bytes

    tuple_data = (72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100)
    expected_bytes = b'Hello world'
    assert _to_bytes_like(tuple_data) == expected_bytes

    invalid_data = 123
    with pytest.raises(TypeError):
        _to_bytes_like(invalid_data)