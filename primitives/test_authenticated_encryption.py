import pytest
from authenticated_encryption import generate_key, _bytes_to_hex_string

def test_generate_key_valid_lengths():
    for key_length in [128, 192, 256]:
        key = generate_key("", key_length)
        assert len(key) == key_length / 4 

def test_generate_key_invalid_length():
    with pytest.raises(ValueError):
        generate_key("", 100)

def test_bytes_to_hex_string():
    byte_key = b'\x00\x01\x02\x03\x04\x05'
    expected_hex_string = '000102030405'
    hex_string = _bytes_to_hex_string(byte_key)
    assert hex_string == expected_hex_string