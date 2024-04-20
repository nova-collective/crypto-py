import pytest
from utils import bytes_to_hex_string

def test_bytes_to_hex_string():
    byte_key = b'\x00\x01\x02\x03\x04\x05'
    expected_hex_string = '000102030405'
    hex_string = bytes_to_hex_string(byte_key)
    assert hex_string == expected_hex_string