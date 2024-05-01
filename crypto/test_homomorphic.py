"""Module providing homomorphic primitives unit tests."""

import os
import pytest
from crypto.homomorphic import (
    _get_algorithm,
    _init_phe,
    he_generate_keys,
    he_encrypt,
    he_sum,
    he_decrypt
)

@pytest.fixture(scope='session', autouse=True)
def cleanup():
    # Setup code
    yield
    # Teardown code
    current_path = os.getcwd()
    if os.path.exists(f"{current_path}/{KEYS_TEST_FILE}"):
        os.remove(f"{current_path}/{KEYS_TEST_FILE}")

KEYS_TEST_FILE = "he_keys_test.json"

def test_get_algorithm():
    algorithms = {
        "rsa": "RSA",
        "el_gamal": "ElGamal",
        "paillier": "Paillier"
    }
    assert _get_algorithm(algorithms, "rsa") == "RSA"
    assert _get_algorithm(algorithms, "paillier") == "Paillier"
    with pytest.raises(KeyError):
        _get_algorithm(algorithms, "non_existent_algorithm")

def test_he_generate_keys():
    he_generate_keys("", algorithm="paillier", key_file=KEYS_TEST_FILE)

def test_init_phe():
    phe = _init_phe("paillier", KEYS_TEST_FILE)
    assert phe.algorithm_name == "Paillier"

def test_he_encrypt_decrypt():
    m = 42
    phe = _init_phe("paillier", KEYS_TEST_FILE)
    encrypted = he_encrypt("", m, "paillier")
    decrypted = he_decrypt("", encrypted, "paillier")
    assert decrypted == m

def test_he_sum():
    m = 42
    n = 58
    phe = _init_phe("paillier", KEYS_TEST_FILE)
    encrypted_m = he_encrypt("", m, "paillier")
    encrypted_n = he_encrypt("", n, "paillier")
    encrypted_sum = he_sum("", encrypted_m, encrypted_n, "paillier")
    decrypted_sum = he_decrypt("", encrypted_sum, "paillier")
    assert decrypted_sum == m + n

def test_multiple_sum():
    m = 10
    n = 20
    o = 30
    phe = _init_phe("paillier", KEYS_TEST_FILE)
    encrypted_m = he_encrypt("", m, "paillier")
    encrypted_n = he_encrypt("", n, "paillier")
    encrypted_o = he_encrypt("", o, "paillier")
    encrypted_sum = he_sum("", encrypted_m, encrypted_n, "paillier")
    encrypted_another_sum = he_sum("", encrypted_sum, encrypted_o, "paillier")
    decrypted_sum = he_decrypt("", encrypted_another_sum, "paillier")
    assert decrypted_sum == 60
    
    

