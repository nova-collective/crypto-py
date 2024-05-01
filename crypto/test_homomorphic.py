"""Module providing homomorphic primitives unit tests."""

import json
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
    encrypted = he_encrypt("", m, "paillier", KEYS_TEST_FILE)
    j_encrypted = json.loads(encrypted)
    
    decrypted = he_decrypt("", j_encrypted["result"], "paillier", KEYS_TEST_FILE)
    j_decrypted = json.loads(decrypted)
    assert j_decrypted["result"] == m

def test_he_sum():
    m = 42
    n = 58
    phe = _init_phe("paillier", KEYS_TEST_FILE)
    encrypted_m = he_encrypt("", m, "paillier", KEYS_TEST_FILE)
    encrypted_n = he_encrypt("", n, "paillier", KEYS_TEST_FILE)
    j_encrypted_m = json.loads(encrypted_m)
    j_encrypted_n = json.loads(encrypted_n)
    
    encrypted_sum = he_sum("", j_encrypted_m["result"], j_encrypted_n["result"], "paillier", KEYS_TEST_FILE)
    j_encrypted_sum = json.loads(encrypted_sum)
    
    decrypted_sum = he_decrypt("", j_encrypted_sum["result"], "paillier", KEYS_TEST_FILE)
    j_decripted_sum = json.loads(decrypted_sum)
    assert j_decripted_sum["result"] == m + n

def test_multiple_sum():
    m = 10
    n = 20
    o = 30
    phe = _init_phe("paillier", KEYS_TEST_FILE)
    encrypted_m = he_encrypt("", m, "paillier", KEYS_TEST_FILE)
    encrypted_n = he_encrypt("", n, "paillier", KEYS_TEST_FILE)
    encrypted_o = he_encrypt("", o, "paillier", KEYS_TEST_FILE)
    j_encrypted_m = json.loads(encrypted_m)
    j_encrypted_n = json.loads(encrypted_n)
    j_encrypted_o = json.loads(encrypted_o)
    
    encrypted_sum = he_sum("", j_encrypted_m["result"], j_encrypted_n["result"], "paillier", KEYS_TEST_FILE)
    j_encrypted_sum = json.loads(encrypted_sum)
    
    encrypted_another_sum = he_sum("", j_encrypted_sum["result"], j_encrypted_o["result"], "paillier", KEYS_TEST_FILE)
    j_encrypted_another_sum = json.loads(encrypted_another_sum)
    
    decrypted_sum = he_decrypt("", j_encrypted_another_sum["result"], "paillier", KEYS_TEST_FILE)
    j_decripted_sum = json.loads(decrypted_sum)
    assert j_decripted_sum["result"] == 60
    
    

