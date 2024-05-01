"""Init file for the crypto module."""

import fire
from crypto.sha import sha3_224, sha3_256, sha3_512
from crypto.authenticated_encryption import generate_key, AESGCM_encrypt, AESGCM_decrypt
from crypto.signatures import generates_key_pair, sign, verify
from crypto.homomorphic import he_encrypt, he_sum, he_decrypt, he_generate_keys

class Crypto:
    """Exposes cryptographic methods"""

    sha3_224           = sha3_224
    sha3_256           = sha3_256
    sha3_512           = sha3_512

    generate_key       = generate_key
    AESGCM_encrypt     = AESGCM_encrypt
    AESGCM_decrypt     = AESGCM_decrypt

    generates_key_pair = generates_key_pair
    sign               = sign
    verify             = verify

    he_generate_keys   = he_generate_keys
    he_encrypt         = he_encrypt
    he_sum             = he_sum
    he_decrypt         = he_decrypt
