import fire
from primitives.sha import sha3_224, sha3_256, sha3_512
from primitives.authenticated_encryption import generate_key, AESGCM_encrypt, AESGCM_decrypt
from primitives.signatures import generates_key_pair, sign, verify
from primitives.homomorphic import he_encrypt, he_sum, he_decrypt, he_keys

class Crypto(object):
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
    
    he_keys            = he_keys
    he_encrypt         = he_encrypt
    he_sum             = he_sum
    he_decrypt         = he_decrypt


if __name__ == '__main__':
    fire.Fire(Crypto)
