import fire
from primitives.sha import sha3_224, sha3_256, sha3_512
from primitives.authenticated_encryption import generate_key

class Crypto(object):
    """Exposes cryptographic methods"""
    
    sha3_224 = sha3_224
    sha3_256 = sha3_256
    sha3_512 = sha3_512
    
    generate_key = generate_key
    

if __name__ == '__main__':
    fire.Fire(Crypto)
