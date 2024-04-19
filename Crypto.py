import fire
from sha import sha3_224, sha3_256, sha3_512

class Crypto(object):
    """Exposes cryptographic methods"""
    
    sha3_224 = sha3_224
    sha3_256 = sha3_256
    sha3_512 = sha3_512
    

if __name__ == '__main__':
    fire.Fire(Crypto)
