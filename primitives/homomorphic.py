from lightphe import LightPHE

algorithms = [
  "RSA",
  "ElGamal",
  "Exponential-ElGamal",
  "Paillier",
  "Damgard-Jurik",
  "Okamoto-Uchiyama",
  "Benaloh",
  "Naccache-Stern",
  "Goldwasser-Micali",
  "EllipticCurve-ElGamal"
]

def _initPhe():
    phe = LightPHE(algorithm_name = algorithms[3], key_file="keys.json")
    return phe
    

def he_keys(self):
    phe = LightPHE(algorithm_name = algorithms[3])
    phe.export_keys("keys.json")
    return

def he_encrypt (self, m):
    phe = _initPhe()
    e = phe.encrypt(m)
    return e

def he_sum (self, m, n):
    phe = _initPhe()
    s =  phe.create_ciphertext_obj(m) + phe.create_ciphertext_obj(n)
    return s

def he_decrypt (self, c):
    phe = _initPhe()
    chiper = phe.create_ciphertext_obj(c)
    d = phe.decrypt(chiper)
    return d