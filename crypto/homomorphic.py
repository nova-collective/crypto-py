"""Module providing homomorphic encryption primitives."""

from lightphe import LightPHE

algorithms = {
    "rsa": "RSA",
    "el_gamal": "ElGamal",
    "exponential_el_gamal": "Exponential-ElGamal",
    "paillier": "Paillier",
    "damgard_jurik": "Damgard-Jurik",
    "okamoto_uchiyama": "Okamoto-Uchiyama",
    "benaloh": "Benaloh",
    "naccache_stern": "Naccache-Stern",
    "goldwasser_micali": "Goldwasser-Micali",
    "elliptic_curve_el_gamal": "EllipticCurve-ElGamal"
}

def _get_algorithm(dictionary, key):
    if key not in dictionary:
        raise KeyError(f"The algorithm '{key}' does not exists.")
    else:
        return dictionary[key]

def _initPhe(algorithm="paillier"):
    alg = _get_algorithm(algorithms, algorithm)
    phe = LightPHE(algorithm_name = algorithms[alg], key_file="he_keys.json")
    return phe


def he_generate_keys(self, algorithm="paillier"):
    alg = _get_algorithm(algorithms, algorithm)
    phe = LightPHE(alg)
    phe.export_keys(target_file = "he_keys.json")
    return

def he_encrypt(self, m, algorithm="paillier"):
    alg = _get_algorithm(algorithms, algorithm)
    phe = _initPhe(alg)
    e = phe.encrypt(m)
    return e

def he_sum(self, m, n, algorithm="paillier"):
    alg = _get_algorithm(algorithms, algorithm)
    phe = _initPhe(alg)
    s =  phe.create_ciphertext_obj(m) + phe.create_ciphertext_obj(n)
    return s

def he_decrypt(self, c, algorithm="paillier"):
    alg = _get_algorithm(algorithms, algorithm)
    phe = _initPhe(alg)
    chiper = phe.create_ciphertext_obj(c)
    d = phe.decrypt(chiper)
    return d