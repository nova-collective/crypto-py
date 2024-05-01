"""
Module providing homomorphic encryption primitives.

@misc{serengil2023lightphe,
  abstract     = {A Lightweight Partially Homomorphic Encryption Library for Python},
  author       = {Serengil, Sefik Ilkin},
  title        = {LightPHE},
  howpublished = {https://github.com/serengil/LightPHE},
  year         = {2023}
}
"""


from lightphe import LightPHE
import json

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

ALLOWED_ALGORITHMS = ""

IS_FIRST = True
for al in algorithms:
    if IS_FIRST:
        ALLOWED_ALGORITHMS = f" {al}"
        IS_FIRST = False
    else:
        ALLOWED_ALGORITHMS = f"{ALLOWED_ALGORITHMS}, {al}"

def _get_algorithm(dictionary, key):
    if key not in dictionary:
        msg = f"The algorithm '{key}' does not exists. Allowed Algorithms are:{ALLOWED_ALGORITHMS}."
        raise KeyError(msg)
    else:
        return dictionary[key]

def _init_phe(algorithm="paillier", key_file="he_keys.json"):
    alg = _get_algorithm(algorithms, algorithm)
    phe = LightPHE(algorithm_name = alg, key_file=key_file)
    return phe


def he_generate_keys(self, algorithm="paillier", key_file="he_keys.json"):
    """_summary_
    This function generates a private-public key pair.
    
    Args:
        algorithm (str, optional): _description_. Defaults to "paillier".
    """
    alg = _get_algorithm(algorithms, algorithm)
    phe = LightPHE(alg)
    phe.export_keys(target_file = key_file)
    
    json_data = json.dumps({ "result": f"generated keys file {key_file}" })
    return json_data

def he_encrypt(self, m, algorithm="paillier", key_file="he_keys.json"):
    """_summary_
    This function encrypt a value based on the algorithm specified.
    The algorithm passed to this function must be the same of that one used 
    for the keys generation.

    Args:
        m (_type_): _description_
        algorithm (str, optional): _description_. Defaults to "paillier".

    Returns:
        _type_: _description_
    """
    phe = _init_phe(algorithm, key_file)
    e = phe.encrypt(m)

    json_data = json.dumps({ "result": e.value })
    return json_data

def he_sum(self, m, n, algorithm="paillier", key_file="he_keys.json"):
    """_summary_
    This function sum two encrypted values, returning the sum still encrypted.
    The algorithm passed to this function must be the same of that one used 
    for the keys generation.

    Args:
        m (_type_): _description_
        n (_type_): _description_
        algorithm (str, optional): _description_. Defaults to "paillier".

    Returns:
        _type_: _description_
    """
    phe = _init_phe(algorithm, key_file)
    s =  phe.create_ciphertext_obj(m) + phe.create_ciphertext_obj(n)

    json_data = json.dumps({ "result": s.value })
    return json_data

def he_decrypt(self, c, algorithm="paillier", key_file="he_keys.json"):
    """_summary_
    This function decrypt a value based on the algorithm specified.
    The algorithm passed to this function must be the same of that one used 
    for the keys generation.
    
    Args:
        c (_type_): _description_
        algorithm (str, optional): _description_. Defaults to "paillier".

    Returns:
        _type_: _description_
    """
    phe = _init_phe(algorithm, key_file)
    chiper = phe.create_ciphertext_obj(c)
    d = phe.decrypt(chiper)
    
    json_data = json.dumps({ "result": d })
    return json_data
