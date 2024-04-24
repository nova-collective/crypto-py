# crypto-py

[![Known Vulnerabilities](https://snyk.io/package/npm/snyk/badge.svg)](https://snyk.io/package/npm/snyk) [![codecov](https://codecov.io/gh/nova-collective/crypto-py/graph/badge.svg?token=6G9KPAO2G9)](https://codecov.io/gh/nova-collective/crypto-py) ![main workflow](https://github.com/nova-collective/crypto-py/actions/workflows/main.yml/badge.svg) [![HitCount](https://hits.dwyl.com/nova-collective/crypto-py.svg)](https://hits.dwyl.com/nova-collective/crypto-py)

A  pre-quantum cryptographic set of utilities written in Python.

## About
This library exposes a set of cryptographic primitives and algorithms implementations that helps with 
the setup of cryptographic protocols.

The library exposes a CLI and methods that can be imported in other projects.

## System requirements

In order to run this library you need [python3](https://www.python.org/downloads/) installed on your machine.

The library is implemented using version `3.11.2`.

## How to run

1. Create your [Python environment](https://docs.python.org/3/library/venv.html);

1. Install the required dependencies with the command:

   `pip install -r requirements.txt`

2. Invoke a method with the following command:

   `python3 Crypto.py <method_name> --param1=<value>`

NOTE: on your system the `python3` binary name could be different.

## Primitives

The following primitives are available:

### SHA-3 family

| primitive | parameters | description | output |
|-----------|------------|-------------|--------|
| sha3_224  |  `input`: string     | returns a SHA-3 hash of 224 bits length | `{ "hash": <hexadecimal_string> }` |
| sha3_256  |  `input`: string     | returns a SHA-3 hash of 256 bits length | `{ "hash": <hexadecimal_string> }` |
| sha3_512  |  `input`: string     | returns a SHA-3 hash of 512 bits length | `{ "hash": <hexadecimal_string> }` |

All the functions return the data as JSON.

### Authenticated encryption family

| primitive | parameters | description | output |
|-----------|------------|-------------|--------|
| generate_key | `key_length`: number | returns an hexadecimal string key of 128, 192, 256 bits length,<br> based on the parameter passed  |  `{ "key": <hexadecimal_string> }` |
| AESGCM_encrypt | `key`: a 365-bit length key <br> `secret`: the secret to encrypt <br> `unencrypted_data`: optional, unencrypted data to associate to the chiper | returns the chiper with the associated data (if any) and the nonce used for the encryption | `{ "chiper": <hexadecimal_string>, "nonce": <hexadecimal_string> }` |
| AESGCM_decrypt | `key`: the same key used for the encryption <br> `nonce`: the nonce returned from the encryption operation <br>`chiper`: the secret to decrypt <br>`unencrypted_data`: optional, unencrypted data to associate to the chiper | returns the decrypted secret as string | `{ "chiper": <hexadecimal_string>, "nonce": <hexadecimal_string> }` |

All the functions return the data as JSON.

### Digital signature family

The following digital signatures utilities implements the [Elliptic Curve Signature Algorithm Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/): 

| primitive | parameters | description | output |
|-----------|------------|-------------|--------|
| generates_key_pair | none | generates a private and public keys pair | `{ "privateKey": <hexadecimal_string>, "publicKey": <hexadecimal_string> }` |
| sign | `private_key`: hexadecimal string <br> `message`: string | signs a message with the private key and produce the signature for the message | `{ "signature": <hexadecimal_string> }` |
| verify | `public_key`: hexadecimal_string <br> `signature`: hexadecimal_string <br> `message`: hexadecimal_string | verifies a signature on a particular message | `{ "result": <"success"\|"failure"> }` |

All the functions return the data as JSON.


## Test

To run the complete unit test suite run the command:

`pytest`


## License

This software is released under the terms of the [GNU General Public License 3.0](https://www.gnu.org/licenses/gpl-3.0.html)