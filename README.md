# crypto-py
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

   `pip Crypto.py <method_name> --param1=<value>`

## Primitives

The following primitives are available:

### SHA-3 family

| primitive | parameters | description |
|-----------|------------|-------------|
| sha3_224  |  input     | returns a sha-3 hash of 224 bits length |
| sha3_256  |  input     | returns a sha-3 hash of 256 bits length |
| sha3_512  |  input     | returns a sha-3 hash of 512 bits length |

### Authenticated encryption family

| primitive | parameters | description |
|-----------|------------|-------------|
| generate_key  |  key_length     | returns an hexadecimal string key of 128, 192, 256 bits length,<br> based on the parameter passed  |


## Test

To run the complete unit test suite run the command:

`pytest`


## License

This software is released under the terms of the [GNU General Public License 3.0](https://www.gnu.org/licenses/gpl-3.0.html)