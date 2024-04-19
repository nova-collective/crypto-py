# Licensed under the GPL GNU General Public License, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.gnu.org/licenses/gpl-3.0.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The setup.py file for Crypto-py."""

from setuptools import setup, find_packages

LONG_DESCRIPTION = """
Crypto-py  exposes a set of cryptographic primitives and algorithms implementations that helps with 
the setup of cryptographic protocols.

The library exposes a CLI and methods that can be imported in other projects.
""".strip()

SHORT_DESCRIPTION = """
A  pre-quantum cryptographic set of utilities written in Python.""".strip()

DEPENDENCIES = [
    'fire'
    'cryptography'
    'pytest'
]

VERSION = '0.1.0'

setup(
    name='fire',
    version=VERSION,
    description=SHORT_DESCRIPTION,
    long_description=LONG_DESCRIPTION,

    author='Christian Palazzo',
    author_email='nova.web3.collective@gmail.com',
    license='GPL-3.0',

    keywords='cryptography python cli command-line-interface',

    install_requires=DEPENDENCIES
)