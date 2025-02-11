# Copyright 2025 Circle Internet Group, Inc. All rights reserved.
#
#  SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import warnings
from cryptography.utils import CryptographyDeprecationWarning
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import pgpy
from datetime import timedelta
import os

def suppress_pgpy_warnings():
    """
    PGPy uses deprecated functions to support decryption of legacy data. 
    These functions are not used in this module. Call suppress_pgpy_warnings()
    prior to calling functions in this file to suppress unnecessary warning messages.
    """
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning, module="pgpy")
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning, module="cryptography.hazmat")


def read_pub_key(pubfile_name):
    """
    Reads a PGP public key from a file.
    
    Args:
        pubfile_name: Path to the public key file in ASCII armored format
        
    Returns:
        PGPKey: The loaded public key object
        
    Raises:
        FileNotFoundError: If pubfile_name does not exist
        PGPError: If file contains invalid key data
    """
    pubkey, _ = pgpy.PGPKey.from_file(pubfile_name)
    return str(pubkey)

def crypto_encrypt_with_keystring(pubkey_string, msg_string):
    """
    Encrypts a message using a PGP public key provided as ASCII armored string.
    
    Args:
        pubkey_string: ASCII armored PGP public key string
        msg_string: Plain text message to encrypt
        
    Returns:
        bytes: The encrypted message as a byte array
        
    Raises:
        PGPError: If pubkey_string contains invalid key data
    """
    recipient_key, _ = pgpy.PGPKey.from_blob(pubkey_string)
    message = pgpy.PGPMessage.new(msg_string)
    encrypted_message = recipient_key.encrypt(message)
    return bytes(encrypted_message)

def crypto_encrypt(pubfile_name, msg_string):
    pubkey_string = read_pub_key(pubfile_name)
    return crypto_encrypt_with_keystring(pubkey_string, msg_string)   

def crypto_decrypt_with_keystring(keyfile_string, byte_array, password=None):
    """
    Decrypts a PGP message using a private key provided as ASCII armored string.
    
    Args:
        keyfile_string: ASCII armored PGP private key string
        byte_array: Encrypted message bytes
        password: Optional password to decrypt private key
        
    Returns:
        str: Decrypted message as UTF-8 string
    """
    private_key, _ = pgpy.PGPKey.from_blob(keyfile_string)
    encrypted_message = pgpy.PGPMessage.from_blob(byte_array)
    if password:
        with private_key.unlock(password):
            decrypted_message = private_key.decrypt(encrypted_message)
            return str(decrypted_message.message)
    else:
        decrypted_message = private_key.decrypt(encrypted_message)
        return str(decrypted_message.message)

def crypto_decrypt(keyfile_name, byte_array, password=None):
    """
    Reads a PGP private key from file and decrypts a message.
    
    Args:
        keyfile_name: Path to private key file
        byte_array: Encrypted message bytes  
        password: Optional password to decrypt private key
        
    Returns:
        str: Decrypted message as UTF-8 string
    """
    with open(keyfile_name, 'rb') as keyfile:  # Changed to binary mode
        keyfile_string = keyfile.read().decode('utf-8')
        return crypto_decrypt_with_keystring(keyfile_string, byte_array, password)

def generate_rsa_keys(outfile, password=None, keylength=3072, name='', comment="no comment", email="no email"):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        # PGPy operations here
        # we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
        key = None
        if keylength == 4096:
            key = pgpy.PGPKey.new(PubKeyAlgorithm.RSA4096, keylength)    
        else:
            key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, keylength)

        # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
        uid = pgpy.PGPUID.new(name, comment=comment, email=email)

        key.add_uid(uid, 
            usage={
                KeyFlags.Sign,
                KeyFlags.EncryptCommunications, 
                KeyFlags.EncryptStorage
            },
            hashes=[
                HashAlgorithm.SHA256,
                HashAlgorithm.SHA384,
                HashAlgorithm.SHA512
            ],
            ciphers=[
                SymmetricKeyAlgorithm.AES256,
                SymmetricKeyAlgorithm.AES192
            ],
            compression=[
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.ZIP
            ],
            key_expiration=timedelta(days=365)
        )

        # protect key with a password
        if password:
            key.protect(password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

        ascii_armored_private_key = bytes(str(key), 'utf-8')
        dir_path = os.path.dirname(outfile)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)    
        with open(outfile + "_key.asc", "wb") as f:
            f.write(ascii_armored_private_key)

        asii_armored_public_key = bytes(str(key.pubkey), 'utf-8')
        with open(outfile + "_pub.asc", "wb") as f:
            f.write(asii_armored_public_key)
