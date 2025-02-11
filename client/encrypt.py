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


# This library uses PyCryptodome to provide RSA encryption with AES-256 session keys.
# Each ciphertext uses a unique AES-256 session key to encrypt the message. The 
# session key is encrypted with RSA PKCS1_OAEP. This library is for research purposes only
# and we recommend using encrypt_pgp instead.

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import io
import os

def read_pub_key(pubfile_name):
    with open(pubfile_name, 'r') as pubfile:
        pubkey_string = pubfile.read()
        return pubkey_string

def crypto_encrypt_with_keystring(pubkey_string, msg_string):
    data = msg_string.encode("utf-8")
    session_key = get_random_bytes(32)
    recipient_key = RSA.import_key(pubkey_string)    

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # write data to byte_stream
    byte_stream = io.BytesIO()
    byte_stream.write(enc_session_key)
    byte_stream.write(cipher_aes.nonce)
    byte_stream.write(tag)
    byte_stream.write(ciphertext)
    
    # return bytes
    byte_array = byte_stream.getvalue()
    return byte_array

def crypto_encrypt(pubfile_name, msg_string):
    pubkey_string = read_pub_key(pubfile_name)
    return crypto_encrypt_with_keystring(pubkey_string, msg_string)   

def crypto_decrypt_with_keystring(keyfile_string, byte_array, password=None):
    # parse byte_array
    private_key = RSA.import_key(keyfile_string, password)
    byte_stream = io.BytesIO(byte_array)
    enc_session_key = byte_stream.read(private_key.size_in_bytes())
    nonce = byte_stream.read(16)
    tag = byte_stream.read(16)
    ciphertext = byte_stream.read()

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # return msg_string
    msg_string = data.decode("utf-8")
    return msg_string

def crypto_decrypt(keyfile_name, byte_array, password=None):
    with open(keyfile_name, 'r') as keyfile:
        keyfile_string = keyfile.read()
        return crypto_decrypt_with_keystring(keyfile_string, byte_array, password)

def generate_rsa_keys(outfile, password=None, keylength=3072):
    key = RSA.generate(keylength)
    private_key = key.export_key(passphrase=password,
        pkcs=8,
        protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
        prot_params={'iteration_count':131072})

    dir_path = os.path.dirname(outfile)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)    
    with open(outfile + "_key.pem", "wb") as f:
        f.write(private_key)

    public_key = key.publickey().export_key()
    with open(outfile + "_pub.pem", "wb") as f:
       f.write(public_key)
