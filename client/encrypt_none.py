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

BLANK_BYTES = "".encode("utf-8")

def read_pub_key(pubfile_name=None):
    return ""

def crypto_encrypt_with_keystring(pubkey_string=None, msg_string=""):
    """
    Returns msg_string encoded as 'utf-8' byte array.
    """
    return msg_string.encode('utf-8')

def crypto_encrypt(pubfile_name=None, msg_string=""):
    """
    Returns msg_string encoded as 'utf-8' byte array.
    """
    return crypto_encrypt_with_keystring(None, msg_string)   

def crypto_decrypt_with_keystring(keyfile_string=None, byte_array=BLANK_BYTES, password=None):
    """
    Returns byte_array decoded into UTF-8 string
    """
    return byte_array.decode("utf-8")


def crypto_decrypt(keyfile_name, byte_array=BLANK_BYTES, password=None):
    """
    Returns byte_array decoded into UTF-8 string
    """
    return crypto_decrypt_with_keystring(None, byte_array, None)

def generate_rsa_keys(ignore_args):
    """
    Does nothing
    """
