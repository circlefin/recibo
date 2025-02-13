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

import argparse
from encrypt import generate_rsa_keys
from recibo import Recibo
from recibo_crypto import ReciboCrypto
from eth_account import Account
import os
import sys

CONFIG_FILE = 'anvil_config.yaml'
recibo = Recibo(CONFIG_FILE)

def set_config_file(config_file):
    global CONFIG_FILE 
    CONFIG_FILE = config_file
    global recibo 
    recibo = Recibo(CONFIG_FILE)

def print_receipt(receipt):
    if receipt is None:
        print("No output")
    elif 'status' in receipt:
        if receipt['status'] == 1:
            print(f"Success! Tx hash: 0x{receipt['transactionHash'].hex()}")
            return 0
        else:
            print('Failed')
            print(receipt)
            return 1
    else:
        print(f"Unexpected output {receipt}")
        return 1

def deploy(args):
    contract_address = recibo.deploy(args.deployer_private_key)
    if contract_address is None:
        return 1
    return 0  

def deploy_recibo(args):
    contract_address = recibo.deploy_recibo(args.deployer_private_key, args.token_address)
    if contract_address is None:
        return 1
    return 0  

def metadata_from_args(args):
    return ReciboCrypto.generate_encrypt_metadata(
        version=ReciboCrypto.VERSION,
        encrypt_alg_id=args.encrypt_alg_id,
        response_pub_key_filename=args.response_pub_keyfile,
        response_encrypt_alg_id=args.response_encrypt_alg_id
    )    

def send_msg(args):
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message, args.encrypt_alg_id)
    print(f'Execute Recibo.sendMsg()')

    metadata = metadata_from_args(args)
    receipt = recibo.send_msg(
        args.owner_private_key, 
        args.receiver_address,
        metadata, 
        ciphertext_msg_as_hex
    ) 
    return print_receipt(receipt)

def respond_to_tx(args):
    print(f'Execute Recibo.sendMsg()')
    receipt = recibo.respond_to_tx(
        args.tx_hash,
        args.owner_private_key,
        None,
        args.message)

    return print_receipt(receipt)


def transfer_with_authorization_with_msg(args):
    owner_address = Account.from_key(args.owner_private_key).address
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message, args.encrypt_alg_id)
    nonce = os.urandom(32)
    valid_after = 0
    valid_before = 115792089237316195423570985008687907853269984665640564039457584007913129639935

    transfer_authorization = recibo.build_transfer_authorization(
        owner_address,
        args.receiver_address,
        args.value,
        valid_after,
        valid_before,
        nonce
    )
    signature = recibo.sign_transfer_authorization(args.owner_private_key, transfer_authorization)

    print(f'Execute Recibo.TransferWithAuthorizationWithMsg()')
    metadata = metadata_from_args(args)
    receipt = recibo.transfer_with_authorization_with_msg(
            args.owner_private_key,
            owner_address,
            args.receiver_address,
            args.value,
            valid_after,
            valid_before,
            nonce,
            signature,
            metadata,
            ciphertext_msg_as_hex
    )
    return print_receipt(receipt)    

def transfer_from_with_msg(args):
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message, args.encrypt_alg_id)

    # owner approves Recibo contract allowance
    print('Execute Token.Approve(Recibo_Contract)')
    receipt = recibo.approve_recibo(args.owner_private_key, args.value)
    print_receipt(receipt)
    if(receipt['status'] != 1):
        print("Could not approve Recibo contract allowance. Exiting")
        return

    # owner calls transferFromWithMsg
    print(f'Execute Recibo.TransferFromWithMsg()')
    metadata = metadata_from_args(args)
    receipt = recibo.transfer_from_with_msg(
        args.owner_private_key, 
        args.receiver_address, 
        args.value, 
        metadata, 
        ciphertext_msg_as_hex
    ) 
    return print_receipt(receipt)

def permit_with_msg(args):
    owner_address = Account.from_key(args.owner_private_key).address
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message, args.encrypt_alg_id)
    deadline = 115792089237316195423570985008687907853269984665640564039457584007913129639935

    permit = recibo.build_permit(
        owner_address,
        args.spender_address,
        args.value,
        deadline
    )
    signature = recibo.sign_permit(args.owner_private_key, permit)

    print(f'Execute Recibo.PermitWithMsg()')
    metadata = metadata_from_args(args)
    receipt = recibo.permit_with_msg(
        args.owner_private_key, 
        args.spender_address, 
        args.value, deadline, 
        signature.v, 
        signature.r, 
        signature.s, 
        metadata, 
        ciphertext_msg_as_hex
    )
    return print_receipt(receipt)    


def permit_and_transfer_with_msg(args):
    owner_address = Account.from_key(args.owner_private_key).address
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message, args.encrypt_alg_id)
    deadline = 115792089237316195423570985008687907853269984665640564039457584007913129639935

    permit = recibo.build_permit(
        owner_address,
        recibo.recibo_config.contract_address,
        args.value,
        deadline
    )
    signature = recibo.sign_permit(args.owner_private_key, permit)

    print(f'Execute Recibo.PermitAndTransferWithMsg()')
    metadata = metadata_from_args(args)
    receipt = recibo.permit_and_transfer_with_msg(
        args.owner_private_key, 
        args.receiver_address, 
        args.value, 
        deadline, 
        signature.v, 
        signature.r, 
        signature.s, 
        metadata, 
        ciphertext_msg_as_hex)    
    return print_receipt(receipt)    


def read_msg(args):
    decryptedtx = recibo.read_msg(args.receiver_address, args.decrypt_keyfile, args.password, args.encrypt_alg_id)
    print(f'Found {len(decryptedtx)} transactions with messages for {args.receiver_address}:')
    print()
    for dtx in decryptedtx:
        print(f'Transaction: {dtx.event}\nTx Hash: {dtx.tx_hash}\nMetadata: {dtx.metadata}\nMessageFrom: {dtx.message_from}\nValue: {dtx.value}\nMessage: {dtx.plaintext}')
        print()
    return 0

def gen_rsa_key(args):
    password = None
    keylength = 3072
    if hasattr(args, 'password'):
        password = args.password
    if hasattr(args, 'keylength') and args.keylength is not None:
        keylength = args.keylength

    generate_rsa_keys(args.outfile, password, keylength)
    return 0

# all commands that send a transaction with a message have these arguments
def add_msg_encryption_args_to_parser(parser):
    parser.add_argument("--message", type=str, required=True, help="Message string")
    parser.add_argument("--encrypt_pub_keyfile", type=str, required=False, help="Location of public key file")
    parser.add_argument("--encrypt_alg_id", type=str, required=False, default=ReciboCrypto.ENCRYPT_PGP, help="Which encryption algorithm to use: pgp (default), none, or RSA_PKCS1_OAEP_AES_EAX.")
    parser.add_argument("--response_pub_keyfile", type=str, required=False, default=None, help="Location of sender's public key file. Add to metadata so receiver can respond.")
    parser.add_argument("--response_encrypt_alg_id", type=str, required=False, default=ReciboCrypto.ENCRYPT_PGP, help="Which encryption algorithm to use for response: pgp (default), none, or RSA_PKCS1_OAEP_AES_EAX.")
    parser.add_argument("--config_file", type=str, required=False, help="Location of recibo yaml config file. Defaults to ./anvil_config.yaml")

def main():
    parser = argparse.ArgumentParser(description="CLI for Recibo class methods")
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for deploy
    parser_deploy = subparsers.add_parser("deploy", help="Deploy token and Recibo contracts")
    parser_deploy.add_argument("--deployer_private_key", type=str, required=False, help="Deployer private key")
    parser_deploy.add_argument("--config_file", type=str, required=False, help="Location of yaml config file. Defaults to ./anvil_config.yaml")

    # Subparser for deploy_recibo
    parser_deploy_recibo = subparsers.add_parser("deploy_recibo", help="Deploy Recibo contract")
    parser_deploy_recibo.add_argument("--deployer_private_key", type=str, required=False, help="Deployer private key")
    parser_deploy_recibo.add_argument("--token_address", type=str, required=True, help="Token address")
    parser_deploy_recibo.add_argument("--config_file", type=str, required=False, help="Location of yaml config file. Defaults to ./anvil_config.yaml")

    # Subparser for send_msg
    parser_send_msg = subparsers.add_parser("send_msg", help="Call send_msg method")
    parser_send_msg.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_send_msg.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    add_msg_encryption_args_to_parser(parser_send_msg)

    # Subparser for respond_to_tx
    parser_respond_to_tx = subparsers.add_parser("respond_to_tx", help="Call send_msg method")
    parser_respond_to_tx.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_respond_to_tx.add_argument("--tx_hash", type=str, required=True, help="Hash of Recibo transaction to which to respond")
    add_msg_encryption_args_to_parser(parser_respond_to_tx)

    # Subparser for transfer_with_authorization_with_msg
    parser_transfer_with_auth = subparsers.add_parser("transfer_with_authorization_with_msg", help="Call transfer_with_authorization_with_msg method")
    parser_transfer_with_auth.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_transfer_with_auth.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_transfer_with_auth.add_argument("--value", type=int, required=True, help="Value")
    add_msg_encryption_args_to_parser(parser_transfer_with_auth)

    # Subparser for transfer_from_with_msg
    parser_transfer_from = subparsers.add_parser("transfer_from_with_msg", help="Call transfer_from_with_msg method")
    parser_transfer_from.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_transfer_from.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_transfer_from.add_argument("--value", type=int, required=True, help="Value")
    add_msg_encryption_args_to_parser(parser_transfer_from)

    # Subparser for permit_with_msg
    parser_permit_with_msg = subparsers.add_parser("permit_with_msg", help="Call permit_with_msg method")
    parser_permit_with_msg.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_permit_with_msg.add_argument("--spender_address", type=str, required=True, help="Spender address")
    parser_permit_with_msg.add_argument("--value", type=int, required=True, help="Value")
    add_msg_encryption_args_to_parser(parser_permit_with_msg)

    # Subparser for permit_and_transfer_with_msg
    parser_permit_and_transfer_with_msg = subparsers.add_parser("permit_and_transfer_with_msg", help="Call permit_and_transfer_with_msg method")
    parser_permit_and_transfer_with_msg.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_permit_and_transfer_with_msg.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_permit_and_transfer_with_msg.add_argument("--value", type=int, required=True, help="Value")
    add_msg_encryption_args_to_parser(parser_permit_and_transfer_with_msg)

    # Subparsers read_msg
    parser_read_msg = subparsers.add_parser("read_msg", help="Download transactions and decrypt messages for specified receiver address")
    parser_read_msg.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_read_msg.add_argument("--decrypt_keyfile", type=str, required=False, help="Message string")
    parser_read_msg.add_argument("--password", type=str, required=False, default=None, help="Password for decrypt_keyfile")
    parser_read_msg.add_argument("--config_file", type=str, required=False, help="Location of recibo yaml config file. Defaults to ./anvil_config.yaml")
    parser_read_msg.add_argument("--encrypt_alg_id", type=str, required=False, default=ReciboCrypto.ENCRYPT_PGP, help="Which encryption algorithm to use: pgp (default), none, or RSA_PKCS1_OAEP_AES_EAX.")
 
    # Subparsers gen_rsa_key
    parser_gen_rsa_key = subparsers.add_parser("gen_rsa_key", help="Generate RSA key pair and save public and private key to a file")
    parser_gen_rsa_key.add_argument("--outfile", type=str, required=True, help="Output file name")
    parser_gen_rsa_key.add_argument("--password", type=str, required=False, help="Protects private key, recommended but not required")
    parser_gen_rsa_key.add_argument("--keylength", type=int, required=False, help="Default is 3072")

    exit_code = 1
    args = parser.parse_args()
    if hasattr(args, 'config_file') and args.config_file is not None:
        set_config_file(args.config_file)


    # need encrypt_pub_keyfile for some commands
    commands = ["send_msg", "respont_to_tx", "transfer_with_authorization_with_msg", 
                "transfer_from_with_msg", "permit_with_msg", "permit_and_transfer_with_msg"]
    if args.command in commands:
        if args.encrypt_alg_id != ReciboCrypto.NOENCRYPT and not hasattr(args, "encrypt_pub_keyfile"):
            parser.print_usage()
            sys.exit("Error: encrypt_pub_keyfile is required when encryption is enabled. To disable encryption use --encrypt_alg_id " + ReciboCrypto.NOENCRYPT)           

    if args.command == "read_msg":
        if args.encrypt_alg_id != ReciboCrypto.NOENCRYPT and not hasattr(args, "decrypt_keyfile"):
            parser.print_usage()
            sys.exit("Error: decrypt_keyfile is required when encryption is enabled. To disable encryption use --encrypt_alg_id " + ReciboCrypto.NOENCRYPT)           

    if args.command == "deploy":
        exit_code = deploy(args)
    elif args.command == "deploy_recibo":
        exit_code = deploy_recibo(args)
    elif args.command == "send_msg":
        exit_code = send_msg(args)
    elif args.command == "respond_to_tx":
        exit_code = respond_to_tx(args)
    elif args.command == "transfer_with_authorization_with_msg":
        exit_code = transfer_with_authorization_with_msg(args)
    elif args.command == "transfer_from_with_msg":
        exit_code = transfer_from_with_msg(args)
    elif args.command == "permit_with_msg":
        exit_code = permit_with_msg(args)
    elif args.command == "permit_and_transfer_with_msg":
        exit_code = permit_and_transfer_with_msg(args)
    elif args.command == "read_msg":
        exit_code = read_msg(args)
    elif args.command == "gen_rsa_key":
        exit_code = gen_rsa_key(args)
 
    else:
        parser.print_help()

    return exit_code

if __name__ == "__main__":
   sys.exit(main())
   