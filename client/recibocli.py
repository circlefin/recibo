# Copyright (c) 2024, Circle Internet Financial, LTD. All rights reserved.
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

def transfer_with_authorization_with_msg(args):
    owner_address = Account.from_key(args.owner_private_key).address
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message)
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
    receipt = recibo.transfer_with_authorization_with_msg(
            args.owner_private_key,
            owner_address,
            args.receiver_address,
            args.value,
            valid_after,
            valid_before,
            nonce,
            signature,
            Recibo.RSA_METADATA,
            ciphertext_msg_as_hex
    )
    return print_receipt(receipt)    

def transfer_from_with_msg(args):
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message)

    # owner approves Recibo contract allowance
    print('Execute Token.Approve(Recibo_Contract)')
    receipt = recibo.approve_recibo(args.owner_private_key, args.value)
    print_receipt(receipt)
    if(receipt['status'] != 1):
        print("Could not approve Recibo contract allowance. Exiting")
        return

    # owner calls transferFromWithMsg
    print(f'Execute Recibo.TransferFromWithMsg()')
    receipt = recibo.transfer_from_with_msg(
        args.owner_private_key, 
        args.receiver_address, 
        args.value, 
        Recibo.RSA_METADATA, 
        ciphertext_msg_as_hex
    ) 
    return print_receipt(receipt)

def permit_with_msg(args):
    owner_address = Account.from_key(args.owner_private_key).address
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message)
    deadline = 115792089237316195423570985008687907853269984665640564039457584007913129639935

    permit = recibo.build_permit(
        owner_address,
        args.spender_address,
        args.value,
        deadline
    )
    signature = recibo.sign_permit(args.owner_private_key, permit)

    print(f'Execute Recibo.PermitWithMsg()')
    receipt = recibo.permit_with_msg(
        args.owner_private_key, 
        args.spender_address, 
        args.value, deadline, 
        signature.v, 
        signature.r, 
        signature.s, 
        Recibo.RSA_METADATA, 
        ciphertext_msg_as_hex
    )
    return print_receipt(receipt)    


def permit_and_transfer_with_msg(args):
    owner_address = Account.from_key(args.owner_private_key).address
    ciphertext_msg_as_hex = Recibo.encrypt(args.encrypt_pub_keyfile, args.message)
    deadline = 115792089237316195423570985008687907853269984665640564039457584007913129639935

    permit = recibo.build_permit(
        owner_address,
        recibo.recibo_config.contract_address,
        args.value,
        deadline
    )
    signature = recibo.sign_permit(args.owner_private_key, permit)

    print(f'Execute Recibo.PermitAndTransferWithMsg()')
    receipt = recibo.permit_and_transfer_with_msg(
        args.owner_private_key, 
        args.receiver_address, 
        args.value, 
        deadline, 
        signature.v, 
        signature.r, 
        signature.s, 
        Recibo.RSA_METADATA, 
        ciphertext_msg_as_hex)    
    return print_receipt(receipt)    


def read_msg(args):
    password = None
    if hasattr(args, 'password'):
        password = args.password

    transfer_events, approve_events = recibo.get_events_for(args.receiver_address)
    events = transfer_events + approve_events
    print(f'Found {len(events)} transactions with messages for {args.receiver_address}:')
    print()
    for event in events:
        message = recibo.decrypt_tx(event.tx_hash, args.decrypt_keyfile, password)
        print(f'Transaction: {event.event}\nTx Hash: {event.tx_hash}\nMessageFrom: {event.message_from}\nValue: {event.value}\nMessage: {message}')
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

    # Subparser for transfer_with_authorization_with_msg
    parser_transfer_with_auth = subparsers.add_parser("transfer_with_authorization_with_msg", help="Call transfer_with_authorization_with_msg method")
    parser_transfer_with_auth.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_transfer_with_auth.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_transfer_with_auth.add_argument("--value", type=int, required=True, help="Value")
    parser_transfer_with_auth.add_argument("--message", type=str, required=True, help="Message string")
    parser_transfer_with_auth.add_argument("--encrypt_pub_keyfile", type=str, required=True, help="Location of public key file")
    parser_transfer_with_auth.add_argument("--config_file", type=str, required=False, help="Location of recibo yaml config file. Defaults to ./anvil_config.yaml")

    # Subparser for transfer_from_with_msg
    parser_transfer_from = subparsers.add_parser("transfer_from_with_msg", help="Call transfer_from_with_msg method")
    parser_transfer_from.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_transfer_from.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_transfer_from.add_argument("--value", type=int, required=True, help="Value")
    parser_transfer_from.add_argument("--message", type=str, required=True, help="Message string")
    parser_transfer_from.add_argument("--encrypt_pub_keyfile", type=str, required=True, help="Message string")
    parser_transfer_from.add_argument("--config_file", type=str, required=False, help="Location of recibo yaml config file. Defaults to ./anvil_config.yaml")

    # Subparser for permit_with_msg
    parser_permit_with_msg = subparsers.add_parser("permit_with_msg", help="Call permit_with_msg method")
    parser_permit_with_msg.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_permit_with_msg.add_argument("--spender_address", type=str, required=True, help="Spender address")
    parser_permit_with_msg.add_argument("--value", type=int, required=True, help="Value")
    parser_permit_with_msg.add_argument("--message", type=str, required=True, help="Message string")
    parser_permit_with_msg.add_argument("--encrypt_pub_keyfile", type=str, required=True, help="Message string")
    parser_permit_with_msg.add_argument("--config_file", type=str, required=False, help="Location of recibo yaml config file. Defaults to ./anvil_config.yaml")

    # Subparser for permit_and_transfer_with_msg
    parser_permit_and_transfer_with_msg = subparsers.add_parser("permit_and_transfer_with_msg", help="Call permit_and_transfer_with_msg method")
    parser_permit_and_transfer_with_msg.add_argument("--owner_private_key", type=str, required=True, help="Owner address")
    parser_permit_and_transfer_with_msg.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_permit_and_transfer_with_msg.add_argument("--value", type=int, required=True, help="Value")
    parser_permit_and_transfer_with_msg.add_argument("--message", type=str, required=True, help="Message string")
    parser_permit_and_transfer_with_msg.add_argument("--encrypt_pub_keyfile", type=str, required=True, help="Message string")
    parser_permit_and_transfer_with_msg.add_argument("--config_file", type=str, required=False, help="Location of recibo yaml config file. Defaults to ./anvil_config.yaml")

    # Subparsers read_msg
    parser_read_msg = subparsers.add_parser("read_msg", help="Download transactions and decrypt messages for specified receiver address")
    parser_read_msg.add_argument("--receiver_address", type=str, required=True, help="Receiver address")
    parser_read_msg.add_argument("--decrypt_keyfile", type=str, required=True, help="Message string")
    parser_read_msg.add_argument("--password", type=str, required=False, help="Password for decrypt_keyfile")
    parser_read_msg.add_argument("--config_file", type=str, required=False, help="Location of recibo yaml config file. Defaults to ./anvil_config.yaml")

    # Subparsers gen_rsa_key
    parser_gen_rsa_key = subparsers.add_parser("gen_rsa_key", help="Generate RSA key pair and save public and private key to a file")
    parser_gen_rsa_key.add_argument("--outfile", type=str, required=True, help="Output file name")
    parser_gen_rsa_key.add_argument("--password", type=str, required=False, help="Protects private key, recommended but not required")
    parser_gen_rsa_key.add_argument("--keylength", type=int, required=False, help="Default is 3072")

    exit_code = 1
    args = parser.parse_args()
    if hasattr(args, 'config_file') and args.config_file is not None:
        set_config_file(args.config_file)

    if args.command == "deploy":
        exit_code = deploy(args)
    elif args.command == "deploy_recibo":
        exit_code = deploy_recibo(args)
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
   