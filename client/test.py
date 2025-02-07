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

from encrypt import crypto_decrypt, crypto_encrypt, generate_rsa_keys
from recibo import Recibo
import os
import psutil
import subprocess
import unittest
from web3 import HTTPProvider
from anvil_web3 import AnvilWeb3


class User:
    def __init__(self, address, private_key, outfile, password):
        self.private_key = private_key
        self.address = address
        self.outfile = outfile
        self.encrypt_pub = outfile + '_pub.pem'
        self.encrypt_key = outfile + '_key.pem'
        self.password = password      

class ReciboTest(unittest.TestCase):
    CONFIG_FILE = 'anvil_config.yaml'
    max_uint256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935

    @staticmethod
    def is_process_running(process_name):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == process_name:
                return True
        return False
    
    @classmethod
    def setUpClass(cls):
        if not cls.is_process_running('anvil'):
            print("Starting anvil process...")
            cls.anvil = subprocess.Popen("anvil", shell=False, stdout=subprocess.DEVNULL)
        else:
            print("Anvil process is already running.")

        cls.recibo = Recibo(cls.CONFIG_FILE)
        w3 = AnvilWeb3(HTTPProvider(cls.recibo.recibo_config.rpc_url))
        test_account_balance = w3.to_wei(10000, 'ether') 

        deployer_acc = w3.eth.account.from_key(w3.keccak(text="deployer"))
        w3.anvil.set_balance(deployer_acc.address, test_account_balance)
        cls.deployer = User(
            deployer_acc.address, 
            '0x' + deployer_acc.key.hex(),
            '../client-test-data/deployer',
            'deployer password'
        )

        alice_acc = w3.eth.account.from_key(w3.keccak(text="alice"))
        w3.anvil.set_balance(alice_acc.address, test_account_balance)
        cls.alice = User(
            alice_acc.address, 
            '0x' + alice_acc.key.hex(),
            'alice',
            None
        )

        bob_acc = w3.eth.account.from_key(w3.keccak(text="bob"))
        w3.anvil.set_balance(bob_acc.address, test_account_balance)
        cls.bob = User(
            bob_acc.address, 
            '0x' + bob_acc.key.hex(),
            '../client-test-data/bob',
            'bob password'
        )
        generate_rsa_keys(cls.deployer.outfile, cls.deployer.password, 3072)
        generate_rsa_keys(cls.alice.outfile, cls.alice.password, 3072)
        generate_rsa_keys(cls.bob.outfile,cls.bob.password, 3072)


        cls.recibo.deploy(cls.deployer.private_key)

    def test_encrypt(self):
        msg = 'hello world'
        ciphertext = crypto_encrypt(self.alice.encrypt_pub, msg)
        plaintext = crypto_decrypt(self.alice.encrypt_key, ciphertext, self.alice.password)
        self.assertEqual(msg, plaintext)

    def test_total_supply(self):
        expected = 2000
        actual = self.recibo.total_supply()
        self.assertEqual(expected, actual)

    def test_balance_of(self):
        expected = 2000
        actual = self.recibo.balance_of(self.deployer.address)
        self.assertEqual(expected, actual)

        expected = 0
        actual = self.recibo.balance_of(self.alice.address)
        self.assertEqual(expected, actual)

    def test_send_msg(self):
        owner = self.deployer
        receiver = self.bob

        # owner calls send_msg
        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)
        receipt = self.recibo.send_msg(owner.private_key, receiver.address, Recibo.RSA_METADATA, message_as_hex) 
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)        

        # verify message decrypts
        tx_hash = receipt['transactionHash'].hex()
        tx = self.recibo.get_transaction(tx_hash)
        plaintext = self.recibo.decrypt(receiver.encrypt_key, tx.message, receiver.password)
        self.assertEqual(plaintext, message)

    def test_respond_to_tx(self):
        owner = self.deployer
        receiver = self.bob

        # owner sends message and includes his public key in metadata
        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)
        metadata = Recibo.generate_encrypt_metadata(Recibo.VERSION, Recibo.ENCRYPT, None, None, owner.encrypt_pub)
        receipt = self.recibo.send_msg(owner.private_key, receiver.address, metadata, message_as_hex) 
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)        

        # respond to tx
        tx_hash = receipt['transactionHash'].hex()
        response_message = "greetings"
        metadata = Recibo.generate_encrypt_metadata(Recibo.VERSION, Recibo.ENCRYPT, None, None, receiver.encrypt_pub)
        receipt = self.recibo.respond_to_tx(tx_hash, receiver.private_key, metadata, response_message)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)        

        # decrypt response
        tx_hash = receipt['transactionHash'].hex()
        tx = self.recibo.get_transaction(tx_hash)
        plaintext = self.recibo.decrypt(owner.encrypt_key, tx.message, owner.password)
        self.assertEqual(response_message, plaintext)

    def test_transferFromWithMsg(self):
        owner = self.deployer
        receiver = self.bob
        value = 10

        # owner approves Recibo contract allowance
        receipt = self.recibo.approve_recibo(owner.private_key, value)
        self.assertEqual(receipt['status'], 1)

        # check allowance
        allowance = self.recibo.allowance(owner.address, self.recibo.recibo_config.contract_address)
        self.assertEqual(value, allowance)

        # check balance
        balance = self.recibo.balance_of(owner.address)
        self.assertGreaterEqual(balance, value)

        # owner calls transferFromWithMsg
        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)
        receipt = self.recibo.transfer_from_with_msg(owner.private_key, receiver.address, value, Recibo.RSA_METADATA, message_as_hex) 
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)        

        # verify message decrypts
        tx_hash = receipt['transactionHash'].hex()
        tx = self.recibo.get_transaction(tx_hash)
        plaintext = self.recibo.decrypt(receiver.encrypt_key, tx.message, receiver.password)
        self.assertEqual(plaintext, message)

    def test_permitWithMsg(self):
        owner = self.deployer
        spender = self.bob
        value = 10
        deadline = ReciboTest.max_uint256

        # generate EIP-2612 permit compatible with ERC20Permit.sol contract
        permit = self.recibo.build_permit(owner.address, spender.address, value, deadline)
        signature = self.recibo.sign_permit(owner.private_key, permit)

        # owners call permitWithMsg 
        message = 'hello world'
        message_as_hex = Recibo.encrypt(spender.encrypt_pub, message)
        receipt = self.recibo.permit_with_msg(owner.private_key, spender.address, value, deadline, signature.v, signature.r, signature.s, Recibo.RSA_METADATA, message_as_hex)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)

        # check allowance
        allowance = self.recibo.allowance(owner.address, spender.address)
        self.assertEqual(value, allowance)

    def test_permitAndTransferFromWithMsg(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        deadline = ReciboTest.max_uint256
        prev_balance = self.recibo.balance_of(receiver.address)

        # generate EIP-2612 permit compatible with ERC20Permit.sol contract
        # to give deployed recibo contract allowance
        permit = self.recibo.build_permit(owner.address, self.recibo.recibo_config.contract_address, value, deadline)
        signature = self.recibo.sign_permit(owner.private_key, permit)

        # owners call permitAndTransferFromWithMsg 
        message = 'hello world'
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)
        receipt = self.recibo.permit_and_transfer_with_msg(owner.private_key, receiver.address, value, deadline, signature.v, signature.r, signature.s, Recibo.RSA_METADATA, message_as_hex)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)

        # check balance
        balance = self.recibo.balance_of(receiver.address)
        self.assertEqual(prev_balance + value, balance)


    def test_transfer_with_authorization_with_msg(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        valid_after = 0
        valid_before = ReciboTest.max_uint256
        nonce = os.urandom(32)
        prev_balance = self.recibo.balance_of(receiver.address)

        # generate EIP-2612 permit compatible with ERC20Permit.sol contract
        # to give deployed recibo contract allowance
        transfer_authorization = self.recibo.build_transfer_authorization(
            owner.address,
            receiver.address,
            value,
            valid_after,
            valid_before,
            nonce
        )
        signature = self.recibo.sign_transfer_authorization(owner.private_key, transfer_authorization)

        # owners call transferWithAuthorizationWithMsg 
        message = 'hello world'
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)
        receipt = self.recibo.transfer_with_authorization_with_msg(
            receiver.private_key,
            owner.address,
            receiver.address,
            value,
            valid_after,
            valid_before,
            nonce,
            signature,
            Recibo.RSA_METADATA,
            message_as_hex
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)

        # check balance
        balance = self.recibo.balance_of(receiver.address)
        self.assertEqual(prev_balance + value, balance)

    # dev note: this test assumes this is only test where testnet_alice receives message
    def test_get_events_for(self):
        owner = self.deployer
        receiver = self.alice
        value = 10
        deadline = ReciboTest.max_uint256
        message = 'hello world'
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)

        # generate TransferWithMsg event
        receipt = self.recibo.approve_recibo(owner.private_key, value)
        self.assertEqual(receipt['status'], 1)
        receipt = self.recibo.transfer_from_with_msg(owner.private_key, receiver.address, value, Recibo.RSA_METADATA, message_as_hex) 
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)
        transfer_tx_hash = receipt['transactionHash'].hex()         

        # generate ApproveWithMsg event
        permit = self.recibo.build_permit(owner.address, receiver.address, value, deadline)
        signature = self.recibo.sign_permit(owner.private_key, permit)
        receipt = self.recibo.permit_with_msg(owner.private_key, receiver.address, value, deadline, signature.v, signature.r, signature.s, Recibo.RSA_METADATA, message_as_hex)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)
        approve_tx_hash = receipt['transactionHash'].hex()     

        # generate SendMsg event
        receipt = self.recibo.send_msg(owner.private_key, receiver.address, Recibo.RSA_METADATA, message_as_hex)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)
        send_tx_hash = receipt['transactionHash'].hex()     

        # check events
        (transfer_events, approve_events, send_msg_events) = self.recibo.get_events_for(receiver.address)
        self.assertEqual(1, len(transfer_events))
        event = transfer_events[0]
        self.assertEqual(event.tx_hash, transfer_tx_hash)
        self.assertEqual(event.message_from, owner.address)
        self.assertEqual(event.message_to, receiver.address)
        self.assertEqual(event.value, value)
        self.assertEqual(event.to, receiver.address)
        self.assertEqual(event.sender, owner.address)

        self.assertEqual(1, len(approve_events))
        event = approve_events[0]
        self.assertEqual(event.tx_hash, approve_tx_hash)
        self.assertEqual(event.message_from, owner.address)
        self.assertEqual(event.message_to, receiver.address)
        self.assertEqual(event.value, value)
        self.assertEqual(event.spender, receiver.address)
        self.assertEqual(event.owner, owner.address)

        self.assertEqual(1, len(send_msg_events))
        event = send_msg_events[0]
        self.assertEqual(event.tx_hash, send_tx_hash)
        self.assertEqual(event.message_from, owner.address)
        self.assertEqual(event.message_to, receiver.address)
        self.assertEqual(event.value, 0)

    def test_get_transaction_and_decrypt_tx(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        message = 'hello world'
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)

        # send transaction
        receipt = self.recibo.approve_recibo(owner.private_key, value)
        self.assertEqual(receipt['status'], 1)
        receipt = self.recibo.transfer_from_with_msg(owner.private_key, receiver.address, value, Recibo.RSA_METADATA, message_as_hex) 
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)
        tx_hash = receipt['transactionHash'].hex()         

        # get transaction
        tx = self.recibo.get_transaction(tx_hash)
        self.assertEqual(tx.message.hex(), message_as_hex[2:])
        self.assertEqual(tx.message_from, owner.address)
        self.assertEqual(tx.message_to, receiver.address)
        self.assertEqual(tx.metadata, Recibo.RSA_METADATA)

        # decrypt transaction
        plaintext, metadata = self.recibo.decrypt_tx(tx_hash, receiver.encrypt_key, receiver.password)
        self.assertEqual(plaintext, message)
        self.assertEqual(metadata, Recibo.RSA_METADATA)

    def test_transfer_with_authorization_with_msg(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        message = 'This is a test message to send over the CLI.'

        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'transfer_with_authorization_with_msg',
            '--owner_private_key', str(owner.private_key),
            '--receiver_address', str(receiver.address),
            '--value', str(value),
            '--encrypt_pub_keyfile', receiver.encrypt_pub,
            '--message', message
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")

    def test_send_msg_cli(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        message = 'This is a test message to send over the CLI.'

        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'send_msg',
            '--owner_private_key', str(owner.private_key),
            '--receiver_address', str(receiver.address),
            '--encrypt_pub_keyfile', receiver.encrypt_pub,
            '--message', message
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")        

    def test_respond_to_tx_cli(self):
        owner = self.deployer
        receiver = self.bob

        # owner sends message and includes his public key in metadata
        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver.encrypt_pub, message)
        metadata = Recibo.generate_encrypt_metadata(Recibo.VERSION, Recibo.ENCRYPT, None, None, owner.encrypt_pub)
        receipt = self.recibo.send_msg(owner.private_key, receiver.address, metadata, message_as_hex) 
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt['status'], 1)        

        # respond to tx
        tx_hash = receipt['transactionHash'].hex()
        message = 'This is a test message to send over the CLI.'

        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'respond_to_tx',
            '--owner_private_key', str(owner.private_key),
            '--tx_hash', tx_hash,
            '--message', message
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")        

    def test_transfer_with_authorization_with_msg_response(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        message = 'This is a test message to send over the CLI.'

        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'transfer_with_authorization_with_msg',
            '--owner_private_key', str(owner.private_key),
            '--receiver_address', str(receiver.address),
            '--value', str(value),
            '--encrypt_pub_keyfile', receiver.encrypt_pub,
            '--response_pub_keyfile', owner.encrypt_pub,
            '--message', message
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")


    def test_transfer_from_with_msg(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        message = 'This is a test message to send over the CLI.'

        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'transfer_from_with_msg',
            '--owner_private_key', str(owner.private_key),
            '--receiver_address', str(receiver.address),
            '--value', str(value),
            '--encrypt_pub_keyfile', receiver.encrypt_pub,
            '--message', message
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")

    def test_permit_with_msg(self):
        owner = self.deployer
        spender = self.bob
        value = 10
        message = 'This is a test message to send over the CLI.'

        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'permit_with_msg',
            '--owner_private_key', str(owner.private_key),
            '--spender_address', str(spender.address),
            '--value', str(value),
            '--encrypt_pub_keyfile', spender.encrypt_pub,
            '--message', message
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")

    def test_permit_and_transfer_with_msg(self):
        owner = self.deployer
        receiver = self.bob
        value = 10
        message = 'This is a test message to send over the CLI.'

        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'permit_and_transfer_with_msg',
            '--owner_private_key', str(owner.private_key),
            '--receiver_address', str(receiver.address),
            '--value', str(value),
            '--encrypt_pub_keyfile', receiver.encrypt_pub,
            '--message', message
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")

    def test_read_msg(self):
        receiver = self.bob
        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'read_msg',
            '--receiver_address', str(receiver.address),
            '--decrypt_keyfile', receiver.encrypt_key,
            '--password', receiver.password
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")


    def test_deploy(self):
        deployer = self.deployer
        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'deploy',
            '--deployer_private_key', str(deployer.private_key)
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI command failed with return code {result.returncode}")

    # dev note: this test redeploys the Recibo contract and breaks invariants in other tests.
    # it has z in the name to indicate it should be run last.
    def test_z_deploy_recibo(self):
        recibo_address = self.recibo.deploy_recibo(self.deployer.private_key, self.recibo.token_config.contract_address)
        self.assertIsNotNone(recibo_address)
        self.assertEquals(self.recibo.recibo_config.contract_address, recibo_address)
        self.assertNotEqual(original_recibo_address, recibo_address)
    
    # dev note: this test redeploys the Recibo contract and breaks invariants in other tests.
    # it has z in the name to indicate it should be run last.
    def test_z_deploy_recibo(self):
        deployer = self.deployer
        # Define the command and arguments
        command = [
            'python3', 'recibocli.py', 'deploy_recibo',
            '--deployer_private_key', str(deployer.private_key),
            '--token_address', str(self.recibo.token_config.contract_address)
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)

if __name__ == '__main__':
    unittest.main()
