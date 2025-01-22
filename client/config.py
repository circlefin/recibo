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

"""
Utility functions for interacting with the blockchain. Works with both
mainnet and anvil.
"""

import json
import os
from web3 import Web3
import yaml

class Config:
    def __init__(self, config_filename, contract_name):
        with open(config_filename, 'r') as file:
            config = yaml.safe_load(file)
        self.rpc_url = config['rpc_url']
        self.contract_creation_block = config['contract_creation_block']

        contract_config = config[contract_name]
        self.env_config_file =  contract_config['local_env_file']
        self.contract_address = get_contract_address(self.env_config_file)
        self.contract_file = contract_config['contract_file']
        self.contract_name = contract_config['contract_name']
        self.constructor_args = contract_config['constructor_args']
        self.abi = get_abi_from_foundry_out(contract_config['foundry_out_json_file'])
        self.bytecode = get_bytecode_from_foundry_out(contract_config['foundry_out_json_file'])

    def deploy(self, deployer_private_key, custom_args=None):
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        mycontract = w3.eth.contract(abi=self.abi, bytecode=self.bytecode)
        tx_function = None
        if custom_args:
            if isinstance(custom_args, list):
                tx_function = mycontract.constructor(*custom_args)
            else:
                tx_function = mycontract.constructor(custom_args)
        else:
            arguments = self.constructor_args
            tx_function = mycontract.constructor(*arguments)
        
        tx_receipt = self.send_transaction(tx_function, deployer_private_key)
        self.contract_address = tx_receipt.contractAddress
        self.save_env(tx_receipt.contractAddress)
        return tx_receipt.contractAddress
   
    def get_contract(self):
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        return w3.eth.contract(address=self.contract_address, abi=self.abi)

    def send_transaction(self, tx_function, sender_private_key):
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        sender_address = w3.eth.account.from_key(sender_private_key).address
        unsent_tx = tx_function.build_transaction({
            "from": sender_address,
            "nonce": w3.eth.get_transaction_count(sender_address)
        })
        signed_tx = w3.eth.account.sign_transaction(unsent_tx, private_key=sender_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt


    # returns a pair (function, decoded_data) from decoded_data is a dictionary of calldata
    def get_transaction(self, tx_hash):
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        contract =  w3.eth.contract(address=self.contract_address, abi=self.abi)
        tx_data = w3.eth.get_transaction(tx_hash)
        input = tx_data['input'].hex()
        function, decoded_data = contract.decode_function_input(input)
        return function, decoded_data

    # Saves the state of the local environment to config.env_config_file.
    def save_env(self, contract_address):
        env = dict()
        env['contract_address'] = contract_address
        with open(self.env_config_file, 'w') as file:
            yaml.dump(env, file)

 
# Returns abi generated by foundry.
# These files are usually stored in out/<ContractName>.sol/<ContractName>.json
def get_abi_from_foundry_out(filename):
    with open(filename, 'r') as file:
        contents = file.read()
    contents_dict = json.loads(contents)
    return contents_dict['abi']

# Returns bytecode generated by foundry.
# These files are usually stored in out/<ContractName>.sol/<ContractName>.json
def get_bytecode_from_foundry_out(filename):
    with open(filename, 'r') as file:
        contents = file.read()
    contents_dict = json.loads(contents)
    return contents_dict['bytecode']['object']

# Read env_config_file to get address of the deployed contract
def get_contract_address(env_config_file):
    if os.path.exists(env_config_file):
        with open(env_config_file, 'r') as file:
            env = yaml.safe_load(file)
            contract_address = env['contract_address']
            return contract_address
    else:
        print("Cannot get contract_address")
        return None

