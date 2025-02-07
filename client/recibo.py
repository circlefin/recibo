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

from config_recibo import ReciboConfig
from config_token import TokenConfig
from encrypt import crypto_encrypt, crypto_decrypt, read_pub_key, crypto_encrypt_with_keystring
from eth_account import Account
import web3
import eth_abi
import json

# Container class to store information abut Recibo transaction
class ReciboTx:
    def __init__(self, decoded_data):
         self.message_to = decoded_data['info']['messageTo']
         self.message_from = decoded_data['info']['messageFrom']
         self.metadata = decoded_data['info']['metadata']
         self.message = decoded_data['info']['message']


# Base Event class to handle common Recibo event attributes
class Event:
    def __init__(self, log):
        """
        Initializes the Event with the log.

        Args:
            log (AttributeDict): The log data for the event returned by web3py event query.
        """
        self.event = log['event'] # name of event
        self.tx_hash = log['transactionHash'].hex()
        self.message_from = log['args']['messageFrom']
        self.message_to = log['args']['messageTo']

    def __str__(self):
        """
        Returns a pretty-printable string representation of the event. Includes
        custom attributes from subclasses.
        """
        s = ''
        for attr in dir(self):
            if attr[0] != '_':
                s += f'{attr}: {getattr(self, attr)}\n'
        return s

# ApproveWithMsgEvent class inheriting from Event
class ApproveWithMsgEvent(Event):
    """
    Initializes the ApproveWithMsgEvent with the log.

    Args:
        log (AttributeDict): The log data for the event returned by web3py event query.
    """
    def __init__(self, log):
        super().__init__(log)
        self.owner = log['args']['owner']
        self.spender = log['args']['spender']
        self.value = log['args']['value']

# TransferWithMsgEvent class inheriting from Event        
class TransferWithMsgEvent(Event):
    def __init__(self, log):
        super().__init__(log)
        self.to = log['args']['to']
        self.sender = log['args']['from']
        self.value = log['args']['value']

# SendMsgEvent class inheriting from Event        
class SendMsgEvent(Event):
    def __init__(self, log):
        super().__init__(log)
        self.sender = log['args']['from']
        self.value = 0

# Information about a Recibo transaction
class DecryptedReciboTx():
    def __init__(self, event, plaintext, metadata):
        for attr in dir(event):
            if not attr.startswith('_'):  # Skip special/protected attributes
                eventvalue = getattr(event, attr)
                setattr(self, attr, eventvalue)
        self.plaintext = plaintext
        self.metadata = metadata


# Recibo class to handle blockchain interactions 
class Recibo():
    PERMIT_TYPEHASH = bytes.fromhex('6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9')
    TRANSFER_TYPEHASH =  bytes.fromhex('7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267')
    MAX_UNIT256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935
    
    VERSION = "circle-0.1beta"
    ENCRYPT =  "RSA_PKCS1_OAEP_AES_EAX"
    NOENCRYPT = "None"

    # IANA media types
    PLAINTEXT = "text/plain;charset=UTF-8"
    PNG = "image/png"
    JPEG = "image/jpeg"
    GIF = "image/gif"

    @staticmethod
    def generate_encrypt_metadata(version, encrypt_alg_id, mime=None, encrypt_pub_key_filename=None, response_pub_key_filename = None):
        metadata = {
            "version": version,
            "encrypt": encrypt_alg_id
        }
        
        if mime:
            metadata["mime"] = mime

        if encrypt_pub_key_filename:
            metadata["encrypt_pub_key"] = read_pub_key(encrypt_pub_key_filename)
            
        if response_pub_key_filename:
            metadata["response_pub_key"] = read_pub_key(response_pub_key_filename)

        return json.dumps(metadata, indent=2)

    RSA_METADATA = generate_encrypt_metadata('circle-0.1beta', 'RSA_PKCS1_OAEP_AES_EAX')    

    def __init__(self, config_file):
        """
        Initializes the Recibo class from a config_file.

        Args:
            config_file (str): Filename of config file
        """
        self.token_config = TokenConfig(config_file)
        self.token = self.token_config.get_contract()

        self.recibo_config = ReciboConfig(config_file)
        self.recibo = self.recibo_config.get_contract()

    @staticmethod
    def ReciboInfoStruct(sender_address, receiver_address, metadata, message_as_hex):
        """
        Returns an array of values that can be passed to the Recibo contract
        whenever it requires a ReciboInfo struct as input.

        Args:
            sender_address (str): Ethereum address starting with 0x prefix.
            receiver_address (str): Ethereum address starting with 0x prefix.
            metadata (str): Arbitrary string with metadata.
            message_as_hex (str): Hex representation of bytes with 0x prefix,
                - typically output of Recibo.encrypt().
        """
        message_bytes = bytes.fromhex(message_as_hex[2:])
        return [sender_address, receiver_address, metadata, message_bytes]

    @staticmethod
    def typed_data_hash(domain_separator, struct_hash):
        """
        Internal. Returns EIP-712 typed data hash (bytes). 

        Args:
            domain_separator (bytes): Output of Recibo.get_token_domain_separator()
            struct_hash (bytes): 32 bytes, output of Recibo.struct_hash(...)
        """
        return web3.Web3.solidity_keccak(
            ['bytes2', 'bytes32', 'bytes32'],
            ['0x1901', domain_separator, struct_hash]
        )

    @staticmethod
    def struct_hash(owner_address, spender_address, value, nonce, deadline):
        """
        Internal. Returns 32 byte struct_hash (bytes) used to construct EIP-2612 permit message.

        Args:
            owner_address (str): Ethereum address starting with 0x prefix.
            spender_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            nonce (int): A uint256 output of Recibo.get_token_nonce() 
            deadline (int): A uint256 representing block time when permit expires
        """
        encoded = eth_abi.encode(
            ['bytes32', 'address', 'address', 'uint256', 'uint256', 'uint256'],
            [Recibo.PERMIT_TYPEHASH, owner_address, spender_address, value, nonce, deadline]
        ).hex()
        return web3.Web3.keccak(hexstr=encoded)

    @staticmethod
    def data_hash(owner_address, receiver_address, value, valid_after, valid_before, nonce):
        """
        Internal. Returns 32 byte data_hash (bytes) used to construct ERC-3009 transfer authorization message.

        Args:
            owner_address (str): Ethereum address starting with 0x prefix.
            receiver_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            valid_after (int): A uint256 representing block time after which authorization is valid
            valid_before (int): A uint256 representing block time when authorization expires
            nonce (bytes): A bytes32 nonce unique to this authorization
        """
        encoded = eth_abi.encode(
            ['bytes32', 'address', 'address', 'uint256', 'uint256', 'uint256', 'bytes32'],
            [Recibo.TRANSFER_TYPEHASH, owner_address, receiver_address, value, valid_after, valid_before, nonce]
        ).hex()
        return web3.Web3.keccak(hexstr=encoded)

    def get_token_nonce(self, owner_address):
        """
        Internal. Returns the next token_nonce that owner_address can use to construct a EIP-2612 permit

        Args:
            owner_address (str): Ethereum address starting with 0x prefix.
        """
        nonce = self.token.functions.nonces(owner_address).call()
        return nonce

    def get_token_domain_separator(self):
        """
        Internal. Returns the token domain separator used for EIP-712 typed data hash.
        """
        domain_separator = self.token.functions.DOMAIN_SEPARATOR().call()
        return domain_separator

    def build_permit(self, owner_address, spender_address, value, deadline):
        """
        Returns an EIP-2612 permit message that can be signed using Recibo.sign_permit()

        Args:
            owner_address (str): Ethereum address starting with 0x prefix.
            spender_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            deadline (int): A uint256 representing block time when permit expires
        """
        # Get the nonce for the owner
        nonce = self.get_token_nonce(owner_address)
        domain_separator = self.get_token_domain_separator()

        # Encode the struct hash
        struct_hash = Recibo.struct_hash(owner_address, spender_address, value, nonce, deadline)

        # encode and sign the message
        permit = Recibo.typed_data_hash(domain_separator, struct_hash)
        return permit

    def sign_permit(self, signer_private_key, permit):
        """
        Signs a EIP-2612 permit message and returns a web3py signed_message object.
        Obtain the signature components as (signed_message.v, signed_message.r, signed_message.s)

        Args:
            signer_private_key (str): Ethereum private key starting with 0x prefix.
            permit (bytes): A 32 byte.
            value (int): Amount of ERC-20 token
            deadline (int): A uint256 representing block time when permit expires
        """
        w3 = web3.Web3(web3.Web3.HTTPProvider(self.recibo_config.rpc_url))
        signed_message = w3.eth.account.unsafe_sign_hash(permit, private_key=signer_private_key)
        return signed_message

    def build_transfer_authorization(
            self,
            owner_address,
            recevier_address,
            value,
            valid_after,
            valid_before,
            nonce
    ):
        """
        Returns an ERC-3009 transfer_authorization message that can be signed using 
        Recibo.sign_transfer_authorization()

        Args:
            owner_address (str): Ethereum address starting with 0x prefix.
            receiver_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            valid_after (int): A uint256 representing block time after which authorization is valid
            valid_before (int): A uint256 representing block time when authorization expires
            nonce (bytes): A bytes32 nonce unique to this authorization
        """
        data_hash = self.data_hash(owner_address, recevier_address, value, valid_after, valid_before, nonce)
        domain_separator = self.get_token_domain_separator()
        transfer_authorization = Recibo.typed_data_hash(domain_separator, data_hash)
        return transfer_authorization

    def sign_transfer_authorization(self, signer_private_key, transfer_authorization):
        """
        Signs a ERC-3009 transfer_authorization message and returns a 65 byte signature:
        32 bytes for r, 32 bytes for s, and 1 byte for v. Pass this signature directly as
        input to Recibo.transfer_with_authorization_with_msg().

        Args:
            signer_private_key (str): Ethereum private key starting with 0x prefix.
            transfer_authorization (bytes): 32 byte output of Recibo.build_transfer_authorization()
        """
        w3 = web3.Web3(web3.Web3.HTTPProvider(self.recibo_config.rpc_url))
        signed_message = w3.eth.account.unsafe_sign_hash(transfer_authorization, private_key=signer_private_key)
        return signed_message.signature

    def send_msg(self, owner_private_key, receiver_address, metadata, message_as_hex):
        """
        Sends an encrypted message on-chain to a specified receiver address.
        
        Args:
            owner_private_key (str): Private key of the message sender
            receiver_address (str): Ethereum address of message recipient 
            metadata (str): JSON string containing message metadata (encryption method, keys, etc)
            message_as_hex (str): Hex-encoded encrypted message content
            
        Returns:
            dict: Transaction receipt from sending the message on-chain
        """
        owner_address = Account.from_key(owner_private_key).address
        info = Recibo.ReciboInfoStruct(owner_address, receiver_address, metadata, message_as_hex)
        tx_function = self.recibo.functions.sendMsg(info)
        receipt = self.recibo_config.send_transaction(tx_function, owner_private_key)
        return receipt

    def approve_recibo(self, owner_private_key, value):
        """
        Calls the ERC-20 token function approve to give the Recibo smart contract an allowance
        to transfer funds from the owner. 

        Args:
            owner_private_key (str): Ethereum private key starting with 0x prefix.
            value (int): allowance amount
        """
        recibo_address = self.recibo_config.contract_address
        tx_function = self.token.functions.approve(
            recibo_address,
            value
        )
        return self.token_config.send_transaction(tx_function, owner_private_key)

    def transfer_from_with_msg(
            self, 
            owner_private_key, 
            receiver_address, 
            value, 
            metadata, 
            message_as_hex
    ):
        """
        Calls the transferFromWithMsg function on the Recibo smart contract. The owner must previously
        have given the Recibo contract an allowance. Returns a web3py receipt object. Typical usage: 

        recibo = Recibo(config_filename)
        value = 10
        receipt = recibo.approve_recibo(owner_private_key, value)
        if receipt['status'] != 1:
            print('Failed to give Recibo contract allowance')
            sys.exit(1)

        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver_pub_keyfile, message)
        receipt = recibo.transfer_from_with_msg(
                    owner_private_key, 
                    receiver.address, 
                    value, 
                    metadata, 
                    message_as_hex) 
        print(receipt)
                    
        
        Args:
            owner_private_key (str): Ethereum private key starting with 0x prefix.
            receiver_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            metadata (str): arbitrary string that will added to calldata in the clear
            message_as_hex (str): Hex representation of bytes with 0x prefix,
                - typically output of Recibo.encrypt().
        """
        owner_address = Account.from_key(owner_private_key).address
        info = Recibo.ReciboInfoStruct(owner_address, receiver_address, metadata, message_as_hex)
        tx_function = self.recibo.functions.transferFromWithMsg(
            receiver_address, value, info
        )
        receipt = self.recibo_config.send_transaction(tx_function, owner_private_key)
        return receipt


    def permit_with_msg(
        self,
        owner_private_key,
        spender_address,
        value,
        deadline,
        v,
        r,
        s,
        metadata,
        message_as_hex
    ):
        """
        Calls the permitWithMsg function on the Recibo smart contract.  Recibo will call
        the EIP-2612 permit() function on the ERC-20 token to give spender_address an
        allowance to transfer funds from the owner.  Returns a web3py 
        receipt object. Typical usage: 

        recibo = Recibo(config_filename)
        value = 10
        deadline = 115792089237316195423570985008687907853269984665640564039457584007913129639935
        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver_pub_keyfile, message)
        permit = self.recibo.build_permit(owner_address, spender_address, value, deadline)
        signature = self.recibo.sign_permit(owner_private_key, permit)
        receipt = recibo.permit_with_msg(
                    owner_private_key, 
                    spender_address, 
                    value,
                    deadline,
                    signature.v,
                    signature.r,
                    signature.s, 
                    metadata, 
                    message_as_hex) 
        print(receipt)            
        
        Args:
            owner_private_key (str): Ethereum private key starting with 0x prefix.
            spender_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            deadline (int): A uint256 representing block time when permit expires
            v (int): portion of an ECDSA signature
            r (int): portion of an ECDSA signature
            s (int): portion of an ECDSA signature
            metadata (str): arbitrary string that will added to calldata in the clear
            message_as_hex (str): Hex representation of bytes with 0x prefix,
                - typically output of Recibo.encrypt().
        """
        owner_address = Account.from_key(owner_private_key).address
        r_as_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
        s_as_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
        info = Recibo.ReciboInfoStruct(owner_address, spender_address, metadata, message_as_hex)
        tx_function = self.recibo.functions.permitWithMsg(owner_address, spender_address, value, deadline, v, r_as_bytes, s_as_bytes, info)
        return self.recibo_config.send_transaction(tx_function, owner_private_key)

    def permit_and_transfer_with_msg(
        self,
        owner_private_key,
        receiver_address,
        value,
        deadline,
        v,
        r,
        s,
        metadata,
        message_as_hex
    ):
        """
        Transfers funds from the owner to the receiver by calling permitAndTransferWithMsg on the
        Recibo smart contract. The owner must sign an EIP-2612 permit() 
        authorizing the Recibo smart contract to transfer funds. The Recibo smart contract will
        use this permit to transfer funds to the receiver address. Typical usage: 

        recibo = Recibo(config_filename)
        value = 10
        deadline = 115792089237316195423570985008687907853269984665640564039457584007913129639935
        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver_pub_keyfile, message)
        permit = recibo.build_permit(
            owner_address, 
            recibo.recibo_config.contract_address, 
            value, 
            deadline)
        signature = self.recibo.sign_permit(owner_private_key, permit)
        receipt = recibo.permit_and_transfer_with_msg(
                    owner_private_key, 
                    receiver_address, 
                    value,
                    deadline,
                    signature.v,
                    signature.r,
                    signature.s, 
                    metadata, 
                    message_as_hex) 
        print(receipt)
                    
        
        Args:
            owner_private_key (str): Ethereum private key starting with 0x prefix.
            receiver_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            deadline (int): A uint256 representing block time when permit expires
            v (int): portion of an ECDSA signature
            r (int): portion of an ECDSA signature
            s (int): portion of an ECDSA signature
            metadata (str): arbitrary string that will added to calldata in the clear
            message_as_hex (str): Hex representation of bytes with 0x prefix,
                - typically output of Recibo.encrypt().
        """
        owner_address = Account.from_key(owner_private_key).address
        r_as_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
        s_as_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
        info = Recibo.ReciboInfoStruct(owner_address, receiver_address, metadata, message_as_hex)
        tx_function = self.recibo.functions.permitAndTransferFromWithMsg(receiver_address, value, deadline, v, r_as_bytes, s_as_bytes, info)
        return self.recibo_config.send_transaction(tx_function, owner_private_key)

    def transfer_with_authorization_with_msg(
        self,
        tx_sender_private_key,
        owner_address, 
        receiver_address,
        value,
        valid_after,
        valid_before,
        nonce,
        signature,
        metadata,
        message_as_hex
    ):
        """
        Transfers funds from the owner to the receiver by calling transferWithAuthorizationWithMsg
        on the Recibo smart contract. The owner must sign an ERC-3009 transfer_authorization. 
        The Recibo smart contract will use this to call transferWithAuthorization() on the 
        ERC-20 token to transfer funds to the receiver address. Typical usage: 

        recibo = Recibo(config_filename)
        value = 10
        valid_after = 0
        valid_before = 115792089237316195423570985008687907853269984665640564039457584007913129639935
        nonce = os.urandom(32)
        message = "hello world"
        message_as_hex = Recibo.encrypt(receiver_pub_keyfile, message)
        transfer_authorization = recibo.build_transfer_authorization(
            owner_address, 
            receiver_address, 
            value, 
            valid_after,
            valid_before,
            nonce)
        signature = self.recibo.sign_transfer_authorization(owner_private_key, transfer_authorization)
        receipt = recibo.transfer_with_authorization_with_msg(
            tx_sender_private_key,
            owner_address,
            receiver_address,
            value,
            valid_after,
            valid_before,
            nonce,
            signature,
            metadata,
            message_as_hex
        )
        print(receipt)
                    
        
        Args:
            tx_sender_private_key (str): Ethereum private key starting with 0x prefix. Can be
                separate from owner or receiver; must have enough gas to execute transaction.
            owner_address (str): Ethereum address starting with 0x prefix.
            receiver_address (str): Ethereum address starting with 0x prefix.
            value (int): Amount of ERC-20 token
            valid_after (int): A uint256 representing block time after which authorization is valid
            valid_before (int): A uint256 representing block time when authorization expires
            nonce (bytes): A bytes32 nonce unique to this authorization
            metadata (str): arbitrary string that will added to calldata in the clear
            message_as_hex (str): Hex representation of bytes with 0x prefix,
                - typically output of Recibo.encrypt().
        """
        info = Recibo.ReciboInfoStruct(owner_address, receiver_address, metadata, message_as_hex)
        tx_function = self.recibo.functions.transferWithAuthorizationWithMsg(owner_address, receiver_address, value, valid_after, valid_before, nonce, signature, info)
        return self.recibo_config.send_transaction(tx_function, tx_sender_private_key)

    def balance_of(self, user_address):
        """
        Retrieves the balance of a given user address from the ERC-20 token.

        Args:
            user_address (str): Ethereum address starting with 0x prefix.

        Returns:
            int: The balance of the user.
        """
        balance = self.token.functions.balanceOf(user_address).call()
        return balance

    def allowance(self, owner_address, spender_address):
        """
        Retrieves the allowance that the owner has given to the spender.

        Args:
            owner_address (str): Ethereum address starting with 0x prefix.
            spender_address (str): Ethereum address starting with 0x prefix.

        Returns:
            int: The amount of tokens the spender is allowed to spend on behalf of the owner.
        """
        allowance = self.token.functions.allowance(owner_address, spender_address).call()
        return allowance

    def total_supply(self):
        """
        Retrieves the total supply of the token.

        Returns:
            int: The total supply of the token.
        """
        totalSupply = self.token.functions.totalSupply().call()
        return totalSupply

    def deploy_recibo(self, deployer_private_key, token_address):
        """
        Deploys the recibo contract. The address of the deployed contract
        will be stored in local environment files (specified in config file) and also
        in self.token_config.contract_address and self.recibo_config.contract address.

        Args:
            deployer_private_key (str): Ethereum private key starting with 0x prefix.
                Account must have enough funds to pas the gas fee for deploying the contract.
            token_address (str): Ethereum address starting with 0x prefix.

        Returns:
            str: The address of the deployed recibo contract.
        """
        recibo_address = self.recibo_config.deploy(deployer_private_key, token_address)
        self.recibo = self.recibo_config.get_contract()
        print(f'Deployed recibo to {recibo_address}')
        return recibo_address

    def deploy(self, deployer_private_key):
        """
        Deploys the token and recibo contracts. The address of the deployed contract
        will be stored in local environment files (specified in config file) and also
        in self.token_config.contract_address and self.recibo_config.contract address.
        Typical usage:

        recibo = Recibo(config_filename)
        recibo_contract_address = recibo.deploy(deployer.private_key)
        token_contract_address = recibo.token_config.contract_address

        Args:
            deployer_private_key (str): Ethereum private key starting with 0x prefix.
                Account must have enough funds to pas the gas fee for deploying both contracts.

        Returns:
            str: The address of the deployed recibo contract.
        """
        token_address = self.token_config.deploy(deployer_private_key)
        self.token = self.token_config.get_contract()
        print(f'Deployed token to {token_address}')
            
        recibo_address = self.recibo_config.deploy(deployer_private_key, token_address)
        self.recibo = self.recibo_config.get_contract()
        print(f'Deployed recibo to {recibo_address}')
        return recibo_address

    @staticmethod
    def encrypt(receiver_pub_key_filename, plaintext):
        """
        Encrypts the given plaintext using the receiver's public key.

        Args:
            receiver_pub_key_filename (str): The filename of the receiver's public key.
                This must be a DER encoded RSA public key.
            plaintext (str): The plaintext message to be encrypted.

        Returns:
            str: The encrypted message as a hex string prefixed with "0x".
        """
        ciphertext = crypto_encrypt(receiver_pub_key_filename, plaintext)
        return "0x" + ciphertext.hex()

    @staticmethod
    def decrypt(receiver_key_filename, ciphertext, password=None):
        """
        Decrypts the given ciphertext using the receiver's private key.

        Args:
            receiver_key_filename (str): The filename of the receiver's private key.
                This must a DER encoded RSA private key.
            ciphertext (str): The ciphertext message to be decrypted.
            password (str or None): Password to access receeiver private key

        Returns:
            str: The decrypted plaintext message.
        """
        plaintext = crypto_decrypt(receiver_key_filename, ciphertext, password)
        return plaintext

    def decrypt_tx(self, tx_hash, receiver_key_filename, password=None):
        """
        Decrypts the message in a transaction using the receiver's private key.
        Retreives the transaction with the specified tx_hash from the blockchain
        and attempts to decrypt the message.

        Args:
            tx_hash (str): The hash of the transaction.
            receiver_key_filename (str): The filename of the receiver's private key.
            password (str or None): Password to access receeiver private key

        Returns:
            str: The decrypted plaintext message from the transaction.
            str: the metadata
        """
        tx = self.get_transaction(tx_hash)
        plaintext = self.decrypt(receiver_key_filename, tx.message, password)
        return plaintext, tx.metadata

    def respond_to_tx(self, tx_hash, owner_private_key, metadata, message_plaintext):
        """
        Responds to a message in a transaction by sending an encrypted response back to the original sender.
        
        Args:
            tx_hash (str): Hash of the transaction containing the original message
            owner_private_key  (str): Private key of the responder 
            metadata  (str): Metadata to attach to response message
            message_plaintext  (str): Plain text response message to encrypt and send
            
        Returns:
            dict: Transaction receipt from sending the response
            
        Flow:
            1. Gets original transaction from blockchain
            2. Extracts response public key from original metadata json
            3. Encrypts response message using sender's public key
            4. Creates ReciboInfo struct with encrypted message
            5. Sends transaction with response message
        """
        tx = self.get_transaction(tx_hash)
        metadata_dict = json.loads(tx.metadata)
        response_pub_key = metadata_dict['response_pub_key']
        ciphertext = crypto_encrypt_with_keystring(response_pub_key, message_plaintext)
        message_as_hex = "0x" + ciphertext.hex()
        owner_address = Account.from_key(owner_private_key).address
        info = Recibo.ReciboInfoStruct(owner_address, tx.message_from, metadata, message_as_hex)
        print(f'info {info[1]}')
        tx_function = self.recibo.functions.sendMsg(info)
        receipt = self.recibo_config.send_transaction(tx_function, owner_private_key)
        return receipt


    def get_events_for(self, message_to_address):
        """
        Retrieves transfer and approve events for a specific message_to address.

        Args:
            message_to_address (str): The address to filter events by.

        Returns:
            tuple: A tuple containing lists of TransferWithMsgEvent, ApproveWithMsgEvent, and SendMsgEvent objects.
        """
        contract = self.recibo_config.get_contract()
        logs = contract.events.TransferWithMsg().get_logs(from_block=self.recibo_config.contract_creation_block)
        transfer_events = [TransferWithMsgEvent(log) for log in logs]

        logs = contract.events.ApproveWithMsg().get_logs(from_block=self.recibo_config.contract_creation_block)
        approve_events = [ApproveWithMsgEvent(log) for log in logs]

        logs = contract.events.SendMsg().get_logs(from_block=self.recibo_config.contract_creation_block)
        sendmsg_events = [SendMsgEvent(log) for log in logs]

        transfer_events = [event for event in transfer_events if event.message_to == message_to_address]
        approve_events = [event for event in approve_events if event.message_to == message_to_address]
        sendmsg_events = [event for event in sendmsg_events if event.message_to == message_to_address]
        return (transfer_events, approve_events, sendmsg_events)

    def get_transaction(self, tx_hash):
        """
        Retrieves and decodes a transaction by its hash.

        Args:
            tx_hash (str): The hash of the transaction.

        Returns:
            ReciboTx: The decoded transaction data.
        """
        function, decoded_data = self.recibo_config.get_transaction(tx_hash)
        return ReciboTx(decoded_data)
    
    def read_msg(self, message_to_address, receiver_key_filename, password=None):
        """
        Retrieves and decrypts all messages sent to a specific address.
        
        Args:
            message_to_address (str): Ethereum address of message recipient
            receiver_key_filename (str): Path to recipient's private key file for decryption
            password (str): Optional password to decrypt private key file
            
        Returns:
            list[DecryptedReciboTx]: List of decrypted transactions containing:
                - Original blockchain event
                - Decrypted message plaintext
                - Message metadata
        """
        transfer_events, approve_events, sendmsg_events = self.get_events_for(message_to_address)
        events = transfer_events + approve_events + sendmsg_events
        results = []
        for event in events:
            plaintext, metadata = self.decrypt_tx(event.tx_hash, receiver_key_filename, password)
            decryptedtx = DecryptedReciboTx(event, plaintext, metadata)
            results.append(decryptedtx)
        return results
