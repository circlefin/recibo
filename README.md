# Recibo

## License
This work is licensed under `SPDX-License-Identifier: Apache-2.0`. It has not been audited, comes with
no guarantees, and is provided as is. Use at your own risk.

## About
We introduce Recibo, a model smart contract that lets payers add encrypted memos to transactions. It works with standard ERC-20 tokens and also supports gasless transactions using ERC-2612 and ERC-3009. Payers route transactions through Recibo to record their memos as function calldata. Recibo can be used for invoicing, SWIFT ISO20022 messages, BSA Travel Rule, and other applications. 

Recibo has four functions to route transactions to the target token. 
- `transferFromWithMsg`: Transfers tokens from msg.sender to receiver with an attached message. Requires prior approval for Recibo to transfer funds.
- `permitWithMsg`: Approves token spending using ERC-2612 permit with an attached message.
- `permitAndTransferFromWithMsg`: Performs ERC-2612 permit and transfer with an attached message.
- `transferWithAuthorizationWithMsg`: Transfers tokens using ERC-3009 authorization with an attached message.

Using Recibo adds about 10,000 gas overhead to a standard token transaction. 
Every 100 bytes of the message uses an additional 560 gas.

This respository contains a Recibo smart contract and a model GaslessToken, a python client, and a CLI. You can deploy the smart contracts on a local anvil test node and interact with them using the CLI.

The python client library `client/recibo.py` has helper functions
to create ERC-2612 permits and ERC-3009 authorizations. We also provide this functionality in the Solidity
unit tests in `test/mock/GaslessTestBase.t.sol`. These could be of independent interest to other projects.


## Build and Run
You will need to do the following steps:

1. Install Foundry and Anvil
2. Install Python and dependencies (in a virtual environment)
3. Build the smart contracts (only need to do this once)
4. Start anvil in a separate terminal using the command `anvil`.
5. Call the CLI to deploy and interact with the smart contract.

### Init Submodules
You need to initialize git submodules
```shell
git submodule update --init --recursive
```

### Install Foundry and Anvil
You will need Foundry to compile the smart contracts. You
will also need to use Anvil if you want to run a local test node.
```
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Install Python and dependencies
You will need Python 3 to run the client and CLI: https://www.python.org/downloads/

We recommend you install requirements into a virtual environment.
Go to the `client` directory and execute the following commands:
```
# Create virtual environment .venv in local dir
cd client
python3 -m venv ./.venv

# start virtual environment
source ./.venv/bin/activate

# Install packages (this will take a few minutes).
pip3 install -r requirements.txt 
```

To exit the virtual environment
```
deactivate
```

To restart the virtual environment
```
source ./.venv/bin/activate
```


### Build & Test
To build the smart contract, go to the Recibo root directory and run:
```
forge build
```

To run the Foundry unit tests, run:
```
forge test
```

To run the client unit tests, start the virtual environment and run:
```
cd client
python3 test.py
```


### Run CLI locally
Open two terminals. In the first terminal, start Anvil. The Anvil CLI will print
the addresses and private keys of ten test accounts. Anvil will fund each account with
10,000 ETH, so you have more than enough gas to execute transactions. NEVER use these same accounts on mainnet or testnet because these are static well known private keys.
```
# Terminal 1: start anvil in foreground
anvil
```

In a second terminal, you will use the Recibo CLI.
```
# Terminal 2: build smart contracts (only need to do once)
forge build

# Go to client directory and start python virtual environment that you previously created.
cd client
source ./.venv/bin/activate

# Deploy GaslessToken and Recibo using a default anvil account private key.
# account[0] private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# We will call this account Alice in the following commands.
# Alice will deploy the GaslessToken and Recibo smart contracts. She will also mint 2000 tokens to herself.
python3 recibocli.py deploy \
    --deployer_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 

```

Bob will need PGP encryption keys to receive encrypted messages.
```
# We will generate a 3072-bit PGP key with a passphrase.
# The public key will be stored in test-data/bob_pub.asc and the private key will be stored in test-data/bob_key.asc.
python3 recibocli.py gen_encrypt_key \
    --outfile test-data/bob \
    --keylength 3072 \
    --password 'my secret passphrase' 
```

Alice can now send tokens to Bob with an encrypted message. The CLI command
`transfer_from_with_msg` will first use the owner's private key  to call the approve() function on the 
GaslessToken to give the Recibo contract an allowance, and then
call the `transferFromWithMsg` function on the Recibo contract to transfer the funds.
```
# account[0] (Alice) private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# account[1] (Bob) address is 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Bob's public key is stored in test-data/bob_pub.asc
python3 recibocli.py transfer_from_with_msg \
    --owner_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --receiver_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --value 15 \
    --message 'Hola my friend! I am sending you 15 USDC for your birthday' 
    --encrypt_pub_keyfile test-data/bob_pub.asc 
```

Bob can download and decrypt all messages sent to his address The client will check the Recibo event logs for
all ApproveWithMsg and TransferWithMsg events and look for the ones where the `MessageTo` field has the
`receiver_address`. The client will then download the corresponding transactions and attempt to decrypt all the 
messages using Bob's private key file.
```
# account[1] (Bob) address is 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Bob's private key is stored in test-data/bob_key.asc
python3 recibocli.py read_msg \
    --receiver_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --decrypt_keyfile test-data/bob_key.asc \
    --password 'my secret passphrase'
```

#### More CLI Commands
Command `permit_with_msg` gives the spender an allowance to spend funds on behalf of the owner. This command only 
works with tokens that support EIP-2612. The client uses the
owner's private key to sign an EIP-2612 permit and then executes the `permitWithMsg()` function
on the Recibo smart contract. The Recibo smart contract will call `permit` on the token.
```
# account[0] (Alice) private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# account[1] (Bob) address is 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Bob's public key is stored in test-data/bob_pub.asc
python3 recibocli.py permit_with_msg \
    --owner_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --spender_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --value 20 \
    --message 'Bonjour my friend! I permit you to spend 20 USDC on your birthday' \
    --encrypt_pub_keyfile test-data/bob_pub.asc 
```

Command `permit_and_transfer_with_msg` transfers funds from the owner to the receiver. This command only works with tokens that support EIP-2612.
The client uses the owner's private key to sign an EIP-2612 permit giving the Recibo smart
contract an allowance to spend the owner's funds. Then the client will call
`permitAndTransferFromWithMsg()` on the Recibo smart contract, which will call `permit()` and then
`transferFrom()` on the token.
```
# account[0] (Alice) private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# account[1] (Bob) address is 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Bob's public key is stored in test-data/bob_pub.asc
python3 recibocli.py permit_and_transfer_with_msg \
    --owner_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --receiver_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --value 25 \
    --message 'Privet my friend! I am sending you 25 USDC for your birthday' \
    --encrypt_pub_keyfile test-data/bob_pub.asc 
```

Command `transfer_with_authorization_with_msg` transfers funds from the owner to the receiver. 
This command only works with tokens that support EIP-3009.
The client uses the owner's private key to sign an EIP-3009 authorization giving the Recibo smart
contract an permission to spend the owner's funds. The client will call
`transferWithAuthorizationWithMsg()` on the Recibo smart contract, which will call `transferWithAuthorization()` 
on the token.
```
# account[0] (Alice) private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# account[1] (Bob) address is 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Bob's public key is stored in test-data/bob_pub.asc
# Alice's public key is stored in test-data/alice_pub.asc
python3 recibocli.py transfer_with_authorization_with_msg \
    --owner_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --receiver_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --value 25 \
    --message 'Privet my friend! I am sending you 25 USDC for your birthday' \
    --encrypt_pub_keyfile test-data/bob_pub.asc 
```

Command `deploy_recibo` will deploy just the Recibo contract and point it to an existing ERC-20 token.
```
# account[0] (Alice) private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# token_address must point to a deployed ERC-20 token.
python3 recibocli.py deploy_recibo \
    --deployer_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --token_address 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955
```

#### Sending Messages and Responses
You can insert a response public key into the metadata of your message. Add the optional parameter
`--response_pub_keyfile <filename>` to any command. 

Alice generates a key pair for herself.
```
# The public key will be stored in test-data/alice_pub.asc and the private key will be stored in test-data/alice_key.asc.
python3 recibocli.py gen_encrypt_key \
    --outfile test-data/alice \
    --keylength 3072 \
    --password 'my secret passphrase'
```

Now Alice transfers tokens to Bob and includes her public key file in the metadata
```
# account[0] (Alice) private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# account[1] (Bob) address is 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Bob's public key is stored in test-data/bob_pub.asc
# Alice's public key is stored in test-data/alice_pub.asc
python3 recibocli.py transfer_with_authorization_with_msg \
    --owner_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --receiver_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --value 25 \
    --message 'Privet my friend! I am sending you 25 USDC for your birthday' \
    --encrypt_pub_keyfile test-data/bob_pub.asc \
    --response_pub_keyfile test-data/alice_pub.asc
```

Bob can use `read_msg` to download all of his transactions
```
# account[1] (Bob) address is 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Bob's private key is stored in test-data/bob_key.asc
python3 recibocli.py read_msg \
    --receiver_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --decrypt_keyfile test-data/bob_key.asc \
    --password 'my secret passphrase'
```

Now Bob chooses a tx_hash and responds using `respond_to_tx`.
```
# account[1] (Bob) private key is 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
# You need to get the tx_hash of the transaction to which Bob is responding
# Bob's public key is stored in test-data/bob_pub.asc
python3 recibocli.py respond_to_tx \
    --owner_private_key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
    --tx_hash 0441bc03fe5c3beeb218ee23fa65e953cea3ed6a8e76bb8f2111d09ac88b517d \
    --message 'Thank you for your generous birthday gift!' \
    --response_pub_keyfile test-data/bob_pub.asc
```

Now Alice can read Bob's response.
```
# account[0] (Alice) address is 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# Alice's private key is stored in test-data/alice_key.asc
python3 recibocli.py read_msg \
    --receiver_address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    --decrypt_keyfile test-data/alice_key.asc \
    --password 'my secret passphrase'
```

Command `send_msg` will send a message using the Recibo contract without transfering any tokens.
```
# account[0] (Alice) private key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# token_address must point to a deployed ERC-20 token.
python3 recibocli.py send_msg \
    --owner_private_key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --receiver_address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
    --message 'Privet my friend! I am sending you 25 USDC for your birthday' \
    --encrypt_pub_keyfile test-data/bob_pub.asc
```


## Dev Notes
By default, all commands will use `anvil_config.yaml` as the configuration file. 
To use your own configuration file, add `--config_file your_filename` as a command argument.

### Deploying to mainnet/testnet
The python client uses the file `anvil_config.yaml`.  To connect to mainnet/testnet,
you need to update the `rpc_url`. The default setting is to use a local anvil node.

### Smart contract address
The client stores the address of the deployed smart contract in local environment files
- `.gasless_token_env` holds the address of the ERC-20 token
- `.recibo_env` has the address of the Recibo smart contract.

Then client creates these files automatically when it deploys the smart contracts using
the `Recibo.deploy()` function. If you want to use an existing deployed smart contract, you
need to modify (or create) these environment files.

Sample environment file:
```
contract_address: '0xbFD3511180A40503D807c9249943431Cf847E5b7'
```

### Deploy new Recibo contract to use an existing ERC-20 token
You need to perform the following two steps:

1. Make sure the `.gasless_token_env` file has the address of the ERC-20 token. 
2. Deploy the Recibo contract using the `deploy_recibo` command. Specify the address of the ERC-20 token.

Troubleshooting: check your yaml config file for the name of the token `local_env_file`..

### Configure the CLI to use an existing Recibo contract and ERC-20 token
You need to perform the following two steps:

1. Make sure the `.gasless_token_env` file has the address of the ERC-20 token. 
2. Make sure the `.recibo_env` file has the address of the Recibo contract. 

Troubleshooting: check your yaml config file for the name of the tokena and Recibo `local_env_file`. These should be two separate files.

### Encryption/Decryption
The Recibo smart contract accepts arbitrary encoded messages along with string metadata that
can contain encoding information. The CLI uses PGP encryption by default but you can use no encryption algorithms by
specifying the `--encrypt_alg_id none` parameter.
