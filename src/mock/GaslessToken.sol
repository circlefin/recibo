/**
 * Copyright 2024 Circle Internet Financial, LTD. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {ERC20Authorized} from "./ERC20Authorized.sol";

pragma solidity ^0.8.24;

/**
 * @title GaslessToken
 * @notice Implements ERC-20 token with ERC-2612 and transferWithAuthorization from EIP=3009
 */
contract GaslessToken is ERC20Authorized {

    /**
    * @notice Execute a transfer with a signed authorization
     * @dev Constructor automatically mints totalSupply to contract deployer
     * @param name          Name of token
     * @param symbol        Symbol of token
     * @param totalSupply   Starting supply, will be minted to contract deployer
     */
    constructor(string memory name, string memory symbol, uint256 totalSupply)
    ERC20Authorized(name, symbol)
    {
        _mint(msg.sender, totalSupply);
    }


    /**
    * @notice Execute a transfer with a signed authorization
     * @dev EOA wallet signatures should be packed in the order of r, s, v.
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param signature     Signature byte array produced by an EOA wallet or a contract wallet
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) public virtual {
        _transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }
}