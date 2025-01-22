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

pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ReciboEvents} from "./ReciboEvents.sol";

/**
 * @title ReciboToken
 * @notice Wraps standard ERC-20 functions to allow messages.
 */
contract ReciboToken is ERC20, ReciboEvents {

    /**
     * @notice Creates a ReciboToken and mints totalSypply to the deployer
     * @dev Constructor automatically mints totalSupply to contract deployer
     * @param name_          Name of token
     * @param symbol_        Symbol of token
     * @param totalSupply   Starting supply, will be minted to contract deployer
     */
    constructor(string memory name_, string memory symbol_, uint256 totalSupply) ERC20(name_, symbol_) {
        _mint(msg.sender, totalSupply);
    }

    /**
      * @dev See {ERC20-transfer}.
      */
    function transferWithMsg(address to, uint256 value, address messageFrom, address messageTo, string calldata metadata, bytes calldata message) public returns (bool) {
        emit TransferWithMsg(msg.sender, to, messageFrom, messageTo, value);
        return transfer(to, value);
    }


    /**
      * @dev See {ERC20-approve}.
      */
    function approveWithMsg(address spender, uint256 value, address messageFrom, address messageTo, string calldata metadata, bytes calldata message) public returns (bool) {
        emit ApproveWithMsg(msg.sender, spender, messageFrom, messageTo, value);
        return approve(spender, value);
    }


    /**
     * @dev See {ERC20-transferFrom}.
     */
    function transferFromWithMsg(address from, address to, uint256 value, address messageFrom, address messageTo, string calldata metadata, bytes calldata message) public returns (bool) {
        emit TransferWithMsg(from, to, messageFrom, messageTo, value);
        return transferFrom(from, to, value);
    }
}
