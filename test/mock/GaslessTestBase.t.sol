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

import {Test, console} from "forge-std/Test.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC20Authorized} from "../../src/mock/ERC20Authorized.sol";

contract GaslessTestBase is Test {
    // from @openzeppelin/contracts/ERC20/extensions/ERC20Permit.sol
    bytes32 public constant PERMIT_TYPEHASH =  keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    // from ERC20Authorized.sol
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_TYPEHASH = 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // Returns signature in ERC-2612 format
    function signPermit(uint256 privateKey, bytes32 digest) public pure returns (uint8, bytes32, bytes32)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return (v, r, s);
    }

    // Returns signature expected by EIP-3009 format
    function signTransfer(uint256 privateKey, bytes32 digest) public pure returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    // Creates a permit digest in ERC-2612 format
    function buildPermitMessage(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        IERC20Permit token
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, token.nonces(owner), deadline));
        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        bytes32 permitMessage = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        return permitMessage;
    }

    // Creates a transfer authorization digest in EIP-3009 format.
    function buildTransferMessage(
        address owner,
        address receiver,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        ERC20Authorized token
    ) public view returns (bytes32) {
        bytes32 dataHash = keccak256(abi.encode(TRANSFER_TYPEHASH, owner, receiver, value, validAfter, validBefore, nonce));
        bytes32 domainSeparator =  token.DOMAIN_SEPARATOR();
        return MessageHashUtils.toTypedDataHash(domainSeparator, dataHash);
    }

    // creates validAfter and validBefore time for EIP-3009 authorization
    function makeValidTime(uint256 timespan) public view returns (uint256, uint256) {
        uint256 validAfter = vm.getBlockTimestamp()-1;
        uint256 validBefore = vm.getBlockTimestamp() + timespan;
        return (validAfter, validBefore);
    }

    // creates a deadline for ERC-2612 permit
    function makeDeadline(uint256 timespan) public view returns (uint256) {
        return vm.getBlockTimestamp() + timespan;
    }

}