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

import {GaslessToken} from "./mock/GaslessToken.sol";
import {ReciboEvents} from "./ReciboEvents.sol";


/**
* @title Recibo
* @notice Lets callers record messages related to ERC-20 transfers
*/
contract Recibo is ReciboEvents {
    GaslessToken public immutable _token;

    struct ReciboInfo {
        address messageFrom;
        address messageTo;
        string metadata;
        bytes message;
    }

    /**
     * @notice Deploys Recibo
     * @dev Constructor sets target GaslessToken
     * @param token         Any GaslessToken
     */
    constructor(GaslessToken token) {
        _token = token;
    }

    /**
     * @notice Transfers tokens from msg.sender to receiver
     * @dev Returns true on success, reverts on failure
     * @param to           Token receiver
     * @param value        Value to transfer
     * @param info         Message
     */
    function transferFromWithMsg(
        address to,
        uint256 value,
        ReciboInfo calldata info
    ) public returns (bool) {
        emit TransferWithMsg(msg.sender, to, info.messageFrom, info.messageTo, value);
        return _token.transferFrom(msg.sender, to, value);
    }


    /**
     * @notice Approve spender allowance
     * @dev Token must support https://eips.ethereum.org/EIPS/eip-2612. The spender may not be this contract.
     * @param owner        Account holder who signed permit
     * @param spender      Give allowance to this address
     * @param value        Allowance amount
     * @param deadline     Approval is valid until this block.timestamp
     * @param v            ECDSA signature
     * @param r            ECDSA signature
     * @param s            ECDSA signature
     * @param info         Message
     */
    function permitWithMsg(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        ReciboInfo calldata info
    ) public {
        require(owner != address(this));
        emit ApproveWithMsg(owner, spender, info.messageFrom, info.messageTo, value);
        _token.permit(owner, spender, value, deadline, v, r, s);
    }


    /**
     * @notice Transfers tokens from msg.sender to receiver
     * @dev Token must support https://eips.ethereum.org/EIPS/eip-2612. The token owner must be msg.sender, who
     *      signs the permit authorizing the spender.
     * @param to            Token receiver
     * @param value         Value to transfer
     * @param deadline      Permit is valid until this block.timestamp
     * @param v             ECDSA signature
     * @param r             ECDSA signature
     * @param s             ECDSA signature
     * @param info          Message
     */
    function permitAndTransferFromWithMsg(
        address to,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        ReciboInfo calldata info
    ) public returns (bool) {
        emit TransferWithMsg(msg.sender, to, info.messageFrom, info.messageTo, value);
        _token.permit(msg.sender, address(this), value, deadline, v, r, s);
        return _token.transferFrom(msg.sender, to, value);
    }

    /**
     * @notice Transfers tokens
     * @dev Token must support https://eips.ethereum.org/EIPS/eip-3009.
     * @param from          Token owner
     * @param to            Token receiver
     * @param value         Value to transfer
     * @param validAfter    Authorization is valid after this block.timestamp
     * @param validBefore   Authorization is valid before this block.timestamp
     * @param nonce         Nonce
     * @param signature     EOA wallet signatures should be packed in the order of r, s, v.
     * @param info          Message
     */
    function transferWithAuthorizationWithMsg(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature,
        ReciboInfo calldata info
    ) public {
        emit TransferWithMsg(from, to, info.messageFrom, info.messageTo, value);
        _token.transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }

}
