/**
* Copyright 2025 Circle Internet Group, Inc. All rights reserved.
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

import {GaslessToken} from "../../src/mock/GaslessToken.sol";
import {GaslessTestBase} from "./GaslessTestBase.t.sol";

contract GaslessTokenTest is GaslessTestBase {
    GaslessToken public token;
    address private user = makeAddr("user");
    address private spender = makeAddr("spender");
    uint256 private minterPrivateKey;
    address private minter;


    uint private deadline;
    uint256 private validBefore;
    uint256 private validAfter;

    function setUp() public {
        (minter, minterPrivateKey) = makeAddrAndKey("minter");

        vm.startPrank(minter);
        token = new GaslessToken("Token", "TKN", 200);
        vm.stopPrank();

        deadline = makeDeadline(10);
        (validAfter, validBefore) = makeValidTime(100);

    }

    function test_transferFrom() public {
        uint startbalance = token.balanceOf(minter);

        vm.startPrank(minter);
        token.approve(spender, 50);
        vm.stopPrank();

        vm.startPrank(spender);
        token.transferFrom(minter, user, 30);
        vm.stopPrank();

        assertEq(token.balanceOf(user), 30);
        assertEq(token.balanceOf(minter), startbalance - 30);
    }

    function test_permitAndTransferFrom() public {
        uint value = 40;
        bytes32 permit = buildPermitMessage(minter, spender, value, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = signPermit(minterPrivateKey, permit);

        uint minterBalance = token.balanceOf(minter);
        uint userBalance = token.balanceOf(user);
        vm.startPrank(user);
        token.permit(minter, spender, value, deadline, v, r, s);
        vm.stopPrank();

        vm.startPrank(spender);
        token.transferFrom(minter, user, value);
        vm.stopPrank();

        assertEq(token.balanceOf(user), userBalance + value);
        assertEq(token.balanceOf(minter), minterBalance - value);
    }

    function test_permitError() public {
        uint value = 1;
        bytes32 permit = buildPermitMessage(minter, spender, 40, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = signPermit(minterPrivateKey, permit);

        vm.startPrank(user);
        vm.expectRevert();
        token.permit(minter, user, value, deadline, v, r, s);
        vm.stopPrank();
    }

    function test_transferWithAuthorization(bytes32 nonce) public {
        uint value = 40;
        bytes32 transfer = buildTransferMessage(minter, user, 40, validAfter, validBefore, nonce, token);
        bytes memory signature = signTransfer(minterPrivateKey, transfer);

        uint minterBalance = token.balanceOf(minter);
        uint userBalance = token.balanceOf(user);
        vm.startPrank(spender);
        token.transferWithAuthorization(minter, user, value, validAfter, validBefore, nonce, signature);
        vm.stopPrank();

        assertEq(token.balanceOf(user), userBalance + value);
        assertEq(token.balanceOf(minter), minterBalance - value);
    }

    function test_transferWithAuthorizationError(bytes32 nonce) public {
        uint value = 1;
        bytes32 transfer = buildTransferMessage(minter, user, 40, validAfter, validBefore, nonce, token);
        bytes memory signature = signTransfer(minterPrivateKey, transfer);

        vm.startPrank(spender);
        vm.expectRevert();
        token.transferWithAuthorization(minter, spender, value, validAfter, validBefore, nonce, signature);
        vm.stopPrank();
    }


}
