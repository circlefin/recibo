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
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {Recibo} from "../src/Recibo.sol";
import {ReciboEvents} from "../src/ReciboEvents.sol";
import {GaslessToken} from "../src/mock/GaslessToken.sol";
import {GaslessTestBase} from "../test/mock/GaslessTestBase.t.sol";

contract ReciboExtensionTest is GaslessTestBase {
    GaslessToken public token;
    Recibo recibo;
    address private user = makeAddr("user");
    address private minter;
    uint256 private minterKey;
    bytes private msgBytes = abi.encode("message");
    Recibo.ReciboInfo private info = Recibo.ReciboInfo(minter, user, "metadata", msgBytes);

    uint private deadline;
    uint256 private validBefore;
    uint256 private validAfter;

    function setUp() public {
        (minter, minterKey) = makeAddrAndKey("minter");

        vm.startPrank(minter);
        token = new GaslessToken("Token", "TKN", 200);
        vm.stopPrank();
        recibo = new Recibo(token);

        deadline = makeDeadline(10);
        (validAfter, validBefore) = makeValidTime(100);
    }

    function test_transferWithMsg() public {
        vm.startPrank(minter);
        uint startbalance = token.balanceOf(minter);
        token.approve(address(recibo), 50);

        vm.expectEmit(address(recibo));
        emit ReciboEvents.TransferWithMsg(minter, user, info.messageFrom, info.messageTo, 50);
        recibo.transferFromWithMsg(user, 50, info);

        vm.stopPrank();
        assertEq(token.balanceOf(user), 50);
        assertEq(token.balanceOf(minter), startbalance - 50);
    }

    function test_permitAndTransferFromWithMsg() public {
        uint value = 40;
        bytes32 permit = buildPermitMessage(minter, address(recibo), 40, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterKey, permit);

        uint minterBalance = token.balanceOf(minter);
        uint userBalance = token.balanceOf(user);
        vm.startPrank(minter);
        vm.expectEmit(address(recibo));
        emit ReciboEvents.TransferWithMsg(minter, user, info.messageFrom, info.messageTo, value);
        recibo.permitAndTransferFromWithMsg(user, value, deadline, v, r, s, info);
        vm.stopPrank();
        assertEq(token.balanceOf(user), userBalance + value);
        assertEq(token.balanceOf(minter), minterBalance - value);
    }

    function test_permitError() public {
        uint value = 1;
        bytes32 permit = buildPermitMessage(minter, address(recibo), 40, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterKey, permit);

        vm.startPrank(user);
        address fakeSigner = 0x4816Daec8E87b4ebCd4f44e6A16c7019aeFA1150;
        vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612InvalidSigner.selector, fakeSigner, user));
        recibo.permitAndTransferFromWithMsg(user, value, deadline, v, r, s, info);
        vm.stopPrank();
    }

    function test_permitWithMsg() public {
        uint value = 40;
        bytes32 permit = buildPermitMessage(minter, user, 40, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterKey, permit);

        uint minterBalance = token.balanceOf(minter);
        uint userBalance = token.balanceOf(user);
        vm.startPrank(user);
        vm.expectEmit(address(recibo));
        emit ReciboEvents.ApproveWithMsg(minter, user, info.messageFrom, info.messageTo, value);
        recibo.permitWithMsg(minter, user, value, deadline, v, r, s, info);
        vm.stopPrank();
        assertEq(token.balanceOf(user), userBalance);
        assertEq(token.balanceOf(minter), minterBalance);
    }

    function test_transferWithAuthorizationMsg(bytes32 nonce) public {
        uint value = 40;
        bytes32 transfer = buildTransferMessage(minter, user, 40, validAfter, validBefore, nonce, token);
        bytes memory signature = signTransfer(minterKey, transfer);

        uint minterBalance = token.balanceOf(minter);
        uint userBalance = token.balanceOf(user);
        vm.startPrank(user);
        vm.expectEmit(address(recibo));
        emit ReciboEvents.TransferWithMsg(minter, user, info.messageFrom, info.messageTo, value);
        recibo.transferWithAuthorizationWithMsg(minter, user, value, validAfter, validBefore, nonce, signature, info);
        vm.stopPrank();

        assertEq(token.balanceOf(user), userBalance + value);
        assertEq(token.balanceOf(minter), minterBalance - value);
    }

    function test_transferWithAuthorizationError(bytes32 nonce) public {
        uint value = 1;
        bytes32 transfer = buildTransferMessage(minter, user, 40, validAfter, validBefore, nonce, token);
        bytes memory signature = signTransfer(minterKey, transfer);

        vm.startPrank(minter);
        vm.expectRevert("Invalid signature");
        recibo.transferWithAuthorizationWithMsg(minter, minter, value, validAfter, validBefore, nonce, signature, info);
        vm.stopPrank();
    }
}
