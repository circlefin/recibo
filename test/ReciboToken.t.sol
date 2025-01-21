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
import {ReciboToken} from "../src/ReciboToken.sol";
import {ReciboEvents} from "../src/ReciboEvents.sol";

contract ReciboTokenTest is Test {
    ReciboToken public token;
    address private minter = makeAddr("minter");
    address private user = makeAddr("user");


    function setUp() public {
        vm.startPrank(minter);
        token = new ReciboToken("Recibo", "RCB", 200);
        vm.stopPrank();
    }

    function test_transferWithMsg(string calldata metadata, string calldata message) public {
        bytes memory msgBytes = abi.encode(message);
        vm.startPrank(minter);
        vm.expectEmit(address(token));
        emit ReciboEvents.TransferWithMsg(minter, user, minter, user, 50);
        token.transferWithMsg(user, 50, minter, user, metadata, msgBytes);
        vm.stopPrank();
        assertEq(token.balanceOf(user), 50);
    }

    function test_approveWithMsg(string calldata metadata, string calldata message) public {
        bytes memory msgBytes = abi.encode(message);
        vm.startPrank(minter);
        vm.expectEmit(address(token));
        emit ReciboEvents.ApproveWithMsg(minter, user, minter, user, 50);
        token.approveWithMsg(user, 50, minter, user, metadata, msgBytes);
        vm.stopPrank();
        assertEq(token.allowance(minter, user), 50);
    }

    function test_transferFromWithMsg(string calldata metadata, string calldata message) public {
        bytes memory msgBytes = abi.encode(message);
        vm.expectEmit(address(token));
        vm.startPrank(minter);
        emit ReciboEvents.ApproveWithMsg(minter, user, minter, user, 50);
        token.approveWithMsg(user, 50, minter, user, metadata, msgBytes);
        vm.stopPrank();
        assertEq(token.allowance(minter, user), 50);

        vm.startPrank(user);
        emit ReciboEvents.TransferWithMsg(minter, user, minter, user, 50);
        token.transferFromWithMsg(minter, user, 30, minter, user, metadata, msgBytes);
        vm.stopPrank();
        assertEq(token.allowance(minter, user), 20);
        assertEq(token.balanceOf(user), 30);
        assertEq(token.balanceOf(minter), 170);
    }
}