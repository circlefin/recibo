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

import {Test, console} from "forge-std/Test.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Recibo} from "../src/Recibo.sol";
import {ReciboEvents} from "../src/ReciboEvents.sol";
import {GaslessToken} from "../src/mock/GaslessToken.sol";
import {GaslessTestBase} from "../test/mock/GaslessTestBase.t.sol";
import {BigMsg} from "../test/mock/BigMsg.t.sol";

contract ReciboGasTest is GaslessTestBase, BigMsg {
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
        deadline = makeDeadline(10);
        (validAfter, validBefore) = makeValidTime(100);

        vm.startPrank(minter);
        token = new GaslessToken("Token", "TKN", 2000);
        recibo = new Recibo(token);
        vm.stopPrank();
    }

    function test_gasless_token_transferFrom() public {
        vm.startPrank(minter);
        token.approve(user, 1);
        vm.stopPrank();

        vm.startPrank(user);
        vm.startSnapshotGas("token", "tranferFrom");
        token.transferFrom(minter, user, 1);
        vm.stopSnapshotGas();
        vm.stopPrank();
    }

    function test_gasless_token_permit_and_transfer() public {
        uint value = 1;
        bytes32 permit = buildPermitMessage(minter, user, value, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterKey, permit);

        vm.startPrank(user);
        vm.startSnapshotGas("token", "permitAndTransferFrom");
        token.permit(minter, user, value, deadline, v, r, s);
        token.transferFrom(minter, user, value);
        vm.stopSnapshotGas();
        vm.stopPrank();
    }

    function test_gasless_token_permit() public {
        uint value = 1;
        bytes32 permit = buildPermitMessage(minter, user, value, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterKey, permit);

        vm.startPrank(user);
        vm.startSnapshotGas("token", "permit");
        token.permit(minter, user, value, deadline, v, r, s);
        vm.stopSnapshotGas();
        vm.stopPrank();
    }

    function test_gasless_token_transfer_with_authorization() public {
        uint value = 1;
        bytes32 nonce = keccak256(abi.encode(1));
        bytes32 transfer = buildTransferMessage(minter, user, value, validAfter, validBefore, nonce, token);
        bytes memory signature = signTransfer(minterKey, transfer);

        vm.startPrank(user);
        vm.startSnapshotGas("token", "transferWithAuthorization");
        token.transferWithAuthorization(minter, user, value, validAfter, validBefore, nonce, signature);
        vm.stopSnapshotGas();
        vm.stopPrank();
    }

    /** 
    * GAS TESTS
    *
    * Each test measures the gas cost of a function call with a message of a specific length.
    * Foundry runs each unit test function as a single transaction. Since gas usage goes down when
    * smart contracts modify "warm" (used) storage addresses, we want to ensure as many addresses
    * as possible are cold. We do this by running measurement in a separate unit test function.
    */

    function measure_transferWithMsg(uint256 len) public {
        string memory group = Strings.toString(len);
        info.message = BigMsg.getBytes(len);

        vm.startPrank(minter);
        token.approve(address(recibo), 1);
 
        vm.expectEmit(address(recibo));
        emit ReciboEvents.TransferWithMsg(minter, user, info.messageFrom, info.messageTo, 1);
        vm.startSnapshotGas("transferWithMsg", group);
        recibo.transferFromWithMsg(user, 1, info);
        vm.stopSnapshotGas();
        vm.stopPrank();
    }

    function test_transferWithMsg10() public {
        measure_transferWithMsg(10);
    }
    function test_transferWithMsg25() public {
        measure_transferWithMsg(25);
    }
    function test_transferWithMsg50() public {
        measure_transferWithMsg(50);
    }
    function test_transferWithMsg75() public {
        measure_transferWithMsg(75);
    }
    function test_transferWithMsg100() public {
        measure_transferWithMsg(100);
    }
    function test_transferWithMsg200() public {
        measure_transferWithMsg(200);
    }
    function test_transferWithMsg300() public {
        measure_transferWithMsg(300);
    }
    function test_transferWithMsg400() public {
        measure_transferWithMsg(400);
    }
    function test_transferWithMsg500() public {
        measure_transferWithMsg(500);
    }
    function test_transferWithMsg600() public {
        measure_transferWithMsg(600);
    }
    function test_transferWithMsg700() public {
        measure_transferWithMsg(700);
    }
    function test_transferWithMsg800() public {
        measure_transferWithMsg(800);
    }
    function test_transferWithMsg900() public {
        measure_transferWithMsg(900);
    }
    function test_transferWithMsg1000() public {
        measure_transferWithMsg(1000);
    }
    function test_transferWithMsg2000() public {
        measure_transferWithMsg(2000);
    }
    function test_transferWithMsg3000() public {
        measure_transferWithMsg(3000);
    }
    function test_transferWithMsg4000() public {
        measure_transferWithMsg(4000);
    }
    function test_transferWithMsg5000() public {
        measure_transferWithMsg(5000);
    }
    function test_transferWithMsg10K() public {
        measure_transferWithMsg(10000);
    }
    function test_transferWithMsg100K() public {
        measure_transferWithMsg(100000);
    }
    function test_transferWithMsg1M() public {
        measure_transferWithMsg(1000000);
    }

    function measure_permitAndTransferFromWithMsg(uint256 len) public {
        string memory group = Strings.toString(len);
        info.message = BigMsg.getBytes(len);

        uint value = 1;
        bytes32 permit = buildPermitMessage(minter, address(recibo), value, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterKey, permit);

        vm.startPrank(minter);
        vm.expectEmit(address(recibo));
        emit ReciboEvents.TransferWithMsg(minter, user, info.messageFrom, info.messageTo, value);
        vm.startSnapshotGas("permitAndTransferFromWithMsg", group);
        recibo.permitAndTransferFromWithMsg(user, value, deadline, v, r, s, info);
        vm.stopSnapshotGas();
        vm.stopPrank();
    }

    function test_permitAndTransferFromWithMsg10() public {
        measure_permitAndTransferFromWithMsg(10);
    }
    function test_permitAndTransferFromWithMsg25() public {
        measure_permitAndTransferFromWithMsg(25);
    }
    function test_permitAndTransferFromWithMsg50() public {
        measure_permitAndTransferFromWithMsg(50);
    }
    function test_permitAndTransferFromWithMsg75() public {
        measure_permitAndTransferFromWithMsg(75);
    }
    function test_permitAndTransferFromWithMsg100() public {
        measure_permitAndTransferFromWithMsg(100);
    }
    function test_permitAndTransferFromWithMsg200() public {
        measure_permitAndTransferFromWithMsg(200);
    }
    function test_permitAndTransferFromWithMsg300() public {
        measure_permitAndTransferFromWithMsg(300);
    }
    function test_permitAndTransferFromWithMsg400() public {
        measure_permitAndTransferFromWithMsg(400);
    }
    function test_permitAndTransferFromWithMsg500() public {
        measure_permitAndTransferFromWithMsg(500);
    }
    function test_permitAndTransferFromWithMsg600() public {
        measure_permitAndTransferFromWithMsg(600);
    }
    function test_permitAndTransferFromWithMsg700() public {
        measure_permitAndTransferFromWithMsg(700);
    }
    function test_permitAndTransferFromWithMsg800() public {
        measure_permitAndTransferFromWithMsg(800);
    }
    function test_permitAndTransferFromWithMsg900() public {
        measure_permitAndTransferFromWithMsg(900);
    }
    function test_permitAndTransferFromWithMsg1000() public {
        measure_permitAndTransferFromWithMsg(1000);
    }
    function test_permitAndTransferFromWithMsg2000() public {
        measure_permitAndTransferFromWithMsg(2000);
    }
    function test_permitAndTransferFromWithMsg3000() public {
        measure_permitAndTransferFromWithMsg(3000);
    }
    function test_permitAndTransferFromWithMsg4000() public {
        measure_permitAndTransferFromWithMsg(4000);
    }
    function test_permitAndTransferFromWithMsg5000() public {
        measure_permitAndTransferFromWithMsg(5000);
    }
    function test_permitAndTransferFromWithMsg10K() public {
        measure_permitAndTransferFromWithMsg(10000);
    }
    function test_permitAndTransferFromWithMsg100K() public {
        measure_permitAndTransferFromWithMsg(100000);
    }
    function test_permitAndTransferFromWithMsg1M() public {
        measure_permitAndTransferFromWithMsg(1000000);
    }

    function measure_permitWithMsg(uint256 len) public {
        string memory group = Strings.toString(len);
        info.message = BigMsg.getBytes(len);

        uint value = 1;
        bytes32 permit = buildPermitMessage(minter, user, value, deadline, token);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterKey, permit);

        vm.expectEmit(address(recibo));
        emit ReciboEvents.ApproveWithMsg(minter, user, info.messageFrom, info.messageTo, value);
        vm.startSnapshotGas("permitWithMsg", group);
        recibo.permitWithMsg(minter, user, value, deadline, v, r, s, info);
        vm.stopSnapshotGas();
    }

   function test_permitWithMsg10() public {
        measure_permitWithMsg(10);
    }
    function test_permitWithMsg25() public {
        measure_permitWithMsg(25);
    }
    function test_permitWithMsg50() public {
        measure_permitWithMsg(50);
    }
    function test_permitWithMsg75() public {
        measure_permitWithMsg(75);
    }
    function test_permitWithMsg100() public {
        measure_permitWithMsg(100);
    }
    function test_permitWithMsg200() public {
        measure_permitWithMsg(200);
    }
    function test_permitWithMsg300() public {
        measure_permitWithMsg(300);
    }
    function test_permitWithMsg400() public {
        measure_permitWithMsg(400);
    }
    function test_permitWithMsg500() public {
        measure_permitWithMsg(500);
    }
    function test_permitWithMsg600() public {
        measure_permitWithMsg(600);
    }
    function test_permitWithMsg700() public {
        measure_permitWithMsg(700);
    }
    function test_permitWithMsg800() public {
        measure_permitWithMsg(800);
    }
    function test_permitWithMsg900() public {
        measure_permitWithMsg(900);
    }
    function test_permitWithMsg1000() public {
        measure_permitWithMsg(1000);
    }
    function test_permitWithMsg2000() public {
        measure_permitWithMsg(2000);
    }
    function test_permitWithMsg3000() public {
        measure_permitWithMsg(3000);
    }
    function test_permitWithMsg4000() public {
        measure_permitWithMsg(4000);
    }
    function test_permitWithMsg5000() public {
        measure_permitWithMsg(5000);
    }
    function test_permitWithMsg10K() public {
        measure_permitWithMsg(10000);
    }
    function test_permitWithMsg100K() public {
        measure_permitWithMsg(100000);
    }
    function test_permitWithMsg1M() public {
        measure_permitWithMsg(1000000);
    }

    function measure_transferWithAuthorizationWithMsg(uint256 len) public {
        string memory group = Strings.toString(len);
        info.message = BigMsg.getBytes(len);

        uint value = 1;
        bytes32 nonce = keccak256(abi.encode(len));
        bytes32 transfer = buildTransferMessage(minter, user, value, validAfter, validBefore, nonce, token);
        bytes memory signature = signTransfer(minterKey, transfer);

        vm.expectEmit(address(recibo));
        emit ReciboEvents.TransferWithMsg(minter, user, info.messageFrom, info.messageTo, value);
        vm.startSnapshotGas("transferWithAuthorizationWithMsg", group);
        recibo.transferWithAuthorizationWithMsg(minter, user, value, validAfter, validBefore, nonce, signature, info);
        vm.stopSnapshotGas();
    }

    function test_transferWithAuthorizationWithMsg10() public {
        measure_transferWithAuthorizationWithMsg(10);
    }
    function test_transferWithAuthorizationWithMsg25() public {
        measure_transferWithAuthorizationWithMsg(25);
    }
    function test_transferWithAuthorizationWithMsg50() public {
        measure_transferWithAuthorizationWithMsg(50);
    }
    function test_transferWithAuthorizationWithMsg75() public {
        measure_transferWithAuthorizationWithMsg(75);
    }
    function test_transferWithAuthorizationWithMsg100() public {
        measure_transferWithAuthorizationWithMsg(100);
    }
    function test_transferWithAuthorizationWithMsg200() public {
        measure_transferWithAuthorizationWithMsg(200);
    }
    function test_transferWithAuthorizationWithMsg300() public {
        measure_transferWithAuthorizationWithMsg(300);
    }
    function test_transferWithAuthorizationWithMsg400() public {
        measure_transferWithAuthorizationWithMsg(400);
    }
    function test_transferWithAuthorizationWithMsg500() public {
        measure_transferWithAuthorizationWithMsg(500);
    }
    function test_transferWithAuthorizationWithMsg600() public {
        measure_transferWithAuthorizationWithMsg(600);
    }
    function test_transferWithAuthorizationWithMsg700() public {
        measure_transferWithAuthorizationWithMsg(700);
    }
    function test_transferWithAuthorizationWithMsg800() public {
        measure_transferWithAuthorizationWithMsg(800);
    }
    function test_transferWithAuthorizationWithMsg900() public {
        measure_transferWithAuthorizationWithMsg(900);
    }
    function test_transferWithAuthorizationWithMsg1000() public {
        measure_transferWithAuthorizationWithMsg(1000);
    }
    function test_transferWithAuthorizationWithMsg2000() public {
        measure_transferWithAuthorizationWithMsg(2000);
    }
    function test_transferWithAuthorizationWithMsg3000() public {
        measure_transferWithAuthorizationWithMsg(3000);
    }
    function test_transferWithAuthorizationWithMsg4000() public {
        measure_transferWithAuthorizationWithMsg(4000);
    }
    function test_transferWithAuthorizationWithMsg5000() public {
        measure_transferWithAuthorizationWithMsg(5000);
    }
    function test_transferWithAuthorizationWithMsg10K() public {
        measure_transferWithAuthorizationWithMsg(10000);
    }
    function test_transferWithAuthorizationWithMsg100K() public {
        measure_transferWithAuthorizationWithMsg(100000);
    }
    function test_transferWithAuthorizationWithMsg1M() public {
        measure_transferWithAuthorizationWithMsg(1000000);
    }    
}
