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

contract BigMsg {

    uint256 constant MAX_BYTES = 1024 * 1024; // 1024 KB
    bytes public MSG_BYTES = generateBytes(MAX_BYTES);

    function generateBytes(uint256 len) internal pure returns (bytes memory) {
        bytes memory result = new bytes(len);
        for(uint i = 0; i < 5000; i++) {
            result[i] = bytes1(uint8(i % 256)); // uint8 0-255
        }
        return result;
    }

    function getBytes(uint len) public view returns (bytes memory) {
        require(len <= MSG_BYTES.length, "Requested length exceeds MSG_BYTES length");

        bytes memory result = new bytes(len);
        for (uint i = 0; i < len; i++) {
            result[i] = MSG_BYTES[i];
        }
        return result;
    }    
}
