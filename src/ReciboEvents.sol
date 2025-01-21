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

/**
 * @title ReciboEvents
 * @notice Defines events
 */
contract ReciboEvents {
    event TransferWithMsg(
        address from,
        address indexed to,
        address indexed messageFrom,
        address indexed messageTo,
        uint256 value
    );

    event ApproveWithMsg(
        address owner,
        address indexed spender,
        address indexed messageFrom,
        address indexed messageTo,
        uint256 value
    );
}