/**
 * Copyright BOOSTRY Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
pragma solidity ^0.8.0;

import "OpenZeppelin/openzeppelin-contracts@5.3.0/contracts/token/ERC20/ERC20.sol";
import {IbetERC20} from "./IbetERC20.sol";
import {Errors} from "../utils/Errors.sol";

contract IbetWST is IbetERC20 {
    /// Account whitelist
    /// account_address => bool
    mapping(address => bool) public accountWhiteList;

    // [EVENT]
    /// @notice Event emitted when an account is added to the whitelist
    /// @dev Triggered when the owner adds an account to the whitelist
    /// @param accountAddress The address of the account added to the whitelist
    event AccountWhiteListAdded(address indexed accountAddress);

    // [EVENT]
    /// @notice Event emitted when an account is removed from the whitelist
    /// @dev Triggered when the owner removes an account from the whitelist
    /// @param accountAddress The address of the account removed from the whitelist
    event AccountWhiteListDeleted(address indexed accountAddress);

    // [CONSTRUCTOR]
    /// @param initialOwner The address of the initial owner
    constructor(address initialOwner) IbetERC20(initialOwner) {}

    // [FUNCTION]
    /// @notice Register an account to the whitelist
    /// @dev Only callable by the owner
    /// @param accountAddress The address of the account to be whitelisted
    function addAccountWhiteList(
        address accountAddress
    ) public onlyOwner returns (bool) {
        // Add to whitelist
        accountWhiteList[accountAddress] = true;
        // Emit event
        emit AccountWhiteListAdded(accountAddress);
        return true;
    }

    // [FUNCTION]
    /// @notice Remove an account from the whitelist
    /// @dev Only callable by the owner
    /// @param accountAddress The address of the account to be removed from the whitelist
    function deleteAccountWhiteList(
        address accountAddress
    ) public onlyOwner returns (bool) {
        // Remove from whitelist
        accountWhiteList[accountAddress] = false;
        // Emit event
        emit AccountWhiteListDeleted(accountAddress);
        return true;
    }

    // [FUNCTION]
    /// @notice Transfer tokens
    /// @dev
    ///   - Overrides ERC20's transfer function
    ///   - The sender (msg.sender) must be registered in the whitelist
    ///   - The recipient must be registered in the whitelist
    /// @param to The address of the recipient
    /// @param value The amount of tokens to be transferred
    function transfer(
        address to,
        uint256 value
    ) public override returns (bool) {
        address from = _msgSender();
        // Check if the sender is whitelisted
        if (accountWhiteList[from] == false) {
            revert Errors.AccountNotWhitelisted(from);
        }
        // Check if the recipient is whitelisted
        if (accountWhiteList[to] == false) {
            revert Errors.AccountNotWhitelisted(to);
        }
        // Proceed with the transfer
        _transfer(from, to, value);
        return true;
    }

    // [FUNCTION]
    /// @notice Transfer tokens on behalf of another address
    /// @dev
    ///   - Overrides ERC20's transferFrom function
    ///   - The sender must be registered in the whitelist
    ///   - The recipient must be registered in the whitelist
    /// @param from The address of the sender
    /// @param to The address of the recipient
    /// @param value The amount of tokens to be transferred
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public override returns (bool) {
        // Check if the sender is whitelisted
        if (accountWhiteList[from] == false) {
            revert Errors.AccountNotWhitelisted(from);
        }
        // Check if the recipient is whitelisted
        if (accountWhiteList[to] == false) {
            revert Errors.AccountNotWhitelisted(to);
        }
        // Consume the allowance
        address spender = _msgSender();
        _spendAllowance(from, spender, value);
        // Proceed with the transfer
        _transfer(from, to, value);
        return true;
    }
}
