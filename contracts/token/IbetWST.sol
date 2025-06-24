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
import {IbetWSTErrors} from "../utils/Errors.sol";

/// @title ibet WST (Worldwide Settlement Token)
/// @dev
///   - This contract extends the IbetERC20 interface to implement a whitelist mechanism for accounts.
///   - Also implements a trade request system for trading WST and SC (Stable Coin) tokens.
contract IbetWST is IbetERC20 {
    /// Account whitelist
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

    // Index of most recent trade request
    uint256 internal _index;

    // State of the trade request
    enum State {
        Pending,
        Executed,
        Cancelled
    }

    // Trade request structure
    struct Trade {
        address sellerSTAccountAddress; // Address of the seller's ST account
        address buyerSTAccountAddress; // Address of the buyer's ST account
        address SCTokenAddress; // Address of the SCToken
        address sellerSCAccountAddress; // Address of the seller's SC account
        address buyerSCAccountAddress; // Address of the buyer's SC account
        uint256 STValue; // Amount of ST tokens to be traded
        uint256 SCValue; // Amount of SC tokens to be traded
        State state; // State of the trade request
        string memo; // Optional memo for the trade request
    }

    // Mapping from index to trade requests
    mapping(uint256 => Trade) internal _trades;

    // [EVENT]
    /// @notice Event emitted when a trade is requested
    /// @dev Triggered when a trade is requested
    /// @param index The index of the trade request
    /// @param sellerSTAccountAddress The address of the seller's ST account
    /// @param buyerSTAccountAddress The address of the buyer's ST account
    /// @param SCTokenAddress The address of the SCToken
    /// @param sellerSCAccountAddress The address of the seller's SC account
    /// @param buyerSCAccountAddress The address of the buyer's SC account
    /// @param STValue The amount of ST tokens to be traded
    /// @param SCValue The amount of SC tokens to be traded
    event TradeRequested(
        uint256 indexed index,
        address indexed sellerSTAccountAddress,
        address indexed buyerSTAccountAddress,
        address SCTokenAddress,
        address sellerSCAccountAddress,
        address buyerSCAccountAddress,
        uint256 STValue,
        uint256 SCValue
    );

    // [EVENT]
    /// @notice Event emitted when a trade is cancelled
    /// @dev Triggered when a trade is cancelled
    /// @param index The index of the trade request
    /// @param sellerSTAccountAddress The address of the seller's ST account
    /// @param buyerSTAccountAddress The address of the buyer's ST account
    /// @param SCTokenAddress The address of the SCToken
    /// @param sellerSCAccountAddress The address of the seller's SC account
    /// @param buyerSCAccountAddress The address of the buyer's SC account
    /// @param STValue The amount of ST tokens to be traded
    /// @param SCValue The amount of SC tokens to be traded
    event TradeCancelled(
        uint256 indexed index,
        address indexed sellerSTAccountAddress,
        address indexed buyerSTAccountAddress,
        address SCTokenAddress,
        address sellerSCAccountAddress,
        address buyerSCAccountAddress,
        uint256 STValue,
        uint256 SCValue
    );

    // [EVENT]
    /// @notice Event emitted when a trade is accepted
    /// @dev Triggered when a trade is accepted
    /// @param index The index of the trade request
    /// @param sellerSTAccountAddress The address of the seller's ST account
    /// @param buyerSTAccountAddress The address of the buyer's ST account
    /// @param SCTokenAddress The address of the SCToken
    /// @param sellerSCAccountAddress The address of the seller's SC account
    /// @param buyerSCAccountAddress The address of the buyer's SC account
    /// @param STValue The amount of ST tokens to be traded
    /// @param SCValue The amount of SC tokens to be traded
    event TradeAccepted(
        uint256 indexed index,
        address indexed sellerSTAccountAddress,
        address indexed buyerSTAccountAddress,
        address SCTokenAddress,
        address sellerSCAccountAddress,
        address buyerSCAccountAddress,
        uint256 STValue,
        uint256 SCValue
    );

    // [CONSTRUCTOR]
    /// @param initialOwner The address of the initial owner
    constructor(
        string memory name,
        address initialOwner
    ) IbetERC20(name, initialOwner) {}

    // [FUNCTION]
    /// @notice Get the number of decimals for the token
    /// @dev Returns 0 as this token does not have decimals
    function decimals() public view override returns (uint8) {
        return 0;
    }

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
            revert IbetWSTErrors.AccountNotWhitelisted(from);
        }
        // Check if the recipient is whitelisted
        if (accountWhiteList[to] == false) {
            revert IbetWSTErrors.AccountNotWhitelisted(to);
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
            revert IbetWSTErrors.AccountNotWhitelisted(from);
        }
        // Check if the recipient is whitelisted
        if (accountWhiteList[to] == false) {
            revert IbetWSTErrors.AccountNotWhitelisted(to);
        }
        // Consume the allowance
        address spender = _msgSender();
        _spendAllowance(from, spender, value);
        // Proceed with the transfer
        _transfer(from, to, value);
        return true;
    }

    // [FUNCTION]
    /// @notice Get the number of trade requests
    /// @dev Returns the index of the most recent trade request
    function getNbTrades() external view returns (uint256) {
        return _index;
    }

    // [FUNCTION]
    /// @notice Get details of a trade request
    /// @dev Returns the details of a trade request by its index
    /// @param index The index of the trade request
    /// @return Trade
    function getTrade(
        uint256 index
    )
        external
        view
        returns (
            address,
            address,
            address,
            address,
            address,
            uint256,
            uint256,
            State,
            string memory
        )
    {
        Trade storage trade = _trades[index];
        return (
            trade.sellerSTAccountAddress,
            trade.buyerSTAccountAddress,
            trade.SCTokenAddress,
            trade.sellerSCAccountAddress,
            trade.buyerSCAccountAddress,
            trade.STValue,
            trade.SCValue,
            trade.state,
            trade.memo
        );
    }

    // [FUNCTION]
    /// @notice Request a trade
    /// @dev
    ///   - The seller's ST account address (msg.sender) must be whitelisted
    ///   - The buyer's ST account address must be whitelisted
    /// @param buyerSTAccountAddress The address of the buyer's ST account
    /// @param SCTokenAddress The address of the SC contract to be traded
    /// @param sellerSCAccountAddress The address of the seller's SC account
    /// @param buyerSCAccountAddress The address of the buyer's SC account
    /// @param STValue The amount of ST tokens to be traded
    /// @param SCValue The amount of SC tokens to be traded
    /// @param memo Optional memo for the trade request
    function requestTrade(
        address buyerSTAccountAddress,
        address SCTokenAddress,
        address sellerSCAccountAddress,
        address buyerSCAccountAddress,
        uint256 STValue,
        uint256 SCValue,
        string memory memo
    ) public returns (bool) {
        address sellerSTAccountAddress = _msgSender();
        // Check if the sellerSTAccountAddress is whitelisted
        if (accountWhiteList[sellerSTAccountAddress] == false) {
            revert IbetWSTErrors.AccountNotWhitelisted(sellerSTAccountAddress);
        }
        // Check if the buyerSTAccountAddress is whitelisted
        if (accountWhiteList[buyerSTAccountAddress] == false) {
            revert IbetWSTErrors.AccountNotWhitelisted(buyerSTAccountAddress);
        }
        // Increment the index for trade requests
        _index++;
        // Create a new trade request
        _trades[_index] = Trade({
            sellerSTAccountAddress: sellerSTAccountAddress,
            buyerSTAccountAddress: buyerSTAccountAddress,
            SCTokenAddress: SCTokenAddress,
            sellerSCAccountAddress: sellerSCAccountAddress,
            buyerSCAccountAddress: buyerSCAccountAddress,
            STValue: STValue,
            SCValue: SCValue,
            state: State.Pending,
            memo: memo
        });
        // Emit the TradeRequested event
        emit TradeRequested(
            _index,
            sellerSTAccountAddress,
            buyerSTAccountAddress,
            SCTokenAddress,
            sellerSCAccountAddress,
            buyerSCAccountAddress,
            STValue,
            SCValue
        );
        return true;
    }

    // [FUNCTION]
    /// @notice Cancel a trade request
    /// @dev
    ///   - The trade request must be in the Pending state
    ///   - The caller must be the seller's ST account address of the trade request
    /// @param index The index of the trade request to be cancelled
    function cancelTrade(uint256 index) public returns (bool) {
        // Check if the trade request is acceptable
        if (_trades[index].state != State.Pending) {
            revert IbetWSTErrors.TradeRequestIsNotAcceptable(index);
        }
        // Check if the caller is the trade request's seller
        address sellerSTAccountAddress = _msgSender();
        if (_trades[index].sellerSTAccountAddress != sellerSTAccountAddress) {
            revert IbetWSTErrors.TradeRequestNotAcceptableByCaller(
                index,
                sellerSTAccountAddress
            );
        }
        // Update the state of the trade request to Cancelled
        _trades[index].state = State.Cancelled;
        // Emit the TradeCancelled event
        emit TradeCancelled(
            index,
            _trades[index].sellerSTAccountAddress,
            _trades[index].buyerSTAccountAddress,
            _trades[index].SCTokenAddress,
            _trades[index].sellerSCAccountAddress,
            _trades[index].buyerSCAccountAddress,
            _trades[index].STValue,
            _trades[index].SCValue
        );
        return true;
    }

    // [FUNCTION]
    /// @notice Accept a trade request
    /// @dev
    ///   - The trade request must be in the Pending state
    ///   - The caller must be the buyer's ST account address of the trade request
    /// @param index The index of the trade request to be accepted
    function acceptTrade(uint256 index) public returns (bool) {
        // Check if the trade request is acceptable
        if (_trades[index].state != State.Pending) {
            revert IbetWSTErrors.TradeRequestIsNotAcceptable(index);
        }
        // Check if the caller is the trade request's buyer
        address buyerSTAccountAddress = _msgSender();
        if (_trades[index].buyerSTAccountAddress != buyerSTAccountAddress) {
            revert IbetWSTErrors.TradeRequestNotAcceptableByCaller(
                index,
                buyerSTAccountAddress
            );
        }
        // Update the state of the trade request to Executed
        _trades[index].state = State.Executed;
        // Transfer ST tokens from the seller's ST account to the buyer's ST account
        _transfer(
            _trades[index].sellerSTAccountAddress,
            _trades[index].buyerSTAccountAddress,
            _trades[index].STValue
        );
        // SC token transfer from buyer's SC account to seller's SC account
        ERC20(_trades[index].SCTokenAddress).transferFrom(
            _trades[index].buyerSCAccountAddress,
            _trades[index].sellerSCAccountAddress,
            _trades[index].SCValue
        );
        // Emit the TradeAccepted event
        emit TradeAccepted(
            index,
            _trades[index].sellerSTAccountAddress,
            _trades[index].buyerSTAccountAddress,
            _trades[index].SCTokenAddress,
            _trades[index].sellerSCAccountAddress,
            _trades[index].buyerSCAccountAddress,
            _trades[index].STValue,
            _trades[index].SCValue
        );
        return true;
    }
}
