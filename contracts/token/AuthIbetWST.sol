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
import {IbetWST} from "./IbetWST.sol";
import {IbetWSTErrors, AuthIbetWSTErrors} from "../utils/Errors.sol";

/// @title IbetWST with Authorization Feature
contract AuthIbetWST is IbetWST {
    // Constant for EIP-712 Domain
    bytes32 public DOMAIN_SEPARATOR;

    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    bytes32 public constant REQUEST_TRADE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "RequestTradeWithAuthorization(address sellerSTAccountAddress,address buyerSTAccountAddress,address SCTokenAddress,address sellerSCAccountAddress,address buyerSCAccountAddress,uint256 STValue,uint256 SCValue,bytes32 nonce)"
        );

    bytes32 public constant ACCEPT_TRADE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("AcceptTradeWithAuthorization(uint256 index,bytes32 nonce)");

    // Mapping to manage the usage status of authorization nonces
    mapping(address => mapping(bytes32 => bool)) public usedNonces;

    // [EVENT]
    /// @notice Event emitted when an authorization is used
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    // [CONSTRUCTOR]
    /// @param initialOwner The address of the initial owner
    constructor(address initialOwner) IbetWST(initialOwner) {
        // Construct the EIP-712 Domain Separator
        uint256 chainID;
        assembly {
            chainID := chainid()
        } // Get the current chain ID
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                // TypeHash for EIP712 Domain
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                // Token name
                keccak256(bytes(name())),
                // Version (using "1" as an example)
                keccak256(bytes("1")),
                // Chain ID
                chainID,
                // Contract address
                address(this)
            )
        );
    }

    // [INTERNAL-FUNCTION]
    /// @param typeHash EIP-712 type hash
    function _transferWithAuthorization(
        bytes32 typeHash,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        // Ensure the timestamp is within the valid range
        if (block.timestamp < validAfter) {
            // Throw an error if validAfter is a future timestamp
            revert AuthIbetWSTErrors.TransactionNotInValidPeriod(
                validAfter,
                validBefore
            );
        }
        if (block.timestamp >= validBefore) {
            // Throw an error if validBefore is a past timestamp
            revert AuthIbetWSTErrors.TransactionNotInValidPeriod(
                validAfter,
                validBefore
            );
        }
        // Ensure the nonce has not been used
        if (usedNonces[from][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(from, nonce);
        }
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress != from && recoveredAddress != address(0)) {
            // Throw an error if the signature does not match the sender's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(from);
        }
        // Mark the nonce as used and emit an event
        usedNonces[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        // Execute the ERC-20 transfer (updates balance and emits Transfer event internally)
        _transfer(from, to, value);
    }

    // [FUNCTION]
    /// @notice Transfer tokens with authorization (signature)
    /// @dev Can be called by anyone
    /// @param from The address of the sender
    /// @param to The address of the recipient
    /// @param value The amount of tokens to transfer
    /// @param validAfter The minimum timestamp when the transaction becomes valid
    /// @param validBefore The maximum timestamp when the transaction becomes invalid
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Call the internal process for transfer with authorization
        _transferWithAuthorization(
            TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
        return true;
    }

    /// @notice Receive tokens with authorization (signature)
    /// @dev Only the recipient can call this function
    /// @param from The address of the sender
    /// @param to The address of the recipient
    /// @param value The amount of tokens to receive
    /// @param validAfter The minimum timestamp when the transaction becomes valid
    /// @param validBefore The maximum timestamp when the transaction becomes invalid
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Check that the caller is the recipient
        address sender = _msgSender();
        if (sender != to) {
            // Throw an error if the caller is not the recipient
            revert AuthIbetWSTErrors.ReceiveTransactionSenderNotRecipient(
                sender,
                to
            );
        }
        // Call the internal process for transfer with authorization
        _transferWithAuthorization(
            RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
        return true;
    }

    /// @notice Request a trade with authorization (signature)
    /// @dev
    ///   - The seller's security token account is the authorizer
    ///   - The seller's security token account must be whitelisted
    ///   - The buyer's security token account must also be whitelisted
    /// @param sellerSTAccountAddress The address of the seller's security token account (signature authorizer)
    /// @param buyerSTAccountAddress The address of the buyer's security token account
    /// @param SCTokenAddress The address of the security token to be traded
    /// @param sellerSCAccountAddress The address of the seller's smart contract account
    /// @param buyerSCAccountAddress The address of the buyer's smart contract account
    /// @param STValue The amount of security tokens to be traded
    /// @param SCValue The amount of smart contract tokens to be traded
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function requestTradeWithAuthorization(
        address sellerSTAccountAddress,
        address buyerSTAccountAddress,
        address SCTokenAddress,
        address sellerSCAccountAddress,
        address buyerSCAccountAddress,
        uint256 STValue,
        uint256 SCValue,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Check if the sellerSTAccountAddress is whitelisted
        if (accountWhiteList[sellerSTAccountAddress] == false) {
            revert IbetWSTErrors.AccountNotWhitelisted(sellerSTAccountAddress);
        }
        // Check if the buyerSTAccountAddress is whitelisted
        if (accountWhiteList[buyerSTAccountAddress] == false) {
            revert IbetWSTErrors.AccountNotWhitelisted(buyerSTAccountAddress);
        }

        // Ensure the nonce has not been used
        if (usedNonces[sellerSTAccountAddress][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(
                sellerSTAccountAddress,
                nonce
            );
        }
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(
                REQUEST_TRADE_WITH_AUTHORIZATION_TYPEHASH,
                sellerSTAccountAddress,
                buyerSTAccountAddress,
                SCTokenAddress,
                sellerSCAccountAddress,
                buyerSCAccountAddress,
                STValue,
                SCValue,
                nonce
            )
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (
            recoveredAddress != sellerSTAccountAddress &&
            recoveredAddress != address(0)
        ) {
            // Throw an error if the signature does not match the sender's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(
                sellerSTAccountAddress
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[sellerSTAccountAddress][nonce] = true;
        emit AuthorizationUsed(sellerSTAccountAddress, nonce);

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
            state: State.Pending
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

    /// @notice Accept a trade request with authorization (signature)
    /// @dev
    ///   - The buyer's security token account is the authorizer
    /// @param index The index of the trade request to accept
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function acceptTradeWithAuthorization(
        uint256 index,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Check if the trade request is acceptable
        if (_trades[index].state != State.Pending) {
            revert IbetWSTErrors.TradeRequestIsNotAcceptable(index);
        }
        // Get the buyer's security token account address from the trade request
        address buyerSTAccountAddress = _trades[index].buyerSTAccountAddress;

        // Ensure the nonce has not been used
        if (usedNonces[buyerSTAccountAddress][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(
                buyerSTAccountAddress,
                nonce
            );
        }
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(ACCEPT_TRADE_WITH_AUTHORIZATION_TYPEHASH, index, nonce)
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (
            recoveredAddress != buyerSTAccountAddress &&
            recoveredAddress != address(0)
        ) {
            // Throw an error if the signature does not match the sender's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(
                buyerSTAccountAddress
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[buyerSTAccountAddress][nonce] = true;
        emit AuthorizationUsed(buyerSTAccountAddress, nonce);

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
