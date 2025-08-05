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
pragma solidity ^0.8.23;

import "OpenZeppelin/openzeppelin-contracts@5.3.0/contracts/token/ERC20/ERC20.sol";
import {IbetWST} from "./IbetWST.sol";
import {AuthIbetWSTErrors} from "../utils/Errors.sol";

/// @title IbetWST with Authorization Feature
contract AuthIbetWST is IbetWST {
    // Constant for EIP-712 Domain
    bytes32 public DOMAIN_SEPARATOR;

    bytes32 public constant MINT_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "MintWithAuthorization(address to,uint256 value,bytes32 nonce)"
        );

    bytes32 public constant BURN_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "BurnWithAuthorization(address from,uint256 value,bytes32 nonce)"
        );

    bytes32 public constant FORCE_BURN_FROM_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "ForceBurnFromWithAuthorization(address account,uint256 value,bytes32 nonce)"
        );

    bytes32 public constant ADD_ACCOUNT_WHITELIST_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "AddAccountWhiteListWithAuthorization(address STAccountAddress,address SCAccountAddressIn,address SCAccountAddressOut,bytes32 nonce)"
        );

    bytes32
        public
        constant DELETE_ACCOUNT_WHITELIST_WITH_AUTHORIZATION_TYPEHASH =
            keccak256(
                "DeleteAccountWhiteListWithAuthorization(address STAccountAddress,bytes32 nonce)"
            );

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
            "RequestTradeWithAuthorization(address sellerSTAccountAddress,address buyerSTAccountAddress,address SCTokenAddress,uint256 STValue,uint256 SCValue,string memory memo,bytes32 nonce)"
        );

    bytes32 public constant CANCEL_TRADE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("CancelTradeWithAuthorization(uint256 index,bytes32 nonce)");

    bytes32 public constant ACCEPT_TRADE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("AcceptTradeWithAuthorization(uint256 index,bytes32 nonce)");

    bytes32 public constant REJECT_TRADE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("RejectTradeWithAuthorization(uint256 index,bytes32 nonce)");

    // Mapping to manage the usage status of authorization nonces
    mapping(address => mapping(bytes32 => bool)) public usedNonces;

    // [EVENT]
    /// @notice Event emitted when an authorization is used
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    // [CONSTRUCTOR]
    /// @param initialOwner The address of the initial owner
    constructor(
        string memory name,
        address initialOwner
    ) IbetWST(name, initialOwner) {
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
                keccak256(bytes(name)),
                // Version
                keccak256(bytes("1")),
                // Chain ID
                chainID,
                // Contract address
                address(this)
            )
        );
    }

    // [FUNCTION]
    /// @notice Mint tokens with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - Token owner must sign the authorization
    /// @param to The address to mint tokens to
    /// @param value The value of tokens to mint
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function mintWithAuthorization(
        address to,
        uint256 value,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(MINT_WITH_AUTHORIZATION_TYPEHASH, to, value, nonce)
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress != owner() || recoveredAddress == address(0)) {
            // Throw an error if the signature does not match the token owner's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(owner());
        }

        // Ensure the nonce has not been used
        if (usedNonces[recoveredAddress][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(
                recoveredAddress,
                nonce
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[recoveredAddress][nonce] = true;
        emit AuthorizationUsed(recoveredAddress, nonce);
        // Mint the tokens to the specified address
        _mint(to, value);
        emit Mint(to, value);

        return true;
    }

    // [FUNCTION]
    /// @notice Burn tokens with authorization
    /// @dev
    ///   - Can be called by anyone
    /// @param from The address from which to burn tokens
    /// @param value The value of tokens to burn
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function burnWithAuthorization(
        address from,
        uint256 value,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(BURN_WITH_AUTHORIZATION_TYPEHASH, from, value, nonce)
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress != from || recoveredAddress == address(0)) {
            // Throw an error if the signature does not match the token sender's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(from);
        }

        // Ensure the nonce has not been used
        if (usedNonces[recoveredAddress][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(
                recoveredAddress,
                nonce
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[recoveredAddress][nonce] = true;
        emit AuthorizationUsed(recoveredAddress, nonce);
        // Burn the tokens from the specified address
        _burn(from, value);
        emit Burn(from, value);

        return true;
    }

    // [FUNCTION]
    /// @notice Force burn tokens from a specified account with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - Token owner must sign the authorization
    /// @param account The address from which to burn tokens
    /// @param value The value of tokens to burn
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function forceBurnFromWithAuthorization(
        address account,
        uint256 value,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(
                FORCE_BURN_FROM_WITH_AUTHORIZATION_TYPEHASH,
                account,
                value,
                nonce
            )
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress != owner() || recoveredAddress == address(0)) {
            // Throw an error if the signature does not match the token owner's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(owner());
        }

        // Ensure the nonce has not been used
        if (usedNonces[recoveredAddress][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(
                recoveredAddress,
                nonce
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[recoveredAddress][nonce] = true;
        emit AuthorizationUsed(recoveredAddress, nonce);
        // Burn the tokens from the specified address
        _burn(account, value);
        emit Burn(account, value);

        return true;
    }

    // [FUNCTION]
    /// @notice Add an account to the whitelist with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - Token owner must sign the authorization
    /// @param STAccountAddress ST account address
    /// @param SCAccountAddressIn SC account address for deposits
    /// @param SCAccountAddressOut SC account address for withdrawals
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function addAccountWhiteListWithAuthorization(
        address STAccountAddress,
        address SCAccountAddressIn,
        address SCAccountAddressOut,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(
                ADD_ACCOUNT_WHITELIST_WITH_AUTHORIZATION_TYPEHASH,
                STAccountAddress,
                SCAccountAddressIn,
                SCAccountAddressOut,
                nonce
            )
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress != owner() || recoveredAddress == address(0)) {
            // Throw an error if the signature does not match the token owner's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(owner());
        }

        // Ensure the nonce has not been used
        if (usedNonces[recoveredAddress][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(
                recoveredAddress,
                nonce
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[recoveredAddress][nonce] = true;
        emit AuthorizationUsed(recoveredAddress, nonce);

        // Add to whitelist
        accountWhiteList[STAccountAddress] = AccountWhiteList({
            STAccountAddress: STAccountAddress,
            SCAccountAddressIn: SCAccountAddressIn,
            SCAccountAddressOut: SCAccountAddressOut,
            listed: true
        });
        // Emit event
        emit AccountWhiteListAdded(STAccountAddress);

        return true;
    }

    // [FUNCTION]
    /// @notice Delete an account from the whitelist with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - Token owner must sign the authorization
    /// @param STAccountAddress The address of the ST account to be removed from the whitelist
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function deleteAccountWhiteListWithAuthorization(
        address STAccountAddress,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Calculate the structHash for the EIP-712 message
        bytes32 structHash = keccak256(
            abi.encode(
                DELETE_ACCOUNT_WHITELIST_WITH_AUTHORIZATION_TYPEHASH,
                STAccountAddress,
                nonce
            )
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress != owner() || recoveredAddress == address(0)) {
            // Throw an error if the signature does not match the token owner's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(owner());
        }

        // Ensure the nonce has not been used
        if (usedNonces[recoveredAddress][nonce]) {
            // Throw an error if the nonce has already been used
            revert AuthIbetWSTErrors.AuthorizationNonceAlreadyUsed(
                recoveredAddress,
                nonce
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[recoveredAddress][nonce] = true;
        emit AuthorizationUsed(recoveredAddress, nonce);

        // Delete from whitelist
        delete accountWhiteList[STAccountAddress];
        // Emit event
        emit AccountWhiteListDeleted(STAccountAddress);

        return true;
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
        if (recoveredAddress != from || recoveredAddress == address(0)) {
            // Throw an error if the signature does not match the sender's address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(from);
        }
        // Mark the nonce as used and emit an event
        usedNonces[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        // Check if the sender is whitelisted
        if (accountWhiteList[from].listed == false) {
            revert AuthIbetWSTErrors.AccountNotWhitelisted(from);
        }
        // Check if the recipient is whitelisted
        if (accountWhiteList[to].listed == false) {
            revert AuthIbetWSTErrors.AccountNotWhitelisted(to);
        }
        // Execute the ERC-20 transfer (updates balance and emits Transfer event internally)
        _transfer(from, to, value);
    }

    // [FUNCTION]
    /// @notice Transfer tokens with authorization
    /// @dev Can be called by anyone
    /// @param from The address of the sender
    /// @param to The address of the recipient
    /// @param value The value of tokens to transfer
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

    // [FUNCTION]
    /// @notice Receive tokens with authorization
    /// @dev Only the recipient can call this function
    /// @param from The address of the sender
    /// @param to The address of the recipient
    /// @param value The value of tokens to receive
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

    // [FUNCTION]
    /// @notice Request a trade with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - The seller's ST account is the authorizer
    ///   - The seller's ST account must be whitelisted
    ///   - The buyer's ST account must be whitelisted
    /// @param sellerSTAccountAddress The address of the seller's ST account (authorizer)
    /// @param buyerSTAccountAddress The address of the buyer's ST account
    /// @param SCTokenAddress The address of the SC contract to be traded
    /// @param STValue The value of ST to be traded
    /// @param SCValue The value of SC to be traded
    /// @param memo Optional memo for the trade request
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function requestTradeWithAuthorization(
        address sellerSTAccountAddress,
        address buyerSTAccountAddress,
        address SCTokenAddress,
        uint256 STValue,
        uint256 SCValue,
        string memory memo,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Check if the sellerSTAccountAddress is whitelisted
        if (accountWhiteList[sellerSTAccountAddress].listed == false) {
            revert AuthIbetWSTErrors.AccountNotWhitelisted(
                sellerSTAccountAddress
            );
        }
        // Check if the buyerSTAccountAddress is whitelisted
        if (accountWhiteList[buyerSTAccountAddress].listed == false) {
            revert AuthIbetWSTErrors.AccountNotWhitelisted(
                buyerSTAccountAddress
            );
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
                STValue,
                SCValue,
                memo,
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
            recoveredAddress != sellerSTAccountAddress ||
            recoveredAddress == address(0)
        ) {
            // Throw an error if the signature does not match the seller's ST account address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(
                sellerSTAccountAddress
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[sellerSTAccountAddress][nonce] = true;
        emit AuthorizationUsed(sellerSTAccountAddress, nonce);

        // Retrieve the SC account addresses from the whitelist
        address sellerSCAccountAddress = accountWhiteList[
            sellerSTAccountAddress
        ].SCAccountAddressIn;
        address buyerSCAccountAddress = accountWhiteList[buyerSTAccountAddress]
            .SCAccountAddressOut;
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
    /// @notice Cancel a trade request with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - The seller's ST account of the trade request is the authorizer
    ///   - The trade request must be in the Pending state
    /// @param index The index of the trade request to accept
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function cancelTradeWithAuthorization(
        uint256 index,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Check if the trade request is acceptable
        if (_trades[index].state != State.Pending) {
            revert AuthIbetWSTErrors.TradeRequestIsNotAcceptable(index);
        }
        // Get the seller's security token account address from the trade request
        address sellerSTAccountAddress = _trades[index].sellerSTAccountAddress;

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
            abi.encode(CANCEL_TRADE_WITH_AUTHORIZATION_TYPEHASH, index, nonce)
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (
            recoveredAddress != sellerSTAccountAddress ||
            recoveredAddress == address(0)
        ) {
            // Throw an error if the signature does not match the seller's ST account address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(
                sellerSTAccountAddress
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[sellerSTAccountAddress][nonce] = true;
        emit AuthorizationUsed(sellerSTAccountAddress, nonce);

        // Update the state of the trade request to Cancelled
        _trades[index].state = State.Cancelled;

        // Emit the TradeAccepted event
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
    /// @notice Accept a trade request with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - The buyer's ST account of the trade request is the authorizer
    ///   - The trade request must be in the Pending state
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
            revert AuthIbetWSTErrors.TradeRequestIsNotAcceptable(index);
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
            recoveredAddress != buyerSTAccountAddress ||
            recoveredAddress == address(0)
        ) {
            // Throw an error if the signature does not match the buyer's ST account address
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

    // [FUNCTION]
    /// @notice Reject a trade request with authorization
    /// @dev
    ///   - Can be called by anyone
    ///   - The buyer's ST account of the trade request is the authorizer
    ///   - The trade request must be in the Pending state
    /// @param index The index of the trade request to reject
    /// @param nonce The authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function rejectTradeWithAuthorization(
        uint256 index,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        // Check if the trade request is acceptable
        if (_trades[index].state != State.Pending) {
            revert AuthIbetWSTErrors.TradeRequestIsNotAcceptable(index);
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
            abi.encode(REJECT_TRADE_WITH_AUTHORIZATION_TYPEHASH, index, nonce)
        );
        // Calculate the signature digest (0x1901 + DomainSeparator + structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        // Verify the signature
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (
            recoveredAddress != buyerSTAccountAddress ||
            recoveredAddress == address(0)
        ) {
            // Throw an error if the signature does not match the buyer's ST account address
            revert AuthIbetWSTErrors.InvalidAuthorizationSignature(
                buyerSTAccountAddress
            );
        }
        // Mark the nonce as used and emit an event
        usedNonces[buyerSTAccountAddress][nonce] = true;
        emit AuthorizationUsed(buyerSTAccountAddress, nonce);

        // Update the state of the trade request to Rejected
        _trades[index].state = State.Rejected;

        // Emit the TradeRejected event
        emit TradeRejected(
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
