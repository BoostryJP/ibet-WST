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

import {AuthIbetWSTErrors} from "../utils/Errors.sol";
import {IbetWST} from "./IbetWST.sol";

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
    /// @notice Internal process for token transfer with signature
    /// @dev This function verifies and executes a signed transaction
    /// @param typeHash EIP-712 type hash
    /// @param from Sender address
    /// @param to Recipient address
    /// @param value Transfer amount
    /// @param validAfter Minimum timestamp when the transaction becomes valid
    /// @param validBefore Maximum timestamp when the transaction becomes invalid
    /// @param nonce Authorization nonce for the transaction
    /// @param v v value of the signature
    /// @param r r value of the signature
    /// @param s s value of the signature
    function _transferWithAuth(
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
        _transferWithAuth(
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
        _transferWithAuth(
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
}
