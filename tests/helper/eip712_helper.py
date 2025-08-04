"""
Copyright BOOSTRY Co., Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
"""

import secrets

from coincurve import PublicKey
from eth_abi import encode
from eth_abi.packed import encode_packed
from eth_utils import keccak, to_checksum_address


def generate_account():
    """
    Generate a new Ethereum account with a private key and address.
    :return: Tuple of (private_key, address)
    """
    private_key = secrets.token_bytes(32)
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = to_checksum_address(keccak(public_key)[-20:])
    return private_key, addr


def generate_domain_separator(
    name: str, version: str, chain_id: int, verifying_contract: str
) -> bytes:
    """
    Generate the EIP-712 DOMAIN_SEPARATOR for a contract.

    :param name: Name of the contract
    :param version: Version of the contract
    :param chain_id: Chain ID where the contract is deployed
    :param verifying_contract: Address of the contract
    :return: EIP-712 DOMAIN_SEPARATOR
    """

    domain_separator = keccak(
        encode(
            [
                "bytes32",  # EIP712Domain type
                "bytes32",  # name type
                "bytes32",  # version type
                "uint256",  # chainId type
                "address",  # verifyingContract type
            ],
            [
                keccak(
                    text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak(name.encode()),
                keccak(version.encode()),
                chain_id,
                to_checksum_address(verifying_contract),
            ],
        )
    )
    return domain_separator


def generate_mint_digest(
    domain_separator: bytes,
    to_address: str,
    value: int,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for minting tokens with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param to_address: Address to mint tokens to
    :param value: Value of tokens to mint
    :param nonce: Nonce for the operation, used to prevent replay attacks
    :return: EIP-712 digest for the mint operation
    """

    type_hash = keccak(
        text="MintWithAuthorization(address to,uint256 value,bytes32 nonce)"
    )

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "address",  # to
                "uint256",  # value
                "bytes32",  # nonce
            ],
            [
                type_hash,
                to_checksum_address(to_address),
                value,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_burn_digest(
    domain_separator: bytes,
    from_address: str,
    value: int,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for burning tokens with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param from_address: Address to burn tokens from
    :param value: Value of tokens to burn
    :param nonce: Nonce for the operation, used to prevent replay attacks
    :return: EIP-712 digest for the burn operation
    """

    type_hash = keccak(
        text="BurnWithAuthorization(address from,uint256 value,bytes32 nonce)"
    )

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "address",  # from
                "uint256",  # value
                "bytes32",  # nonce
            ],
            [
                type_hash,
                to_checksum_address(from_address),
                value,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_add_account_whitelist_digest(
    domain_separator: bytes,
    st_account_address: str,
    sc_account_address: str,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for adding an account to the whitelist.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param st_account_address: Address of the ST account to add to the whitelist
    :param sc_account_address: Address of the SC account to add to the whitelist
    :param nonce: Nonce for the operation, used to prevent replay attacks
    :return: EIP-712 digest for the add whitelist operation
    """

    type_hash = keccak(
        text="AddAccountWhiteListWithAuthorization(address STAccountAddress,address SCAccountAddress,bytes32 nonce)"
    )

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "address",  # STAccountAddress
                "address",  # SCAccountAddress
                "bytes32",  # nonce
            ],
            [
                type_hash,
                to_checksum_address(st_account_address),
                to_checksum_address(sc_account_address),
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_delete_account_whitelist_digest(
    domain_separator: bytes,
    st_account_address: str,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for deleting an account from the whitelist.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param st_account_address: Address of the ST account to delete from the whitelist
    :param nonce: Nonce for the operation, used to prevent replay attacks
    :return: EIP-712 digest for the delete whitelist operation
    """

    type_hash = keccak(
        text="DeleteAccountWhiteListWithAuthorization(address STAccountAddress,bytes32 nonce)"
    )

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "address",  # STAccountAddress
                "bytes32",  # nonce
            ],
            [
                type_hash,
                to_checksum_address(st_account_address),
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_transfer_digest(
    domain_separator: bytes,
    _from: str,
    _to: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for transfer with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param _from: from address
    :param _to: to address
    :param value: value to transfer
    :param valid_after: block timestamp after which the transfer is valid
    :param valid_before: block timestamp before which the transfer is valid
    :param nonce: nonce for the transfer, used to prevent replay attacks
    :return: EIP-712 digest for the transfer
    """

    type_hash = keccak(
        text="TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    )

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "address",  # from
                "address",  # to
                "uint256",  # value
                "uint256",  # validAfter
                "uint256",  # validBefore
                "bytes32",  # nonce
            ],
            [
                type_hash,
                to_checksum_address(_from),
                to_checksum_address(_to),
                value,
                valid_after,
                valid_before,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_receive_digest(
    domain_separator: bytes,
    _from: str,
    _to: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for receive with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param _from: from address
    :param _to: to address
    :param value: value to transfer
    :param valid_after: block timestamp after which the transfer is valid
    :param valid_before: block timestamp before which the transfer is valid
    :param nonce: nonce for the transfer, used to prevent replay attacks
    :return: EIP-712 digest for the transfer
    """

    type_hash = keccak(
        text="ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    )

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "address",  # from
                "address",  # to
                "uint256",  # value
                "uint256",  # validAfter
                "uint256",  # validBefore
                "bytes32",  # nonce
            ],
            [
                type_hash,
                to_checksum_address(_from),
                to_checksum_address(_to),
                value,
                valid_after,
                valid_before,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_request_trade_digest(
    domain_separator: bytes,
    seller_st_account_address: str,
    buyer_st_account_address: str,
    sc_token_address: str,
    st_value: int,
    sc_value: int,
    memo: str,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for request trade with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param seller_st_account_address: Seller's ST account address
    :param buyer_st_account_address: Buyer's ST account address
    :param sc_token_address: SC contract address
    :param st_value: Value of ST to trade
    :param sc_value: Value of SC to trade
    :param memo: Optional memo for the trade request
    :param nonce: Nonce for the trade, used to prevent replay attacks
    :return: EIP-712 digest for the trade request
    """

    type_hash = keccak(
        text="RequestTradeWithAuthorization(address sellerSTAccountAddress,address buyerSTAccountAddress,address SCTokenAddress,uint256 STValue,uint256 SCValue,string memory memo,bytes32 nonce)"
    )

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "address",  # sellerSTAccountAddress
                "address",  # buyerSTAccountAddress
                "address",  # SCTokenAddress
                "uint256",  # STValue
                "uint256",  # SCValue
                "string",  # memo
                "bytes32",  # nonce
            ],
            [
                type_hash,
                to_checksum_address(seller_st_account_address),
                to_checksum_address(buyer_st_account_address),
                to_checksum_address(sc_token_address),
                st_value,
                sc_value,
                memo,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_cancel_trade_digest(
    domain_separator: bytes,
    index: int,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for cancel trade with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param index: Index of the trade to cancel
    :param nonce: Nonce for the trade, used to prevent replay attacks
    :return: EIP-712 digest for the trade cancellation
    """

    type_hash = keccak(text="CancelTradeWithAuthorization(uint256 index,bytes32 nonce)")

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "uint256",  # index
                "bytes32",  # nonce
            ],
            [
                type_hash,
                index,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_accept_trade_digest(
    domain_separator: bytes,
    index: int,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for accept trade with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param index: Index of the trade to accept
    :param nonce: Nonce for the trade, used to prevent replay attacks
    :return: EIP-712 digest for the trade acceptance
    """

    type_hash = keccak(text="AcceptTradeWithAuthorization(uint256 index,bytes32 nonce)")

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "uint256",  # index
                "bytes32",  # nonce
            ],
            [
                type_hash,
                index,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest


def generate_reject_trade_digest(
    domain_separator: bytes,
    index: int,
    nonce: bytes,
) -> bytes:
    """
    Generate the EIP-712 digest for reject trade with authorization.

    :param domain_separator: EIP-712 DOMAIN_SEPARATOR
    :param index: Index of the trade to reject
    :param nonce: Nonce for the trade, used to prevent replay attacks
    :return: EIP-712 digest for the trade rejection
    """

    type_hash = keccak(text="RejectTradeWithAuthorization(uint256 index,bytes32 nonce)")

    struct_hash = keccak(
        encode(
            [
                "bytes32",  # typeHash
                "uint256",  # index
                "bytes32",  # nonce
            ],
            [
                type_hash,
                index,
                nonce,
            ],
        )
    )
    digest = keccak(
        encode_packed(
            [
                "bytes2",  # EIP-712 prefix
                "bytes32",  # domainSeparator
                "bytes32",  # structHash
            ],
            [
                "\x19\x01".encode(),
                domain_separator,
                struct_hash,
            ],
        )
    )
    return digest
