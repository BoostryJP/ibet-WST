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

from types import SimpleNamespace
from typing import Any, cast

from ape import accounts as ape_accounts, networks
from ape.pytest.contextmanagers import RevertsContextManager
from eth_utils.address import to_checksum_address
from eth_utils.conversions import to_hex

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
_FUNDED_SENDERS: set[str] = set()


def _custom_error_type(contract_container, error_name: str):
    matching_errors = [
        abi for abi in contract_container.contract_type.errors if abi.name == error_name
    ]

    if len(matching_errors) == 1:
        return getattr(contract_container, error_name)

    error_abi = matching_errors[0]
    return contract_container._create_custom_error_type(error_abi)


def reverts(
    expected: Any = None,
    error_name: str | None = None,
    **error_inputs,
):
    """
    Context manager for asserting that a transaction reverts with a specific error.

    Parameters:
    - expected: The expected error message or pattern. This can be a string or a regular expression pattern.
    - error_name: The name of the custom error to check for. If provided, this will be used to construct the expected error message.
    - error_inputs: Additional inputs for custom errors, if applicable.

    Returns:
    - A context manager that can be used with a `with` statement to assert that a transaction reverts with the specified error.
    """
    if error_name is not None:
        expected_message = _custom_error_type(expected, error_name)
    else:
        expected_message = expected

    return RevertsContextManager(expected_message=expected_message, **error_inputs)


def sign_hash(digest: bytes, private_key: bytes):
    """
    Sign a hash with the given private key.
    """

    provider = cast(Any, getattr(networks, "provider"))
    signed = provider.web3.eth.account._sign_hash(digest, private_key)
    return SimpleNamespace(
        v=signed.v,
        r=signed.r.to_bytes(32, "big"),
        s=signed.s.to_bytes(32, "big"),
        signature=signed.signature,
        message_hash=signed.message_hash,
    )


def recover_hash(*args, **kwargs):
    """
    Recover the address that signed a given hash.
    """

    provider = cast(Any, getattr(networks, "provider"))
    return provider.web3.eth.account._recover_hash(*args, **kwargs)


def chain_id() -> int:
    """
    Get the current chain ID from the provider.
    """

    provider = cast(Any, getattr(networks, "provider"))
    return provider.chain_id


def tx_sender(sender):
    """
    Get the transaction sender address, and fund it if necessary.

    Note:
    - This function is intended to be used in tests where the sender may not be a funded account.
    - The sender can be any address, and if it is not already funded, it will be funded with 1 ether from the first test account.
    """

    if not isinstance(sender, str):
        raise TypeError("tx_sender() expects a raw address string")

    test_accounts = cast(Any, getattr(ape_accounts, "test_accounts"))

    sender_address = to_checksum_address(sender)
    normalized = sender_address.lower()
    if normalized not in _FUNDED_SENDERS:
        test_accounts[0].transfer(sender_address, 10**18)
        _FUNDED_SENDERS.add(normalized)

    return sender_address


def normalize_abi_value(canonical_type, value):
    """
    Normalize ABI value based on its canonical type.
    """

    if canonical_type == "address":
        return to_checksum_address(value)

    if canonical_type == "bool":
        return bool(value)

    if canonical_type == "bytes32":
        return to_hex(value)

    return value


def event_args(tx, event):
    """
    Extract event arguments from a transaction receipt for a specific event.
    """

    logs = tx.events.filter(event)
    assert logs

    normalized_args = dict(logs[-1].event_arguments)
    for abi_input in event.abi.inputs:
        if abi_input.name not in normalized_args:
            continue

        normalized_args[abi_input.name] = normalize_abi_value(
            abi_input.canonical_type,
            normalized_args[abi_input.name],
        )

    return normalized_args
