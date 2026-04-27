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
pragma solidity ^0.8.34;

import "OpenZeppelin/openzeppelin-contracts@5.3.0/contracts/token/ERC20/ERC20.sol";
import "OpenZeppelin/openzeppelin-contracts@5.3.0/contracts/access/Ownable.sol";

contract MockERC20 is ERC20, Ownable {
    constructor(
        string memory name,
        address initialOwner
    ) ERC20(name, "") Ownable(initialOwner) {}

    // [EVENT]
    /// @notice Emitted when tokens are minted
    event Mint(address indexed to, uint256 value);

    // [FUNCTION]
    /// @notice Mints tokens to the specified address
    /// @param to Address to receive the minted tokens
    /// @param value Amount of tokens to mint
    function mint(address to, uint256 value) external onlyOwner {
        _mint(to, value);
        emit Mint(to, value);
    }

    // [FUNCTION]
    /// @notice Transfers tokens (for testing purposes)
    /// @dev
    ///   - Overrides the ERC20 transfer function
    ///   - Fake function that simply returns true without any implementation
    /// @param to Address of the recipient
    /// @param value Amount of tokens to transfer
    function transfer(
        address to,
        uint256 value
    ) public override returns (bool) {
        return true;
    }

    // [FUNCTION]
    /// @notice Transfers tokens on behalf of another address
    /// @dev
    ///   - Overrides the ERC20 transferFrom function
    ///   - Fake function that simply returns true without any implementation
    /// @param from Address of the sender
    /// @param to Address of the recipient
    /// @param value Amount of tokens to transfer
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public override returns (bool) {
        return true;
    }
}
