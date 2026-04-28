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

contract IbetERC20 is ERC20, Ownable {
    constructor(
        string memory name,
        address initialOwner
    ) ERC20(name, "IWST") Ownable(initialOwner) {}

    // [EVENT]
    /// @notice Emitted when tokens are minted
    event Mint(address indexed to, uint256 value);

    // [EVENT]
    /// @notice Emitted when tokens are burned
    event Burn(address indexed from, uint256 value);

    // [FUNCTION]
    /// @notice Mint tokens to a specified address
    /// @param to The address to mint tokens to
    /// @param value The value of tokens to mint
    function mint(address to, uint256 value) external onlyOwner {
        _mint(to, value);
        emit Mint(to, value);
    }

    // [FUNCTION]
    /// @notice Burn tokens from the caller's account
    /// @param value The value of tokens to burn
    function burn(uint256 value) external {
        _burn(_msgSender(), value);
        emit Burn(_msgSender(), value);
    }

    // [FUNCTION]
    /// @notice Burn tokens from a specified account
    /// @param account The address from which to burn tokens
    /// @param value The value of tokens to burn
    function burnFrom(address account, uint256 value) external {
        _spendAllowance(account, _msgSender(), value);
        _burn(account, value);
        emit Burn(account, value);
    }

    // [FUNCTION]
    /// @notice Force burn tokens from a specified account (only callable by the owner)
    /// @param account The address from which to burn tokens
    /// @param value The value of tokens to burn
    function forceBurnFrom(address account, uint256 value) external onlyOwner {
        _burn(account, value);
        emit Burn(account, value);
    }
}
