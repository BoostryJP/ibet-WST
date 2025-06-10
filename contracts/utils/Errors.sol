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

/// @title Errors for ibetWST
interface IbetWSTErrors {
    /// @dev Error thrown when an account is not registered in the whitelist
    error AccountNotWhitelisted(address accountAddress);

    /// @dev Error thrown when the trade status is not Acceptable
    error TradeRequestIsNotAcceptable(uint256 index);

    /// @dev Error thrown when the caller does not have permission to accept the trade
    error TradeRequestNotAcceptableByCaller(uint256 index, address caller);
}

interface AuthIbetWSTErrors {
    /// @dev トランザクションが有効期間内ではない場合にスローされるエラー
    error TransactionNotInValidPeriod(uint256 validAfter, uint256 validBefore);

    /// @dev 認可ナンスが既に使用されている場合にスローされるエラー
    error AuthorizationNonceAlreadyUsed(address from, bytes32 nonce);

    /// @dev 認可の署名が無効な場合にスローされるエラー
    error InvalidAuthorizationSignature(address authorizer);

    /// @dev 受取移転トランザクションの送信者が受取人ではない場合にスローされるエラー
    error ReceiveTransactionSenderNotRecipient(address sender, address to);
}
