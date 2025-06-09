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

import brownie


class TestDeploy:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "IbetERC20"
        assert token.symbol() == ""
        assert token.decimals() == 18
        assert token.totalSupply() == 0
        assert token.balanceOf(issuer.address) == 0


class TestAddAccountWhiteList:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the owner can add an account to the whitelist
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # add account to whitelist
        tx = token.addAccountWhiteList(user_1.address, {"from": issuer})

        # assertion
        assert token.accountWhiteList(user_1.address) is True

        assert tx.events["AccountWhiteListAdded"]["accountAddress"] == user_1.address

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that a non-owner cannot add an account to the whitelist
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # add account to whitelist by non-owner
        with brownie.reverts(f"OwnableUnauthorizedAccount: {user_1.address.lower()}"):
            token.addAccountWhiteList(user_1.address, {"from": user_1})


class TestDeleteAccountWhiteList:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the owner can add an account to the whitelist
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # add account to whitelist
        token.addAccountWhiteList(user_1.address, {"from": issuer})

        # delete account from whitelist
        tx = token.deleteAccountWhiteList(user_1.address, {"from": issuer})

        # assertion
        assert token.accountWhiteList(user_1.address) is False

        assert tx.events["AccountWhiteListDeleted"]["accountAddress"] == user_1.address

    # Normal_2
    # - Check that the owner can delete an account from the whitelist
    # - Account is not in the whitelist
    def test_normal_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # initially, account is not in the whitelist
        assert token.accountWhiteList(user_1.address) is False

        # delete account from whitelist
        # (should not raise an error even if the account is not in the whitelist)
        tx = token.deleteAccountWhiteList(user_1.address, {"from": issuer})

        # assertion
        assert token.accountWhiteList(user_1.address) is False

        assert tx.events["AccountWhiteListDeleted"]["accountAddress"] == user_1.address

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that a non-owner cannot add an account to the whitelist
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # add account to whitelist
        token.addAccountWhiteList(user_1.address, {"from": issuer})

        # add account to whitelist by non-owner
        with brownie.reverts(f"OwnableUnauthorizedAccount: {user_1.address.lower()}"):
            token.deleteAccountWhiteList(user_1.address, {"from": user_1})


class TestTransfer:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the transfer is successful when both accounts are in the whitelist
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})
        token.addAccountWhiteList(transfer_to.address, {"from": issuer})

        # transfer
        tx = token.transfer(transfer_to.address, 50, {"from": transfer_from})

        # assertion
        assert token.balanceOf(transfer_from.address) == 50
        assert token.balanceOf(transfer_to.address) == 50

        assert tx.events["Transfer"]["from"] == transfer_from.address
        assert tx.events["Transfer"]["to"] == transfer_to.address
        assert tx.events["Transfer"]["value"] == 50

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the transfer fails when the sender is not in the whitelist
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # transfer
        with brownie.reverts(
            revert_msg=f"AccountNotWhitelisted: {transfer_from.address.lower()}"
        ):
            token.transfer(transfer_to.address, 50, {"from": transfer_from})

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to.address) == 0

    # Error_2
    # - Check that the transfer fails when the recipient is not in the whitelist
    def test_error_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # add transfer_from to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})

        # transfer
        with brownie.reverts(
            revert_msg=f"AccountNotWhitelisted: {transfer_to.address.lower()}"
        ):
            token.transfer(transfer_to.address, 50, {"from": transfer_from})

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to.address) == 0

    # Error_3
    # - Check that the transfer fails when the sender does not have enough balance
    def test_error_3(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})
        token.addAccountWhiteList(transfer_to.address, {"from": issuer})

        # transfer
        with brownie.reverts(
            revert_msg=f"ERC20InsufficientBalance: {transfer_from.address.lower()}, 100, 101"
        ):
            token.transfer(transfer_to.address, 101, {"from": transfer_from})

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to.address) == 0

    # Error_4
    # - Check that the transfer fails when the recipient is the zero address
    def test_error_4(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = brownie.ZERO_ADDRESS

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})
        token.addAccountWhiteList(transfer_to, {"from": issuer})

        # transfer
        with brownie.reverts(revert_msg=f"ERC20InvalidReceiver: {transfer_to}"):
            token.transfer(transfer_to, 50, {"from": transfer_from})

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to) == 0


class TestTransferFrom:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the transfer is successful when both accounts are in the whitelist
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})
        token.addAccountWhiteList(transfer_to.address, {"from": issuer})

        # approve transfer
        token.approve(transfer_to.address, 50, {"from": transfer_from})

        # transferFrom
        tx = token.transferFrom(
            transfer_from.address, transfer_to.address, 50, {"from": transfer_to}
        )

        # assertion
        assert token.balanceOf(transfer_from.address) == 50
        assert token.balanceOf(transfer_to.address) == 50

        assert tx.events["Transfer"]["from"] == transfer_from.address
        assert tx.events["Transfer"]["to"] == transfer_to.address
        assert tx.events["Transfer"]["value"] == 50

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the transfer fails when the sender is not in the whitelist
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # approve transfer
        token.approve(transfer_to.address, 50, {"from": transfer_from})

        # transferFrom
        with brownie.reverts(
            revert_msg=f"AccountNotWhitelisted: {transfer_from.address.lower()}"
        ):
            token.transferFrom(
                transfer_from.address, transfer_to.address, 50, {"from": transfer_to}
            )

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to.address) == 0

    # Error_2
    # - Check that the transfer fails when the recipient is not in the whitelist
    def test_error_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # approve transfer
        token.approve(transfer_to.address, 50, {"from": transfer_from})

        # add transfer_from to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})

        # transferFrom
        with brownie.reverts(
            revert_msg=f"AccountNotWhitelisted: {transfer_to.address.lower()}"
        ):
            token.transferFrom(
                transfer_from.address, transfer_to.address, 50, {"from": transfer_to}
            )

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to.address) == 0

    # Error_3
    # - Check that the transfer fails when the sender does not have enough allowance
    def test_error_3(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = users["eoa4"]

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # approve transfer
        token.approve(transfer_to.address, 50, {"from": transfer_from})

        # add accounts to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})
        token.addAccountWhiteList(transfer_to.address, {"from": issuer})

        # transfer
        with brownie.reverts(
            revert_msg=f"ERC20InsufficientAllowance: {transfer_to.address.lower()}, 50, 51"
        ):
            token.transferFrom(
                transfer_from.address, transfer_to.address, 51, {"from": transfer_to}
            )

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to.address) == 0

    # Error_4
    # - Check that the transfer fails when the recipient is the zero address
    def test_error_4(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = brownie.ZERO_ADDRESS

        # deploy
        token = admin.deploy(IbetWST, issuer.address)

        # mint
        token.mint(transfer_from.address, 100, {"from": issuer})

        # approve transfer
        token.approve(issuer.address, 50, {"from": transfer_from})

        # add accounts to whitelist
        token.addAccountWhiteList(transfer_from.address, {"from": issuer})
        token.addAccountWhiteList(transfer_to, {"from": issuer})

        # transferFrom
        with brownie.reverts(revert_msg=f"ERC20InvalidReceiver: {transfer_to}"):
            token.transferFrom(transfer_from.address, transfer_to, 50, {"from": issuer})

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to) == 0
