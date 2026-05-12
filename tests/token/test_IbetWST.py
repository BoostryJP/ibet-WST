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

from tests.helper.ape_utils import ZERO_ADDRESS, event_args, reverts


class TestDeploy:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "IbetWST"
        assert token.symbol() == "IWST"
        assert token.decimals() == 0
        assert token.totalSupply() == 0
        assert token.balanceOf(issuer.address) == 0


class TestSetAccountManager:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the owner can enable and disable an account manager
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        account_manager = users["eoa3"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # enable account manager
        tx_enable = token.setAccountManager(
            account_manager.address,
            True,
            sender=issuer,
        )

        # disable account manager
        tx_disable = token.setAccountManager(
            account_manager.address,
            False,
            sender=issuer,
        )

        # assertion
        assert event_args(tx_enable, token.AccountManagerUpdated)["accountManager"] == (
            account_manager.address
        )
        assert event_args(tx_enable, token.AccountManagerUpdated)["enabled"] is True
        assert event_args(tx_disable, token.AccountManagerUpdated)[
            "accountManager"
        ] == (account_manager.address)
        assert event_args(tx_disable, token.AccountManagerUpdated)["enabled"] is False
        assert token.accountManagers(account_manager.address) is False

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that a non-owner cannot update an account manager
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        account_manager = users["eoa3"]
        other = users["eoa4"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # update account manager by non-owner
        with reverts(token, "OwnableUnauthorizedAccount", account=other.address):
            token.setAccountManager(
                account_manager.address,
                True,
                sender=other,
            )


class TestAddAccountWhiteList:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the owner can add an account to the whitelist
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1_st = users["eoa3"]
        user_1_sc_in = users["eoa4"]
        user_1_sc_out = users["eoa5"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add account to whitelist
        tx = token.addAccountWhiteList(
            user_1_st.address,
            user_1_sc_in.address,
            user_1_sc_out.address,
            sender=issuer,
        )

        # assertion
        assert token.accountWhiteList(user_1_st.address) == (
            user_1_st.address,
            user_1_sc_in.address,
            user_1_sc_out.address,
            True,
        )

        assert (
            event_args(tx, token.AccountWhiteListAdded)["accountAddress"]
            == user_1_st.address
        )

    # Normal_2
    # - Check that a delegated account manager can add an account to the whitelist
    def test_normal_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        account_manager = users["eoa3"]
        user_1_st = users["eoa4"]
        user_1_sc_in = users["eoa5"]
        user_1_sc_out = users["eoa6"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # delegate whitelist management
        tx_delegate = token.setAccountManager(
            account_manager.address,
            True,
            sender=issuer,
        )

        # add account to whitelist by delegated account manager
        tx_add = token.addAccountWhiteList(
            user_1_st.address,
            user_1_sc_in.address,
            user_1_sc_out.address,
            sender=account_manager,
        )

        # assertion
        assert token.accountManagers(account_manager.address) is True
        assert event_args(tx_delegate, token.AccountManagerUpdated)[
            "accountManager"
        ] == (account_manager.address)
        assert event_args(tx_delegate, token.AccountManagerUpdated)["enabled"] is True
        assert token.accountWhiteList(user_1_st.address) == (
            user_1_st.address,
            user_1_sc_in.address,
            user_1_sc_out.address,
            True,
        )
        assert event_args(tx_add, token.AccountWhiteListAdded)["accountAddress"] == (
            user_1_st.address
        )

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that a non-owner cannot add an account to the whitelist
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1_st = users["eoa3"]
        user_1_sc_in = users["eoa4"]
        user_1_sc_out = users["eoa5"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add account to whitelist by non-owner or non-delegated account manager
        with reverts(
            token.AccountWhiteListOperationNotPermitted,
            caller=user_1_st.address,
        ):
            token.addAccountWhiteList(
                user_1_st.address,
                user_1_sc_in.address,
                user_1_sc_out.address,
                sender=user_1_st,
            )


class TestDeleteAccountWhiteList:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the owner can add an account to the whitelist
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1_st = users["eoa3"]
        user_1_sc = users["eoa4"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add account to whitelist
        token.addAccountWhiteList(
            user_1_st.address,
            user_1_sc.address,
            user_1_sc.address,
            sender=issuer,
        )

        # delete account from whitelist
        tx = token.deleteAccountWhiteList(user_1_st.address, sender=issuer)

        # assertion
        assert token.accountWhiteList(user_1_st.address) == (
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            False,
        )

        assert (
            event_args(tx, token.AccountWhiteListDeleted)["accountAddress"]
            == user_1_st.address
        )

    # Normal_2
    # - Check that the owner can delete an account from the whitelist
    # - Account is not in the whitelist
    def test_normal_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1_st = users["eoa3"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # initially, account is not in the whitelist
        assert token.accountWhiteList(user_1_st.address) == (
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            False,
        )

        # delete account from whitelist
        # (should not raise an error even if the account is not in the whitelist)
        tx = token.deleteAccountWhiteList(user_1_st.address, sender=issuer)

        # assertion
        assert token.accountWhiteList(user_1_st.address) == (
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            False,
        )

        assert (
            event_args(tx, token.AccountWhiteListDeleted)["accountAddress"]
            == user_1_st.address
        )

    # Normal_3
    # - Check that a delegated account manager can delete an account from the whitelist
    def test_normal_3(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        account_manager = users["eoa3"]
        user_1_st = users["eoa4"]
        user_1_sc = users["eoa5"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # delegate whitelist management
        token.setAccountManager(account_manager.address, True, sender=issuer)

        # add account to whitelist
        token.addAccountWhiteList(
            user_1_st.address,
            user_1_sc.address,
            user_1_sc.address,
            sender=account_manager,
        )

        # delete account from whitelist by delegated account manager
        tx = token.deleteAccountWhiteList(
            user_1_st.address,
            sender=account_manager,
        )

        # assertion
        assert token.accountWhiteList(user_1_st.address) == (
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            False,
        )
        assert (
            event_args(tx, token.AccountWhiteListDeleted)["accountAddress"]
            == user_1_st.address
        )

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that a non-owner cannot add an account to the whitelist
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1_st = users["eoa3"]
        user_1_sc = users["eoa4"]

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add account to whitelist
        token.addAccountWhiteList(
            user_1_st.address,
            user_1_sc.address,
            user_1_sc.address,
            sender=issuer,
        )

        # add account to whitelist by non-owner or non-delegated account manager
        with reverts(
            token.AccountWhiteListOperationNotPermitted,
            caller=user_1_st.address,
        ):
            token.deleteAccountWhiteList(user_1_st.address, sender=user_1_st)


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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )
        token.addAccountWhiteList(
            transfer_to.address,
            transfer_to.address,
            transfer_to.address,
            sender=issuer,
        )

        # transfer
        tx = token.transfer(transfer_to.address, 50, sender=transfer_from)

        # assertion
        assert token.balanceOf(transfer_from.address) == 50
        assert token.balanceOf(transfer_to.address) == 50

        assert event_args(tx, token.Transfer)["from"] == transfer_from.address
        assert event_args(tx, token.Transfer)["to"] == transfer_to.address
        assert event_args(tx, token.Transfer)["value"] == 50

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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # transfer
        with reverts(
            token.AccountNotWhitelisted,
            accountAddress=transfer_from.address,
        ):
            token.transfer(transfer_to.address, 50, sender=transfer_from)

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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # add transfer_from to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )

        # transfer
        with reverts(
            token.AccountNotWhitelisted,
            accountAddress=transfer_to.address,
        ):
            token.transfer(transfer_to.address, 50, sender=transfer_from)

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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )
        token.addAccountWhiteList(
            transfer_to.address,
            transfer_to.address,
            transfer_to.address,
            sender=issuer,
        )

        # transfer
        with reverts(
            token.ERC20InsufficientBalance,
            sender=transfer_from.address,
            balance=100,
            needed=101,
        ):
            token.transfer(transfer_to.address, 101, sender=transfer_from)

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to.address) == 0

    # Error_4
    # - Check that the transfer fails when the recipient is the zero address
    def test_error_4(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        transfer_from = users["eoa3"]
        transfer_to = ZERO_ADDRESS

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )
        token.addAccountWhiteList(transfer_to, transfer_to, transfer_to, sender=issuer)

        # transfer
        with reverts(token, "ERC20InvalidReceiver", receiver=transfer_to):
            token.transfer(transfer_to, 50, sender=transfer_from)

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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )
        token.addAccountWhiteList(
            transfer_to.address,
            transfer_to.address,
            transfer_to.address,
            sender=issuer,
        )

        # approve transfer
        token.approve(transfer_to.address, 50, sender=transfer_from)

        # transferFrom
        tx = token.transferFrom(
            transfer_from.address,
            transfer_to.address,
            50,
            sender=transfer_to,
        )

        # assertion
        assert token.balanceOf(transfer_from.address) == 50
        assert token.balanceOf(transfer_to.address) == 50

        assert event_args(tx, token.Transfer)["from"] == transfer_from.address
        assert event_args(tx, token.Transfer)["to"] == transfer_to.address
        assert event_args(tx, token.Transfer)["value"] == 50

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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # approve transfer
        token.approve(transfer_to.address, 50, sender=transfer_from)

        # transferFrom
        with reverts(
            token.AccountNotWhitelisted,
            accountAddress=transfer_from.address,
        ):
            token.transferFrom(
                transfer_from.address,
                transfer_to.address,
                50,
                sender=transfer_to,
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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # approve transfer
        token.approve(transfer_to.address, 50, sender=transfer_from)

        # add transfer_from to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )

        # transferFrom
        with reverts(
            token.AccountNotWhitelisted,
            accountAddress=transfer_to.address,
        ):
            token.transferFrom(
                transfer_from.address,
                transfer_to.address,
                50,
                sender=transfer_to,
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
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # approve transfer
        token.approve(transfer_to.address, 50, sender=transfer_from)

        # add accounts to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )
        token.addAccountWhiteList(
            transfer_to.address,
            transfer_to.address,
            transfer_to.address,
            sender=issuer,
        )

        # transfer
        with reverts(
            token.ERC20InsufficientAllowance,
            spender=transfer_to.address,
            allowance=50,
            needed=51,
        ):
            token.transferFrom(
                transfer_from.address,
                transfer_to.address,
                51,
                sender=transfer_to,
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
        transfer_to = ZERO_ADDRESS

        # deploy
        token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # mint
        token.mint(transfer_from.address, 100, sender=issuer)

        # approve transfer
        token.approve(issuer.address, 50, sender=transfer_from)

        # add accounts to whitelist
        token.addAccountWhiteList(
            transfer_from.address,
            transfer_from.address,
            transfer_from.address,
            sender=issuer,
        )
        token.addAccountWhiteList(transfer_to, transfer_to, transfer_to, sender=issuer)

        # transferFrom
        with reverts(token, "ERC20InvalidReceiver", receiver=transfer_to):
            token.transferFrom(transfer_from.address, transfer_to, 50, sender=issuer)

        # assertion
        assert token.balanceOf(transfer_from.address) == 100
        assert token.balanceOf(transfer_to) == 0


class TestRequestTrade:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the requestTrade is successful when both accounts are in the whitelist
    def test_normal_1(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc_in = users["eoa4"]
        seller_sc_out = users["eoa5"]
        buyer_st = users["eoa6"]
        buyer_sc_in = users["eoa7"]
        buyer_sc_out = users["eoa8"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc_in.address,
            seller_sc_out.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc_in.address,
            buyer_sc_out.address,
            sender=issuer,
        )

        # requestTrade
        tx = st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # assertion
        assert st_token.getNbTrades() == 1

        assert st_token.getTrade(1) == (
            seller_st.address,
            buyer_st.address,
            sc_token.address,
            seller_sc_in.address,
            buyer_sc_out.address,
            100,
            200,
            0,  # status (Pending)
            "trade_memo",
        )

        assert event_args(tx, st_token.TradeRequested)["index"] == 1
        assert (
            event_args(tx, st_token.TradeRequested)["sellerSTAccountAddress"]
            == seller_st.address
        )
        assert (
            event_args(tx, st_token.TradeRequested)["buyerSTAccountAddress"]
            == buyer_st.address
        )
        assert (
            event_args(tx, st_token.TradeRequested)["SCTokenAddress"]
            == sc_token.address
        )
        assert (
            event_args(tx, st_token.TradeRequested)["sellerSCAccountAddress"]
            == seller_sc_in.address
        )
        assert (
            event_args(tx, st_token.TradeRequested)["buyerSCAccountAddress"]
            == buyer_sc_out.address
        )
        assert event_args(tx, st_token.TradeRequested)["STValue"] == 100
        assert event_args(tx, st_token.TradeRequested)["SCValue"] == 200

    # Normal_2
    # - Check that the requestTrade is successful when the same seller requests multiple trades
    def test_normal_2(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # requestTrade 1st time
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # requestTrade 2nd time with different values
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            200,  # ST value
            300,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # assertion
        assert st_token.getNbTrades() == 2

        assert st_token.getTrade(1) == (
            seller_st.address,
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,
            200,
            0,  # status (Pending)
            "trade_memo",
        )

        assert st_token.getTrade(2) == (
            seller_st.address,
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            200,
            300,
            0,  # status (Pending)
            "trade_memo",
        )

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the requestTrade fails when the seller is not in the whitelist
    def test_error_1(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        buyer_st = users["eoa4"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # requestTrade
        with reverts(
            st_token.AccountNotWhitelisted,
            accountAddress=seller_st.address,
        ):
            st_token.requestTrade(
                buyer_st.address,
                sc_token.address,
                100,  # ST value
                200,  # SC value
                "trade_memo",
                sender=seller_st,
            )

        # assertion
        assert st_token.getNbTrades() == 0

    # Error_2
    # - Check that the requestTrade fails when the buyer is not in the whitelist
    def test_error_2(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST account to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )

        # requestTrade
        with reverts(
            st_token.AccountNotWhitelisted,
            accountAddress=buyer_st.address,
        ):
            st_token.requestTrade(
                buyer_st.address,
                sc_token.address,
                100,  # ST value
                200,  # SC value
                "trade_memo",
                sender=seller_st,
            )

        # assertion
        assert st_token.getNbTrades() == 0


class TestCancelTrade:
    ##########################################################
    # Normal
    ##########################################################

    #  Normal_1
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # cancelTrade
        index = st_token.getNbTrades()
        tx = st_token.cancelTrade(index, sender=seller_st)

        # assertion
        assert st_token.getTrade(1)[7] == 2  # status (Cancelled)

        assert event_args(tx, st_token.TradeCancelled)["index"] == index
        assert (
            event_args(tx, st_token.TradeCancelled)["sellerSTAccountAddress"]
            == seller_st.address
        )
        assert (
            event_args(tx, st_token.TradeCancelled)["buyerSTAccountAddress"]
            == buyer_st.address
        )
        assert (
            event_args(tx, st_token.TradeCancelled)["SCTokenAddress"]
            == st_token.address
        )
        assert (
            event_args(tx, st_token.TradeCancelled)["sellerSCAccountAddress"]
            == seller_sc.address
        )
        assert (
            event_args(tx, st_token.TradeCancelled)["buyerSCAccountAddress"]
            == buyer_sc.address
        )
        assert event_args(tx, st_token.TradeCancelled)["STValue"] == 100
        assert event_args(tx, st_token.TradeCancelled)["SCValue"] == 200

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the cancelTrade fails when the trade is not in Pending status
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # cancelTrade (1st time)
        index = st_token.getNbTrades()
        st_token.cancelTrade(index, sender=seller_st)

        # cancelTrade (2nd time)
        with reverts(st_token, "TradeRequestIsNotAcceptable", index=index):
            st_token.cancelTrade(index, sender=seller_st)

    # Error_2
    # - Check that the cancelTrade fails when the caller is not the seller
    def test_error_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # cancelTrade
        index = st_token.getNbTrades()
        with reverts(
            st_token.TradeRequestNotAcceptableByCaller,
            index=index,
            caller=buyer_st.address,
        ):
            st_token.cancelTrade(index, sender=buyer_st)


class TestAcceptTrade:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the acceptTrade is successful with valid situation
    def test_normal_1(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token & mint seller balance
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st.address, 100, sender=issuer)

        # deploy SC token & mint buyer balance
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # ST: acceptTrade
        tx = st_token.acceptTrade(1, sender=buyer_st)

        # assertion
        assert st_token.getTrade(1)[7] == 1  # status (Executed)

        assert st_token.balanceOf(seller_st.address) == 0
        assert st_token.balanceOf(buyer_st.address) == 100
        assert sc_token.balanceOf(seller_sc.address) == 200
        assert sc_token.balanceOf(buyer_sc.address) == 0

        assert event_args(tx, st_token.TradeAccepted)["index"] == 1
        assert (
            event_args(tx, st_token.TradeAccepted)["sellerSTAccountAddress"]
            == seller_st.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["buyerSTAccountAddress"]
            == buyer_st.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["SCTokenAddress"] == sc_token.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["sellerSCAccountAddress"]
            == seller_sc.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["buyerSCAccountAddress"]
            == buyer_sc.address
        )
        assert event_args(tx, st_token.TradeAccepted)["STValue"] == 100
        assert event_args(tx, st_token.TradeAccepted)["SCValue"] == 200

    # Normal_2
    # - Check that the acceptTrade is successful with same seller and buyer SC accounts
    def test_normal_2(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = seller_sc  # Reusing seller_sc as buyer_sc for this test

        # deploy ST token & mint seller balance
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st.address, 100, sender=issuer)

        # deploy SC token & mint buyer balance
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # ST: acceptTrade
        tx = st_token.acceptTrade(1, sender=buyer_st)

        # assertion
        assert st_token.getTrade(1)[7] == 1  # status (Executed)

        assert st_token.balanceOf(seller_st.address) == 0
        assert st_token.balanceOf(buyer_st.address) == 100
        assert (
            sc_token.balanceOf(seller_sc.address) == 200
        )  # seller_sc is same as buyer_sc
        assert (
            sc_token.balanceOf(buyer_sc.address) == 200
        )  # buyer_sc is same as seller_sc

        assert event_args(tx, st_token.TradeAccepted)["index"] == 1
        assert (
            event_args(tx, st_token.TradeAccepted)["sellerSTAccountAddress"]
            == seller_st.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["buyerSTAccountAddress"]
            == buyer_st.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["SCTokenAddress"] == sc_token.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["sellerSCAccountAddress"]
            == seller_sc.address
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["buyerSCAccountAddress"]
            == buyer_sc.address
        )
        assert event_args(tx, st_token.TradeAccepted)["STValue"] == 100
        assert event_args(tx, st_token.TradeAccepted)["SCValue"] == 200

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the acceptTrade fails when the trade is not in Pending status
    def test_error_1(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token & mint seller balance
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st.address, 100, sender=issuer)

        # deploy SC token & mint buyer balance
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # ST: acceptTrade
        st_token.acceptTrade(1, sender=buyer_st)

        # ST: acceptTrade again
        with reverts(st_token, "TradeRequestIsNotAcceptable", index=1):
            st_token.acceptTrade(1, sender=buyer_st)

    # Error_2
    # - Check that the acceptTrade fails when the caller is not the buyer
    def test_error_2(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token & mint seller balance
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st.address, 100, sender=issuer)

        # deploy SC token & mint buyer balance
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # ST: acceptTrade
        with reverts(
            st_token.TradeRequestNotAcceptableByCaller,
            index=1,
            caller=seller_st.address,
        ):
            st_token.acceptTrade(1, sender=seller_st)

    # Error_3
    # - Check that the acceptTrade fails when the buyer does not have enough ST balance
    def test_error_3(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token & mint seller balance
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st.address, 100, sender=issuer)

        # deploy SC token & mint buyer balance
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            101,  # ST value, insufficient
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # ST: acceptTrade
        with reverts(
            st_token.ERC20InsufficientBalance,
            sender=seller_st.address,
            balance=100,
            needed=101,
        ):
            st_token.acceptTrade(1, sender=buyer_st)

    # Error_4
    # - Check that the acceptTrade fails when the ST contract does not have enough SC allowance
    def test_error_4(self, IbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token & mint seller balance
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st.address, 100, sender=issuer)

        # deploy SC token & mint buyer balance
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            201,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # SC: approve transfer
        sc_token.approve(
            st_token.address, 200, sender=buyer_sc
        )  # insufficient allowance

        # ST: acceptTrade
        with reverts(
            st_token.ERC20InsufficientAllowance,
            spender=st_token.address,
            allowance=200,
            needed=201,
        ):
            st_token.acceptTrade(1, sender=buyer_st)

    # Error_5
    # - SC token transfer did not succeed
    # - This is a case where the SC token is not a valid ERC20 token
    def test_error_5(self, IbetWST, MockERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token & mint seller balance
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st.address, 100, sender=issuer)

        # deploy SC token (Fake ERC20) & mint buyer balance
        sc_token = MockERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # ST: acceptTrade
        with reverts("SC token transfer did not succeed"):
            st_token.acceptTrade(1, sender=buyer_st)

        # assertion
        assert st_token.balanceOf(seller_st.address) == 100
        assert st_token.balanceOf(buyer_st.address) == 0


class TestRejectTrade:
    ##########################################################
    # Normal
    ##########################################################

    #  Normal_1
    def test_normal_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # rejectTrade
        index = st_token.getNbTrades()
        tx = st_token.rejectTrade(index, sender=buyer_st)

        # assertion
        assert st_token.getTrade(1)[7] == 3  # status (Rejected)

        assert event_args(tx, st_token.TradeRejected)["index"] == index
        assert (
            event_args(tx, st_token.TradeRejected)["sellerSTAccountAddress"]
            == seller_st.address
        )
        assert (
            event_args(tx, st_token.TradeRejected)["buyerSTAccountAddress"]
            == buyer_st.address
        )
        assert (
            event_args(tx, st_token.TradeRejected)["SCTokenAddress"] == st_token.address
        )
        assert (
            event_args(tx, st_token.TradeRejected)["sellerSCAccountAddress"]
            == seller_sc.address
        )
        assert (
            event_args(tx, st_token.TradeRejected)["buyerSCAccountAddress"]
            == buyer_sc.address
        )
        assert event_args(tx, st_token.TradeRejected)["STValue"] == 100
        assert event_args(tx, st_token.TradeRejected)["SCValue"] == 200

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the rejectTrade fails when the trade is not in Pending status
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # rejectTrade (1st time)
        index = st_token.getNbTrades()
        st_token.rejectTrade(index, sender=buyer_st)

        # rejectTrade (2nd time)
        with reverts(st_token, "TradeRequestIsNotAcceptable", index=index):
            st_token.rejectTrade(index, sender=buyer_st)

    # Error_2
    # - Check that the rejectTrade fails when the caller is not the buyer
    def test_error_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = IbetWST.deploy("IbetWST", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st.address,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st.address,
            buyer_sc.address,
            buyer_sc.address,
            sender=issuer,
        )

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            sender=seller_st,
        )

        # rejectTrade
        index = st_token.getNbTrades()
        with reverts(
            st_token.TradeRequestNotAcceptableByCaller,
            index=index,
            caller=seller_st.address,
        ):
            st_token.rejectTrade(index, sender=seller_st)
