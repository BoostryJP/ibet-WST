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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "IbetWST"
        assert token.symbol() == ""
        assert token.decimals() == 0
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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        token = admin.deploy(IbetWST, "IbetWST", issuer.address)

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
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # requestTrade
        tx = st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # assertion
        assert st_token.getNbTrades() == 1

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

        assert tx.events["TradeRequested"]["index"] == 1
        assert (
            tx.events["TradeRequested"]["sellerSTAccountAddress"] == seller_st.address
        )
        assert tx.events["TradeRequested"]["buyerSTAccountAddress"] == buyer_st.address
        assert tx.events["TradeRequested"]["SCTokenAddress"] == sc_token.address
        assert (
            tx.events["TradeRequested"]["sellerSCAccountAddress"] == seller_sc.address
        )
        assert tx.events["TradeRequested"]["buyerSCAccountAddress"] == buyer_sc.address
        assert tx.events["TradeRequested"]["STValue"] == 100
        assert tx.events["TradeRequested"]["SCValue"] == 200

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
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # requestTrade 1st time
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # requestTrade 2nd time with different values
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            200,  # ST value
            300,  # SC value
            "trade_memo",
            {"from": seller_st},
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
        seller_sc = users["eoa4"]
        buyer_st = users["eoa5"]
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # requestTrade
        with brownie.reverts(
            revert_msg=f"AccountNotWhitelisted: {seller_st.address.lower()}"
        ):
            st_token.requestTrade(
                buyer_st.address,
                sc_token.address,
                seller_sc.address,
                buyer_sc.address,
                100,  # ST value
                200,  # SC value
                "trade_memo",
                {"from": seller_st},
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
        buyer_sc = users["eoa6"]

        # deploy ST token
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST account to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})

        # requestTrade
        with brownie.reverts(
            revert_msg=f"AccountNotWhitelisted: {buyer_st.address.lower()}"
        ):
            st_token.requestTrade(
                buyer_st.address,
                sc_token.address,
                seller_sc.address,
                buyer_sc.address,
                100,  # ST value
                200,  # SC value
                "trade_memo",
                {"from": seller_st},
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
        buyer_st = users["eoa4"]

        # deploy ST token
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            seller_st.address,
            buyer_st.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # cancelTrade
        index = st_token.getNbTrades()
        tx = st_token.cancelTrade(index, {"from": seller_st})

        # assertion
        assert st_token.getTrade(1)[7] == 2  # status (Cancelled)

        assert tx.events["TradeCancelled"]["index"] == index
        assert (
            tx.events["TradeCancelled"]["sellerSTAccountAddress"] == seller_st.address
        )
        assert tx.events["TradeCancelled"]["buyerSTAccountAddress"] == buyer_st.address
        assert tx.events["TradeCancelled"]["SCTokenAddress"] == st_token.address
        assert (
            tx.events["TradeCancelled"]["sellerSCAccountAddress"] == seller_st.address
        )
        assert tx.events["TradeCancelled"]["buyerSCAccountAddress"] == buyer_st.address
        assert tx.events["TradeCancelled"]["STValue"] == 100
        assert tx.events["TradeCancelled"]["SCValue"] == 200

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the cancelTrade fails when the trade is not in Pending status
    def test_error_1(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        buyer_st = users["eoa4"]

        # deploy ST token
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            seller_st.address,
            buyer_st.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # cancelTrade (1st time)
        index = st_token.getNbTrades()
        st_token.cancelTrade(index, {"from": seller_st})

        # cancelTrade (2nd time)
        with brownie.reverts(revert_msg=f"TradeRequestIsNotAcceptable: {index}"):
            st_token.cancelTrade(index, {"from": seller_st})

    # Error_2
    # - Check that the cancelTrade fails when the caller is not the seller
    def test_error_2(self, IbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        seller_st = users["eoa3"]
        buyer_st = users["eoa4"]

        # deploy ST token
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # requestTrade
        st_token.requestTrade(
            buyer_st.address,
            st_token.address,
            seller_st.address,
            buyer_st.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # cancelTrade
        index = st_token.getNbTrades()
        with brownie.reverts(
            revert_msg=f"TradeRequestNotAcceptableByCaller: {index}, {buyer_st.address.lower()}"
        ):
            st_token.cancelTrade(index, {"from": buyer_st})


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
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)
        st_token.mint(seller_st.address, 100, {"from": issuer})

        # deploy SC token & mint buyer balance
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # ST: acceptTrade
        tx = st_token.acceptTrade(1, {"from": buyer_st})

        # assertion
        assert st_token.getTrade(1)[7] == 1  # status (Executed)

        assert st_token.balanceOf(seller_st.address) == 0
        assert st_token.balanceOf(buyer_st.address) == 100
        assert sc_token.balanceOf(seller_sc.address) == 200
        assert sc_token.balanceOf(buyer_sc.address) == 0

        assert tx.events["TradeAccepted"]["index"] == 1
        assert tx.events["TradeAccepted"]["sellerSTAccountAddress"] == seller_st.address
        assert tx.events["TradeAccepted"]["buyerSTAccountAddress"] == buyer_st.address
        assert tx.events["TradeAccepted"]["SCTokenAddress"] == sc_token.address
        assert tx.events["TradeAccepted"]["sellerSCAccountAddress"] == seller_sc.address
        assert tx.events["TradeAccepted"]["buyerSCAccountAddress"] == buyer_sc.address
        assert tx.events["TradeAccepted"]["STValue"] == 100
        assert tx.events["TradeAccepted"]["SCValue"] == 200

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
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)
        st_token.mint(seller_st.address, 100, {"from": issuer})

        # deploy SC token & mint buyer balance
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # ST: acceptTrade
        st_token.acceptTrade(1, {"from": buyer_st})

        # ST: acceptTrade again
        with brownie.reverts(revert_msg="TradeRequestIsNotAcceptable: 1"):
            st_token.acceptTrade(1, {"from": buyer_st})

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
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)
        st_token.mint(seller_st.address, 100, {"from": issuer})

        # deploy SC token & mint buyer balance
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # ST value
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # ST: acceptTrade
        with brownie.reverts(
            revert_msg=f"TradeRequestNotAcceptableByCaller: 1, {seller_st.address.lower()}"
        ):
            st_token.acceptTrade(1, {"from": seller_st})

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
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)
        st_token.mint(seller_st.address, 100, {"from": issuer})

        # deploy SC token & mint buyer balance
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            101,  # ST value, insufficient
            200,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # ST: acceptTrade
        with brownie.reverts(
            revert_msg=f"ERC20InsufficientBalance: {seller_st.address.lower()}, 100, 101"
        ):
            st_token.acceptTrade(1, {"from": buyer_st})

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
        st_token = admin.deploy(IbetWST, "IbetWST", issuer.address)
        st_token.mint(seller_st.address, 100, {"from": issuer})

        # deploy SC token & mint buyer balance
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # ST: add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st.address, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st.address, {"from": issuer})

        # ST: requestTrade
        st_token.requestTrade(
            buyer_st.address,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # ST value
            201,  # SC value
            "trade_memo",
            {"from": seller_st},
        )

        # SC: approve transfer
        sc_token.approve(
            st_token.address, 200, {"from": buyer_sc}
        )  # insufficient allowance

        # ST: acceptTrade
        with brownie.reverts(
            revert_msg=f"ERC20InsufficientAllowance: {st_token.address.lower()}, 200, 201"
        ):
            st_token.acceptTrade(1, {"from": buyer_st})
