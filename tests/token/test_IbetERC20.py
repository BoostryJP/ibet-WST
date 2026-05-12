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

from tests.helper.ape_utils import event_args, reverts


class TestDeploy:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "IbetERC20"
        assert token.symbol() == "IWST"
        assert token.decimals() == 18
        assert token.totalSupply() == 0
        assert token.balanceOf(issuer.address) == 0


class TestMint:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the issuer can mint tokens
    def test_normal_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        tx = token.mint(issuer.address, 10, sender=issuer)
        event = event_args(tx, token.Mint)

        # assertion
        assert token.name() == "IbetERC20"
        assert token.symbol() == "IWST"
        assert token.decimals() == 18
        assert token.totalSupply() == 10
        assert token.balanceOf(issuer.address) == 10

        assert event["to"] == issuer.address
        assert event["value"] == 10

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that only the issuer can mint tokens
    def test_error_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        other = users["eoa3"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        with reverts(token, "OwnableUnauthorizedAccount", account=other.address):
            token.mint(issuer.address, 10, sender=other)


class TestBurn:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the user that holds the tokens can burn them
    def test_normal_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        token.mint(user_1.address, 10, sender=issuer)

        # burn
        tx = token.burn(10, sender=user_1)
        event = event_args(tx, token.Burn)

        # assertion
        assert token.name() == "IbetERC20"
        assert token.symbol() == "IWST"
        assert token.decimals() == 18
        assert token.totalSupply() == 0
        assert token.balanceOf(user_1.address) == 0

        assert event["from"] == user_1.address
        assert event["value"] == 10

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the user cannot burn more tokens than they hold
    def test_error_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        token.mint(user_1.address, 10, sender=issuer)

        # burn
        with reverts(
            token.ERC20InsufficientBalance,
            sender=user_1.address,
            balance=10,
            needed=11,
        ):
            token.burn(11, sender=user_1)


class TestBurnFrom:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the user can burn tokens on behalf of another user if they have approval
    def test_normal_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]
        user_2 = users["eoa4"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        token.mint(user_1.address, 10, sender=issuer)

        # approve
        token.approve(user_2.address, 5, sender=user_1)

        # burnFrom
        tx = token.burnFrom(user_1.address, 5, sender=user_2)
        event = event_args(tx, token.Burn)

        # assertion
        assert token.name() == "IbetERC20"
        assert token.symbol() == "IWST"
        assert token.decimals() == 18
        assert token.totalSupply() == 5
        assert token.balanceOf(user_1.address) == 5

        assert event["from"] == user_1.address
        assert event["value"] == 5

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that the user cannot burn tokens on behalf of another user if they do not have approval
    def test_error_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]
        user_2 = users["eoa4"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        token.mint(user_1.address, 10, sender=issuer)

        # burnFrom
        with reverts(
            token.ERC20InsufficientAllowance,
            spender=user_2.address,
            allowance=0,
            needed=5,
        ):
            token.burnFrom(user_1.address, 5, sender=user_2)


class TestForceBurnFrom:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Check that the owner can force burn tokens from any user
    def test_normal_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        token.mint(user_1.address, 10, sender=issuer)

        # forceBurnFrom
        tx = token.forceBurnFrom(user_1.address, 5, sender=issuer)
        event = event_args(tx, token.Burn)

        # assertion
        assert token.name() == "IbetERC20"
        assert token.symbol() == "IWST"
        assert token.decimals() == 18
        assert token.totalSupply() == 5
        assert token.balanceOf(user_1.address) == 5

        assert event["from"] == user_1.address
        assert event["value"] == 5

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - Check that only the owner can force burn tokens from any user
    def test_error_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]
        other = users["eoa4"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        token.mint(user_1.address, 10, sender=issuer)

        # forceBurnFrom
        with reverts(token, "OwnableUnauthorizedAccount", account=other.address):
            token.forceBurnFrom(user_1.address, 5, sender=other)

    # Error_2
    # - Check that the owner cannot force burn more tokens than the user holds
    def test_error_2(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_1 = users["eoa3"]

        # deploy
        token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # mint
        token.mint(user_1.address, 10, sender=issuer)

        # forceBurnFrom
        with reverts(
            token.ERC20InsufficientBalance,
            sender=user_1.address,
            balance=10,
            needed=11,
        ):
            token.forceBurnFrom(user_1.address, 11, sender=issuer)
