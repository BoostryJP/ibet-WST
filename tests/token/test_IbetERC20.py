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
    def test_normal_1(self, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        # deploy
        token = admin.deploy(IbetERC20, issuer.address)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "IbetERC20"
        assert token.symbol() == ""
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
        token = admin.deploy(IbetERC20, issuer.address)

        # mint
        token.mint(issuer.address, 10, {"from": issuer})

        # assertion
        assert token.name() == "IbetERC20"
        assert token.symbol() == ""
        assert token.decimals() == 18
        assert token.totalSupply() == 10
        assert token.balanceOf(issuer.address) == 10

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
        token = admin.deploy(IbetERC20, issuer.address)

        # mint
        with brownie.reverts(
            revert_msg=f"OwnableUnauthorizedAccount: {other.address.lower()}"
        ):
            token.mint(issuer.address, 10, {"from": other})


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
        token = admin.deploy(IbetERC20, issuer.address)

        # mint
        token.mint(user_1.address, 10, {"from": issuer})

        # burn
        token.burn(10, {"from": user_1})

        # assertion
        assert token.name() == "IbetERC20"
        assert token.symbol() == ""
        assert token.decimals() == 18
        assert token.totalSupply() == 0
        assert token.balanceOf(user_1.address) == 0

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
        token = admin.deploy(IbetERC20, issuer.address)

        # mint
        token.mint(user_1.address, 10, {"from": issuer})

        # burn
        with brownie.reverts(
            revert_msg=f"ERC20InsufficientBalance: {user_1.address.lower()}, 10, 11"
        ):
            token.burn(11, {"from": user_1})


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
        token = admin.deploy(IbetERC20, issuer.address)

        # mint
        token.mint(user_1.address, 10, {"from": issuer})

        # approve
        token.approve(user_2.address, 5, {"from": user_1})

        # burnFrom
        token.burnFrom(user_1.address, 5, {"from": user_2})

        # assertion
        assert token.name() == "IbetERC20"
        assert token.symbol() == ""
        assert token.decimals() == 18
        assert token.totalSupply() == 5
        assert token.balanceOf(user_1.address) == 5

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
        token = admin.deploy(IbetERC20, issuer.address)

        # mint
        token.mint(user_1.address, 10, {"from": issuer})

        # burnFrom
        with brownie.reverts(
            revert_msg=f"ERC20InsufficientAllowance: {user_2.address.lower()}, 0, 5"
        ):
            token.burnFrom(user_1.address, 5, {"from": user_2})
