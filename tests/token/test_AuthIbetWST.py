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

import brownie

from tests.helper import eip712_helper


class TestDeploy:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "IbetERC20"
        assert token.symbol() == ""
        assert token.decimals() == 18
        assert token.totalSupply() == 0
        assert token.balanceOf(issuer.address) == 0

        domain_separator = eip712_helper.generate_domain_separator(
            name=token.name(),
            version="1",
            chain_id=brownie.chain.id,
            verifying_contract=token.address,
        )
        assert token.DOMAIN_SEPARATOR() == "0x" + domain_separator.hex()


class TestTransferWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_transfer_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        tx = token.transferWithAuthorization(
            from_user_addr,
            to_user_addr,
            _value,
            _valid_after,
            _valid_before,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": issuer},
        )

        # assertion
        assert tx.events["AuthorizationUsed"]["authorizer"] == from_user_addr
        assert tx.events["AuthorizationUsed"]["nonce"] == nonce.hex()

        assert tx.events["Transfer"]["from"] == from_user_addr
        assert tx.events["Transfer"]["to"] == to_user_addr
        assert tx.events["Transfer"]["value"] == 100

        assert token.balanceOf(from_user_addr) == 900
        assert token.balanceOf(to_user_addr) == 100

        assert token.usedNonces(from_user_addr, nonce) is True

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - valid_after is in the future
    def test_error_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 2**32 - 1  # max uint32
        _valid_before = 2**32 - 1  # max uint32

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_transfer_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with brownie.reverts(
            f"TransactionNotInValidPeriod: {_valid_after}, {_valid_before}"
        ):
            token.transferWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": issuer},
            )

        # assertion
        assert token.balanceOf(from_user_addr) == 1000
        assert token.balanceOf(to_user_addr) == 0

        assert token.usedNonces(from_user_addr, nonce) is False

    # Error_2
    # - valid_before is in the past
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 10

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_transfer_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with brownie.reverts(
            f"TransactionNotInValidPeriod: {_valid_after}, {_valid_before}"
        ):
            token.transferWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": issuer},
            )

        # assertion
        assert token.balanceOf(from_user_addr) == 1000
        assert token.balanceOf(to_user_addr) == 0

        assert token.usedNonces(from_user_addr, nonce) is False

    # Error_3
    # - nonce is already used
    def test_error_3(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_transfer_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # transfer with authorization (1st time)
        # - transaction is sent not by from_user but by issuer
        token.transferWithAuthorization(
            from_user_addr,
            to_user_addr,
            _value,
            _valid_after,
            _valid_before,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": issuer},
        )

        # transfer with authorization (2nd time)
        # - transaction is sent not by from_user but by issuer
        with brownie.reverts(
            f"AuthorizationNonceAlreadyUsed: {from_user_addr.lower()}, {nonce}"
        ):
            token.transferWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": issuer},
            )

    # Error_4
    # - Signature is not valid
    def test_error_4(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_transfer_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with brownie.reverts(
            f"InvalidAuthorizationSignature: {from_user_addr.lower()}"
        ):
            token.transferWithAuthorization(
                from_user_addr,
                to_user_addr,
                10000,  # value is not correct
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": issuer},
            )

    # Error_5
    # - value exceeds balance
    def test_error_5(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 1001  # value exceeds balance
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_transfer_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with brownie.reverts(
            f"ERC20InsufficientBalance: {from_user_addr.lower()}, 1000, 1001"
        ):
            token.transferWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": issuer},
            )


class TestReceiveWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_receive_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest by from_user
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # receive with authorization
        tx = token.receiveWithAuthorization(
            from_user_addr,
            to_user_addr,
            _value,
            _valid_after,
            _valid_before,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": to_user_addr},
        )

        # assertion
        assert tx.events["AuthorizationUsed"]["authorizer"] == from_user_addr
        assert tx.events["AuthorizationUsed"]["nonce"] == nonce.hex()

        assert tx.events["Transfer"]["from"] == from_user_addr
        assert tx.events["Transfer"]["to"] == to_user_addr
        assert tx.events["Transfer"]["value"] == 100

        assert token.balanceOf(from_user_addr) == 900
        assert token.balanceOf(to_user_addr) == 100

        assert token.usedNonces(from_user_addr, nonce) is True

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - valid_after is in the future
    def test_error_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 2**32 - 1  # max uint32
        _valid_before = 2**32 - 1  # max uint32

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_receive_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest by from_user
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # receive with authorization
        with brownie.reverts(
            f"TransactionNotInValidPeriod: {_valid_after}, {_valid_before}"
        ):
            token.receiveWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": to_user_addr},
            )

        # assertion
        assert token.balanceOf(from_user_addr) == 1000
        assert token.balanceOf(to_user_addr) == 0

        assert token.usedNonces(from_user_addr, nonce) is False

    # Error_2
    # - valid_before is in the past
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 10

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_receive_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest by from_user
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # receive with authorization
        with brownie.reverts(
            f"TransactionNotInValidPeriod: {_valid_after}, {_valid_before}"
        ):
            token.receiveWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": to_user_addr},
            )

        # assertion
        assert token.balanceOf(from_user_addr) == 1000
        assert token.balanceOf(to_user_addr) == 0

        assert token.usedNonces(from_user_addr, nonce) is False

    # Error_3
    # - nonce is already used
    def test_error_3(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_receive_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest by from_user
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # receive with authorization (1st time)
        token.receiveWithAuthorization(
            from_user_addr,
            to_user_addr,
            _value,
            _valid_after,
            _valid_before,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": to_user_addr},
        )

        # receive with authorization (2nd time)
        with brownie.reverts(
            f"AuthorizationNonceAlreadyUsed: {from_user_addr.lower()}, {nonce}"
        ):
            token.receiveWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": to_user_addr},
            )

    # Error_4
    # - Signature is not valid
    def test_error_4(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_receive_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest by from_user
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # receive with authorization
        with brownie.reverts(
            f"InvalidAuthorizationSignature: {from_user_addr.lower()}"
        ):
            token.receiveWithAuthorization(
                from_user_addr,
                to_user_addr,
                10000,  # value is not correct
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": to_user_addr},
            )

    # Error_5
    # - value exceeds balance
    def test_error_5(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 1001  # value exceeds balance
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate transfer digest
        digest = eip712_helper.generate_receive_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            _from=from_user_addr,
            _to=to_user_addr,
            value=_value,
            valid_after=_valid_after,
            valid_before=_valid_before,
            nonce=nonce,
        )

        # sign the digest by from_user
        signature = brownie.web3.eth.account._sign_hash(digest, from_user_pk)

        # receive with authorization
        with brownie.reverts(
            f"ERC20InsufficientBalance: {from_user_addr.lower()}, 1000, 1001"
        ):
            token.receiveWithAuthorization(
                from_user_addr,
                to_user_addr,
                _value,
                _valid_after,
                _valid_before,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": to_user_addr},
            )


class TestRequestTradeWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st_addr, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st_addr, {"from": issuer})

        # generate nonce
        nonce = brownie.web3.keccak(secrets.token_bytes(32))

        # generate request trade digest
        digest = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            seller_sc_account_address=seller_sc.address,
            buyer_sc_account_address=buyer_sc.address,
            st_value=100,
            sc_value=200,
            nonce=nonce,
        )

        # sign the digest by seller_st_addr
        signature = brownie.web3.eth.account._sign_hash(digest, seller_st_pk)

        # request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        tx = st_token.requestTradeWithAuthorization(
            seller_st_addr,
            buyer_st_addr,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # st_value
            200,  # sc_value
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": relayer},
        )

        # assertion
        assert st_token.getNbTrades() == 1

        assert st_token.getTrade(1) == (
            seller_st_addr,
            buyer_st_addr,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,
            200,
            0,  # status (Pending)
        )

        assert tx.events["TradeRequested"]["index"] == 1
        assert tx.events["TradeRequested"]["sellerSTAccountAddress"] == seller_st_addr
        assert tx.events["TradeRequested"]["buyerSTAccountAddress"] == buyer_st_addr
        assert tx.events["TradeRequested"]["SCTokenAddress"] == sc_token.address
        assert (
            tx.events["TradeRequested"]["sellerSCAccountAddress"] == seller_sc.address
        )
        assert tx.events["TradeRequested"]["buyerSCAccountAddress"] == buyer_sc.address
        assert tx.events["TradeRequested"]["STValue"] == 100
        assert tx.events["TradeRequested"]["SCValue"] == 200


class TestAcceptTradeWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(seller_st_addr, {"from": issuer})
        st_token.addAccountWhiteList(buyer_st_addr, {"from": issuer})

        # [REQUEST-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # [REQUEST-TRADE] generate nonce
        nonce_1 = brownie.web3.keccak(secrets.token_bytes(32))

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            seller_sc_account_address=seller_sc.address,
            buyer_sc_account_address=buyer_sc.address,
            st_value=100,
            sc_value=200,
            nonce=nonce_1,
        )

        # [REQUEST-TRADE] sign the digest by seller_st_addr
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, seller_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        st_token.requestTradeWithAuthorization(
            seller_st_addr,
            buyer_st_addr,
            sc_token.address,
            seller_sc.address,
            buyer_sc.address,
            100,  # st_value
            200,  # sc_value
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = brownie.web3.keccak(secrets.token_bytes(32))

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        tx = st_token.acceptTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # assertion
        assert st_token.getTrade(1)[7] == 1  # status (Executed)

        assert st_token.balanceOf(seller_st_addr) == 0
        assert st_token.balanceOf(buyer_st_addr) == 100
        assert sc_token.balanceOf(seller_sc.address) == 200
        assert sc_token.balanceOf(buyer_sc.address) == 0

        assert tx.events["TradeAccepted"]["index"] == 1
        assert tx.events["TradeAccepted"]["sellerSTAccountAddress"] == seller_st_addr
        assert tx.events["TradeAccepted"]["buyerSTAccountAddress"] == buyer_st_addr
        assert tx.events["TradeAccepted"]["SCTokenAddress"] == sc_token.address
        assert tx.events["TradeAccepted"]["sellerSCAccountAddress"] == seller_sc.address
        assert tx.events["TradeAccepted"]["buyerSCAccountAddress"] == buyer_sc.address
        assert tx.events["TradeAccepted"]["STValue"] == 100
        assert tx.events["TradeAccepted"]["SCValue"] == 200
