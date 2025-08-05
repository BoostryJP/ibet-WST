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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "AuthIbetWST"
        assert token.symbol() == ""
        assert token.decimals() == 0
        assert token.totalSupply() == 0
        assert token.balanceOf(issuer.address) == 0

        domain_separator = eip712_helper.generate_domain_separator(
            name=token.name(),
            version="1",
            chain_id=brownie.chain.id,
            verifying_contract=token.address,
        )
        assert token.DOMAIN_SEPARATOR() == "0x" + domain_separator.hex()


class TestMintWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate mint digest
        digest = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user.address,
            value=100,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, issuer_pk)

        # mint with authorization
        # - transaction is sent not by issuer but by relayer
        tx = token.mintWithAuthorization(
            user.address,
            100,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": relayer},
        )

        # assertion
        assert token.usedNonces(issuer_addr, nonce) is True
        assert tx.events["AuthorizationUsed"]["authorizer"] == issuer_addr
        assert tx.events["AuthorizationUsed"]["nonce"] == brownie.web3.to_hex(nonce)

        assert token.balanceOf(user.address) == 100

        assert tx.events["Mint"]["to"] == user.address
        assert tx.events["Mint"]["value"] == 100

    ##########################################################
    # Error
    ##########################################################

    # Error_1_1
    # - authorization signature is not valid
    #   - signature is incorrect
    def test_error_1_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate mint digest
        digest = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user.address,
            value=100,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, issuer_pk)

        # mint with authorization
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {issuer_addr.lower()}"):
            token.mintWithAuthorization(
                relayer.address,  # incorrect account address
                100,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )

    # Error_1_2
    # - authorization signature is not valid
    #   - signature is signed by other account, not token owner
    def test_error_1_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        other_pk, other_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate mint digest
        digest = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user.address,
            value=100,
            nonce=nonce,
        )

        # sign the digest
        # - signature is signed by other account, not token owner
        signature = brownie.web3.eth.account._sign_hash(digest, other_pk)

        # mint with authorization
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {issuer_addr.lower()}"):
            token.mintWithAuthorization(
                user.address,
                100,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate mint digest
        digest = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user.address,
            value=100,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, issuer_pk)

        # mint with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": relayer},
        )

        # mint with authorization (2nd time)
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(
            f"AuthorizationNonceAlreadyUsed: {issuer_addr.lower()}, {nonce}"
        ):
            token.mintWithAuthorization(
                user.address,
                100,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )


class TestBurnWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user_pk, user_addr = eip712_helper.generate_account()
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [MINT] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [MINT] generate mint digest
        digest_1 = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user_addr,
            value=100,
            nonce=nonce_1,
        )

        # [MINT] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user_addr,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [BURN] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [BURN] generate burn digest
        digest_2 = eip712_helper.generate_burn_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            from_address=user_addr,
            value=100,
            nonce=nonce_2,
        )

        # [BURN] sign the digest
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, user_pk)

        # [BURN] burn with authorization
        # - transaction is sent not by user but by relayer
        tx = token.burnWithAuthorization(
            user_addr,
            100,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # assertion
        assert token.usedNonces(user_addr, nonce_2) is True
        assert tx.events["AuthorizationUsed"]["authorizer"] == user_addr
        assert tx.events["AuthorizationUsed"]["nonce"] == brownie.web3.to_hex(nonce_2)

        assert token.balanceOf(user_addr) == 0

        assert tx.events["Burn"]["from"] == user_addr
        assert tx.events["Burn"]["value"] == 100

    ##########################################################
    # Error
    ##########################################################

    # Error_1_1
    # - authorization signature is not valid
    #   - signature is incorrect
    def test_error_1_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [MINT] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [MINT] generate mint digest
        digest_1 = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user.address,
            value=100,
            nonce=nonce_1,
        )

        # [MINT] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [BURN] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [BURN] generate burn digest
        digest_2 = eip712_helper.generate_burn_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            from_address=user.address,
            value=100,
            nonce=nonce_2,
        )

        # [BURN] sign the digest
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, issuer_pk)

        # [BURN] burn with authorization
        # - transaction is sent not by user but by relayer
        with brownie.reverts(
            f"InvalidAuthorizationSignature: {relayer.address.lower()}"
        ):
            token.burnWithAuthorization(
                relayer.address,  # incorrect account address
                100,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_1_2
    # - authorization signature is not valid
    #   - signature is signed by other account, not the user
    def test_error_1_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        other_pk, other_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [MINT] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [MINT] generate mint digest
        digest_1 = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user.address,
            value=100,
            nonce=nonce_1,
        )

        # [MINT] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [BURN] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [BURN] generate burn digest
        digest_2 = eip712_helper.generate_burn_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            from_address=user.address,
            value=100,
            nonce=nonce_2,
        )

        # [BURN] sign the digest
        # - signature is signed by other account, not token owner
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, other_pk)

        # [BURN] burn with authorization
        # - transaction is sent not by user but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {user.address.lower()}"):
            token.burnWithAuthorization(
                user.address,
                100,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user_pk, user_addr = eip712_helper.generate_account()
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [MINT] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [MINT] generate mint digest
        digest_1 = eip712_helper.generate_mint_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            to_address=user_addr,
            value=100,
            nonce=nonce_1,
        )

        # [MINT] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user_addr,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [BURN] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [BURN] generate burn digest
        digest_2 = eip712_helper.generate_burn_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            from_address=user_addr,
            value=100,
            nonce=nonce_2,
        )

        # [BURN] sign the digest
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, user_pk)

        # [BURN] burn with authorization (1st time)
        # - transaction is sent not by user but by relayer
        token.burnWithAuthorization(
            user_addr,
            100,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # [BURN] burn with authorization (2nd time)
        # - transaction is sent not by user but by relayer
        with brownie.reverts(
            f"AuthorizationNonceAlreadyUsed: {user_addr.lower()}, {nonce_2}"
        ):
            token.burnWithAuthorization(
                user_addr,
                100,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )


class TestAddAccountWhiteListWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user_st = users["eoa2"]
        user_sc_in = users["eoa3"]
        user_sc_out = users["eoa4"]
        relayer = users["eoa5"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate add account whitelist digest
        digest = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user_st.address,
            sc_account_address_in=user_sc_in.address,
            sc_account_address_out=user_sc_out.address,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, issuer_pk)

        # add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        tx = token.addAccountWhiteListWithAuthorization(
            user_st.address,
            user_sc_in.address,
            user_sc_out.address,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": relayer},
        )

        # assertion
        assert token.usedNonces(issuer_addr, nonce) is True
        assert tx.events["AuthorizationUsed"]["authorizer"] == issuer_addr
        assert tx.events["AuthorizationUsed"]["nonce"] == brownie.web3.to_hex(nonce)

        assert token.accountWhiteList(user_st.address) == (
            user_st.address,
            user_sc_in.address,
            user_sc_out.address,
            True,
        )
        assert tx.events["AccountWhiteListAdded"]["accountAddress"] == user_st.address

    ##########################################################
    # Error
    ##########################################################

    # Error_1_1
    # - authorization signature is not valid
    #   - signature is incorrect
    def test_error_1_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user_st = users["eoa2"]
        user_sc_in = users["eoa3"]
        user_sc_out = users["eoa4"]
        relayer = users["eoa5"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate add account whitelist digest
        digest = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user_st.address,
            sc_account_address_in=user_sc_in.address,
            sc_account_address_out=user_sc_out.address,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, issuer_pk)

        # add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {issuer_addr.lower()}"):
            token.addAccountWhiteListWithAuthorization(
                relayer.address,  # incorrect account address
                user_sc_in.address,
                user_sc_out.address,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )

    # Error_1_2
    # - authorization signature is not valid
    #   - signature is signed by other account, not token owner
    def test_error_1_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        other_pk, other_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate add account whitelist digest
        digest = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            sc_account_address_in=user.address,
            sc_account_address_out=user.address,
            nonce=nonce,
        )

        # sign the digest
        # - signature is signed by other account, not token owner
        signature = brownie.web3.eth.account._sign_hash(digest, other_pk)

        # add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {issuer_addr.lower()}"):
            token.addAccountWhiteListWithAuthorization(
                user.address,
                user.address,
                user.address,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate add account whitelist digest
        digest = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            sc_account_address_in=user.address,
            sc_account_address_out=user.address,
            nonce=nonce,
        )

        # sign the digest
        signature = brownie.web3.eth.account._sign_hash(digest, issuer_pk)

        # add account to whitelist with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.addAccountWhiteListWithAuthorization(
            user.address,
            user.address,
            user.address,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": relayer},
        )

        # add account to whitelist with authorization (2nd time)
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(
            f"AuthorizationNonceAlreadyUsed: {issuer_addr.lower()}, {nonce}"
        ):
            token.addAccountWhiteListWithAuthorization(
                user.address,
                user.address,
                user.address,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )


class TestDeleteAccountWhiteListWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [ADD-WHITELIST] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [ADD-WHITELIST] generate add account whitelist digest
        digest_1 = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            sc_account_address_in=user.address,
            sc_account_address_out=user.address,
            nonce=nonce_1,
        )

        # [ADD-WHITELIST] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [ADD-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        token.addAccountWhiteListWithAuthorization(
            user.address,
            user.address,
            user.address,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [DELETE-WHITELIST] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [DELETE-WHITELIST] generate delete account whitelist digest
        digest_2 = eip712_helper.generate_delete_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            nonce=nonce_2,
        )

        # [DELETE-WHITELIST] sign the digest
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, issuer_pk)

        # [DELETE-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        tx = token.deleteAccountWhiteListWithAuthorization(
            user.address,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # assertion
        assert token.usedNonces(issuer_addr, nonce_2) is True
        assert tx.events["AuthorizationUsed"]["authorizer"] == issuer_addr
        assert tx.events["AuthorizationUsed"]["nonce"] == brownie.web3.to_hex(nonce_2)

        assert token.accountWhiteList(user.address) == (
            brownie.ZERO_ADDRESS,
            brownie.ZERO_ADDRESS,
            brownie.ZERO_ADDRESS,
            False,
        )
        assert tx.events["AccountWhiteListDeleted"]["accountAddress"] == user.address

    ##########################################################
    # Error
    ##########################################################

    # Error_1_1
    # - authorization signature is not valid
    #   - signature is incorrect
    def test_error_1_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [ADD-WHITELIST] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [ADD-WHITELIST] generate add account whitelist digest
        digest_1 = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            sc_account_address_in=user.address,
            sc_account_address_out=user.address,
            nonce=nonce_1,
        )

        # [ADD-WHITELIST] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [ADD-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        token.addAccountWhiteListWithAuthorization(
            user.address,
            user.address,
            user.address,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [DELETE-WHITELIST] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [DELETE-WHITELIST] generate delete account whitelist digest
        digest_2 = eip712_helper.generate_delete_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            nonce=nonce_2,
        )

        # [DELETE-WHITELIST] sign the digest
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, issuer_pk)

        # [DELETE-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {issuer_addr.lower()}"):
            token.deleteAccountWhiteListWithAuthorization(
                relayer.address,  # incorrect account address
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_1_2
    # - authorization signature is not valid
    #   - signature is signed by other account, not token owner
    def test_error_1_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        other_pk, other_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [ADD-WHITELIST] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [ADD-WHITELIST] generate add account whitelist digest
        digest_1 = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            sc_account_address_in=user.address,
            sc_account_address_out=user.address,
            nonce=nonce_1,
        )

        # [ADD-WHITELIST] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [ADD-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        token.addAccountWhiteListWithAuthorization(
            user.address,
            user.address,
            user.address,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [DELETE-WHITELIST] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [DELETE-WHITELIST] generate delete account whitelist digest
        digest_2 = eip712_helper.generate_delete_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            nonce=nonce_2,
        )

        # [DELETE-WHITELIST] sign the digest
        # - signature is signed by other account, not token owner
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, other_pk)

        # [DELETE-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {issuer_addr.lower()}"):
            token.deleteAccountWhiteListWithAuthorization(
                user.address,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer_addr)

        # [ADD-WHITELIST] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [ADD-WHITELIST] generate add account whitelist digest
        digest_1 = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            sc_account_address_in=user.address,
            sc_account_address_out=user.address,
            nonce=nonce_1,
        )

        # [ADD-WHITELIST] sign the digest
        signature_1 = brownie.web3.eth.account._sign_hash(digest_1, issuer_pk)

        # [ADD-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        token.addAccountWhiteListWithAuthorization(
            user.address,
            user.address,
            user.address,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [DELETE-WHITELIST] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [DELETE-WHITELIST] generate delete account whitelist digest
        digest_2 = eip712_helper.generate_delete_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            nonce=nonce_2,
        )

        # [DELETE-WHITELIST] sign the digest
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, issuer_pk)

        # [DELETE-WHITELIST] add account to whitelist with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.deleteAccountWhiteListWithAuthorization(
            user.address,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # [DELETE-WHITELIST] add account to whitelist with authorization (2nd time)
        # - transaction is sent not by issuer but by relayer
        with brownie.reverts(
            f"AuthorizationNonceAlreadyUsed: {issuer_addr.lower()}, {nonce_2}"
        ):
            token.deleteAccountWhiteListWithAuthorization(
                user.address,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )


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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        assert tx.events["AuthorizationUsed"]["nonce"] == brownie.web3.to_hex(nonce)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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

    # Error_6_1
    # - account is not whitelisted: from_user
    def test_error_6_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        with brownie.reverts(f"AccountNotWhitelisted: {from_user_addr.lower()}"):
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

    # Error_6_2
    # - account is not whitelisted: to_user
    def test_error_6_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        with brownie.reverts(f"AccountNotWhitelisted: {to_user_addr.lower()}"):
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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        assert tx.events["AuthorizationUsed"]["nonce"] == brownie.web3.to_hex(nonce)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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

    # Error_6_1
    # - account is not whitelisted: from_user
    def test_error_6_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        with brownie.reverts(f"AccountNotWhitelisted: {from_user_addr.lower()}"):
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

    # Error_6_2
    # - account is not whitelisted: to_user
    def test_error_6_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        from_user_pk, from_user_addr = eip712_helper.generate_account()
        to_user_pk, to_user_addr = eip712_helper.generate_account()

        _value = 100
        _valid_after = 0
        _valid_before = 2**32 - 1

        # deploy
        token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, {"from": issuer})

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

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
        with brownie.reverts(f"AccountNotWhitelisted: {to_user_addr.lower()}"):
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
        seller_sc_in = users["eoa3"]
        seller_sc_out = users["eoa4"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc_in = users["eoa5"]
        buyer_sc_out = users["eoa6"]

        relayer = users["eoa7"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc_in.address,
            seller_sc_out.address,
            {"from": issuer},
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc_in.address, buyer_sc_out.address, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate request trade digest
        digest = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
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
            seller_sc_in.address,
            buyer_sc_out.address,
            100,
            200,
            0,  # status (Pending)
            "trade_memo",
        )

        assert tx.events["TradeRequested"]["index"] == 1
        assert tx.events["TradeRequested"]["sellerSTAccountAddress"] == seller_st_addr
        assert tx.events["TradeRequested"]["buyerSTAccountAddress"] == buyer_st_addr
        assert tx.events["TradeRequested"]["SCTokenAddress"] == sc_token.address
        assert (
            tx.events["TradeRequested"]["sellerSCAccountAddress"]
            == seller_sc_in.address
        )
        assert (
            tx.events["TradeRequested"]["buyerSCAccountAddress"] == buyer_sc_out.address
        )
        assert tx.events["TradeRequested"]["STValue"] == 100
        assert tx.events["TradeRequested"]["SCValue"] == 200

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - seller_st_addr is not whitelisted
    def test_error_1(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()

        relayer = users["eoa3"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate request trade digest
        digest = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
            nonce=nonce,
        )

        # sign the digest by seller_st_addr
        signature = brownie.web3.eth.account._sign_hash(digest, seller_st_pk)

        # request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with brownie.reverts(f"AccountNotWhitelisted: {seller_st_addr.lower()}"):
            st_token.requestTradeWithAuthorization(
                seller_st_addr,
                buyer_st_addr,
                sc_token.address,
                100,  # st_value
                200,  # sc_value
                "trade_memo",
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )

        # assertion
        assert st_token.getNbTrades() == 0

    # Error_2
    # - buyer_st_addr is not whitelisted
    def test_error_2(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()

        relayer = users["eoa4"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate request trade digest
        digest = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
            nonce=nonce,
        )

        # sign the digest by seller_st_addr
        signature = brownie.web3.eth.account._sign_hash(digest, seller_st_pk)

        # request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with brownie.reverts(f"AccountNotWhitelisted: {buyer_st_addr.lower()}"):
            st_token.requestTradeWithAuthorization(
                seller_st_addr,
                buyer_st_addr,
                sc_token.address,
                100,  # st_value
                200,  # sc_value
                "trade_memo",
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )

        # assertion
        assert st_token.getNbTrades() == 0

    # Error_3
    # - nonce is already used
    def test_error_3(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate request trade digest
        digest = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
            nonce=nonce,
        )

        # sign the digest by seller_st_addr
        signature = brownie.web3.eth.account._sign_hash(digest, seller_st_pk)

        # request trade with authorization (1st time)
        st_token.requestTradeWithAuthorization(
            seller_st_addr,
            buyer_st_addr,
            sc_token.address,
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce,
            signature.v,
            signature.r,
            signature.s,
            {"from": relayer},
        )

        # request trade with authorization (2nd time)
        # - transaction is sent not by seller_st_addr but by relayer
        with brownie.reverts(
            f"AuthorizationNonceAlreadyUsed: {seller_st_addr.lower()}, {nonce}"
        ):
            st_token.requestTradeWithAuthorization(
                seller_st_addr,
                buyer_st_addr,
                sc_token.address,
                100,  # st_value
                200,  # sc_value
                "trade_memo",
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )

    # Error_4
    # - Signature is not valid
    def test_error_4(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # generate nonce
        nonce = secrets.token_bytes(32)

        # generate request trade digest
        digest = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
            nonce=nonce,
        )

        # sign the digest by seller_st_addr
        signature = brownie.web3.eth.account._sign_hash(digest, seller_st_pk)

        # request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with brownie.reverts(
            f"InvalidAuthorizationSignature: {seller_st_addr.lower()}"
        ):
            st_token.requestTradeWithAuthorization(
                seller_st_addr,
                buyer_st_addr,
                sc_token.address,
                1000,  # st_value, value is not correct
                200,  # sc_value
                "trade_memo",
                nonce,
                signature.v,
                signature.r,
                signature.s,
                {"from": relayer},
            )


class TestCancelTradeWithAuthorization:
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
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [CANCEL-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [CANCEL-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_cancel_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [CANCEL-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, seller_st_pk)

        # [CANCEL-TRADE] request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        tx = st_token.cancelTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # assertion
        assert st_token.getTrade(1)[7] == 2  # status (Canceled)

        assert st_token.balanceOf(seller_st_addr) == 100
        assert st_token.balanceOf(buyer_st_addr) == 0

        assert tx.events["TradeCancelled"]["index"] == 1
        assert tx.events["TradeCancelled"]["sellerSTAccountAddress"] == seller_st_addr
        assert tx.events["TradeCancelled"]["buyerSTAccountAddress"] == buyer_st_addr
        assert tx.events["TradeCancelled"]["SCTokenAddress"] == sc_token.address
        assert (
            tx.events["TradeCancelled"]["sellerSCAccountAddress"] == seller_sc.address
        )
        assert tx.events["TradeCancelled"]["buyerSCAccountAddress"] == buyer_sc.address
        assert tx.events["TradeCancelled"]["STValue"] == 100
        assert tx.events["TradeCancelled"]["SCValue"] == 200

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - The trade is not cancellable
    def test_error_1(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [CANCEL-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [CANCEL-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_cancel_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [CANCEL-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, seller_st_pk)

        # [CANCEL-TRADE] request trade with authorization (1st time)
        # - transaction is sent not by seller_st_addr but by relayer
        st_token.cancelTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # [CANCEL-TRADE] request trade with authorization (2nd time)
        with brownie.reverts(f"TradeRequestIsNotAcceptable: {index}"):
            st_token.cancelTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_2
    # - Signature is not valid
    def test_error_2(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [CANCEL-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [CANCEL-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_cancel_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            index=index + 1,  # index is not correct
            nonce=nonce_2,
        )

        # [CANCEL-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, seller_st_pk)

        # [CANCEL-TRADE] request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with brownie.reverts(
            f"InvalidAuthorizationSignature: {seller_st_addr.lower()}"
        ):
            st_token.cancelTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )


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
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

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

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - The trade is not acceptable
    def test_error_1(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization (1st time)
        # - transaction is sent not by buyer_st_addr but by relayer
        st_token.acceptTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # [REQUEST-TRADE] request trade with authorization (2nd time)
        # - transaction is sent not by buyer_st_addr but by relayer
        with brownie.reverts(f"TradeRequestIsNotAcceptable: {index}"):
            st_token.acceptTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_2
    # - Signature is not valid
    def test_error_2(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with brownie.reverts(
            "InvalidAuthorizationSignature: 0x0000000000000000000000000000000000000000"
        ):
            st_token.acceptTradeWithAuthorization(
                index + 1,  # index is not correct
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_3
    # - ST balance of seller_st_addr is not enough
    def test_error_3(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, {"from": buyer_sc})

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=1000,  # value is greater than balance
            sc_value=200,
            memo="trade_memo",
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
            1000,  # st_value, value is greater than balance
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with brownie.reverts(
            f"ERC20InsufficientBalance: {seller_st_addr.lower()}, 100, 1000"
        ):
            st_token.acceptTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_4
    # - SC allowance of buyer_sc is not enough
    def test_error_4(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)
        sc_token.mint(buyer_sc.address, 200, {"from": issuer})

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with brownie.reverts(
            f"ERC20InsufficientAllowance: {st_token.address.lower()}, 0, 200"
        ):
            st_token.acceptTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )


class TestRejectTradeWithAuthorization:
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
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [REJECT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [REJECT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_reject_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REJECT-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REJECT-TRADE] reject trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        tx = st_token.rejectTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # assertion
        assert st_token.getTrade(1)[7] == 3  # status (Rejected)

        assert st_token.balanceOf(seller_st_addr) == 100
        assert st_token.balanceOf(buyer_st_addr) == 0

        assert tx.events["TradeRejected"]["index"] == 1
        assert tx.events["TradeRejected"]["sellerSTAccountAddress"] == seller_st_addr
        assert tx.events["TradeRejected"]["buyerSTAccountAddress"] == buyer_st_addr
        assert tx.events["TradeRejected"]["SCTokenAddress"] == sc_token.address
        assert tx.events["TradeRejected"]["sellerSCAccountAddress"] == seller_sc.address
        assert tx.events["TradeRejected"]["buyerSCAccountAddress"] == buyer_sc.address
        assert tx.events["TradeRejected"]["STValue"] == 100
        assert tx.events["TradeRejected"]["SCValue"] == 200

    ##########################################################
    # Error
    ##########################################################

    # Error_1
    # - The trade is not rejectable
    def test_error_1(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [REJECT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [REJECT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_reject_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            index=index,
            nonce=nonce_2,
        )

        # [REJECT-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REJECT-TRADE] reject trade with authorization (1st time)
        # - transaction is sent not by buyer_st_addr but by relayer
        st_token.rejectTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            {"from": relayer},
        )

        # [REJECT-TRADE] reject trade with authorization (2nd time)
        with brownie.reverts(f"TradeRequestIsNotAcceptable: {index}"):
            st_token.rejectTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )

    # Error_2
    # - Signature is not valid
    def test_error_2(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = admin.deploy(AuthIbetWST, "AuthIbetWST", issuer.address)
        st_token.mint(seller_st_addr, 100, {"from": issuer})

        # deploy SC token
        sc_token = admin.deploy(IbetERC20, "IbetERC20", issuer.address)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr, seller_sc.address, seller_sc.address, {"from": issuer}
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, {"from": issuer}
        )

        # [REQUEST-TRADE] generate nonce
        nonce_1 = secrets.token_bytes(32)

        # [REQUEST-TRADE] generate request trade digest
        digest_1 = eip712_helper.generate_request_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            seller_st_account_address=seller_st_addr,
            buyer_st_account_address=buyer_st_addr,
            sc_token_address=sc_token.address,
            st_value=100,
            sc_value=200,
            memo="trade_memo",
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
            100,  # st_value
            200,  # sc_value
            "trade_memo",
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            {"from": relayer},
        )

        # [REJECT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [REJECT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_reject_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(),
            index=index + 1,  # index is not correct
            nonce=nonce_2,
        )

        # [REJECT-TRADE] sign the digest by buyer_st_addr
        signature_2 = brownie.web3.eth.account._sign_hash(digest_2, buyer_st_pk)

        # [REJECT-TRADE] reject trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with brownie.reverts(f"InvalidAuthorizationSignature: {buyer_st_addr.lower()}"):
            st_token.rejectTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                {"from": relayer},
            )
