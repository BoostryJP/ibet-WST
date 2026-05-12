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

from tests.helper import eip712_helper
from tests.helper.ape_utils import (
    ZERO_ADDRESS,
    chain_id,
    event_args,
    recover_hash,
    reverts,
    sign_hash,
    to_hex,
    tx_sender,
)


class TestDeploy:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    def test_normal_1(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # assertion
        assert token.owner() == issuer.address
        assert token.name() == "AuthIbetWST"
        assert token.symbol() == "IWST"
        assert token.decimals() == 0
        assert token.totalSupply() == 0
        assert token.balanceOf(issuer.address) == 0

        domain_separator = eip712_helper.generate_domain_separator(
            name=token.name(),
            version="1",
            chain_id=chain_id(),
            verifying_contract=token.address,
        )
        assert to_hex(token.DOMAIN_SEPARATOR()) == "0x" + domain_separator.hex()


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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, issuer_pk)

        # mint with authorization
        # - transaction is sent not by issuer but by relayer
        tx = token.mintWithAuthorization(
            user.address,
            100,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            sender=relayer,
        )

        # assertion
        assert token.usedNonces(issuer_addr, nonce) is True
        assert event_args(tx, token.AuthorizationUsed)["authorizer"] == issuer_addr
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce)

        assert token.balanceOf(user.address) == 100

        assert event_args(tx, token.Mint)["to"] == user.address
        assert event_args(tx, token.Mint)["value"] == 100

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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, issuer_pk)

        # mint with authorization
        # - transaction is sent not by issuer but by relayer
        with reverts(token, "InvalidAuthorizationSignature", authorizer=issuer_addr):
            token.mintWithAuthorization(
                relayer.address,  # incorrect account address
                100,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, other_pk)

        # mint with authorization
        # - transaction is sent not by issuer but by relayer
        with reverts(token, "InvalidAuthorizationSignature", authorizer=issuer_addr):
            token.mintWithAuthorization(
                user.address,
                100,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                sender=relayer,
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, issuer_pk)

        # mint with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            sender=relayer,
        )

        # mint with authorization (2nd time)
        # - transaction is sent not by issuer but by relayer
        with reverts(
            token.AuthorizationNonceAlreadyUsed,
            authorizer=issuer_addr,
            nonce=nonce,
        ):
            token.mintWithAuthorization(
                user.address,
                100,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user_addr,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, user_pk)

        # [BURN] burn with authorization
        # - transaction is sent not by user but by relayer
        tx = token.burnWithAuthorization(
            user_addr,
            100,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert token.usedNonces(user_addr, nonce_2) is True
        assert event_args(tx, token.AuthorizationUsed)["authorizer"] == user_addr
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce_2)

        assert token.balanceOf(user_addr) == 0

        assert event_args(tx, token.Burn)["from"] == user_addr
        assert event_args(tx, token.Burn)["value"] == 100

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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, issuer_pk)

        # [BURN] burn with authorization
        # - transaction is sent not by user but by relayer
        with reverts(
            token.InvalidAuthorizationSignature,
            authorizer=relayer.address,
        ):
            token.burnWithAuthorization(
                relayer.address,  # incorrect account address
                100,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, other_pk)

        # [BURN] burn with authorization
        # - transaction is sent not by user but by relayer
        with reverts(token, "InvalidAuthorizationSignature", authorizer=user.address):
            token.burnWithAuthorization(
                user.address,
                100,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user_pk, user_addr = eip712_helper.generate_account()
        relayer = users["eoa3"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user_addr,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, user_pk)

        # [BURN] burn with authorization (1st time)
        # - transaction is sent not by user but by relayer
        token.burnWithAuthorization(
            user_addr,
            100,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # [BURN] burn with authorization (2nd time)
        # - transaction is sent not by user but by relayer
        with reverts(
            token.AuthorizationNonceAlreadyUsed,
            authorizer=user_addr,
            nonce=nonce_2,
        ):
            token.burnWithAuthorization(
                user_addr,
                100,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )

    # Error_3
    # - insufficient balance
    def test_error_3(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        user_pk, user_addr = eip712_helper.generate_account()
        relayer = users["eoa3"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

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
        signature_2 = sign_hash(digest_2, user_pk)

        # [BURN] burn with authorization
        # - transaction is sent not by user but by relayer
        with reverts(
            token.ERC20InsufficientBalance,
            sender=user_addr,
            balance=0,
            needed=100,
        ):
            token.burnWithAuthorization(
                user_addr,
                100,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )


class TestForceBurnFromWithAuthorization:
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
        )

        # [FORCE-BURN-FROM] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [FORCE-BURN-FROM] generate force burn from digest
        digest_2 = eip712_helper.generate_force_burn_from_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            account_address=user.address,
            value=50,
            nonce=nonce_2,
        )

        # [FORCE-BURN-FROM] sign the digest
        # - signature is signed by issuer
        signature_2 = sign_hash(digest_2, issuer_pk)

        # [FORCE-BURN-FROM] force burn from with authorization
        # - transaction is sent not by user but by relayer
        tx = token.forceBurnFromWithAuthorization(
            user.address,
            50,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert token.usedNonces(issuer_addr, nonce_2) is True
        assert event_args(tx, token.AuthorizationUsed)["authorizer"] == issuer_addr
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce_2)

        assert token.balanceOf(user.address) == 50

        assert event_args(tx, token.Burn)["from"] == user.address
        assert event_args(tx, token.Burn)["value"] == 50

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
        other = users["eoa4"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
        )

        # [FORCE-BURN-FROM] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [FORCE-BURN-FROM] generate force burn from digest
        digest_2 = eip712_helper.generate_force_burn_from_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            account_address=user.address,
            value=50,
            nonce=nonce_2,
        )

        # [FORCE-BURN-FROM] sign the digest
        signature_2 = sign_hash(digest_2, issuer_pk)

        # [FORCE-BURN-FROM] force burn from with authorization
        # - transaction is sent not by user but by relayer
        with reverts(token, "InvalidAuthorizationSignature", authorizer=issuer_addr):
            token.forceBurnFromWithAuthorization(
                other.address,  # incorrect account address
                50,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
        )

        # [FORCE-BURN-FROM] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [FORCE-BURN-FROM] generate force burn from digest
        digest_2 = eip712_helper.generate_force_burn_from_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            account_address=user.address,
            value=50,
            nonce=nonce_2,
        )

        # [FORCE-BURN-FROM] sign the digest
        # - signature is signed by other account, not token owner
        signature_2 = sign_hash(digest_2, other_pk)

        # [FORCE-BURN-FROM] force burn from with authorization
        # - transaction is sent not by user but by relayer
        with reverts(token, "InvalidAuthorizationSignature", authorizer=issuer_addr):
            token.forceBurnFromWithAuthorization(
                user.address,
                50,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

        # [MINT] mint with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.mintWithAuthorization(
            user.address,
            100,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
        )

        # [FORCE-BURN-FROM] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [FORCE-BURN-FROM] generate force burn from digest
        digest_2 = eip712_helper.generate_force_burn_from_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            account_address=user.address,
            value=50,
            nonce=nonce_2,
        )

        # [FORCE-BURN-FROM] sign the digest
        signature_2 = sign_hash(digest_2, issuer_pk)

        # [FORCE-BURN-FROM] force burn from with authorization (1st time)
        # - transaction is sent not by user but by relayer
        token.forceBurnFromWithAuthorization(
            user.address,
            50,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # [FORCE-BURN-FROM] force burn from with authorization (2nd time)
        # - transaction is sent not by user but by relayer
        with reverts(
            token.AuthorizationNonceAlreadyUsed,
            authorizer=issuer_addr,
            nonce=nonce_2,
        ):
            token.forceBurnFromWithAuthorization(
                user.address,
                50,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )

    # Error_3
    # - insufficient balance
    def test_error_3(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

        # [FORCE-BURN-FROM] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [FORCE-BURN-FROM] generate force burn from digest
        digest_2 = eip712_helper.generate_force_burn_from_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            account_address=user.address,
            value=50,
            nonce=nonce_2,
        )

        # [FORCE-BURN-FROM] sign the digest
        signature_2 = sign_hash(digest_2, issuer_pk)

        # [FORCE-BURN-FROM] force burn from with authorization
        # - transaction is sent not by user but by relayer
        with reverts(
            token.ERC20InsufficientBalance,
            sender=user.address,
            balance=0,
            needed=50,
        ):
            token.forceBurnFromWithAuthorization(
                user.address,
                50,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, issuer_pk)

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
            sender=relayer,
        )

        # assertion
        assert token.usedNonces(issuer_addr, nonce) is True
        assert event_args(tx, token.AuthorizationUsed)["authorizer"] == issuer_addr
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce)

        assert token.accountWhiteList(user_st.address) == (
            user_st.address,
            user_sc_in.address,
            user_sc_out.address,
            True,
        )
        assert (
            event_args(tx, token.AccountWhiteListAdded)["accountAddress"]
            == user_st.address
        )

    # Normal_2
    # - Check that a delegated account manager can add an account to the whitelist with authorization
    def test_normal_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        account_manager_pk, account_manager_addr = eip712_helper.generate_account()
        user_st = users["eoa3"]
        user_sc_in = users["eoa4"]
        user_sc_out = users["eoa5"]
        relayer = users["eoa6"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # delegate whitelist management
        token.setAccountManager(account_manager_addr, True, sender=issuer)

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

        # sign the digest by delegated account manager
        signature = sign_hash(digest, account_manager_pk)

        # add account to whitelist with authorization
        tx = token.addAccountWhiteListWithAuthorization(
            user_st.address,
            user_sc_in.address,
            user_sc_out.address,
            nonce,
            signature.v,
            signature.r,
            signature.s,
            sender=relayer,
        )

        # assertion
        assert token.usedNonces(account_manager_addr, nonce) is True
        assert (
            event_args(tx, token.AuthorizationUsed)["authorizer"]
            == account_manager_addr
        )
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce)
        assert token.accountWhiteList(user_st.address) == (
            user_st.address,
            user_sc_in.address,
            user_sc_out.address,
            True,
        )
        assert (
            event_args(tx, token.AccountWhiteListAdded)["accountAddress"]
            == user_st.address
        )

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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, issuer_pk)

        invalid_digest = eip712_helper.generate_add_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=relayer.address,
            sc_account_address_in=user_sc_in.address,
            sc_account_address_out=user_sc_out.address,
            nonce=nonce,
        )
        invalid_recovered_address = recover_hash(
            invalid_digest,
            vrs=(signature.v, signature.r, signature.s),
        )

        # add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with reverts(
            token.AccountWhiteListOperationNotPermitted,
            caller=invalid_recovered_address,
        ):
            token.addAccountWhiteListWithAuthorization(
                relayer.address,  # incorrect account address
                user_sc_in.address,
                user_sc_out.address,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, other_pk)

        # add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with reverts(
            token.AccountWhiteListOperationNotPermitted,
            caller=other_addr,
        ):
            token.addAccountWhiteListWithAuthorization(
                user.address,
                user.address,
                user.address,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                sender=relayer,
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature = sign_hash(digest, issuer_pk)

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
            sender=relayer,
        )

        # add account to whitelist with authorization (2nd time)
        # - transaction is sent not by issuer but by relayer
        with reverts(
            token.AuthorizationNonceAlreadyUsed,
            authorizer=issuer_addr,
            nonce=nonce,
        ):
            token.addAccountWhiteListWithAuthorization(
                user.address,
                user.address,
                user.address,
                nonce,
                signature.v,
                signature.r,
                signature.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

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
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, issuer_pk)

        # [DELETE-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        tx = token.deleteAccountWhiteListWithAuthorization(
            user.address,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert token.usedNonces(issuer_addr, nonce_2) is True
        assert event_args(tx, token.AuthorizationUsed)["authorizer"] == issuer_addr
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce_2)

        assert token.accountWhiteList(user.address) == (
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            False,
        )
        assert (
            event_args(tx, token.AccountWhiteListDeleted)["accountAddress"]
            == user.address
        )

    # Normal_2
    # - Check that a delegated account manager can delete an account from the whitelist with authorization
    def test_normal_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]
        account_manager_pk, account_manager_addr = eip712_helper.generate_account()
        user = users["eoa3"]
        relayer = users["eoa4"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # delegate whitelist management
        token.setAccountManager(account_manager_addr, True, sender=issuer)

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

        # [ADD-WHITELIST] sign the digest by delegated account manager
        signature_1 = sign_hash(
            digest_1,
            account_manager_pk,
        )

        # [ADD-WHITELIST] add account to whitelist with authorization
        token.addAccountWhiteListWithAuthorization(
            user.address,
            user.address,
            user.address,
            nonce_1,
            signature_1.v,
            signature_1.r,
            signature_1.s,
            sender=relayer,
        )

        # [DELETE-WHITELIST] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [DELETE-WHITELIST] generate delete account whitelist digest
        digest_2 = eip712_helper.generate_delete_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=user.address,
            nonce=nonce_2,
        )

        # [DELETE-WHITELIST] sign the digest by delegated account manager
        signature_2 = sign_hash(
            digest_2,
            account_manager_pk,
        )

        # [DELETE-WHITELIST] delete account from whitelist with authorization
        tx = token.deleteAccountWhiteListWithAuthorization(
            user.address,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert token.usedNonces(account_manager_addr, nonce_2) is True
        assert (
            event_args(tx, token.AuthorizationUsed)["authorizer"]
            == account_manager_addr
        )
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce_2)
        assert token.accountWhiteList(user.address) == (
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            False,
        )
        assert (
            event_args(tx, token.AccountWhiteListDeleted)["accountAddress"]
            == user.address
        )

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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

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
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, issuer_pk)

        invalid_digest = eip712_helper.generate_delete_account_whitelist_digest(
            domain_separator=token.DOMAIN_SEPARATOR(),
            st_account_address=relayer.address,
            nonce=nonce_2,
        )
        invalid_recovered_address = recover_hash(
            invalid_digest,
            vrs=(signature_2.v, signature_2.r, signature_2.s),
        )

        # [DELETE-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with reverts(
            token.AccountWhiteListOperationNotPermitted,
            caller=invalid_recovered_address,
        ):
            token.deleteAccountWhiteListWithAuthorization(
                relayer.address,  # incorrect account address
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

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
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, other_pk)

        # [DELETE-WHITELIST] add account to whitelist with authorization
        # - transaction is sent not by issuer but by relayer
        with reverts(
            token.AccountWhiteListOperationNotPermitted,
            caller=other_addr,
        ):
            token.deleteAccountWhiteListWithAuthorization(
                user.address,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )

    # Error_2
    # - nonce is already used
    def test_error_2(self, AuthIbetWST, users):
        admin = users["eoa1"]
        issuer_pk, issuer_addr = eip712_helper.generate_account()
        user = users["eoa2"]
        relayer = users["eoa3"]

        # deploy
        token = AuthIbetWST.deploy("AuthIbetWST", issuer_addr, sender=admin)

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
        signature_1 = sign_hash(digest_1, issuer_pk)

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
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, issuer_pk)

        # [DELETE-WHITELIST] add account to whitelist with authorization (1st time)
        # - transaction is sent not by issuer but by relayer
        token.deleteAccountWhiteListWithAuthorization(
            user.address,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # [DELETE-WHITELIST] add account to whitelist with authorization (2nd time)
        # - transaction is sent not by issuer but by relayer
        with reverts(
            token.AuthorizationNonceAlreadyUsed,
            authorizer=issuer_addr,
            nonce=nonce_2,
        ):
            token.deleteAccountWhiteListWithAuthorization(
                user.address,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

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
            sender=issuer,
        )

        # assertion
        assert event_args(tx, token.AuthorizationUsed)["authorizer"] == from_user_addr
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce)

        assert event_args(tx, token.Transfer)["from"] == from_user_addr
        assert event_args(tx, token.Transfer)["to"] == to_user_addr
        assert event_args(tx, token.Transfer)["value"] == 100

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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with reverts(
            token.TransactionNotInValidPeriod,
            validAfter=_valid_after,
            validBefore=_valid_before,
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
                sender=issuer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with reverts(
            token.TransactionNotInValidPeriod,
            validAfter=_valid_after,
            validBefore=_valid_before,
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
                sender=issuer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

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
            sender=issuer,
        )

        # transfer with authorization (2nd time)
        # - transaction is sent not by from_user but by issuer
        with reverts(
            token.AuthorizationNonceAlreadyUsed,
            authorizer=from_user_addr,
            nonce=nonce,
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
                sender=issuer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with reverts(
            token.InvalidAuthorizationSignature,
            authorizer=from_user_addr,
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
                sender=issuer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with reverts(
            token.ERC20InsufficientBalance,
            sender=from_user_addr,
            balance=1000,
            needed=1001,
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
                sender=issuer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with reverts(
            AuthIbetWST, "AccountNotWhitelisted", accountAddress=from_user_addr
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
                sender=issuer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # transfer with authorization
        # - transaction is sent not by from_user but by issuer
        with reverts(AuthIbetWST, "AccountNotWhitelisted", accountAddress=to_user_addr):
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
                sender=issuer,
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

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
            sender=tx_sender(to_user_addr),
        )

        # assertion
        assert event_args(tx, token.AuthorizationUsed)["authorizer"] == from_user_addr
        assert event_args(tx, token.AuthorizationUsed)["nonce"] == to_hex(nonce)

        assert event_args(tx, token.Transfer)["from"] == from_user_addr
        assert event_args(tx, token.Transfer)["to"] == to_user_addr
        assert event_args(tx, token.Transfer)["value"] == 100

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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # receive with authorization
        with reverts(
            token.TransactionNotInValidPeriod,
            validAfter=_valid_after,
            validBefore=_valid_before,
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
                sender=tx_sender(to_user_addr),
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # receive with authorization
        with reverts(
            token.TransactionNotInValidPeriod,
            validAfter=_valid_after,
            validBefore=_valid_before,
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
                sender=tx_sender(to_user_addr),
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

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
            sender=tx_sender(to_user_addr),
        )

        # receive with authorization (2nd time)
        with reverts(
            token.AuthorizationNonceAlreadyUsed,
            authorizer=from_user_addr,
            nonce=nonce,
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
                sender=tx_sender(to_user_addr),
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # receive with authorization
        with reverts(
            token.InvalidAuthorizationSignature,
            authorizer=from_user_addr,
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
                sender=tx_sender(to_user_addr),
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
        )
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # receive with authorization
        with reverts(
            token.ERC20InsufficientBalance,
            sender=from_user_addr,
            balance=1000,
            needed=1001,
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
                sender=tx_sender(to_user_addr),
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            to_user_addr, to_user_addr, to_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # receive with authorization
        with reverts(
            AuthIbetWST, "AccountNotWhitelisted", accountAddress=from_user_addr
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
                sender=tx_sender(to_user_addr),
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
        token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # mint tokens to from_user
        token.mint(from_user_addr, 1000, sender=issuer)

        # add accounts to whitelist
        token.addAccountWhiteList(
            from_user_addr, from_user_addr, from_user_addr, sender=issuer
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
        signature = sign_hash(digest, from_user_pk)

        # receive with authorization
        with reverts(AuthIbetWST, "AccountNotWhitelisted", accountAddress=to_user_addr):
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
                sender=tx_sender(to_user_addr),
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc_in.address,
            seller_sc_out.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr,
            buyer_sc_in.address,
            buyer_sc_out.address,
            sender=issuer,
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
        signature = sign_hash(digest, seller_st_pk)

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
            sender=relayer,
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

        assert event_args(tx, st_token.TradeRequested)["index"] == 1
        assert (
            event_args(tx, st_token.TradeRequested)["sellerSTAccountAddress"]
            == seller_st_addr
        )
        assert (
            event_args(tx, st_token.TradeRequested)["buyerSTAccountAddress"]
            == buyer_st_addr
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

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
        signature = sign_hash(digest, seller_st_pk)

        # request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with reverts(
            AuthIbetWST, "AccountNotWhitelisted", accountAddress=seller_st_addr
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
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
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
        signature = sign_hash(digest, seller_st_pk)

        # request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with reverts(
            AuthIbetWST, "AccountNotWhitelisted", accountAddress=buyer_st_addr
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
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature = sign_hash(digest, seller_st_pk)

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
            sender=relayer,
        )

        # request trade with authorization (2nd time)
        # - transaction is sent not by seller_st_addr but by relayer
        with reverts(
            st_token.AuthorizationNonceAlreadyUsed,
            authorizer=seller_st_addr,
            nonce=nonce,
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
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature = sign_hash(digest, seller_st_pk)

        # request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with reverts(
            st_token.InvalidAuthorizationSignature,
            authorizer=seller_st_addr,
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
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [CANCEL-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [CANCEL-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_cancel_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [CANCEL-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, seller_st_pk)

        # [CANCEL-TRADE] request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        tx = st_token.cancelTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert st_token.getTrade(1)[7] == 2  # status (Canceled)

        assert st_token.balanceOf(seller_st_addr) == 100
        assert st_token.balanceOf(buyer_st_addr) == 0

        assert event_args(tx, st_token.TradeCancelled)["index"] == 1
        assert (
            event_args(tx, st_token.TradeCancelled)["sellerSTAccountAddress"]
            == seller_st_addr
        )
        assert (
            event_args(tx, st_token.TradeCancelled)["buyerSTAccountAddress"]
            == buyer_st_addr
        )
        assert (
            event_args(tx, st_token.TradeCancelled)["SCTokenAddress"]
            == sc_token.address
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [CANCEL-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [CANCEL-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_cancel_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [CANCEL-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, seller_st_pk)

        # [CANCEL-TRADE] request trade with authorization (1st time)
        # - transaction is sent not by seller_st_addr but by relayer
        st_token.cancelTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # [CANCEL-TRADE] request trade with authorization (2nd time)
        with reverts(AuthIbetWST, "TradeRequestIsNotAcceptable", index=index):
            st_token.cancelTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, seller_st_pk)

        # [CANCEL-TRADE] request trade with authorization
        # - transaction is sent not by seller_st_addr but by relayer
        with reverts(
            st_token.InvalidAuthorizationSignature,
            authorizer=seller_st_addr,
        ):
            st_token.cancelTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )


class TestAcceptTradeWithAuthorization:
    ##########################################################
    # Normal
    ##########################################################

    # Normal_1
    # - Accept trade with authorization
    def test_normal_1(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [ACCEPT-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        tx = st_token.acceptTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert st_token.getTrade(1)[7] == 1  # status (Executed)

        assert st_token.balanceOf(seller_st_addr) == 0
        assert st_token.balanceOf(buyer_st_addr) == 100
        assert sc_token.balanceOf(seller_sc.address) == 200
        assert sc_token.balanceOf(buyer_sc.address) == 0

        assert event_args(tx, st_token.TradeAccepted)["index"] == 1
        assert (
            event_args(tx, st_token.TradeAccepted)["sellerSTAccountAddress"]
            == seller_st_addr
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["buyerSTAccountAddress"]
            == buyer_st_addr
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
    # - Accept trade with authorization (same SC for seller and buyer)
    def test_normal_2(self, AuthIbetWST, IbetERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = seller_sc  # Use the same account for both seller and buyer SC

        relayer = users["eoa5"]

        # deploy ST token
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [ACCEPT-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        tx = st_token.acceptTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert st_token.getTrade(1)[7] == 1  # status (Executed)

        assert st_token.balanceOf(seller_st_addr) == 0
        assert st_token.balanceOf(buyer_st_addr) == 100
        assert (
            sc_token.balanceOf(seller_sc.address) == 200
        )  # seller_sc is same as buyer_sc
        assert (
            sc_token.balanceOf(buyer_sc.address) == 200
        )  # buyer_sc is same as seller_sc

        assert event_args(tx, st_token.TradeAccepted)["index"] == 1
        assert (
            event_args(tx, st_token.TradeAccepted)["sellerSTAccountAddress"]
            == seller_st_addr
        )
        assert (
            event_args(tx, st_token.TradeAccepted)["buyerSTAccountAddress"]
            == buyer_st_addr
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [ACCEPT-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization (1st time)
        # - transaction is sent not by buyer_st_addr but by relayer
        st_token.acceptTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # [REQUEST-TRADE] request trade with authorization (2nd time)
        # - transaction is sent not by buyer_st_addr but by relayer
        with reverts(AuthIbetWST, "TradeRequestIsNotAcceptable", index=index):
            st_token.acceptTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [ACCEPT-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with reverts(
            st_token.InvalidAuthorizationSignature,
            authorizer=ZERO_ADDRESS,
        ):
            st_token.acceptTradeWithAuthorization(
                index + 1,  # index is not correct
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
        )

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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [ACCEPT-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with reverts(
            st_token.ERC20InsufficientBalance,
            sender=seller_st_addr,
            balance=100,
            needed=1000,
        ):
            st_token.acceptTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REQUEST-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REQUEST-TRADE] request trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with reverts(
            st_token.ERC20InsufficientAllowance,
            spender=st_token.address,
            allowance=0,
            needed=200,
        ):
            st_token.acceptTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )

    # Error_5
    # - SC token transfer did not succeed
    # - This is a case where the SC token is not a valid ERC20 token
    def test_error_5(self, AuthIbetWST, MockERC20, users):
        admin = users["eoa1"]
        issuer = users["eoa2"]

        seller_st_pk, seller_st_addr = eip712_helper.generate_account()
        seller_sc = users["eoa3"]
        buyer_st_pk, buyer_st_addr = eip712_helper.generate_account()
        buyer_sc = users["eoa4"]

        relayer = users["eoa5"]

        # deploy ST token
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token (Fake ERC20)
        sc_token = MockERC20.deploy("IbetERC20", issuer.address, sender=admin)
        sc_token.mint(buyer_sc.address, 200, sender=issuer)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [ACCEPT-TRADE] SC: approve transfer
        sc_token.approve(st_token.address, 200, sender=buyer_sc)

        # [ACCEPT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [ACCEPT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_accept_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [ACCEPT-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [ACCEPT-TRADE] request trade with authorization
        # - ERC20 transfer is reverted
        with reverts("SC token transfer did not succeed"):
            st_token.acceptTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )

        # assertion
        assert st_token.balanceOf(seller_st_addr) == 100
        assert st_token.balanceOf(buyer_st_addr) == 0


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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
        )

        # [REJECT-TRADE] generate nonce
        nonce_2 = secrets.token_bytes(32)

        # [REJECT-TRADE] generate request trade digest
        index = st_token.getNbTrades()
        digest_2 = eip712_helper.generate_reject_trade_digest(
            domain_separator=st_token.DOMAIN_SEPARATOR(), index=index, nonce=nonce_2
        )

        # [REJECT-TRADE] sign the digest by buyer_st_addr
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REJECT-TRADE] reject trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        tx = st_token.rejectTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # assertion
        assert st_token.getTrade(1)[7] == 3  # status (Rejected)

        assert st_token.balanceOf(seller_st_addr) == 100
        assert st_token.balanceOf(buyer_st_addr) == 0

        assert event_args(tx, st_token.TradeRejected)["index"] == 1
        assert (
            event_args(tx, st_token.TradeRejected)["sellerSTAccountAddress"]
            == seller_st_addr
        )
        assert (
            event_args(tx, st_token.TradeRejected)["buyerSTAccountAddress"]
            == buyer_st_addr
        )
        assert (
            event_args(tx, st_token.TradeRejected)["SCTokenAddress"] == sc_token.address
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REJECT-TRADE] reject trade with authorization (1st time)
        # - transaction is sent not by buyer_st_addr but by relayer
        st_token.rejectTradeWithAuthorization(
            index,
            nonce_2,
            signature_2.v,
            signature_2.r,
            signature_2.s,
            sender=relayer,
        )

        # [REJECT-TRADE] reject trade with authorization (2nd time)
        with reverts(AuthIbetWST, "TradeRequestIsNotAcceptable", index=index):
            st_token.rejectTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
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
        st_token = AuthIbetWST.deploy("AuthIbetWST", issuer.address, sender=admin)
        st_token.mint(seller_st_addr, 100, sender=issuer)

        # deploy SC token
        sc_token = IbetERC20.deploy("IbetERC20", issuer.address, sender=admin)

        # add ST accounts to whitelist
        st_token.addAccountWhiteList(
            seller_st_addr,
            seller_sc.address,
            seller_sc.address,
            sender=issuer,
        )
        st_token.addAccountWhiteList(
            buyer_st_addr, buyer_sc.address, buyer_sc.address, sender=issuer
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
        signature_1 = sign_hash(digest_1, seller_st_pk)

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
            sender=relayer,
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
        signature_2 = sign_hash(digest_2, buyer_st_pk)

        # [REJECT-TRADE] reject trade with authorization
        # - transaction is sent not by buyer_st_addr but by relayer
        with reverts(
            st_token.InvalidAuthorizationSignature,
            authorizer=buyer_st_addr,
        ):
            st_token.rejectTradeWithAuthorization(
                index,
                nonce_2,
                signature_2.v,
                signature_2.r,
                signature_2.s,
                sender=relayer,
            )
