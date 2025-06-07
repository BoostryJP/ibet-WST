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

from typing import TypedDict

import pytest
from brownie import web3
from web3.middleware import geth_poa_middleware

web3.middleware_onion.inject(geth_poa_middleware, layer=0)


class Users(TypedDict):
    admin: str
    trader: str
    issuer: str
    agent: str
    user1: str
    user2: str


@pytest.fixture()
def users(accounts):
    admin = accounts[0]
    user1 = accounts[1]
    user2 = accounts[2]
    user3 = accounts[3]
    user4 = accounts[4]
    user5 = accounts[5]
    users = {
        "admin": admin,
        "user1": user1,
        "user2": user2,
        "user3": user3,
        "user4": user4,
        "user5": user5,
    }

    yield users
