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

from subprocess import DEVNULL
from typing import Generator, TypedDict

import pytest
from brownie import web3
from brownie.network.rpc import anvil as brownie_anvil_rpc
from web3.middleware.geth_poa import geth_poa_middleware

web3.middleware_onion.inject(geth_poa_middleware, layer=0)
setattr(brownie_anvil_rpc, "PIPE", DEVNULL)


class Users(TypedDict):
    eoa1: str
    eoa2: str
    eoa3: str
    eoa4: str
    eoa5: str
    eoa6: str
    eoa7: str
    eoa8: str
    eoa9: str
    eoa10: str


@pytest.fixture()
def users(accounts) -> Generator[Users, None, None]:
    users: Users = {
        "eoa1": accounts[0],
        "eoa2": accounts[1],
        "eoa3": accounts[2],
        "eoa4": accounts[3],
        "eoa5": accounts[4],
        "eoa6": accounts[5],
        "eoa7": accounts[6],
        "eoa8": accounts[7],
        "eoa9": accounts[8],
        "eoa10": accounts[9],
    }

    yield users
