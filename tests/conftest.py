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

import pytest


@pytest.fixture()
def users(accounts):
    eoa1 = accounts[0]
    eoa2 = accounts[1]
    eoa3 = accounts[2]
    eoa4 = accounts[3]
    eoa5 = accounts[4]
    eoa6 = accounts[5]
    eoa7 = accounts[6]
    eoa8 = accounts[7]
    eoa9 = accounts[8]
    eoa10 = accounts[9]
    users = {
        "eoa1": eoa1,
        "eoa2": eoa2,
        "eoa3": eoa3,
        "eoa4": eoa4,
        "eoa5": eoa5,
        "eoa6": eoa6,
        "eoa7": eoa7,
        "eoa8": eoa8,
        "eoa9": eoa9,
        "eoa10": eoa10,
    }

    yield users
