"""
Copyright BOOSTRY Co., Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
"""

import pytest
from hypothesis import event, settings, strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    rule,
    run_state_machine_as_test,
)

pytestmark = [
    pytest.mark.pbt,
    pytest.mark.filterwarnings(
        "ignore:The recursion limit will not be reset.*:"
        "hypothesis.errors.HypothesisWarning"
    ),
]

HOLDER_KEYS = ("eoa2", "eoa3", "eoa4", "eoa5")
SPENDER_KEY = "eoa6"
HOLDER_STRATEGY = st.sampled_from(HOLDER_KEYS)
AMOUNT_STRATEGY = st.integers(min_value=1, max_value=25)
TRADE_INDEX_STRATEGY = st.integers(min_value=0, max_value=100)
TRADE_ACTION_STRATEGY = st.sampled_from(("accept", "cancel", "reject"))

PBT_MAX_EXAMPLES = 25
PBT_STATEFUL_STEP_COUNT = 20
INITIAL_SC_BALANCE = 500


class IbetWSTBalanceAndTradeStateMachine(RuleBasedStateMachine):
    """Check WST balances, allowances, and trades with random operations."""

    def __init__(self, wst_class, sc_class, users):
        super().__init__()
        self.users = users
        self.owner = users["eoa1"]
        self.wst = wst_class.deploy("IbetWST", self.owner, sender=self.owner)
        self.sc = sc_class.deploy("SettlementCoin", self.owner, sender=self.owner)

        # Expected contract state used for comparison.
        self.wst_balance = {key: 0 for key in HOLDER_KEYS}
        self.sc_balance = {key: INITIAL_SC_BALANCE for key in HOLDER_KEYS}
        self.sc_allowance = {key: INITIAL_SC_BALANCE for key in HOLDER_KEYS}
        # WST allowances given to the shared spender account.
        self.allowance = {key: 0 for key in HOLDER_KEYS}
        self.total_supply = 0
        self.trades = {}
        # Trade IDs start at 1.
        self.next_trade_id = 1

        # Prepare each holder for WST transfers and SC settlement.
        for key in HOLDER_KEYS:
            account = self._account(key)
            self.wst.addAccountWhiteList(
                account.address,
                account.address,
                account.address,
                sender=self.owner,
            )
            self.sc.mint(account.address, INITIAL_SC_BALANCE, sender=self.owner)
            self.sc.approve(self.wst.address, INITIAL_SC_BALANCE, sender=account)

    def _account(self, key):
        return self.users[key]

    def _address(self, key):
        return self._account(key).address

    @staticmethod
    def _bounded_amount(raw_amount, available_amount):
        """Fit a generated amount into the available balance."""
        return 1 + ((raw_amount - 1) % available_amount)

    def _pending_trade_ids(self):
        return [
            trade_id for trade_id, trade in self.trades.items() if trade["state"] == 0
        ]

    @rule(holder_key=HOLDER_STRATEGY, amount=AMOUNT_STRATEGY)
    def mint(self, holder_key, amount):
        event("mint")
        self.wst.mint(self._address(holder_key), amount, sender=self.owner)
        self.wst_balance[holder_key] += amount
        self.total_supply += amount

    @rule(holder_key=HOLDER_STRATEGY, amount=AMOUNT_STRATEGY)
    def burn(self, holder_key, amount):
        available = self.wst_balance[holder_key]
        if available == 0:
            event("burn: no balance")
            return

        event("burn")
        amount = self._bounded_amount(amount, available)
        self.wst.burn(amount, sender=self._account(holder_key))
        self.wst_balance[holder_key] -= amount
        self.total_supply -= amount

    @rule(
        from_key=HOLDER_STRATEGY,
        to_key=HOLDER_STRATEGY,
        amount=AMOUNT_STRATEGY,
    )
    def transfer(self, from_key, to_key, amount):
        available = self.wst_balance[from_key]
        if from_key == to_key or available == 0:
            event("transfer: inapplicable")
            return

        event("transfer")
        amount = self._bounded_amount(amount, available)
        self.wst.transfer(self._address(to_key), amount, sender=self._account(from_key))
        self.wst_balance[from_key] -= amount
        self.wst_balance[to_key] += amount

    @rule(holder_key=HOLDER_STRATEGY, amount=AMOUNT_STRATEGY)
    def approve_spender(self, holder_key, amount):
        event("approve spender")
        self.wst.approve(
            self._address(SPENDER_KEY), amount, sender=self._account(holder_key)
        )
        self.allowance[holder_key] = amount

    @rule(
        from_key=HOLDER_STRATEGY,
        to_key=HOLDER_STRATEGY,
        amount=AMOUNT_STRATEGY,
    )
    def transfer_from(self, from_key, to_key, amount):
        available = min(self.wst_balance[from_key], self.allowance[from_key])
        if from_key == to_key or available == 0:
            event("transferFrom: inapplicable")
            return

        event("transferFrom")
        amount = self._bounded_amount(amount, available)
        self.wst.transferFrom(
            self._address(from_key),
            self._address(to_key),
            amount,
            sender=self._account(SPENDER_KEY),
        )
        self.wst_balance[from_key] -= amount
        self.wst_balance[to_key] += amount
        self.allowance[from_key] -= amount

    @rule(
        seller_key=HOLDER_STRATEGY,
        buyer_key=HOLDER_STRATEGY,
        st_value=AMOUNT_STRATEGY,
        sc_value=AMOUNT_STRATEGY,
    )
    def request_trade(self, seller_key, buyer_key, st_value, sc_value):
        if seller_key == buyer_key:
            event("request trade: same holder")
            return

        event("request trade")
        # Requesting a trade does not move any tokens yet.
        self.wst.requestTrade(
            self._address(buyer_key),
            self.sc.address,
            st_value,
            sc_value,
            "pbt",
            sender=self._account(seller_key),
        )
        self.trades[self.next_trade_id] = {
            "seller": seller_key,
            "buyer": buyer_key,
            "st_value": st_value,
            "sc_value": sc_value,
            "state": 0,
        }
        self.next_trade_id += 1

    @rule(
        trade_index=TRADE_INDEX_STRATEGY,
        action=TRADE_ACTION_STRATEGY,
    )
    def resolve_trade(self, trade_index, action):
        pending_ids = self._pending_trade_ids()
        if not pending_ids:
            event(f"{action} trade: no pending trade")
            return

        # Pick one of the trades that is still pending.
        trade_id = pending_ids[trade_index % len(pending_ids)]
        trade = self.trades[trade_id]
        seller_key = trade["seller"]
        buyer_key = trade["buyer"]

        if action == "accept":
            # Accept only when both sides have enough balance and allowance.
            can_accept = (
                self.wst_balance[seller_key] >= trade["st_value"]
                and self.sc_balance[buyer_key] >= trade["sc_value"]
                and self.sc_allowance[buyer_key] >= trade["sc_value"]
            )
            if not can_accept:
                event("accept trade: insufficient balance")
                return

            event("accept trade")
            self.wst.acceptTrade(trade_id, sender=self._account(buyer_key))
            self.wst_balance[seller_key] -= trade["st_value"]
            self.wst_balance[buyer_key] += trade["st_value"]
            self.sc_balance[buyer_key] -= trade["sc_value"]
            self.sc_balance[seller_key] += trade["sc_value"]
            self.sc_allowance[buyer_key] -= trade["sc_value"]
            trade["state"] = 1
        elif action == "cancel":
            event("cancel trade")
            self.wst.cancelTrade(trade_id, sender=self._account(seller_key))
            trade["state"] = 2
        else:
            event("reject trade")
            self.wst.rejectTrade(trade_id, sender=self._account(buyer_key))
            trade["state"] = 3

    @invariant()
    def contract_state_matches_model(self):
        assert self.wst.totalSupply() == self.total_supply
        assert self.wst.getNbTrades() == self.next_trade_id - 1

        for key in HOLDER_KEYS:
            address = self._address(key)
            assert self.wst.balanceOf(address) == self.wst_balance[key]
            assert self.sc.balanceOf(address) == self.sc_balance[key]
            assert (
                self.sc.allowance(address, self.wst.address) == self.sc_allowance[key]
            )
            assert (
                self.wst.allowance(address, self._address(SPENDER_KEY))
                == self.allowance[key]
            )

        assert sum(self.wst_balance.values()) == self.total_supply
        assert sum(self.sc_balance.values()) == INITIAL_SC_BALANCE * len(HOLDER_KEYS)

        for trade_id, expected in self.trades.items():
            assert self.wst.getTrade(trade_id) == (
                self._address(expected["seller"]),
                self._address(expected["buyer"]),
                self.sc.address,
                self._address(expected["seller"]),
                self._address(expected["buyer"]),
                expected["st_value"],
                expected["sc_value"],
                expected["state"],
                "pbt",
            )


def test_ibet_wst_balance_and_trade_stateful_pbt(IbetWST, IbetERC20, users):
    stateful_settings = settings(
        max_examples=PBT_MAX_EXAMPLES,
        stateful_step_count=PBT_STATEFUL_STEP_COUNT,
        deadline=None,
    )
    run_state_machine_as_test(
        lambda: IbetWSTBalanceAndTradeStateMachine(IbetWST, IbetERC20, users),
        settings=stateful_settings,
    )
