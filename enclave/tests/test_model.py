import pytest

from vesper.model import to_order
from vesper.order import Allowlist, Order, Token

# The Base token set from docs/venue.md.
BASE = Allowlist(
    [
        Token(symbol="USDC", decimals=6),
        Token(symbol="WETH", decimals=18, aliases=("eth", "ether")),
        Token(symbol="CBBTC", decimals=8, aliases=("bitcoin", "btc")),
    ]
)

ORDER = Order(
    action="SELL",
    sell_token="USDC",
    buy_token="WETH",
    sell_amount=2000_000000,
    floor_amount=800_000_000_000_000_000,
)


def answer(**overrides) -> dict:
    """What the model returns, with one field bent out of shape at a time."""
    return {
        "parsed": True,
        "action": "SELL",
        "sell_token": "USDC",
        "buy_token": "WETH",
        "sell_amount": "2000",
        "floor_amount": "0.8",
        **overrides,
    }


def test_converts_the_models_human_amounts_into_token_units():
    order, reason = to_order(answer(), BASE)

    assert order == ORDER
    assert reason is None


def test_accepts_an_order_with_no_floor():
    order, reason = to_order(answer(floor_amount=None), BASE)

    assert order is not None
    assert order.floor_amount is None
    assert reason is None


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"parsed": False}, "did not read this as an order"),
        ({"buy_token": "PEPE"}, "not on the allowlist"),
        ({"sell_token": "PEPE"}, "not on the allowlist"),
        ({"buy_token": "usdc"}, "cannot be sold for itself"),
        ({"action": "BUY"}, "not an action"),
        ({"sell_amount": "0.0000001"}, "6 decimals"),
        ({"sell_amount": "0"}, "not a positive amount"),
        ({"sell_amount": "-100"}, "not a positive amount"),
        ({"floor_amount": "cheap"}, "not a floor"),
    ],
)
def test_the_gate_refuses_and_says_which_check_failed(overrides, expected):
    order, reason = to_order(answer(**overrides), BASE)

    assert order is None
    assert expected in reason
