"""Turn a spoken sentence into an order, from a terminal.

    python -m vesper.cli "sell two thousand USDC into ETH floor 0.8"
    python -m vesper.cli            # then type a line at a time, ctrl-d to stop

Needs OPENAI_API_KEY in enclave/.env or the environment.
"""

from __future__ import annotations

import sys

from vesper.model import Proposal, propose
from vesper.order import Allowlist, Token

BASE = Allowlist(
    [
        Token(symbol="USDC", decimals=6),
        Token(symbol="WETH", decimals=18, aliases=("eth", "ether")),
        Token(symbol="CBBTC", decimals=8, aliases=("bitcoin", "btc")),
    ]
)


def format_units(amount: int, decimals: int) -> str:
    whole, fraction = divmod(amount, 10**decimals)
    digits = str(fraction).rjust(decimals, "0").rstrip("0")
    return f"{whole}.{digits}" if digits else str(whole)


def _row(label: str, human: str, units: str = "") -> str:
    return f"  {label:<8} {human:<25} {units}".rstrip()


def render(transcript: str, result: Proposal, allowlist: Allowlist = BASE) -> str:
    """What the model made of one sentence, or why there is nothing to act on."""
    if result.error is not None:
        return f'unavailable  "{transcript}"\n  {result.error}'

    order = result.order
    if order is None:
        return f'refused    "{transcript}"\n  {result.reason}'

    sell = allowlist.lookup(order.sell_token)
    buy = allowlist.lookup(order.buy_token)
    assert sell is not None and buy is not None

    lines = [
        f'accepted   "{transcript}"',
        _row("action", order.action),
        _row(
            "sell",
            f"{format_units(order.sell_amount, sell.decimals)} {order.sell_token}",
            str(order.sell_amount),
        ),
        _row("buy", order.buy_token),
    ]
    if order.floor_amount is not None:
        lines.append(
            _row(
                "floor",
                f"{format_units(order.floor_amount, buy.decimals)} {order.buy_token}",
                str(order.floor_amount),
            )
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    lines = [" ".join(argv)] if argv else (line.strip() for line in sys.stdin)

    for transcript in lines:
        if not transcript:
            continue
        print(render(transcript, propose(transcript, BASE)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
