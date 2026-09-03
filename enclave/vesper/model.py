"""The model that turns a sentence into an order.

It reads the raw transcript and returns a structured order, or nothing. The allowlist is applied
here rather than left to the model: a token it invented never becomes an Order, whatever it says.
What the model produces is a proposal until a person hears it read back and the chain allows it.

Needs OPENAI_API_KEY, which is read from enclave/.env or the environment. Override the model with
VESPER_MODEL.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from pathlib import Path

from dataclasses import dataclass

from vesper.order import Allowlist, Order

ENDPOINT = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-5-mini"

SYSTEM = """You turn one spoken sentence into a swap order. The order is read back to the speaker
before anything happens and the chain enforces their limits, so a wrong order costs them a
correction. An invented one costs them money. Guessing is worse than refusing.

Set parsed to false if the sentence is not a complete swap instruction, if the quantity is not a
definite number (for example "half my USDC"), or if you are filling in anything the speaker did not
say. Amounts are in whole token units as decimal strings, never in base units. floor_amount is the
least the speaker will accept of the buy token, or null."""

SCHEMA = {
    "name": "order",
    "strict": True,
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["parsed", "action", "sell_token", "buy_token", "sell_amount", "floor_amount"],
        "properties": {
            "parsed": {"type": "boolean"},
            "action": {"type": ["string", "null"], "enum": ["SELL", None]},
            "sell_token": {"type": ["string", "null"]},
            "buy_token": {"type": ["string", "null"]},
            "sell_amount": {"type": ["string", "null"]},
            "floor_amount": {"type": ["string", "null"]},
        },
    },
}


def api_key() -> str | None:
    if os.environ.get("OPENAI_API_KEY"):
        return os.environ["OPENAI_API_KEY"]
    env = Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("OPENAI_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


def _units(amount: str, decimals: int) -> int | None:
    try:
        scaled = Decimal(amount) * (10**decimals)
    except (InvalidOperation, TypeError):
        return None
    if scaled != scaled.to_integral_value() or scaled <= 0:
        return None
    return int(scaled)


def to_order(payload: dict, allowlist: Allowlist) -> tuple[Order | None, str | None]:
    """Decide whether the model's answer becomes an Order.

    Returns (order, None) or (None, reason). The reason is for a person to read: it says which
    check the model's answer failed, not that it "seemed wrong".
    """
    if not payload.get("parsed"):
        return None, "the model did not read this as an order"

    sell = allowlist.lookup(payload.get("sell_token") or "")
    if sell is None:
        return None, f"{payload.get('sell_token')!r} is not on the allowlist"

    buy = allowlist.lookup(payload.get("buy_token") or "")
    if buy is None:
        return None, f"{payload.get('buy_token')!r} is not on the allowlist"

    if sell.symbol == buy.symbol:
        return None, f"{sell.symbol} cannot be sold for itself"

    if payload.get("action") != "SELL":
        return None, f"{payload.get('action')!r} is not an action this can perform"

    sell_amount = _units(payload.get("sell_amount"), sell.decimals)
    if sell_amount is None:
        return None, (
            f"{payload.get('sell_amount')!r} is not a positive amount"
            f" {sell.symbol} can hold to {sell.decimals} decimals"
        )

    floor = payload.get("floor_amount")
    floor_amount = None if floor in (None, "") else _units(floor, buy.decimals)
    if floor not in (None, "") and floor_amount is None:
        return None, f"{floor!r} is not a floor {buy.symbol} can hold"

    return Order(
        action="SELL",
        sell_token=sell.symbol,
        buy_token=buy.symbol,
        sell_amount=sell_amount,
        floor_amount=floor_amount,
    ), None


@dataclass
class Proposal:
    """One round trip: what the model said, and what the gate did with it."""

    raw: dict | None = None
    order: Order | None = None
    reason: str | None = None
    error: str | None = None


def propose(transcript: str, allowlist: Allowlist) -> Proposal:
    """Ask the model for an order and run its answer through the gate."""
    key = api_key()
    if key is None:
        return Proposal(error="no OPENAI_API_KEY in the environment or enclave/.env")

    body = json.dumps(
        {
            "model": os.environ.get("VESPER_MODEL", DEFAULT_MODEL),
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": transcript},
            ],
            "response_format": {"type": "json_schema", "json_schema": SCHEMA},
        }
    ).encode()

    request = urllib.request.Request(
        ENDPOINT,
        data=body,
        headers={"authorization": f"Bearer {key}", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
        raw = json.loads(payload["choices"][0]["message"]["content"])
    except urllib.error.HTTPError as error:
        return Proposal(error=f"{error.code} {error.read().decode()[:200]}")
    except Exception as error:  # network, timeout, malformed response
        return Proposal(error=str(error))

    order, reason = to_order(raw, allowlist)
    return Proposal(raw=raw, order=order, reason=reason)
