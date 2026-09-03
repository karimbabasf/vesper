"""The order, and the tokens an account will let it touch.

An Order is what the model derives from one sentence and what the chain is later asked to allow.
Amounts are integers in the token's own base units, never floats: a uint256 of USDC does not
survive a float, and neither does a floor you promised out loud.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Token:
    symbol: str
    decimals: int
    aliases: tuple[str, ...] = ()
    # Where it lives on Base. Empty for a token the console can name but not trade.
    address: str = ""


@dataclass
class Allowlist:
    tokens: list[Token]
    _by_word: dict[str, Token] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._by_word = {}
        for token in self.tokens:
            for word in (token.symbol, *token.aliases):
                self._by_word[word.lower()] = token

    def lookup(self, word: str) -> Token | None:
        return self._by_word.get(word.lower())


@dataclass(frozen=True)
class Order:
    action: str
    sell_token: str
    buy_token: str
    sell_amount: int
    floor_amount: int | None
