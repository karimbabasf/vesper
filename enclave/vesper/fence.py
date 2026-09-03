"""What the chain will allow, read from the chain.

Every number here comes from a call to the deployed VoicePolicy. Nothing is cached and nothing is
inferred from the enclave's own state: the point of the fence is that it answers independently of
whatever this process believes.
"""

from __future__ import annotations

from dataclasses import dataclass

from vesper.chain import Deployment, RPC, cast

# The tokens the console knows how to talk about, by address on Base.
WETH = "0x4200000000000000000000000000000000000006"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


@dataclass
class Limits:
    allowed: bool
    per_trade_cap: int
    daily_cap: int
    biometric_threshold: int
    remaining_today: int

    def verdict(self, sell_amount: int) -> tuple[str, str]:
        """What the fence would say about this amount, and why, in the words it would use."""
        if not self.allowed:
            return "refused", "this token is not on the allowlist"
        if sell_amount > self.per_trade_cap:
            return "refused", f"over the single trade cap of {self.per_trade_cap}"
        if sell_amount > self.remaining_today:
            return "refused", f"only {self.remaining_today} left in today's budget"
        if sell_amount > self.biometric_threshold:
            return "face", "above the threshold, so this one needs a passkey"
        return "allowed", "inside every limit"


@dataclass
class Session:
    key: str
    expiry: int

    @property
    def live(self) -> bool:
        return int(self.key, 16) != 0


def _words(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if line.strip()]


def limits(deployment: Deployment, token: str) -> Limits:
    raw = _words(
        cast(
            "call", deployment.policy, "limits(address,address)(uint128,uint128,uint128,bool)",
            deployment.account, token, "--rpc-url", RPC,
        )
    )
    remaining = _words(
        cast(
            "call", deployment.policy, "remainingToday(address,address)(uint256)",
            deployment.account, token, "--rpc-url", RPC,
        )
    )[0]
    return Limits(
        per_trade_cap=int(raw[0].split()[0]),
        daily_cap=int(raw[1].split()[0]),
        biometric_threshold=int(raw[2].split()[0]),
        allowed=raw[3] == "true",
        remaining_today=int(remaining.split()[0]),
    )


def session(deployment: Deployment) -> Session:
    raw = _words(
        cast(
            "call", deployment.policy,
            "sessions(address)(address,uint48,bytes32,bytes32,bytes32,bytes32)",
            deployment.account, "--rpc-url", RPC,
        )
    )
    return Session(key=raw[0], expiry=int(raw[1].split()[0]))


def balance(token: str, account: str) -> int:
    return int(
        _words(cast("call", token, "balanceOf(address)(uint256)", account, "--rpc-url", RPC))[0]
        .split()[0]
    )
