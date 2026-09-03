"""Place a real order on Base, through the fence.

Nothing here decides anything. It quotes, builds a user operation, has the session key sign it, and
hands it to the EntryPoint. Every check that matters happens in VoicePolicy, on chain, after this
code has had its say.

The session key is read from contracts/.env for now. In the finished system it is generated inside
the enclave at boot and never written anywhere, which is the whole point of step 5.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

RPC = "https://mainnet.base.org"
COW_API = "https://api.cow.fi/base/api/v1"
ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

ORDER_TUPLE = (
    "(address,address,address,uint256,uint256,uint32,bytes32,uint256,bytes32,bool,bytes32,bytes32)"
)
USEROP_TUPLE = "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes)"

# The deployed v0.7 EntryPoint answers to these selectors, and they are not the ones cast derives
# from the struct signature above. The encoding matches, only the canonical string does not, so
# these two are called by raw selector. Confirmed against the deployed bytecode on Base.
SEL_GET_USER_OP_HASH = "0x22cdde4c"
SEL_HANDLE_OPS = "0x765e827f"

KIND_SELL = "0xf3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775"
BALANCE_ERC20 = "0x5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9"

DEADLINE_SECONDS = 300


def env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


CONTRACTS_ENV = Path(__file__).resolve().parents[2] / "contracts" / ".env"


def cast(*args: str) -> str:
    done = subprocess.run(["cast", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"cast {' '.join(args[:2])} failed: {done.stderr.strip()[:300]}")
    return done.stdout.strip()


def post(url: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


def get(url: str) -> tuple[int, dict | None]:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, None


@dataclass
class Deployment:
    owner_key: str
    session_key: str
    account: str
    gate: str
    policy: str
    settings: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Deployment":
        values = env(CONTRACTS_ENV)
        return cls(
            owner_key=values["PRIVATE_KEY"],
            session_key=values["SESSION_PRIVATE_KEY"],
            account=values["ACCOUNT"],
            gate=values["GATE"],
            policy=values["POLICY"],
            settings=values,
        )


def quote(sell_token: str, buy_token: str, sell_amount: int, account: str) -> dict:
    """Ask CoW what this trade is worth right now. An estimate with a short shelf life."""
    status, body = post(
        f"{COW_API}/quote",
        {
            "sellToken": sell_token,
            "buyToken": buy_token,
            "from": account,
            "receiver": account,
            "sellAmountBeforeFee": str(sell_amount),
            "kind": "sell",
            "partiallyFillable": False,
            "sellTokenBalance": "erc20",
            "buyTokenBalance": "erc20",
            "signingScheme": "presign",
            "onchainOrder": False,
            "priceQuality": "optimal",
            "validFor": DEADLINE_SECONDS,
        },
    )
    if status != 200:
        raise RuntimeError(f"quote refused: {json.dumps(body)[:300]}")
    return body["quote"]


def build_order(quoted: dict, account: str, floor: int | None) -> dict:
    """The order as it will be signed. buyAmount is the floor, and it is what gets spoken."""
    return {
        "sellToken": quoted["sellToken"],
        "buyToken": quoted["buyToken"],
        "receiver": account,
        "sellAmount": quoted["sellAmount"],
        "buyAmount": str(floor if floor is not None else quoted["buyAmount"]),
        "validTo": int(time.time()) + DEADLINE_SECONDS,
        "appData": quoted["appData"],
        # CoW takes its fee inside the price now; an order carrying a fee is rejected outright.
        "feeAmount": "0",
        "kind": "sell",
        "partiallyFillable": False,
        "sellTokenBalance": "erc20",
        "buyTokenBalance": "erc20",
    }


def register_with_cow(order: dict, account: str) -> str:
    """Tell the orderbook the order exists. It waits for the onchain presignature before filling."""
    status, body = post(
        f"{COW_API}/orders",
        {**order, "from": account, "signingScheme": "presign", "signature": "0x"},
    )
    if status not in (200, 201):
        raise RuntimeError(f"orderbook refused: {json.dumps(body)[:300]}")
    return body


def _order_args(order: dict) -> str:
    return (
        f'({order["sellToken"]},{order["buyToken"]},{order["receiver"]},'
        f'{order["sellAmount"]},{order["buyAmount"]},{order["validTo"]},'
        f'{order["appData"]},{order["feeAmount"]},{KIND_SELL},false,'
        f"{BALANCE_ERC20},{BALANCE_ERC20})"
    )


def presign(order: dict, deployment: Deployment) -> dict:
    """Build the user operation, sign it with the session key, and hand it to the EntryPoint.

    The account never sees a decision: the EntryPoint asks VoicePolicy, and only a SIG_OK gets as
    far as calling the gate.
    """
    place = cast("calldata", f"placeOrder({ORDER_TUPLE})", _order_args(order))
    execution = (
        deployment.gate.lower().replace("0x", "")
        + f"{0:064x}"
        + place.replace("0x", "")
    )
    call_data = cast("calldata", "execute(bytes32,bytes)", "0x" + "00" * 32, "0x" + execution)

    nonce = cast(
        "call", ENTRY_POINT, "getNonce(address,uint192)(uint256)",
        deployment.account, "0", "--rpc-url", RPC,
    ).split()[0]

    verification_gas, call_gas, pre_verification = 400_000, 600_000, 120_000
    max_fee, priority_fee = 200_000_000, 2_000_000  # 0.2 gwei and 0.002 gwei
    account_gas_limits = f"0x{verification_gas:032x}{call_gas:032x}"
    gas_fees = f"0x{priority_fee:032x}{max_fee:032x}"

    def op(signature: str) -> str:
        return (
            f"({deployment.account},{nonce},0x,{call_data},{account_gas_limits},"
            f"{pre_verification},{gas_fees},{signature})"
        )

    op_hash = cast(
        "call", ENTRY_POINT,
        "--data", SEL_GET_USER_OP_HASH
        + cast("abi-encode", f"f({USEROP_TUPLE})", op("0x")).removeprefix("0x"),
        "--rpc-url", RPC,
    )

    session_sig = cast("wallet", "sign", "--private-key", deployment.session_key, op_hash)
    packed = cast(
        "abi-encode",
        "f(bytes,bool,(bytes,string,bytes32,bytes32))",
        session_sig,
        "false",
        '(0x,"",0x' + "00" * 32 + ",0x" + "00" * 32 + ")",
    )

    owner = cast("wallet", "address", "--private-key", deployment.owner_key)
    receipt = cast(
        "send", ENTRY_POINT,
        "--data", SEL_HANDLE_OPS
        + cast(
            "abi-encode", f"f({USEROP_TUPLE}[],address)", f"[{op(packed)}]", owner
        ).removeprefix("0x"),
        "--private-key", deployment.owner_key, "--rpc-url", RPC, "--json",
    )
    return json.loads(receipt)


SETTLEMENT = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41"


def presigned(uid: str) -> bool:
    """Ask the settlement contract directly. The only answer that counts."""
    result = cast(
        "call", SETTLEMENT, "preSignature(bytes)(uint256)", uid, "--rpc-url", RPC
    )
    return result.split()[0] != "0"


def status(uid: str) -> dict | None:
    code, body = get(f"{COW_API}/orders/{uid}")
    return body if code == 200 else None
