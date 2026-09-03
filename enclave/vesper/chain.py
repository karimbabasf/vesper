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
SETTLEMENT = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41"

ORDER_TUPLE = (
    "(address,address,address,uint256,uint256,uint32,bytes32,uint256,bytes32,bool,bytes32,bytes32)"
)

# Nine fields. The eight-field version of this string produced selectors the deployed EntryPoint
# does not answer to, and operations laid out one field short: paymasterAndData was missing, so the
# signature landed where the paymaster belongs. Checked by selector, not by memory:
#   handleOps(USEROP_TUPLE[],address) -> 0x765e827f, present in the deployed bytecode.
USEROP_TUPLE = "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)"

# One assertion, matching the Assertion struct in src/WebAuthn.sol.
ASSERTION_TUPLE = "(bytes,string,uint256,uint256,bytes32,bytes32)"

KIND_SELL = "0xf3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775"
BALANCE_ERC20 = "0x5a28e9363bb942b639270062aa6bb295f434bcdfc42c97267bf003f272060dc9"

DEADLINE_SECONDS = 300

# Enough for validation plus one setPreSignature, measured on a fork at 195k for the whole
# operation. Rounded up rather than tuned: the account pays for what it uses, not what it asks for.
VERIFICATION_GAS = 400_000
CALL_GAS = 600_000
PRE_VERIFICATION_GAS = 120_000
MAX_FEE_WEI = 200_000_000  # 0.2 gwei
PRIORITY_FEE_WEI = 2_000_000  # 0.002 gwei

EMPTY_ASSERTION = '(0x,"",0,0,0x' + "00" * 32 + ",0x" + "00" * 32 + ")"


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
    policy: str
    settings: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Deployment":
        values = env(CONTRACTS_ENV)
        return cls(
            owner_key=values["PRIVATE_KEY"],
            session_key=values["SESSION_PRIVATE_KEY"],
            account=values["ACCOUNT"],
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


def order_args(order: dict) -> str:
    return (
        f'({order["sellToken"]},{order["buyToken"]},{order["receiver"]},'
        f'{order["sellAmount"]},{order["buyAmount"]},{order["validTo"]},'
        f'{order["appData"]},{order["feeAmount"]},{KIND_SELL},false,'
        f"{BALANCE_ERC20},{BALANCE_ERC20})"
    )


def order_digest_challenge(order: dict) -> str:
    """keccak256(abi.encode(order)), which is what a passkey has to sign over above the threshold."""
    encoded = cast("abi-encode", f"f({ORDER_TUPLE})", order_args(order))
    return cast("keccak", encoded)


def _assertion_arg(assertion: dict | None) -> str:
    if assertion is None:
        return EMPTY_ASSERTION
    return (
        f'({assertion["authenticatorData"]},"{assertion["clientDataJSON"]}",'
        f'{assertion["challengeIndex"]},{assertion["typeIndex"]},'
        f'{assertion["r"]},{assertion["s"]})'
    )


def build_user_op(order: dict, deployment: Deployment) -> tuple[str, str]:
    """The unsigned operation, and the hash the EntryPoint will want signed."""
    call_data = cast("calldata", f"placeOrder({ORDER_TUPLE})", order_args(order))

    nonce = cast(
        "call", ENTRY_POINT, "getNonce(address,uint192)(uint256)",
        deployment.account, "0", "--rpc-url", RPC,
    ).split()[0]

    account_gas_limits = f"0x{VERIFICATION_GAS:032x}{CALL_GAS:032x}"
    gas_fees = f"0x{PRIORITY_FEE_WEI:032x}{MAX_FEE_WEI:032x}"

    def op(signature: str) -> str:
        return (
            f"({deployment.account},{nonce},0x,{call_data},{account_gas_limits},"
            f"{PRE_VERIFICATION_GAS},{gas_fees},0x,{signature})"
        )

    op_hash = cast(
        "call", ENTRY_POINT, f"getUserOpHash({USEROP_TUPLE})(bytes32)", op("0x"),
        "--rpc-url", RPC,
    ).split()[0]
    return op(""), op_hash


def presign(order: dict, deployment: Deployment, assertion: dict | None = None) -> dict:
    """Sign the operation with the session key and hand it to the EntryPoint.

    The account never sees a decision: the EntryPoint asks VoicePolicy, and only a SIG_OK gets as
    far as calling placeOrder. Above the biometric threshold the policy also wants `assertion`,
    which is a real WebAuthn assertion over keccak256(abi.encode(order)).
    """
    template, op_hash = build_user_op(order, deployment)

    session_sig = cast("wallet", "sign", "--private-key", deployment.session_key, op_hash)
    packed = cast(
        "abi-encode",
        f"f(bytes,bool,{ASSERTION_TUPLE})",
        session_sig,
        "true" if assertion else "false",
        _assertion_arg(assertion),
    )

    owner = cast("wallet", "address", "--private-key", deployment.owner_key)
    receipt = cast(
        "send", ENTRY_POINT, f"handleOps({USEROP_TUPLE}[],address)",
        f"[{template[:-1]}{packed})]", owner,
        "--private-key", deployment.owner_key, "--rpc-url", RPC, "--json",
    )
    return json.loads(receipt)


def presigned(uid: str) -> bool:
    """Ask the settlement contract directly. The only answer that counts."""
    result = cast(
        "call", SETTLEMENT, "preSignature(bytes)(uint256)", uid, "--rpc-url", RPC
    )
    return result.split()[0] != "0"


def order_uid(order: dict, account: str) -> str:
    """orderDigest || owner || validTo, the 56 bytes the settlement stores."""
    separator = cast("call", SETTLEMENT, "domainSeparator()(bytes32)", "--rpc-url", RPC).split()[0]
    type_hash = "0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489"
    struct_hash = cast(
        "keccak",
        cast(
            "abi-encode",
            "f(bytes32,address,address,address,uint256,uint256,uint32,bytes32,uint256,bytes32,bool,bytes32,bytes32)",
            type_hash, order["sellToken"], order["buyToken"], order["receiver"],
            order["sellAmount"], order["buyAmount"], str(order["validTo"]), order["appData"],
            order["feeAmount"], KIND_SELL, "false", BALANCE_ERC20, BALANCE_ERC20,
        ),
    )
    digest = cast("keccak", "0x1901" + separator[2:] + struct_hash[2:])
    return digest + account.lower().replace("0x", "") + f"{int(order['validTo']):08x}"


def status(uid: str) -> dict | None:
    code, body = get(f"{COW_API}/orders/{uid}")
    return body if code == 200 else None
