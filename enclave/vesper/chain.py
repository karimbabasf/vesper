"""Place a real order on Base, through the fence.

Nothing here decides anything. It quotes, builds a user operation, has the session key sign it, and
hands it to the EntryPoint. Every check that matters happens in VoicePolicy, on chain, after this
code has had its say.

The session key is read from contracts/.env for now. In the finished system it is generated inside
the enclave at boot and never written anywhere, which is the whole point of step 5.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# Point VESPER_RPC at `anvil --fork-url https://mainnet.base.org` to rehearse the whole path,
# including the transactions, without spending anything.
RPC = os.environ.get("VESPER_RPC", "https://mainnet.base.org")
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

# Enough for validation plus one setPreSignature, measured on a fork at about 230k for the whole
# operation. VoicePolicy will refuse anything above its own ceilings, and it charges the account's
# ether budget the worst case these numbers describe, so asking for far more than needed costs
# budget even when it costs no gas. maxFeePerGas is the one that matters: Base runs near 0.006 gwei.
VERIFICATION_GAS = 400_000
CALL_GAS = 400_000
PRE_VERIFICATION_GAS = 120_000
MAX_FEE_WEI = 200_000_000  # 0.2 gwei
PRIORITY_FEE_WEI = 2_000_000  # 0.002 gwei

def env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


CONTRACTS_ENV = Path(
    os.environ.get("VESPER_CONTRACTS_ENV")
    or Path(__file__).resolve().parents[2] / "contracts" / ".env"
)


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


def order_digest_challenge(order: dict, op_hash: str) -> str:
    """What a passkey signs above the threshold: keccak256(abi.encode(order, opHash)).

    The order alone is not enough. It would let one approval be replayed by any later operation
    carrying the same order, for as long as the order stayed valid. opHash carries the chain, the
    EntryPoint, the account and the nonce, so an approval is good for exactly one operation.
    """
    encoded = cast("abi-encode", f"f({ORDER_TUPLE},bytes32)", order_args(order), op_hash)
    return cast("keccak", encoded)


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _bytes32(value: str) -> bytes:
    return bytes.fromhex(value.removeprefix("0x")).rjust(32, b"\x00")


def _tail(data: bytes) -> bytes:
    """One dynamic value: its length, then its bytes padded out to a whole number of words."""
    padding = (-len(data)) % 32
    return _word(len(data)) + data + b"\x00" * padding


def encode_signature(session_sig: str, assertion: dict | None) -> str:
    """abi.encode(bytes sessionSig, bool hasAssertion, Assertion assertion).

    Written here rather than handed to `cast abi-encode` because clientDataJSON is a JSON object
    and cast takes tuples as a quoted string. Passing a string full of quotes through that parser
    is a shell-escaping problem on the one path where a mistake means a signature over the wrong
    bytes. Thirty lines of encoder is the cheaper risk, and test_signature_encoding.py pins it
    against cast for the cases cast can express.
    """
    signature = bytes.fromhex(session_sig.removeprefix("0x"))

    if assertion is None:
        authenticator, client_data = b"", b""
        challenge_index = type_index = 0
        r = s = b"\x00" * 32
    else:
        authenticator = bytes.fromhex(assertion["authenticatorData"].removeprefix("0x"))
        client_data = assertion["clientDataJSON"].encode()
        challenge_index = int(assertion["challengeIndex"])
        type_index = int(assertion["typeIndex"])
        r, s = _bytes32(assertion["r"]), _bytes32(assertion["s"])

    # The Assertion tuple is dynamic, so it is its own block and its offsets count from its start.
    inner_head = 6 * 32
    inner = (
        _word(inner_head)
        + _word(inner_head + len(_tail(authenticator)))
        + _word(challenge_index)
        + _word(type_index)
        + r
        + s
        + _tail(authenticator)
        + _tail(client_data)
    )

    head = 3 * 32
    encoded = (
        _word(head)
        + _word(1 if assertion is not None else 0)
        + _word(head + len(_tail(signature)))
        + _tail(signature)
        + inner
    )
    return "0x" + encoded.hex()


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
    packed = encode_signature(session_sig, assertion)

    owner = cast("wallet", "address", "--private-key", deployment.owner_key)
    receipt = cast(
        "send", ENTRY_POINT, f"handleOps({USEROP_TUPLE}[],address)",
        f"[{template[:-1]}{packed})]", owner,
        "--private-key", deployment.owner_key, "--rpc-url", RPC, "--json",
    )
    return json.loads(receipt)


def register_passkey(x: str, y: str, rp_id_hash: str, deployment: Deployment) -> dict:
    """Point the fence at a passkey that exists on this machine.

    The session key and its expiry are read back and rewritten unchanged: registerSession sets the
    whole record at once, so registering a passkey without carrying the current key across would
    revoke the agent as a side effect.
    """
    current = cast(
        "call", deployment.policy,
        "sessions(address)(address,uint48,bytes32,bytes32,bytes32,bytes32)",
        deployment.account, "--rpc-url", RPC,
    ).split()
    key, expiry, attestation = current[0], current[1], current[2]

    register = cast(
        "calldata", "registerSession(address,bytes32,uint48,bytes32,bytes32,bytes32)",
        key, attestation, expiry, rp_id_hash, x, y,
    )
    receipt = cast(
        "send", deployment.account, "ownerCall(address,uint256,bytes)(bytes)",
        deployment.policy, "0", register,
        "--private-key", deployment.owner_key, "--rpc-url", RPC, "--json",
    )
    return json.loads(receipt)


def cancel(uid: str, deployment: Deployment) -> dict:
    """Disarm an order that is already presigned.

    Revoking the session key stops new orders and does nothing to armed ones: a presignature is an
    instruction a solver may still act on until validTo. This is the other half of the kill switch,
    and it goes through the owner rather than the fence, because the fence has no authority over an
    order that already exists.
    """
    disarm = cast("calldata", "setPreSignature(bytes,bool)", uid, "false")
    receipt = cast(
        "send", deployment.account, "ownerCall(address,uint256,bytes)(bytes)",
        SETTLEMENT, "0", disarm,
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
