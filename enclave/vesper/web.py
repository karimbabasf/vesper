"""The operator console.

    python -m vesper.web        # then open http://127.0.0.1:8787

One page, four hands. A sentence goes in; the model reads it, the allowlist turns it into units,
CoW prices it, and the fence on Base says whether it is allowed. Only the last of those four is
authoritative, and the page is laid out to make that obvious.

Standard library only, no build step. It reads the deployed addresses from contracts/.env and says
so plainly when there are none.
"""

from __future__ import annotations

import json
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from vesper import chain, fence
from vesper.cli import BASE, format_units
from vesper.model import propose

STATIC = Path(__file__).parent / "static"
TYPES = {".html": "text/html; charset=utf-8", ".woff2": "font/woff2", ".txt": "text/plain"}

# The two the account is funded for. Anything else is refused before it reaches the chain.
SYMBOLS = {fence.WETH.lower(): "WETH", fence.USDC.lower(): "USDC"}


def deployment() -> chain.Deployment | None:
    try:
        return chain.Deployment.load()
    except (FileNotFoundError, KeyError):
        return None


def read(instruction: str) -> dict:
    """Walk the sentence through all four hands and report what each one said."""
    proposal = propose(instruction, BASE)

    answer = {
        "model": {"text": None, "tone": "quiet"},
        "gate": {"text": "waiting", "tone": "quiet"},
        "cow": {"text": "waiting", "tone": "quiet"},
        "fence": {"text": "waiting", "tone": "quiet"},
        "budget": None,
        "placeable": False,
        "needsFace": False,
        "order": None,
    }

    if proposal.raw is not None:
        answer["model"] = {"text": json.dumps(proposal.raw, indent=2), "tone": None}

    if proposal.error is not None:
        answer["model"] = {"text": proposal.error, "tone": "no"}
        return answer

    order = proposal.order
    if order is None:
        answer["gate"] = {"text": proposal.reason or "no order in that", "tone": "no"}
        return answer

    sell = BASE.lookup(order.sell_token)
    buy = BASE.lookup(order.buy_token)
    assert sell is not None and buy is not None

    answer["gate"] = {
        "tone": None,
        "rows": [
            ["sell", f"{format_units(order.sell_amount, sell.decimals)} {sell.symbol}"],
            ["buy", buy.symbol],
            ["units", str(order.sell_amount)],
            *(
                [["floor", f"{format_units(order.floor_amount, buy.decimals)} {buy.symbol}"]]
                if order.floor_amount is not None
                else []
            ),
        ],
    }

    live = deployment()
    if live is None:
        answer["cow"] = {"text": "nothing deployed yet, so nothing to quote against", "tone": "quiet"}
        answer["fence"] = {"text": "no account on Base yet", "tone": "quiet"}
        return answer

    try:
        quoted = chain.quote(sell.address, buy.address, order.sell_amount, live.account)
    except Exception as error:  # a quote is an opinion, and losing it is not fatal
        answer["cow"] = {"text": f"no quote: {error}", "tone": "no"}
        quoted = None

    floor = order.floor_amount
    if quoted is not None:
        expected = int(quoted["buyAmount"])
        answer["cow"] = {
            "tone": None,
            "rows": [
                ["expected", f"{format_units(expected, buy.decimals)} {buy.symbol}"],
                ["floor", f"{format_units(floor, buy.decimals)} {buy.symbol}" if floor
                          else f"{format_units(expected, buy.decimals)} {buy.symbol} (the quote)"],
                ["good for", f"{chain.DEADLINE_SECONDS} seconds"],
            ],
        }

    limits = fence.limits(live, sell.address)
    state, why = limits.verdict(order.sell_amount)
    tone = {"allowed": None, "face": "face", "refused": "no"}[state]

    answer["fence"] = {
        "text": why,
        "tone": tone,
        "rows": [
            ["per trade", format_units(limits.per_trade_cap, sell.decimals)],
            ["left today", format_units(limits.remaining_today, sell.decimals)],
            ["needs a face above", format_units(limits.biometric_threshold, sell.decimals)],
        ],
    }
    answer["budget"] = budget_of(limits, sell.symbol, sell.decimals)
    answer["placeable"] = state in ("allowed", "face")
    answer["needsFace"] = state == "face"
    if answer["placeable"]:
        answer["order"] = {
            "sellToken": sell.address,
            "buyToken": buy.address,
            "sellAmount": str(order.sell_amount),
            "floor": None if floor is None else str(floor),
        }
    return answer


def budget_of(limits: fence.Limits, symbol: str, decimals: int) -> dict:
    return {
        "symbol": symbol,
        "cap": limits.daily_cap,
        "remaining": limits.remaining_today,
        "capText": format_units(limits.daily_cap, decimals),
        "remainingText": format_units(limits.remaining_today, decimals),
        "foot": "Drains as you trade, comes back as time passes."
        if limits.remaining_today
        else "Spent. It returns in proportion to the time since you spent it.",
    }


def budget() -> dict:
    live = deployment()
    if live is None:
        return {"budget": None}
    limits = fence.limits(live, fence.WETH)
    return {"budget": budget_of(limits, "WETH", 18)}


def prepare(request: dict) -> dict:
    """Fix the exact order, and say what a passkey would have to sign over.

    Two phases, because a passkey signs a challenge derived from the finished order and the order is
    not finished until CoW has priced it. The browser gets the exact order back here and hands the
    same one to /place, so the thing the face approved and the thing that gets signed are the same
    bytes and not two orders that merely look alike.
    """
    live = deployment()
    if live is None:
        return {"ok": False, "why": "No account deployed."}

    asked = request["order"]
    quoted = chain.quote(
        asked["sellToken"], asked["buyToken"], int(asked["sellAmount"]), live.account
    )
    floor = None if asked["floor"] is None else int(asked["floor"])
    order = chain.build_order(quoted, live.account, floor)
    _, op_hash = chain.build_user_op(order, live)
    return {
        "ok": True,
        "order": order,
        "challenge": chain.order_digest_challenge(order, op_hash),
        "uid": chain.order_uid(order, live.account),
    }


def register_passkey(request: dict) -> dict:
    live = deployment()
    if live is None:
        return {"ok": False, "receipt": ["No account deployed."]}

    result = chain.register_passkey(
        request["x"], request["y"], request["rpIdHash"], live
    )
    return {"ok": True, "receipt": [f"tx {result.get('transactionHash', '?')}", "passkey registered"]}


def place(request: dict) -> dict:
    """Register the order with CoW, then presign it through the EntryPoint."""
    live = deployment()
    if live is None:
        return {"ok": False, "receipt": ["No account deployed."], "budget": None}

    order = request["order"]
    assertion = request.get("assertion")

    receipt = []
    try:
        chain.register_with_cow(order, live.account)
        receipt.append("orderbook accepted it")

        result = chain.presign(order, live, assertion)
        receipt.append(f"tx {result.get('transactionHash', '?')}")

        uid = chain.order_uid(order, live.account)
        receipt.append(f"uid {uid}")
        receipt.append(
            "settlement holds the signature" if chain.presigned(uid)
            else "settlement does not hold it, so nothing will fill"
        )
    except Exception as error:
        receipt.append(str(error)[:400])
        return {"ok": False, "receipt": receipt, "budget": budget()["budget"]}

    return {"ok": True, "receipt": receipt, "uid": uid, "budget": budget()["budget"]}


def disarm(request: dict) -> dict:
    """Take back a presignature. The only thing that stops an order a solver has not filled yet."""
    live = deployment()
    if live is None:
        return {"ok": False, "receipt": ["No account deployed."]}

    uid = request["uid"]
    result = chain.cancel(uid, live)
    still = chain.presigned(uid)
    return {
        "ok": not still,
        "receipt": [
            f"tx {result.get('transactionHash', '?')}",
            "the settlement has let it go" if not still else "still armed, which should not happen",
        ],
    }


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:
        if self.path == "/":
            self._send(200, (STATIC / "console.html").read_bytes(), TYPES[".html"])
        elif self.path == "/budget":
            self._json(budget())
        elif self.path.startswith("/static/"):
            name = Path(self.path).name  # no traversal: the basename and nothing else
            asset = STATIC / name
            if not asset.is_file():
                self._send(404, b"not found", "text/plain")
                return
            self._send(200, asset.read_bytes(), TYPES.get(asset.suffix, "application/octet-stream"))
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        routes = {
            "/read": lambda body: read(body["instruction"]),
            "/prepare": prepare,
            "/place": place,
            "/disarm": disarm,
            "/passkey": register_passkey,
        }
        handler = routes.get(self.path)
        if handler is None:
            self._send(404, b"not found", "text/plain")
            return

        length = int(self.headers.get("content-length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json({"error": "that was not json"}, 400)
            return

        try:
            self._json(handler(body))
        except Exception:
            traceback.print_exc()
            self._json({"error": "the console broke, see the terminal"}, 500)


def make_server(port: int = 8787) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), _Handler)


if __name__ == "__main__":
    server = make_server()
    print(f"open http://127.0.0.1:{server.server_address[1]}")
    server.serve_forever()
