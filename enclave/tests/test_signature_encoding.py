"""Pin the hand-written signature encoder against cast, for the shapes cast can express.

The encoder exists because clientDataJSON is full of quote characters and cast takes tuples as a
quoted string. That is a shell-escaping problem on the path where a mistake means signing the wrong
bytes, so the encoder is checked rather than trusted.
"""

import subprocess

from vesper.chain import ASSERTION_TUPLE, encode_signature

SIG = "0x" + "ab" * 65


def by_cast(session_sig: str, tuple_arg: str, has: str) -> str:
    done = subprocess.run(
        ["cast", "abi-encode", f"f(bytes,bool,{ASSERTION_TUPLE})", session_sig, has, tuple_arg],
        capture_output=True, text=True, check=True,
    )
    return done.stdout.strip()


def test_no_assertion_matches_cast():
    empty = '(0x,"",0,0,0x' + "00" * 32 + ",0x" + "00" * 32 + ")"
    assert encode_signature(SIG, None) == by_cast(SIG, empty, "false")


def test_an_assertion_with_a_quote_free_client_data_matches_cast():
    assertion = {
        "authenticatorData": "0x" + "11" * 37,
        "clientDataJSON": "plain text, no quotes",
        "challengeIndex": 23,
        "typeIndex": 1,
        "r": "0x" + "22" * 32,
        "s": "0x" + "33" * 32,
    }
    argument = (
        f'({assertion["authenticatorData"]},"{assertion["clientDataJSON"]}",'
        f'{assertion["challengeIndex"]},{assertion["typeIndex"]},'
        f'{assertion["r"]},{assertion["s"]})'
    )
    assert encode_signature(SIG, assertion) == by_cast(SIG, argument, "true")


def test_real_client_data_round_trips_through_cast_decode():
    """The case cast cannot encode. Decode what we produced and check every field came back."""
    json_text = '{"type":"webauthn.get","challenge":"AAAA","origin":"https://localhost"}'
    assertion = {
        "authenticatorData": "0x" + "44" * 37,
        "clientDataJSON": json_text,
        "challengeIndex": 23,
        "typeIndex": 1,
        "r": "0x" + "55" * 32,
        "s": "0x" + "66" * 32,
    }
    encoded = encode_signature(SIG, assertion)
    decoded = subprocess.run(
        ["cast", "abi-decode", f"f()(bytes,bool,{ASSERTION_TUPLE})", encoded],
        capture_output=True, text=True, check=True,
    ).stdout

    assert "44" * 37 in decoded
    # cast prints a decoded string with its quotes escaped, which is the whole reason the encoder
    # is here: the same characters have to survive going the other way through its tuple parser.
    assert json_text.replace('"', '\\"') in decoded
    assert "55" * 32 in decoded
    assert "66" * 32 in decoded
    assert "true" in decoded


def test_the_order_uid_matches_the_value_solidity_produces():
    """One order, one uid, pinned on both sides of the language boundary.

    The enclave builds the uid to ask the settlement whether an order is armed, and the contract
    builds it to arm one. If the two ever disagree the console reports a perfectly good trade as
    unarmed, which is the kind of failure that sends you looking in the wrong place. The same
    constant is asserted in contracts/test/VesperAccount.t.sol.
    """
    from vesper.chain import order_uid

    order = {
        "sellToken": "0x4200000000000000000000000000000000000006",
        "buyToken": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "receiver": "0x8F54eaF529124254DF304D369ADcE6c84E838747",
        "sellAmount": "1000000000000000",
        "buyAmount": "2400000",
        "validTo": 1800000000,
        "appData": "0x" + "00" * 32,
        "feeAmount": "0",
    }
    assert order_uid(order, "0x8F54eaF529124254DF304D369ADcE6c84E838747") == (
        "0xc144da4e37238c28eb1b02160a3135cef11d503ebfa377585fae5e4bcae92965"
        "8f54eaf529124254df304d369adce6c84e838747"
        "6b49d200"
    )
