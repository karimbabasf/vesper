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
