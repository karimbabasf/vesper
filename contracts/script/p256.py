#!/usr/bin/env python3
"""Sign a message hash with P-256, for the passkey tests.

Pure standard library on purpose: this exists so a fork test can hand the real RIP-7212 precompile
a signature it has never seen, and a test dependency that needs installing is a test nobody runs.

    p256.py pubkey <hex private key>            -> x,y
    p256.py sign   <hex private key> <hex hash> -> r,s      (s already in the low half)
"""

import sys

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def inverse(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        slope = (3 * p[0] * p[0] + A) * inverse(2 * p[1], P) % P
    else:
        slope = (q[1] - p[1]) * inverse(q[0] - p[0], P) % P
    x = (slope * slope - p[0] - q[0]) % P
    return (x, (slope * (p[0] - x) - p[1]) % P)


def multiply(k: int, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def sign(private: int, digest: int):
    # Deterministic k, derived from the key and the message. Not RFC 6979, but this only ever
    # signs test vectors and a repeatable k makes a failing test repeatable too.
    k = (pow(private ^ digest, 3, N - 1) + 1) % N
    while True:
        point = multiply(k, (GX, GY))
        r = point[0] % N
        if r:
            s = inverse(k, N) * (digest + r * private) % N
            if s:
                # WebAuthn verifiers reject the high half, so fold it down.
                return r, min(s, N - s)
        k = (k + 1) % N


def main() -> None:
    command, private = sys.argv[1], int(sys.argv[2], 16)
    if command == "pubkey":
        x, y = multiply(private, (GX, GY))
        print(f"0x{x:064x}{y:064x}")
    elif command == "sign":
        r, s = sign(private, int(sys.argv[3], 16))
        print(f"0x{r:064x}{s:064x}")
    else:
        raise SystemExit(f"unknown command {command}")


if __name__ == "__main__":
    main()
