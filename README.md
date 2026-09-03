# Vesper

A voice agent that can execute swaps and cannot do anything else.

You say "sell two thousand USDC into ETH". The agent reads back the amount and a price floor. You
say do it. Above a limit you set, your phone asks for your face. The trade settles at or above the
floor you heard.

The design does not try to make the agent trustworthy. It makes its authority small enough that
being untrustworthy does not matter:

- The model reads your words, but it does not write the sentence you hear back. That is rendered
  from the finished order by template code, so a wrong or jailbroken model cannot say one number and
  sign another.
- The signing key is generated inside an Intel TDX enclave, lives only in memory, and dies on
  restart. Your phone checks a measurement of the exact code before it enables the microphone.
- The account is a contract. A validator module re-checks the target, the tokens, the caps and, above
  a threshold, a WebAuthn assertion from your passkey. It is the only thing that can actually say no.
- The price you hear is written into the signed order, so a filler cannot go below it.

Full design: [docs/superpowers/specs/2026-09-03-vesper-v1-design.md](docs/superpowers/specs/2026-09-03-vesper-v1-design.md).
Verified onchain addresses and constants: [docs/venue.md](docs/venue.md).

## How this gets built

Six steps, each a hard gate on the next, listed in the design doc. Every step ships a way to see it
work, committed alongside it: a page or a command that makes the behaviour visible rather than a
description of it. Step 1 ships `vesper.web`.

## Status

Design approved. Step 0 (venue verification) and step 1 (the order builder) are done.

## How to run it

There is no application yet, only the part that turns a sentence into an order, and two ways to run
it. Set up once:

```bash
cd enclave && python3 -m venv .venv && .venv/bin/pip install pytest
```

From a terminal:

```bash
cd enclave && .venv/bin/python -m vesper.cli "sell two thousand USDC into ETH floor 0.8"
```

```
accepted   "sell two thousand USDC into ETH floor 0.8"
  action   SELL
  sell     2000 USDC                 2000000000
  buy      WETH
  floor    0.8 WETH                  800000000000000000
```

With no argument it reads a line at a time from standard input.

Needs an OpenAI key in `enclave/.env` as `OPENAI_API_KEY=...`, or in the environment. Without one
you get `unavailable` and the reason, never a silent refusal. `VESPER_MODEL` overrides the model,
which defaults to `gpt-5-mini`.

The allowlist and the unit conversion are applied in code after the model answers, so an invented
token never becomes an order and the model never handles a uint256.

In a browser, at http://127.0.0.1:8787:

```bash
cd enclave && .venv/bin/python -m vesper.web
```

Two panels: what the model returned, and what the gate did with it. Six examples to click,
including ones that should produce nothing. Standard library only, no build step.

## How to test it

```bash
cd enclave && .venv/bin/python -m pytest
```

Eleven tests, all of them on `to_order`, which is the code that decides whether the model's answer
becomes an order at all. Nothing here calls the API, so the suite runs offline and costs nothing.

There is deliberately no test of the model's own reading of a sentence. That needs an eval set run
against the real API when the prompt or the model changes, not a unit test.
