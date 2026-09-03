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
- The account is a contract, and a user operation can make it do exactly one thing: presign one CoW
  order. A validator module re-checks the tokens, the caps, the price, the ether the operation's own
  gas will cost, and, once the day's spend crosses a threshold, a WebAuthn assertion from your
  passkey over that exact order. It is the only thing that can actually say no.
- The price you hear is written into the signed order, so a filler cannot go below it, and the
  contract holds a worst acceptable price of its own so a compromised agent cannot write a bad one.

Full design: [docs/superpowers/specs/2026-09-03-vesper-v1-design.md](docs/superpowers/specs/2026-09-03-vesper-v1-design.md).
Verified onchain addresses and constants: [docs/venue.md](docs/venue.md).

## How this gets built

Six steps, each a hard gate on the next, listed in the design doc. Every step ships a way to see it
work, committed alongside it: a page or a command that makes the behaviour visible rather than a
description of it. Step 1 ships `vesper.web`.

## Status

Steps 0 to 4 are done: the venue is verified, a sentence becomes an order, the contracts hold, and
both the plain path and the passkey path run end to end against the real EntryPoint, the real CoW
settlement and the real P-256 precompile on Base. Step 5 is the enclave and has not started.

## How to run it

Set up once:

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

The console, at http://127.0.0.1:8787:

```bash
cd enclave && .venv/bin/python -m vesper.web
```

A sentence goes in and four hands report on it in the order they touch it: the model, the allowlist,
CoW's live price, and the fence on Base. Only the last one decides anything, and the page is laid
out to say so. The daily budget is read from the chain. Placing is hold to confirm, and above the
threshold your passkey signs the exact order first. Standard library only, no build step.

It needs `contracts/.env` to name a deployed `ACCOUNT` and `POLICY`. Without one the first two hands
still work and the other two say there is nothing to read.

## The contracts

`VoicePolicy` is an ERC-7579 validator module, and one function in it decides whether any of this is
safe. `VesperAccount` is the account it fences: it holds the funds, and the only thing a user
operation can make it do is presign one CoW order.

```bash
cd contracts && forge test
```

The completion criterion is not "the tests pass". It is that **every check has a test that fails
when you delete that check**, which is a claim you can run:

```bash
cd contracts && python3 script/mutation_report.py
```

It replaces each guard with an empty block, runs the suite, and puts the guard back. The result is
in [contracts/mutation-report.md](contracts/mutation-report.md). One check cannot be caught and the
report says why, with the argument, rather than leaving it out.

Unit tests are not enough on their own here, and that is not a figure of speech: the whole suite was
green on a design the deployed CoW settlement rejects outright, because the mock in the test
directory was more permissive than the real contract. So there is a second suite that runs the whole
path against Base at a pinned block, using the deployed EntryPoint, the deployed settlement and the
deployed P-256 precompile:

```bash
cd contracts && FOUNDRY_PROFILE=live forge test --match-path test/Live.t.sol
```

It needs the network and it needs `cast` on your path. Nothing gets deployed with real money until
it passes there.

Four independent reviews went at these contracts before deployment. What they found, what was
changed, and what is accepted with the reason: [docs/audit-2026-09-03.md](docs/audit-2026-09-03.md).

## How to test it

```bash
cd enclave && .venv/bin/python -m pytest
```

Fourteen tests. Eleven are on `to_order`, the code that decides whether the model's answer becomes
an order at all; three pin the hand-written ABI encoder for the signature blob against `cast`.
Nothing here calls the API, so the suite runs offline and costs nothing.

There is deliberately no test of the model's own reading of a sentence. That needs an eval set run
against the real API when the prompt or the model changes, not a unit test.
