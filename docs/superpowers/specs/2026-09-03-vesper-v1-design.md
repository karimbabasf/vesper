# Vesper v1: a voice agent that can only trade inside a fence

Date: 2026-09-03
Status: approved design, ready for an implementation plan
Name: Vesper. The evening star, and evening prayers said aloud.
Source of truth for the concepts: `~/Developer/artifacts/html/voice-trading-agent-textbook.html`

## 1. What v1 is

You open a page on your desktop, scan a QR with your phone, tap to start a call, and say
"sell two thousand USDC into ETH". The agent reads back the amount and a floor. You say do it.
Above a limit you set, your phone asks for your face. Ten seconds later a swap has settled at or
above the floor you heard.

The design does not try to make the agent trustworthy. It makes the agent's authority small enough
that being untrustworthy does not matter.

| The naive version | Vesper |
|---|---|
| The agent holds the wallet key. | The agent holds a session key with caps, in memory inside a sealed processor, dead on restart. |
| The model decides the trade. | The model reads your words. The order it produces is read back to you in a sentence it did not write, and the chain refuses anything outside your limits. |
| The wallet signs what it is told. | The wallet is a contract. A validator re-checks target, tokens, caps and, above a limit, your face. |
| You trust the operator. | Your phone checks a measurement of the exact code and refuses the microphone on a mismatch. |
| You hope for a good price. | You hear a floor, and the floor is written into the signed order. |

Three tiers, with a hard line between each. The browsers hold no authority. The enclave holds a
limited key and does the thinking. The chain holds the rules and is the only thing that can say no
in a way that counts. Read left to right: authority increases, code gets smaller and dumber.

## 2. Scope

**In v1**

- Swaps only. No transfers, no bridging, no lending, no balance management.
- One chain, one settlement target, one allowlist of tokens set by you before any call.
- Two web surfaces: a desktop console and a mobile handset page. No native app.
- One enclave image on Phala dstack (Intel TDX).
- The model is the parser. There is no second derivation in v1.
- One ERC-7579 account with one custom validator module and one order gate contract.
- CoW Protocol as the only execution venue.

**Explicitly not in v1** (see section 11 for the v2 list)

- No local speech recognition or synthesis. Two vendors hear your voice, and we say so.
- No speaker verification.
- No dollar-denominated caps, so no price oracle anywhere in the system.
- No second parser cross-checking the model. Removed 2026-09-03, see section 6.
- No automatic session key rotation.
- No router fallback when no solver fills.
- No hardware box, no PSTN phone number, no second chain.

## 3. The three decisions that shape the contract

The source document ends by saying to answer these before writing any Solidity. Answered here.

### 3.1 Caps are denominated in token units, not dollars

A dollar cap needs a price, a price needs an oracle, and an oracle is a new trusted component and a
new attack surface for the sake of elegance. v1 stores caps per token, in that token's own units.

```
allowlist[account][token] = {
    allowed:            bool
    perTradeCap:        uint256   // token units, e.g. 5_000e6 USDC
    dailyCap:           uint256   // token units, rolling 24h
    biometricThreshold: uint256   // token units, above this the passkey is required
}
```

Caps bind the **sell** side only, because that is the side whose size you control. The buy side is
bounded by the floor in the order. `valueOf()` does not exist in v1 and neither does an oracle.

Cost of this choice: a daily cap of 5,000 USDC and a daily cap of 2 WETH are separate budgets that
do not know about each other, so a determined attacker inside the fence can spend both. That is
acceptable, and it is stated in the threat model rather than hidden.

### 3.2 CoW orders are placed by an explicit gate call, not by pre-signature on a raw uid

The problem: `GPv2Settlement.setPreSignature(bytes orderUid, bool)` takes only a uid. A uid is
`orderDigest || owner || validTo`. The validator cannot recover the sell token, the buy token, the
amount or the floor from it, so it cannot enforce anything.

The fix: the account calls a thin contract, `VoiceOrderGate.placeOrder(Order calldata o)`.
The gate recomputes the CoW EIP-712 digest from the struct, builds the uid, and calls
`setPreSignature`. Because the full order struct is in the calldata, the validator decodes it and
checks real fields. `VoiceOrderGate` is the only address the validator will ever allow as a target.

The gate holds no funds, has no owner, and has no state. It is a pure translator. It is in the
trusted computing base only in the sense that a bug in it could let a malformed order through, so it
gets the same hostile test suite as the validator.

ERC-1271 signing is the v2 path, needed for partially fillable and TWAP-style orders.

### 3.3 An enclave restart is a rotation, and the console is responsible for noticing

The session key is never sealed, so a restart destroys it. That is the feature. It also means:

- The handset's WebRTC connection drops. On reconnect it re-fetches the attestation quote, gets a
  new session public key, and therefore a different four-word code.
- The console polls two things: the session public key the enclave reports, and the key registered
  onchain. A mismatch shows a loud banner, disables the call button, and offers one action:
  "register this session key", which is one transaction from the root owner.
- Orders already presigned onchain stand. They are floor-protected and carry a short `validTo`, so
  the worst case is a fill you already approved at a price you already heard.
- Orders in flight but not yet submitted are lost. This is correct behaviour, not a bug to paper over.

v1 registration is manual and root-owner-signed. Auto-rotation is v2.

## 4. Components

### 4.1 Console (desktop web)

Next.js, TypeScript. No authority of any kind. It does five things:

1. Connect the root wallet, deploy the ERC-7579 account, install `VoicePolicy`, fund the account.
2. Set the allowlist, per-trade cap, daily cap and biometric threshold, one row per token.
3. Register the enclave's session key and its attestation hash. Show the current image measurement
   and whether it matches the pinned constant.
4. Show the four-word code for the live session, the live transcript, every proposed order, every
   refusal with the field that disagreed, and every fill.
5. Revoke. One button, one transaction, always available, works whether or not anything else works.

### 4.2 Handset (mobile web, same Next.js app, a `/handset` route)

Joined by scanning a QR on the console. Before it will enable the microphone it fetches the TDX
attestation quote, verifies the certificate chain, compares MRTD and RTMRs against a pinned
constant compiled into the page, and confirms the 64 report-data bytes commit to this session's
public key. On any mismatch it shows a full-screen stop and does not offer a retry that skips the check.

Then: tap to start the call, WebRTC to the enclave, and a WebAuthn passkey prompt when an order is
over the biometric threshold. The passkey is created during pairing and registered as the account's
device signer in the same flow.

### 4.3 Enclave (Phala dstack, Intel TDX, one docker-compose)

| Process | Job | Trusted? |
|---|---|---|
| LiveKit server + agent worker | DTLS-SRTP terminates here. Plaintext audio exists only in encrypted RAM. | yes |
| STT / TTS clients | Deepgram in, Cartesia out, over TLS. **The one leak.** | no, for confidentiality |
| LLM client | Remote model. Returns a proposed order as JSON. | no |
| Quoter and local policy | CoW quote, then allowlist and caps checked locally for speed and manners. | advisory only |
| Signer | secp256k1 keypair generated on boot, in memory, never written, never exported. | yes |
| Attestation service | Serves the TDX quote with the session public key in report data, and derives the four-word code. | yes |

Language: Python, because the LiveKit Agents SDK is mature there and the order builder wants to sit
in the same process as the transcript with no serialization in between.

### 4.4 Onchain (see section 3 for the two decisions that shaped it)

- **ERC-7579 account**, Kernel v3 via the ZeroDev SDK and bundler. Root owner is your existing EOA.
  Alternative considered: Biconomy Nexus with Rhinestone ModuleKit. Kernel wins on bundler and
  paymaster ergonomics, which matters when the demo is on a conference wifi.
- **`VoicePolicy`**, a validator module. About thirty lines decide whether any of this is safe.
- **`VoiceOrderGate`**, the only permitted target.

## 5. One swap, boundary by boundary

| # | Crossing | What crosses | What the receiver may assume |
|---|---|---|---|
| 1 | handset to enclave | TDX quote: MRTD, RTMRs, cert chain, 64 report bytes | the code is the exact pinned image, and this quote is about this connection. Not that the image is well written. |
| 2 | console to handset | QR with room name and a short-lived join token | nothing worth stealing. A room is worthless without the passkey and the caps. |
| 3 | audio | SRTP frames in, decrypted inside; then out to Deepgram, and text out to Cartesia | the only two crossings that leave the sealed box |
| 4 | transcript to model | the raw string, and back a JSON order | a proposal. The allowlist and the unit conversion are applied to it in code, not trusted from it |
| 5 | enclave to CoW | quote request | an estimate with a short shelf life. The local cap check here is manners, not safety |
| 6 | enclave to your ears | amount and floor, rendered from the order struct by template code, never composed by the model | the numbers you hear are the numbers in the bytes about to be signed |
| 7 | handset to enclave | WebAuthn assertion, challenge = `keccak256(abi.encode(order))` | useless for any other order |
| 8 | enclave to chain | userOp whose signature field packs the session signature and, above threshold, the assertion | |
| 9 | account to validator | `validateUserOp` | everything the enclave checked, re-checked by code the enclave cannot influence |
| 10 | chain to solvers | the presigned order, into a batch auction | the winner settles at or above the floor or not at all |

Signature packing:

```solidity
signature = abi.encode(
    sessionKeySig,      // 65 bytes secp256k1, from inside the enclave
    hasAssertion,       // bool
    webauthnAssertion   // authenticatorData, clientDataJSON, r, s  (empty below threshold)
);
```

## 6. The model, and what actually holds it

The model is the parser. There is no second derivation of your sentence in v1.

An earlier version of this design had one: a hand-written grammar that parsed the raw transcript
independently, and refused whenever it disagreed with the model. It was built, and it was removed on
2026-09-03. The reason is in one transcript:

```
"go ahead and change 200 usdc to eth for me"
  grammar    refused
  model      SELL 200 USDC into WETH
```

Three things killed it, any one of which was enough: "go ahead and" before the verb, "change" not
being in its action set, and "for me" trailing. That is not a dangerous sentence, it is how a person
speaks. A grammar cannot tell the difference between input that is dangerous and input that is
merely unfamiliar, so it refuses both at about the same rate, and a system that refuses ordinary
speech teaches you to stop listening to its refusals. The choice was widen the grammar until it
agrees with the model on everything, which checks nothing, or drop it. Dropped.

**What constrains the model instead**, in the order it applies:

1. **The allowlist is applied in code, after the model answers.** A symbol the model invented never
   becomes an `Order`, whatever confidence it claims. Same for a sell token equal to the buy token.
2. **Amounts are converted in code.** The model returns whole token units as a decimal string; the
   builder scales by the token's decimals and refuses anything that is not an exact positive
   integer. The model never handles a uint256.
3. **The read-back is rendered from the finished order by template code.** This is the important
   one. The model does not write the sentence you hear. Because that sentence is generated from the
   same struct that gets hashed and signed, a model that is wrong, jailbroken, or replaced cannot
   say one number and sign another. The confirmation means something precisely because the model had
   no hand in it.
4. **You say yes.** Nothing is signed without it.
5. **`validateUserOp` re-checks all of it onchain**, where the enclave has no influence at all.

**What this costs, stated plainly.** Nothing checks the model's reading of your words except you. If
it hears twenty thousand when you said two thousand, the read-back says twenty thousand, and if you
confirm without listening, and it is inside your caps and on an allowlisted token, the trade
happens. The second derivation existed to catch exactly that case. v1 accepts the risk and bounds it
with the caps; section 11 carries the v2 answer, which is a second model rather than a grammar.

## 7. The four-word code

The gap: your handset verified an enclave and your console shows a session. Nothing yet proves they
are the same enclave. An attacker in the middle can relay a genuine attestation from a real enclave
to your phone while sending your audio somewhere else. Each half is individually valid.

The fix, the same trick as a secure messenger's safety number:

```python
material = sha256(mrtd || rtmr || session_pubkey || room_id)
words    = [WORDLIST[chunk] for chunk in first_four_11bit_chunks(material)]
# "harbour, lantern, copper, ridge"
```

The console renders the words from the attestation it verified. The agent speaks the words derived
inside the enclave from its own live state. A human compares them in one second. An attacker who
split the channel cannot make both sides agree without the enclave's secrets.

Use a phonetically distinct 2048-word list, so heard and seen cannot be confused. Four words is 44
bits, which is ample when an attacker gets one attempt per session. A mismatch stops the console
dead. It is not a warning triangle someone can click past.

## 8. VoicePolicy

```solidity
function validateUserOp(PackedUserOperation calldata op, bytes32 opHash)
    external returns (uint256)
{
    Session storage s = sessions[op.sender];
    if (s.key == address(0))                        return SIG_FAIL;  // revoked or never registered
    if (s.attestationHash != expectedHash)          return SIG_FAIL;  // not the image you approved
    if (block.timestamp > s.expiry)                 return SIG_FAIL;  // the key aged out

    (address target, bytes calldata data) = decodeCall(op.callData);
    if (target != VOICE_ORDER_GATE)                 return SIG_FAIL;  // one address in the world

    Order memory o = decodeOrder(data);
    Limits storage L = allowlist[op.sender][o.sellToken];
    if (!L.allowed)                                 return SIG_FAIL;
    if (!allowlist[op.sender][o.buyToken].allowed)  return SIG_FAIL;
    if (o.sellAmount > L.perTradeCap)               return SIG_FAIL;
    if (spentToday(op.sender, o.sellToken) + o.sellAmount > L.dailyCap) return SIG_FAIL;

    (bytes memory sessionSig, bool hasAssert, WebAuthn memory a) = decodeSig(op.signature);
    if (!verifySecp256k1(opHash, sessionSig, s.key)) return SIG_FAIL;

    if (o.sellAmount > L.biometricThreshold) {
        if (!hasAssert)                             return SIG_FAIL;
        if (!a.userVerified)                        return SIG_FAIL;  // the check people forget
        if (a.rpIdHash != s.rpIdHash)               return SIG_FAIL;
        if (a.challenge != keccak256(abi.encode(o))) return SIG_FAIL; // binds face to THIS order
        if (!verifyP256(a, s.passkeyPubKey))        return SIG_FAIL;  // RIP-7212, FCL fallback
    }

    recordSpend(op.sender, o.sellToken, o.sellAmount);
    return SIG_OK;
}
```

Everything upstream, all the audio and the model and the enclave, exists to make the inputs to those
thirty lines trustworthy enough to be worth checking. Build and attack this before anything else.

## 9. The seams

Every boundary is also a check. Removing any one of them has a named consequence.

| Boundary | The check | Remove it and |
|---|---|---|
| handset to enclave | pinning on the measurement | you talk to any server that claims to be the enclave |
| attestation to session | 64 report bytes commit to the session key | a genuine quote from a real enclave is replayed in front of a fake one |
| console and agent | four words compared by a human | the two halves you verified are not proven to be the same box |
| order to the sentence you hear | the read-back is rendered from the order, not written by the model | a compromised model can say one number and sign another |
| room to order | allowlist and caps, checked twice | anyone speaking near your phone can trade anything, in any size |
| order to your ears | amount and floor spoken absolutely | you never see the numbers before they bind |
| you to order | assertion challenge = order hash | a stolen phone or a captured signature approves a different trade |
| enclave to chain | `validateUserOp` re-checking all of it | the enclave becomes the last word and everything above is advisory |
| chain to fill | the settlement contract enforces the floor | the spoken price was a hope, not a limit |
| you to everything | root revocation, one transaction | no kill switch independent of the system working |

Each layer is independent, not merely stacked. The read-back does not depend on the model being
honest, because the model does not write it. The validator does not depend on the read-back having
happened. The passkey does not depend on the phone being unstolen. Revocation does not depend on any
of it.

## 10. Threat model

| Attacker | What they get |
|---|---|
| Compromised model provider | Bounded, not blocked. It cannot make the read-back lie, because that sentence is rendered from the order. It can produce a wrong order, and you have to hear it and say no. Under the caps, on an allowlisted token, a wrong order you confirm goes through. This is the cost of dropping the second parser. |
| Someone shouting at your phone | Bounded. Allowlisted tokens only, under the per-trade cap, and above the threshold it stops at your face. |
| Phala node operator | Nothing directly. Memory encryption blocks the read; a swapped image changes the measurement and the handset refuses the microphone. |
| Stolen phone | Bounded, then blocked. The passkey needs your face above the threshold, the session key alone is capped, and revocation ends it. |
| Rogue or fully compromised enclave | Still fenced. No target but the gate, no token off the list, nothing over the caps, nothing over the threshold without a valid assertion. |
| Network attacker in the middle | Caught. The quote is bound to the session and the four words will not match on both sides. |
| MEV bot | Bounded by design. Batch settlement removes the ordering advantage and the floor is enforced by the contract. |
| A fast market | You get the floor you heard or no fill. Keep `validTo` short so a dead intent cannot wake up. |
| Deepgram or Cartesia | **Succeeds.** They hear everything you say. This is the real hole in v1. |

Trusted computing base, written out honestly:

| Trusting | For what | If it fails |
|---|---|---|
| Intel silicon and certs | the enclave is real and sealed | the key is readable, though caps and passkey still hold |
| Phala hardware | genuine TDX, not emulated | same as above |
| your own image | that the code inside is correct | the measurement proves it did not change, not that it is good |
| `VoicePolicy` and `VoiceOrderGate` | the thirty lines in section 8 | total loss up to the account balance. Audit these first |
| CoW and its solvers | settling at or above the floor | bounded: the contract enforces the floor, so the risk is a missed fill |
| Deepgram and Cartesia | confidentiality, and the words the model reads | your voice is heard, and a corrupted transcript reaches the model and then the read-back. You are the check on that |
| the bundler | inclusion only | delay or censorship, never a different trade |
| your phone and your face | the top-end approval | an attacker with both is inside your threshold. Caps still bound them |

## 11. What is still wrong, and the v2 list

Say these before someone else does.

| # | Residual risk in v1 | v2 fix |
|---|---|---|
| 1 | Two vendors hear your voice. | whisper.cpp and Piper inside the enclave. Expect worse token-name recognition, a flatter voice, and real work on the latency budget. |
| 2 | A measurement without a reproducible build is half a proof. It shows the image did not change, not what is in it. | Reproducible builds and a published measurement. Much easier to add at the start than later. |
| 3 | Side channels are the honest TEE caveat and there is no clean claim to make. | Nothing fixes this. It is why the caps and the passkey exist: they hold even if the enclave is fully lost. |
| 4 | The system knows your voice, not you. Anyone making sound near a live session can propose. | Speaker verification inside the enclave, as a second identification signal and never as authorisation. |
| 4b | Nothing checks the model's reading of your words except you. A misheard order that stays inside the caps is a real order if you confirm it without listening. | A second derivation of the same transcript, compared with the model's. Tried in v1 and removed: a hand-written grammar refused ordinary speech ("go ahead and change 200 usdc to eth for me") as often as it caught anything, so it taught you to ignore refusals. Revisit with a second model rather than a grammar. |
| 5 | Restart equals rotation, and manual re-registration is friction people will route around. | A registry that accepts any session key carrying a matching attestation hash, pre-authorised by the root owner once. |
| 6 | Caps are per token, so separate budgets do not know about each other. | Dollar-denominated caps, which means an oracle, which is a new trusted component. Only worth it with a reason. |
| 7 | A no-fill is a dead end. | Router fallback after `validTo` expires, at a fresh quote, spoken again before it binds. |
| 8 | Cloud only. | The same image on a TDX mini PC on your own network, verified by the handset the same way. |
| 9 | Browser only. | PSTN, a native app, more chains. |

## 12. Build plan

Six steps. Each produces something showable on its own, and each is a hard gate on the next.
Nothing from a later step is started before the earlier one is done.

**Every step ships a way to see it work, and that artifact is committed.** Not a screenshot and not
a description: a page or a command someone can run that makes the step's behaviour visible. Step 1
ships `vesper.web`, which puts the model's raw answer next to the gate's decision. A step without
one is not finished, because a component you cannot watch is a component nobody will trust.

**Step 0. Verify the venue. DONE 2026-09-03, see `docs/venue.md`.** Base mainnet is confirmed:
CoW is live and accepts `presign`, the settlement and vault relayer addresses check out, the EIP-712
domain separator computed offline matches the deployed contract, and RIP-7212 works on both Base and
Base Sepolia. The Arbitrum fallback is not needed.

One finding changes the steps below: **CoW has no Base Sepolia deployment, but RIP-7212 does.** So
steps 2, 4 and 5 run on Base Sepolia for free, and only step 3 and the demo need Base mainnet and
real money.

**Step 1. The order builder, with the model behind it. DONE 2026-09-03.** `vesper.model` turns a
sentence into an `Order` under a structured-output schema, with the allowlist and the unit
conversion applied in code afterwards. `vesper.cli` and `vesper.web` run it by hand.
Done when: an invented token, a fractional base unit, a sell token equal to the buy token, a zero
or negative amount, a non-sale action and an unparseable floor all produce nothing, under `pytest`,
with no network call in the suite.

**Step 2. `VoicePolicy` and `VoiceOrderGate`, with tests written to attack them.** Foundry, local
and Base Sepolia. Target EntryPoint v0.7, `PackedUserOperation`.
Done when: every line of the function in section 8 has a test that fails when that line is deleted.
That is the completion criterion, and it is checkable by deleting lines.

**Step 3. The account on chain, one trade signed by hand.** No voice, no enclave. Kernel v3 account,
modules installed, allowlist and caps set from a script, one CoW order placed through the gate.
Done when: a fill on CoW that respected a floor you set, with the transaction hash in the repo.
This step spends real money on Base, roughly 20 to 50 dollars total, because CoW testnet solver
liquidity is not reliable enough to prove anything.

**Step 4. The passkey path.** WebAuthn registration on the handset page, assertion over an order
hash, verified onchain.
Done when: a trade above the threshold succeeds with an assertion and the identical trade fails
without one, both onchain, both linked in the repo.

**Step 5. The enclave, empty at first.** dstack deployment, attestation service, session key
generated on boot, handset pinning and the four-word code. No audio yet.
Done when: changing one byte of the image makes the handset refuse to enable the microphone, and
the four words on the console match the four words in the enclave's own output.

**Step 6. The voice pipeline into the working stack.** LiveKit, Deepgram, Cartesia, the model from
step 1 and the signer from step 5, plus the template read-back described in section 6.
Done when: the demo runs. By this point it is the easy part.

## 13. What to demo, in order

The refusal first, not the trade.

1. Change one byte of the image. Let the handset refuse the microphone.
2. Ask for a token that is not on the allowlist, and for more than a cap allows. Let it refuse.
3. Revoke mid-session and watch a signed operation fail onchain.
4. Then, and only then, do a trade.

The trade working is the least interesting thing here. Everyone has seen a trade work.

## 14. Repository layout

```
vesper/
  contracts/          Foundry. VoicePolicy.sol, VoiceOrderGate.sol, hostile tests
  enclave/            Python. model.py, order.py, cli.py, web.py, agent worker, attestation service
  app/                Next.js. / is the console, /handset is the phone page
  scripts/            deploy, set allowlist, register session key, revoke
  docs/               venue.md, and this spec under superpowers/specs/
```

## 15. Open items

- Whether the ETHOnline sponsor tracks pull the chain off Base. Nothing in the design depends on it;
  the chain is a deployment target, not an architecture choice. The event runs 2026-09-04 to
  2026-09-16, so v1 has thirteen days.
