# Mutation report

Each check below was replaced with an empty block and the suite was run. `caught` means a
test failed, which is the only evidence that the check is doing anything.

23 of 25 checks are caught by a test. 2 cannot be, with reasons below.

| File | Line | Check | Result |
|---|---|---|---|
| `src/VoicePolicy.sol` | 103 | `if (session.key == address(0)) return SIG_FAIL;` | exempt |
| `src/VoicePolicy.sol` | 104 | `if (block.timestamp > session.expiry) return SIG_FAIL; // the key has aged out` | caught |
| `src/VoicePolicy.sol` | 107 | `if (target != address(gate)) return SIG_FAIL; // one address in the world` | caught |
| `src/VoicePolicy.sol` | 108 | `if (bytes4(callData) != VoiceOrderGate.placeOrder.selector) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 113 | `if (!sellLimits.allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 114 | `if (!limits[op.sender][order.buyToken].allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 116 | `if (order.sellAmount > sellLimits.perTradeCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 118 | `return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 124 | `if (!_validSessionSignature(opHash, sessionSig, session.key)) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 127 | `if (!hasAssertion) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 136 | `) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 185 | `if (signature.length != 65) return false;` | caught |
| `src/VoicePolicy.sol` | 196 | `return false;` | caught |
| `src/VoiceOrderGate.sol` | 38 | `if (order.kind != GPv2Order.KIND_SELL) revert NotASale();` | caught |
| `src/VoiceOrderGate.sol` | 39 | `if (order.partiallyFillable) revert PartialFillsNotSupported();` | caught |
| `src/VoiceOrderGate.sol` | 43 | `) revert NotErc20Balances();` | caught |
| `src/VoiceOrderGate.sol` | 46 | `if (order.receiver != msg.sender) revert ReceiverMustBeTheAccount();` | caught |
| `src/VoiceOrderGate.sol` | 49 | `if (order.buyAmount == 0) revert NoFloor();` | caught |
| `src/WebAuthn.sol` | 33 | `if (assertion.authenticatorData.length < 37) return false;` | caught |
| `src/WebAuthn.sol` | 35 | `if (bytes32(_slice(assertion.authenticatorData, 0, 32)) != rpIdHash) return false;` | caught |
| `src/WebAuthn.sol` | 38 | `if (flags & FLAG_USER_PRESENT == 0) return false;` | caught |
| `src/WebAuthn.sol` | 40 | `if (flags & FLAG_USER_VERIFIED == 0) return false;` | caught |
| `src/WebAuthn.sol` | 42 | `if (!_challengeMatches(assertion.clientDataJSON, challenge)) return false;` | caught |
| `src/WebAuthn.sol` | 84 | `if (needle.length > haystack.length) return false;` | caught |
| `src/WebAuthn.sol` | 95 | `return false;` | exempt |

## Why the exempt checks cannot be caught

- `src/VoicePolicy.sol:103` redundant by construction: ecrecover returns address(0) on failure and _validSessionSignature rejects that, so a zero session key can never validate. The line is here so the revoked case reads plainly at the top of the function.
- `src/WebAuthn.sol:95` the final statement of _contains, where Solidity already returns the default. Replacing it with an empty block is not a mutation, so nothing could catch it.
