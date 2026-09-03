# Mutation report

Each check below was replaced with an empty block and the suite was run. `caught` means a
test failed, which is the only evidence that the check is doing anything.

29 of 30 checks are caught by a test. 1 cannot be, with reasons below.

| File | Line | Check | Result |
|---|---|---|---|
| `src/VoicePolicy.sol` | 112 | `if (msg.sender != op.sender) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 120 | `if (op.callData.length != 4 + GPv2Order.ENCODED_LENGTH) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 121 | `if (bytes4(op.callData) != IVesperAccount.placeOrder.selector) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 130 | `if (key == address(0)) return SIG_FAIL;` | exempt |
| `src/VoicePolicy.sol` | 131 | `if (block.timestamp > expiry) return SIG_FAIL; // the key has aged out` | caught |
| `src/VoicePolicy.sol` | 134 | `if (!sellLimits.allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 135 | `if (!limits[op.sender][order.buyToken].allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 139 | `if (order.sellAmount > sellLimits.perTradeCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 141 | `return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 147 | `if (!_validSessionSignature(opHash, sessionSig, key)) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 150 | `if (!hasAssertion) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 160 | `) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 194 | `if (signature.length != 65) return false;` | caught |
| `src/VoicePolicy.sol` | 205 | `return false;` | caught |
| `src/VesperAccount.sol` | 56 | `if (msg.sender != entryPoint) revert NotEntryPoint();` | caught |
| `src/VesperAccount.sol` | 81 | `if (msg.sender != entryPoint) revert NotEntryPoint();` | caught |
| `src/VesperAccount.sol` | 83 | `if (order.kind != GPv2Order.KIND_SELL) revert NotASale();` | caught |
| `src/VesperAccount.sol` | 84 | `if (order.partiallyFillable) revert PartialFillsNotSupported();` | caught |
| `src/VesperAccount.sol` | 88 | `) revert NotErc20Balances();` | caught |
| `src/VesperAccount.sol` | 91 | `if (order.receiver != address(this)) revert ReceiverMustBeTheAccount();` | caught |
| `src/VesperAccount.sol` | 94 | `if (order.buyAmount == 0) revert NoFloor();` | caught |
| `src/VesperAccount.sol` | 109 | `if (msg.sender != owner) revert NotOwner();` | caught |
| `src/WebAuthn.sol` | 42 | `if (assertion.authenticatorData.length < 37) return false;` | caught |
| `src/WebAuthn.sol` | 44 | `if (bytes32(_slice(assertion.authenticatorData, 0, 32)) != rpIdHash) return false;` | caught |
| `src/WebAuthn.sol` | 47 | `if (flags & FLAG_USER_PRESENT == 0) return false;` | caught |
| `src/WebAuthn.sol` | 49 | `if (flags & FLAG_USER_VERIFIED == 0) return false;` | caught |
| `src/WebAuthn.sol` | 55 | `if (!_equalAt(clientData, assertion.typeIndex, EXPECTED_TYPE)) return false;` | caught |
| `src/WebAuthn.sol` | 68 | `if (!_equalAt(clientData, assertion.challengeIndex, expected)) return false;` | caught |
| `src/WebAuthn.sol` | 85 | `if (offset > haystack.length || needle.length > haystack.length - offset) return false;` | caught |
| `src/WebAuthn.sol` | 87 | `if (haystack[offset + i] != needle[i]) return false;` | caught |

## Why the exempt checks cannot be caught

- `src/VoicePolicy.sol:130` redundant by construction: ecrecover returns address(0) on failure and _validSessionSignature rejects that, so a zero session key can never validate. The line is here so the revoked case reads plainly at the top of the function.
