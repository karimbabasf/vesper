# Mutation report

Each check below was replaced with an empty block and the suite was run. `caught` means a
test failed, which is the only evidence that the check is doing anything.

52 of 53 checks are caught by a test. 1 cannot be, with reasons below.

| File | Line | Check | Result |
|---|---|---|---|
| `src/VoicePolicy.sol` | 150 | `if (msg.sender != op.sender) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 158 | `if (op.callData.length != 4 + GPv2Order.ENCODED_LENGTH) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 159 | `if (bytes4(op.callData) != IVesperAccount.placeOrder.selector) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 164 | `if (op.paymasterAndData.length != 0) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 167 | `if (!gasFieldsOk) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 177 | `if (!_wellFormed(order, op.sender)) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 182 | `if (key == address(0)) return SIG_FAIL;` | exempt |
| `src/VoicePolicy.sol` | 183 | `if (block.timestamp > expiry) return SIG_FAIL; // the key has aged out` | caught |
| `src/VoicePolicy.sol` | 186 | `if (!sellLimits.allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 187 | `if (!limits[op.sender][order.buyToken].allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 191 | `if (order.sellAmount > sellLimits.perTradeCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 194 | `if (spent + order.sellAmount > sellLimits.dailyCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 200 | `if (floor == 0) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 202 | `if (order.buyAmount < (order.sellAmount * floor) / 1e18) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 208 | `if (!gasLimits.allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 209 | `if (maxCost > gasLimits.perTradeCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 210 | `if (gasSpent + maxCost > gasLimits.dailyCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 216 | `if (!_signaturesOk(op, opHash, key, order, needsFace)) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 253 | `if (order.kind != GPv2Order.KIND_SELL) return false;` | caught |
| `src/VoicePolicy.sol` | 254 | `if (order.partiallyFillable) return false;` | caught |
| `src/VoicePolicy.sol` | 258 | `) return false;` | caught |
| `src/VoicePolicy.sol` | 259 | `if (order.receiver != account) return false;` | caught |
| `src/VoicePolicy.sol` | 260 | `if (order.buyAmount == 0) return false;` | caught |
| `src/VoicePolicy.sol` | 264 | `if (order.sellToken == ETH || order.buyToken == ETH) return false;` | caught |
| `src/VoicePolicy.sol` | 268 | `if (order.feeAmount != 0) return false;` | caught |
| `src/VoicePolicy.sol` | 270 | `if (order.sellToken == order.buyToken) return false;` | caught |
| `src/VoicePolicy.sol` | 272 | `if (order.validTo <= block.timestamp) return false;` | caught |
| `src/VoicePolicy.sol` | 273 | `if (order.validTo > block.timestamp + MAX_ORDER_LIFETIME) return false;` | caught |
| `src/VoicePolicy.sol` | 288 | `if (!_validSessionSignature(opHash, sessionSig, key)) return false;` | caught |
| `src/VoicePolicy.sol` | 290 | `if (!hasAssertion) return false;` | caught |
| `src/VoicePolicy.sol` | 332 | `if (signature.length != 65) return false;` | caught |
| `src/VoicePolicy.sol` | 343 | `return false;` | caught |
| `src/VesperAccount.sol` | 65 | `) revert ZeroAddress();` | caught |
| `src/VesperAccount.sol` | 82 | `if (msg.sender != entryPoint) revert NotEntryPoint();` | caught |
| `src/VesperAccount.sol` | 107 | `if (msg.sender != entryPoint) revert NotEntryPoint();` | caught |
| `src/VesperAccount.sol` | 109 | `if (order.kind != GPv2Order.KIND_SELL) revert NotASale();` | caught |
| `src/VesperAccount.sol` | 110 | `if (order.partiallyFillable) revert PartialFillsNotSupported();` | caught |
| `src/VesperAccount.sol` | 114 | `) revert NotErc20Balances();` | caught |
| `src/VesperAccount.sol` | 117 | `if (order.receiver != address(this)) revert ReceiverMustBeTheAccount();` | caught |
| `src/VesperAccount.sol` | 120 | `if (order.buyAmount == 0) revert NoFloor();` | caught |
| `src/VesperAccount.sol` | 127 | `if (order.feeAmount != 0) revert FeeMustBeZero();` | caught |
| `src/VesperAccount.sol` | 129 | `if (order.validTo <= block.timestamp) revert AlreadyExpired();` | caught |
| `src/VesperAccount.sol` | 130 | `if (order.validTo > block.timestamp + MAX_ORDER_LIFETIME) revert ArmedTooLong();` | caught |
| `src/VesperAccount.sol` | 133 | `if (order.sellToken == order.buyToken) revert NotASwap();` | caught |
| `src/VesperAccount.sol` | 149 | `if (msg.sender != owner) revert NotOwner();` | caught |
| `src/WebAuthn.sol` | 42 | `if (assertion.authenticatorData.length < 37) return false;` | caught |
| `src/WebAuthn.sol` | 51 | `if (signedRpIdHash != rpIdHash) return false;` | caught |
| `src/WebAuthn.sol` | 54 | `if (flags & FLAG_USER_PRESENT == 0) return false;` | caught |
| `src/WebAuthn.sol` | 56 | `if (flags & FLAG_USER_VERIFIED == 0) return false;` | caught |
| `src/WebAuthn.sol` | 62 | `if (!_equalAt(clientData, assertion.typeIndex, EXPECTED_TYPE)) return false;` | caught |
| `src/WebAuthn.sol` | 75 | `if (!_equalAt(clientData, assertion.challengeIndex, expected)) return false;` | caught |
| `src/WebAuthn.sol` | 91 | `if (offset > haystack.length || needle.length > haystack.length - offset) return false;` | caught |
| `src/WebAuthn.sol` | 93 | `if (haystack[offset + i] != needle[i]) return false;` | caught |

## Why the exempt checks cannot be caught

- `src/VoicePolicy.sol:182` redundant by construction: ecrecover returns address(0) on failure and _validSessionSignature rejects that, so a zero session key can never validate. The line is here so the revoked case reads plainly at the top of the function.
