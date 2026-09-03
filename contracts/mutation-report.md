# Mutation report

Each check below was replaced with an empty block and the suite was run. `caught` means a
test failed, which is the only evidence that the check is doing anything.

53 of 55 checks are caught by a test. 2 cannot be, with reasons below.

| File | Line | Check | Result |
|---|---|---|---|
| `src/VoicePolicy.sol` | 153 | `if (msg.sender != op.sender) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 161 | `if (op.callData.length != 4 + GPv2Order.ENCODED_LENGTH) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 162 | `if (bytes4(op.callData) != IVesperAccount.placeOrder.selector) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 167 | `if (op.paymasterAndData.length != 0) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 170 | `if (!gasFieldsOk) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 180 | `if (!_wellFormed(order, op.sender)) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 185 | `if (key == address(0)) return SIG_FAIL;` | exempt |
| `src/VoicePolicy.sol` | 186 | `if (block.timestamp > expiry) return SIG_FAIL; // the key has aged out` | caught |
| `src/VoicePolicy.sol` | 189 | `if (!sellLimits.allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 190 | `if (!limits[op.sender][order.buyToken].allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 194 | `if (order.sellAmount > sellLimits.perTradeCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 197 | `if (spent + order.sellAmount > sellLimits.dailyCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 203 | `if (floor == 0) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 212 | `if (order.buyAmount * 1e18 < order.sellAmount * floor) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 218 | `if (!gasLimits.allowed) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 219 | `if (maxCost > gasLimits.perTradeCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 220 | `if (gasSpent + maxCost > gasLimits.dailyCap) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 233 | `if (!_signaturesOk(op, opHash, key, order, needsFace)) return SIG_FAIL;` | caught |
| `src/VoicePolicy.sol` | 278 | `if (order.kind != GPv2Order.KIND_SELL) return false;` | caught |
| `src/VoicePolicy.sol` | 279 | `if (order.partiallyFillable) return false;` | caught |
| `src/VoicePolicy.sol` | 283 | `) return false;` | caught |
| `src/VoicePolicy.sol` | 284 | `if (order.receiver != account) return false;` | caught |
| `src/VoicePolicy.sol` | 287 | `if (order.sellAmount == 0) return false;` | caught |
| `src/VoicePolicy.sol` | 288 | `if (order.buyAmount == 0) return false;` | exempt |
| `src/VoicePolicy.sol` | 291 | `if (order.buyAmount > type(uint128).max) return false;` | caught |
| `src/VoicePolicy.sol` | 295 | `if (order.sellToken == ETH || order.buyToken == ETH) return false;` | caught |
| `src/VoicePolicy.sol` | 299 | `if (order.feeAmount != 0) return false;` | caught |
| `src/VoicePolicy.sol` | 301 | `if (order.sellToken == order.buyToken) return false;` | caught |
| `src/VoicePolicy.sol` | 303 | `if (order.validTo <= block.timestamp) return false;` | caught |
| `src/VoicePolicy.sol` | 304 | `if (order.validTo > block.timestamp + MAX_ORDER_LIFETIME) return false;` | caught |
| `src/VoicePolicy.sol` | 319 | `if (!_validSessionSignature(opHash, sessionSig, key)) return false;` | caught |
| `src/VoicePolicy.sol` | 321 | `if (!hasAssertion) return false;` | caught |
| `src/VoicePolicy.sol` | 363 | `if (signature.length != 65) return false;` | caught |
| `src/VoicePolicy.sol` | 374 | `return false;` | caught |
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

- `src/VoicePolicy.sol:185` redundant by construction: ecrecover returns address(0) on failure and _validSessionSignature rejects that, so a zero session key can never validate. The line is here so the revoked case reads plainly at the top of the function.
- `src/VoicePolicy.sol:288` implied by the price floor two checks later: floor is at least one and sellAmount is at least one, so a zero buyAmount always fails buyAmount * 1e18 < sellAmount * floor. It stays because _wellFormed is deliberately line for line with VesperAccount.placeOrder, which has no floor check and where the same line is load bearing and tested.
