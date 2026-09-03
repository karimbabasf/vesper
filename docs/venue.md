# Venue verification (build plan step 0)

Verified 2026-09-03 against live networks. Every value below came from a command in this file, not
from documentation. Re-run the commands to re-verify.

## Verdict

Base mainnet is the venue. Everything the design needs is live there.

One finding changes the build plan: **CoW is not deployed on Base Sepolia**, but **RIP-7212 is**.
So the plan splits by what each step actually needs. See "Consequences" at the end.

## Chain

| | |
|---|---|
| Network | Base mainnet |
| Chain id | 8453 |
| RPC used | `https://mainnet.base.org` |
| Testnet | Base Sepolia, chain id 84532, `https://sepolia.base.org` |

## 1. CoW Protocol orderbook API

`GET https://api.cow.fi/{network}/api/v1/version`

| Network path | HTTP | Version |
|---|---|---|
| `base` | 200 | `v2.377.1@b1433c53` |
| `arbitrum_one` | 200 | same |
| `mainnet` | 200 | same |
| `sepolia` | 200 | same |
| `base_sepolia` | **404** | not deployed |

## 2. The API accepts `presign`, and quotes real prices on Base

`POST https://api.cow.fi/base/api/v1/quote` with `"signingScheme":"presign"`, selling 2,000 USDC
into WETH. HTTP 200, and the response echoes the scheme back rather than rejecting it.

```
sellAmount   1999997586        (1,999.997586 USDC)
buyAmount     831828813864475916   (0.8318 WETH)
feeAmount          2414        (0.002414 USDC)
gasAmount        190664
signingScheme  "presign"
protocolFeeBps      2
```

Reproduce:

```bash
curl -s -X POST https://api.cow.fi/base/api/v1/quote -H 'content-type: application/json' -d '{
  "sellToken":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "buyToken":"0x4200000000000000000000000000000000000006",
  "from":"0x0000000000000000000000000000000000000001",
  "receiver":"0x0000000000000000000000000000000000000001",
  "sellAmountBeforeFee":"2000000000","kind":"sell","partiallyFillable":false,
  "sellTokenBalance":"erc20","buyTokenBalance":"erc20",
  "signingScheme":"presign","onchainOrder":false,"priceQuality":"fast","validFor":180}'
```

## 3. Onchain addresses, Base 8453

| Contract | Address | Evidence |
|---|---|---|
| `GPv2Settlement` | `0x9008D19f58AAbD9eD0D60971565AA8510560ab41` | 16,165 bytes of code |
| `GPv2VaultRelayer` | `0xC92E8bdf79f0507f65a392b0ab4667716BFE0110` | 4,590 bytes; also returned by `settlement.vaultRelayer()` |
| RIP-7212 P-256 precompile | `0x0000000000000000000000000000000000000100` | see section 4 |
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | 16,035 bytes, both chains |
| EntryPoint v0.8 | `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108` | 21,738 bytes, both chains |
| EntryPoint v0.6 | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` | 23,689 bytes, both chains |

The account approves the **vault relayer**, not the settlement contract. That is the address token
allowances go to.

### Selectors confirmed present in the settlement bytecode

| Function | Selector |
|---|---|
| `setPreSignature(bytes,bool)` | `0xec6cb13f` |
| `preSignature(bytes)` | `0xd08d33d1` |
| `invalidateOrder(bytes)` | `0x15337bc0` |

### EIP-712 constants for `VoiceOrderGate`

The gate recomputes the CoW order digest onchain, so it needs the exact domain. The computed
separator matches the deployed contract byte for byte, which confirms both the address and the
domain fields.

```
domainSeparator (onchain and computed, identical)
  0xd72ffa789b6fae41254d0b5a13e6e1e92ed947ec6a251edf1cf0b6c02c257b4b

  = keccak256(abi.encode(
      keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
      keccak256("Gnosis Protocol"),
      keccak256("v2"),
      8453,
      0x9008D19f58AAbD9eD0D60971565AA8510560ab41))

ORDER_TYPE_HASH
  0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489

  = keccak256("Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,"
              "uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,"
              "bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)")
```

The domain separator is chain-specific. Deploying anywhere but Base 8453 changes it.

## 4. RIP-7212 is live on both Base chains

A fresh P-256 key was generated locally, a message signed, and the 160-byte input
`hash || r || s || x || y` sent to `0x...0100` by `eth_call`.

| Chain | Valid signature | Corrupted signature |
|---|---|---|
| 8453 Base | `0x00..01` | `0x` (empty) |
| 84532 Base Sepolia | `0x00..01` | `0x` (empty) |

Behaviour matches the spec: 32 bytes of `1` on success, empty return on failure.

Note for the validator: **empty return and a missing precompile look identical**. Treat a short
return as a failure, and keep a FreshCryptoLib fallback path so the module is portable to a chain
without the precompile.

## 5. Token allowlist, Base

| Symbol | Address | Decimals |
|---|---|---|
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | 6 |
| WETH | `0x4200000000000000000000000000000000000006` | 18 |
| cbBTC | `0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf` | 8 |

Symbols and decimals were read from the contracts, not copied from a token list. Decimals matter
because v1 caps are denominated in token units.

## Consequences for the build plan

1. **The Arbitrum fallback is not needed.** Base is confirmed.
2. **Steps 2, 4 and 5 run on Base Sepolia for free.** The validator, the passkey path and the
   enclave attestation need RIP-7212 and an EntryPoint, and both are on 84532.
3. **Only step 3 and the demo need Base mainnet and real money**, because CoW has no Base Sepolia
   deployment. That shrinks the real spend to one funded account near the end rather than
   throughout.
4. **EntryPoint v0.7 is the target.** `PackedUserOperation` in the validator signature is correct
   for it. v0.8 is also live if Kernel's tooling prefers it; v0.6 uses a different struct and would
   change the validator signature, so it is out.
5. **The gate's digest computation is pinned** to the two constants in section 3.
