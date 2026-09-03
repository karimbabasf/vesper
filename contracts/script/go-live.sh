#!/usr/bin/env bash
# Deploy the fence and one account behind it, once.
#
#     cd contracts && bash script/go-live.sh
#
# Reads PRIVATE_KEY and SESSION_PRIVATE_KEY from contracts/.env, deploys, writes the new addresses
# back into that file, sweeps whatever the previous account was holding into the new one, and sets
# the limits, the floors and the session key. Then it reads every one of those back off the chain,
# because a deploy script printing what it meant to do is not evidence that it did.
#
# Run test/Live.t.sol first. It exercises this whole path against Base at a pinned block for free,
# and it exists because two bugs each cost a reverted transaction here before it did.
set -euo pipefail

cd "$(dirname "$0")/.."
# Override both to rehearse the whole thing against `anvil --fork-url https://mainnet.base.org`
# before spending anything. That is what the dry run in the README does.
RPC=${RPC:-https://mainnet.base.org}
ENV_FILE=${ENV_FILE:-.env}

set -a && . "$ENV_FILE" && set +a
OWNER=$(cast wallet address --private-key "$PRIVATE_KEY")

echo "owner    $OWNER"
echo "balance  $(cast balance "$OWNER" --rpc-url $RPC --ether) ETH"
echo

if [ "${SKIP_FORK_SUITE:-}" != "1" ]; then
  echo "== fork suite =="
  FOUNDRY_PROFILE=live forge test --match-path test/Live.t.sol >/dev/null
  echo "passed, so the path works against the deployed contracts"
  echo
fi

echo "== deploy =="
OUT=$(forge script script/Deploy.s.sol --rpc-url $RPC --broadcast 2>&1)
NEW_POLICY=$(echo "$OUT" | grep -A1 '^  policy' | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
NEW_ACCOUNT=$(echo "$OUT" | grep -A1 '^  account' | grep -oE '0x[0-9a-fA-F]{40}' | head -1)

if [ -z "$NEW_POLICY" ] || [ -z "$NEW_ACCOUNT" ]; then
  echo "could not read the addresses out of the deploy output:"
  echo "$OUT" | tail -30
  exit 1
fi
echo "policy   $NEW_POLICY"
echo "account  $NEW_ACCOUNT"
echo

# Keep the previous account named, so setup can sweep it rather than stranding the balance.
python3 - "$ENV_FILE" "$NEW_POLICY" "$NEW_ACCOUNT" <<'PY'
import sys, pathlib
path, policy, account = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
lines, old = [], None
for line in path.read_text().splitlines():
    if line.startswith("ACCOUNT="):
        old = line.split("=", 1)[1].strip()
        continue
    if line.startswith(("POLICY=", "GATE=", "OLD_ACCOUNT=")):
        continue
    lines.append(line)
if old and old.lower() != account.lower():
    lines.append(f"OLD_ACCOUNT={old}")
lines += [f"POLICY={policy}", f"ACCOUNT={account}"]
path.write_text("\n".join(lines) + "\n")
print(f"wrote {path}" + (f", sweeping {old}" if old else ""))
PY
echo

echo "== setup =="
set -a && . "$ENV_FILE" && set +a
forge script script/Setup.s.sol --rpc-url $RPC --broadcast >/dev/null
echo "done"
echo

echo "== read back from the chain =="
WETH=0x4200000000000000000000000000000000000006
USDC=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
SESSION=$(cast wallet address --private-key "$SESSION_PRIVATE_KEY")

printf 'account eth      %s\n' "$(cast balance "$ACCOUNT" --rpc-url $RPC --ether)"
printf 'account weth     %s\n' "$(cast call $WETH 'balanceOf(address)(uint256)' "$ACCOUNT" --rpc-url $RPC)"
printf 'session onchain  %s\n' "$(cast call "$POLICY" 'sessions(address)(address,uint48,bytes32,bytes32,bytes32,bytes32)' "$ACCOUNT" --rpc-url $RPC | head -1)"
printf 'session expected %s\n' "$SESSION"
printf 'weth limits      %s\n' "$(cast call "$POLICY" 'limits(address,address)(uint128,uint128,uint128,bool)' "$ACCOUNT" $WETH --rpc-url $RPC | tr '\n' ' ')"
printf 'gas limits       %s\n' "$(cast call "$POLICY" 'limits(address,address)(uint128,uint128,uint128,bool)' "$ACCOUNT" 0x0000000000000000000000000000000000000000 --rpc-url $RPC | tr '\n' ' ')"
printf 'floor weth/usdc  %s\n' "$(cast call "$POLICY" 'minBuyPerSell(address,address,address)(uint256)' "$ACCOUNT" $WETH $USDC --rpc-url $RPC)"
printf 'relayer approval %s\n' "$(cast call $WETH 'allowance(address,address)(uint256)' "$ACCOUNT" 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110 --rpc-url $RPC)"
printf 'owner left       %s ETH\n' "$(cast balance "$OWNER" --rpc-url $RPC --ether)"
