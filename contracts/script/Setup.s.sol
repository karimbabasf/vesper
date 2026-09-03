// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {VesperAccount} from "../src/VesperAccount.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";

interface IWETH {
    function deposit() external payable;
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice Fund the account, set the fence, and register the session key.
///
///     forge script script/Setup.s.sol --rpc-url https://mainnet.base.org --broadcast
///
/// Everything here is signed by the owner. The session key can do none of it: it can only place
/// orders, and only inside the limits this script writes.
///
/// Set OLD_ACCOUNT to sweep a previous deployment's WETH and ether across first, so redeploying
/// costs gas and not the balance.
contract Setup is Script {
    address constant WETH = 0x4200000000000000000000000000000000000006;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant VAULT_RELAYER = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;

    /// @dev Deliberately above anything this wallet can afford to trade, so the first end to end
    ///      run needs no passkey. Lowered later to demonstrate the biometric path.
    ///
    ///      The daily cap is a bucket that refills over a day, not a counter that resets, so at
    ///      most twice this can leave in twenty four hours. Set it to half what you would accept
    ///      losing. VoicePolicy._spentToday explains why no cheap rate limiter does better.
    uint128 constant WETH_PER_TRADE = 0.002 ether;
    uint128 constant WETH_DAILY = 0.005 ether;
    uint128 constant WETH_FACE_ABOVE = 0.002 ether;

    /// @dev Gas is ether leaving the account, and the operation asks for its own gas, so it gets a
    ///      budget like anything else.
    ///
    ///      The budget is charged what the operation could cost, not what it did, because at
    ///      validation time nothing knows the second number. On Base that over-meters by a lot:
    ///      the enclave asks for 0.05 gwei and the chain charges around 0.006. So the failure mode
    ///      the ether budget creates is a freeze rather than a drain. A stolen key can exhaust it
    ///      in a handful of maximum-gas operations and then nothing trades, including the owner's
    ///      own operator, until it refills. That is recoverable in one ownerCall and losing a day
    ///      of trading beats losing the ether, but it is a real change of failure mode and it is
    ///      written down here rather than discovered.
    ///
    ///      Per operation is set just above what one real operation charges, so an attacker cannot
    ///      spend the day's budget faster than the operator would.
    uint128 constant GAS_PER_OPERATION = 0.00006 ether;
    uint128 constant GAS_DAILY = 0.002 ether;

    /// @dev The worst price the owner will accept, in buy base units per 1e18 sell base units.
    ///      A manual price, not an oracle: CoW guarantees only the limit price in the order, and
    ///      the key that writes that limit is the one assumed stolen. Computed 2026-09-03 at about
    ///      2,400 USDC per WETH, with twenty percent of slack, and it needs refreshing when the
    ///      price moves further than that. Stale here refuses trades rather than allowing bad ones.
    uint128 constant FLOOR_WETH_FOR_USDC = 1_920_000_000;
    uint128 constant FLOOR_USDC_FOR_WETH = 333_333_333_333_333_333_333_333_333;

    function run() external {
        uint256 ownerPk = vm.envUint("PRIVATE_KEY");
        VesperAccount account = VesperAccount(payable(vm.envAddress("ACCOUNT")));
        VoicePolicy policy = VoicePolicy(vm.envAddress("POLICY"));
        address sessionKey = vm.addr(vm.envUint("SESSION_PRIVATE_KEY"));

        address oldAccount = vm.envOr("OLD_ACCOUNT", address(0));
        uint256 toAccount = vm.envOr("FUND_WEI", uint256(0));
        uint256 toWrap = vm.envOr("WRAP_WEI", uint256(0));

        vm.startBroadcast(ownerPk);

        if (oldAccount != address(0)) {
            VesperAccount old = VesperAccount(payable(oldAccount));
            uint256 strandedWeth = IWETH(WETH).balanceOf(oldAccount);
            if (strandedWeth > 0) {
                old.ownerCall(
                    WETH, 0, abi.encodeCall(IWETH.transfer, (address(account), strandedWeth))
                );
            }
            if (oldAccount.balance > 0) {
                old.ownerCall(address(account), oldAccount.balance, "");
            }
        }

        if (toAccount > 0) payable(address(account)).transfer(toAccount);

        // Wrap, then let CoW's relayer move the WETH when a solver fills.
        if (toWrap > 0) account.ownerCall(WETH, toWrap, abi.encodeCall(IWETH.deposit, ()));
        account.ownerCall(
            WETH, 0, abi.encodeCall(IWETH.approve, (VAULT_RELAYER, type(uint256).max))
        );

        account.ownerCall(
            address(policy),
            0,
            abi.encodeCall(
                VoicePolicy.setLimits,
                (
                    WETH,
                    VoicePolicy.Limits({
                        perTradeCap: WETH_PER_TRADE,
                        dailyCap: WETH_DAILY,
                        biometricThreshold: WETH_FACE_ABOVE,
                        allowed: true
                    })
                )
            )
        );
        account.ownerCall(
            address(policy),
            0,
            abi.encodeCall(
                VoicePolicy.setLimits,
                (
                    USDC,
                    VoicePolicy.Limits({
                        perTradeCap: 5_000000,
                        dailyCap: 20_000000,
                        biometricThreshold: 2_000000,
                        allowed: true
                    })
                )
            )
        );

        account.ownerCall(
            address(policy),
            0,
            abi.encodeCall(
                VoicePolicy.setLimits,
                (
                    address(0),
                    VoicePolicy.Limits({
                        perTradeCap: GAS_PER_OPERATION,
                        dailyCap: GAS_DAILY,
                        // Deliberately out of reach. The passkey gates the sell token's spend,
                        // and gas is not a sell token, so the ether budget is face-free by
                        // construction: it is a loss limit, not something a human approves.
                        // Asking for a face to pay for gas would mean no unattended operation at
                        // all, which is the whole product.
                        biometricThreshold: type(uint128).max,
                        allowed: true
                    })
                )
            )
        );

        account.ownerCall(
            address(policy), 0,
            abi.encodeCall(VoicePolicy.setFloor, (WETH, USDC, FLOOR_WETH_FOR_USDC))
        );
        account.ownerCall(
            address(policy), 0,
            abi.encodeCall(VoicePolicy.setFloor, (USDC, WETH, FLOOR_USDC_FOR_WETH))
        );

        account.ownerCall(
            address(policy),
            0,
            abi.encodeCall(
                VoicePolicy.registerSession,
                (
                    sessionKey,
                    keccak256("no enclave yet, step 5"),
                    uint48(block.timestamp + 30 days),
                    // WebAuthn puts sha256(rpId) in authenticatorData, and rpId is the hostname
                    // the console is served from. sha256("localhost").
                    0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763,
                    bytes32(0),
                    bytes32(0)
                )
            )
        );

        vm.stopBroadcast();

        console.log("account eth  ", address(account).balance);
        console.log("account weth ", IWETH(WETH).balanceOf(address(account)));
        console.log("session key  ", sessionKey);
        console.log("");
        console.log("The passkey is registered as zero, so nothing above the face threshold can");
        console.log("trade until a real one is set up from the console. That is the fence failing");
        console.log("closed, not a bug.");
    }
}
