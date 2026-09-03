// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GPv2Order, PackedUserOperation, SIG_FAIL} from "../src/Types.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";
import {Fixtures, USDC, WETH} from "./Fixtures.sol";
import {Passkey} from "./Passkey.sol";

/// @notice Regression test for audit finding 1: validateUserOp used to trust any caller,
///         so a stranger could replay an observed signature and exhaust the daily budget.
contract GriefingTest is Test {
    VoicePolicy policy;
    address account = address(0xA11CE);
    uint256 sessionPk = 0xE1C1A7E;

    function setUp() public {
        policy = new VoicePolicy();

        vm.warp(1_700_000_000);
        vm.startPrank(account);
        policy.registerSession(
            vm.addr(sessionPk), keccak256("image"), uint48(block.timestamp + 1 days),
            Passkey.RP_ID_HASH, Passkey.PUBKEY_X, Passkey.PUBKEY_Y
        );
        policy.setLimits(
            USDC,
            VoicePolicy.Limits({
                allowed: true, perTradeCap: 5_000e6, dailyCap: 20_000e6, biometricThreshold: 5_000e6
            })
        );
        policy.setLimits(
            WETH,
            VoicePolicy.Limits({
                allowed: true, perTradeCap: 5_000e6, dailyCap: 20_000e6, biometricThreshold: 5_000e6
            })
        );
        vm.stopPrank();
    }

    function test_a_stranger_cannot_burn_the_daily_budget() public {
        // One legitimate operation, signed once by the enclave and observed on chain by anyone.
        bytes32 opHash = keccak256("some op the attacker watched go by");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            sessionPk, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", opHash))
        );
        bytes memory signature = Fixtures.signature(abi.encodePacked(r, s, v));

        assertEq(policy.remainingToday(account, USDC), 20_000e6);

        // The attacker never needs a key. They replay the pair they saw, four times.
        vm.startPrank(address(0xBAD));
        for (uint256 i = 0; i < 4; i++) {
            GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 5_000e6);
            PackedUserOperation memory op =
                Fixtures.userOp(account, Fixtures.placeOrderCall(order), signature);
            assertEq(policy.validateUserOp(op, opHash), SIG_FAIL);
        }
        vm.stopPrank();

        // Untouched: a caller that is not the account gets nowhere.
        assertEq(policy.remainingToday(account, USDC), 20_000e6);
    }
}
