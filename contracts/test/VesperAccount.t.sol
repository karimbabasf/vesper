// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GPv2Order, PackedUserOperation, SIG_FAIL, SIG_OK} from "../src/Types.sol";
import {VesperAccount} from "../src/VesperAccount.sol";
import {VoiceOrderGate} from "../src/VoiceOrderGate.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";
import {Fixtures, MockSettlement, PEPE, USDC, WETH} from "./Fixtures.sol";
import {Passkey} from "./Passkey.sol";

contract Sink {
    uint256 public seen;
    bool public shouldRevert;

    function ping() external payable {
        if (shouldRevert) revert("no");
        seen += 1;
    }

    function setRevert(bool value) external {
        shouldRevert = value;
    }
}

contract VesperAccountTest is Test {
    VesperAccount account;
    VoicePolicy policy;
    VoiceOrderGate gate;
    MockSettlement settlement;
    Sink sink;

    address entryPoint = address(0xEE);
    address owner = address(0x0BE1);
    uint256 sessionPk = 0xE1C1A7E;

    function setUp() public {
        settlement = new MockSettlement();
        gate = new VoiceOrderGate(settlement);
        policy = new VoicePolicy(gate);
        account = new VesperAccount(entryPoint, policy, owner);
        sink = new Sink();

        vm.warp(1_700_000_000);
        vm.startPrank(address(account));
        policy.registerSession(
            vm.addr(sessionPk),
            keccak256("approved image"),
            uint48(block.timestamp + 1 days),
            Passkey.RP_ID_HASH,
            Passkey.PUBKEY_X,
            Passkey.PUBKEY_Y
        );
        _allow(USDC);
        _allow(WETH);
        vm.stopPrank();

        vm.deal(address(account), 1 ether);
    }

    function test_only_the_entry_point_may_ask_for_validation() public {
        PackedUserOperation memory op = _op(1_000e6);

        vm.expectRevert(VesperAccount.NotEntryPoint.selector);
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_the_validators_verdict_is_passed_through_unchanged() public {
        vm.prank(entryPoint);
        assertEq(account.validateUserOp(_op(1_000e6), keccak256("op"), 0), SIG_OK);
    }

    function test_a_refusal_from_the_validator_is_passed_through_too() public {
        vm.prank(entryPoint);
        assertEq(account.validateUserOp(_op(1_000e6, PEPE), keccak256("op"), 0), SIG_FAIL);
    }

    function test_pays_the_entry_point_what_it_is_missing() public {
        uint256 before = entryPoint.balance;

        vm.prank(entryPoint);
        account.validateUserOp(_op(1_000e6), keccak256("op"), 0.1 ether);

        assertEq(entryPoint.balance - before, 0.1 ether);
    }

    function test_a_stranger_cannot_make_the_account_call_anything() public {
        vm.expectRevert(VesperAccount.NotSelfOrOwner.selector);
        account.execute(bytes32(0), abi.encodePacked(address(sink), uint256(0), abi.encodeCall(Sink.ping, ())));
    }

    function test_the_entry_point_can_make_the_account_call() public {
        vm.prank(entryPoint);
        account.execute(
            bytes32(0), abi.encodePacked(address(sink), uint256(0), abi.encodeCall(Sink.ping, ()))
        );

        assertEq(sink.seen(), 1);
    }

    function test_a_failing_call_reverts_rather_than_reporting_success() public {
        sink.setRevert(true);

        vm.prank(entryPoint);
        vm.expectRevert();
        account.execute(
            bytes32(0), abi.encodePacked(address(sink), uint256(0), abi.encodeCall(Sink.ping, ()))
        );
    }

    function test_the_owner_can_always_empty_the_account() public {
        uint256 before = owner.balance;

        vm.prank(owner);
        account.ownerCall(owner, 1 ether, "");

        assertEq(owner.balance - before, 1 ether);
        assertEq(address(account).balance, 0);
    }

    function test_nobody_else_can_use_the_escape_hatch() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(VesperAccount.NotOwner.selector);
        account.ownerCall(address(0xBAD), 1 ether, "");
    }

    // --- helpers ----------------------------------------------------------------------------

    function _allow(address token) private {
        policy.setLimits(
            token,
            VoicePolicy.Limits({
                allowed: true,
                perTradeCap: 5_000e6,
                dailyCap: 20_000e6,
                biometricThreshold: 2_000e6
            })
        );
    }

    function _op(uint256 amount) private view returns (PackedUserOperation memory) {
        return _op(amount, USDC);
    }

    function _op(uint256 amount, address sellToken)
        private
        view
        returns (PackedUserOperation memory op)
    {
        GPv2Order.Data memory order =
            Fixtures.order(address(account), sellToken, WETH, amount);
        op = Fixtures.userOp(
            address(account), Fixtures.placeOrderCall(address(gate), order), ""
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            sessionPk,
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256("op")))
        );
        op.signature = Fixtures.signature(abi.encodePacked(r, s, v));
    }
}
