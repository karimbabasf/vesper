// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GPv2Order, PackedUserOperation, SIG_FAIL, SIG_OK} from "../src/Types.sol";
import {VesperAccount} from "../src/VesperAccount.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";
import {Fixtures, MockSettlement, PEPE, USDC, WETH} from "./Fixtures.sol";
import {Passkey} from "./Passkey.sol";

contract VesperAccountTest is Test {
    VesperAccount account;
    VoicePolicy policy;
    MockSettlement settlement;

    address entryPoint = address(0xEE);
    address owner = address(0x0BE1);
    uint256 sessionPk = 0xE1C1A7E;

    function setUp() public {
        settlement = new MockSettlement();
        policy = new VoicePolicy();
        account = new VesperAccount(entryPoint, policy, owner, settlement);

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

    // --- validation -------------------------------------------------------------------------

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

    // --- placing an order -------------------------------------------------------------------

    function test_the_entry_point_can_place_an_order() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);

        vm.prank(entryPoint);
        bytes memory uid = account.placeOrder(order);

        assertEq(uid.length, 56);
        assertTrue(settlement.preSignature(uid) != 0);
    }

    /// @dev The settlement only accepts a presignature from the address inside the uid, which is
    ///      what the first design missed. Building the uid around this account is what makes the
    ///      call land at all.
    function test_the_uid_names_this_account_as_the_owner() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);

        vm.prank(entryPoint);
        bytes memory uid = account.placeOrder(order);

        address ownerInUid;
        assembly { ownerInUid := shr(96, mload(add(uid, 64))) }
        assertEq(ownerInUid, address(account));
    }

    function test_a_stranger_cannot_place_an_order() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);

        vm.prank(address(0xBAD));
        vm.expectRevert(VesperAccount.NotEntryPoint.selector);
        account.placeOrder(order);
    }

    /// @dev Even the owner goes through ownerCall. One privileged path, not two.
    function test_the_owner_cannot_place_an_order_directly() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);

        vm.prank(owner);
        vm.expectRevert(VesperAccount.NotEntryPoint.selector);
        account.placeOrder(order);
    }

    function test_refuses_an_order_that_pays_someone_else() public {
        GPv2Order.Data memory order = Fixtures.order(address(0xBAD), USDC, WETH, 1_000e6);

        vm.prank(entryPoint);
        vm.expectRevert(VesperAccount.ReceiverMustBeTheAccount.selector);
        account.placeOrder(order);
    }

    function test_refuses_an_order_with_no_floor() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);
        order.buyAmount = 0;

        vm.prank(entryPoint);
        vm.expectRevert(VesperAccount.NoFloor.selector);
        account.placeOrder(order);
    }

    function test_refuses_a_buy_order() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);
        order.kind = keccak256("buy");

        vm.prank(entryPoint);
        vm.expectRevert(VesperAccount.NotASale.selector);
        account.placeOrder(order);
    }

    function test_refuses_a_partially_fillable_order() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);
        order.partiallyFillable = true;

        vm.prank(entryPoint);
        vm.expectRevert(VesperAccount.PartialFillsNotSupported.selector);
        account.placeOrder(order);
    }

    function test_refuses_balances_held_anywhere_but_the_token() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);
        order.sellTokenBalance = keccak256("external");

        vm.prank(entryPoint);
        vm.expectRevert(VesperAccount.NotErc20Balances.selector);
        account.placeOrder(order);
    }

    function test_refuses_buy_balances_held_anywhere_but_the_token() public {
        GPv2Order.Data memory order = Fixtures.order(address(account), USDC, WETH, 1_000e6);
        order.buyTokenBalance = keccak256("internal");

        vm.prank(entryPoint);
        vm.expectRevert(VesperAccount.NotErc20Balances.selector);
        account.placeOrder(order);
    }

    /// @dev The account has no general execute and no fallback, so the EntryPoint cannot be talked
    ///      into calling anything else on it even if the validator were wrong.
    function test_the_account_answers_no_other_selector() public {
        vm.prank(entryPoint);
        (bool ok,) = address(account).call(abi.encodeWithSignature("execute(bytes32,bytes)", bytes32(0), ""));
        assertFalse(ok);
    }

    // --- the escape hatch -------------------------------------------------------------------

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

    function test_a_failing_owner_call_reverts_rather_than_reporting_success() public {
        vm.prank(owner);
        vm.expectRevert();
        account.ownerCall(address(settlement), 0, abi.encodeWithSignature("nope()"));
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
        op = Fixtures.userOp(address(account), Fixtures.placeOrderCall(order), "");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            sessionPk,
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256("op")))
        );
        op.signature = Fixtures.signature(abi.encodePacked(r, s, v));
    }
}
