// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GPv2Order, MAX_ORDER_LIFETIME, PackedUserOperation, SIG_FAIL, SIG_OK} from "../src/Types.sol";
import {Assertion} from "../src/WebAuthn.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";
import {CBBTC, Fixtures, USDC, WETH} from "./Fixtures.sol";
import {Passkey} from "./Passkey.sol";

/// @notice Every way value was found leaving the account that the caps did not count.
///
/// Two independent reviews went at the fence at once. Between them these are the holes: gas paid
/// out of the account as ether, a price floor the same key that is compromised gets to write, a
/// biometric threshold that only ever looked at one order, a token sold for itself, and a fence
/// whose SIG_OK did not mean the call would go through. Each has a test here that fails when its
/// check is removed.
contract DrainsTest is Test {
    VoicePolicy policy;

    address account = address(0xA11CE);
    uint256 sessionPk = 0xE1C1A7E;

    uint128 constant PER_TRADE = 5_000e6;
    uint128 constant DAILY = 20_000e6;
    uint128 constant FACE_ABOVE = 2_000e6;

    function setUp() public {
        policy = new VoicePolicy();

        vm.warp(1_700_000_000);
        vm.startPrank(account);
        policy.registerSession(
            vm.addr(sessionPk),
            keccak256("approved image"),
            uint48(block.timestamp + 30 days),
            Passkey.RP_ID_HASH,
            Passkey.PUBKEY_X,
            Passkey.PUBKEY_Y
        );
        _allow(USDC, FACE_ABOVE);
        _allow(WETH, FACE_ABOVE);
        _allow(CBBTC, FACE_ABOVE);
        policy.setLimits(
            address(0),
            VoicePolicy.Limits({
                perTradeCap: uint128(Fixtures.maxCost()),
                dailyCap: uint128(Fixtures.maxCost() * 3),
                biometricThreshold: type(uint128).max,
                allowed: true
            })
        );
        policy.setFloor(USDC, WETH, 1);
        policy.setFloor(WETH, USDC, 1);
        vm.stopPrank();
    }

    // --- the gas fields ------------------------------------------------------------------------
    //
    // Every input to the EntryPoint's prefund is chosen by whoever signs the operation, and the
    // account pays it in ether. A one wei trade barely moves the token budget, so without a bound
    // here the ether is not bounded at all.

    function test_refuses_more_verification_gas_than_the_ceiling() public {
        PackedUserOperation memory op = _op(1_000e6);
        op.accountGasLimits = bytes32(((policy.MAX_VERIFICATION_GAS() + 1) << 128) | 400_000);

        assertEq(_validate(_resign(op)), SIG_FAIL);
    }

    function test_refuses_more_call_gas_than_the_ceiling() public {
        PackedUserOperation memory op = _op(1_000e6);
        op.accountGasLimits = bytes32((uint256(400_000) << 128) | (policy.MAX_CALL_GAS() + 1));

        assertEq(_validate(_resign(op)), SIG_FAIL);
    }

    function test_refuses_more_pre_verification_gas_than_the_ceiling() public {
        PackedUserOperation memory op = _op(1_000e6);
        op.preVerificationGas = policy.MAX_PRE_VERIFICATION_GAS() + 1;

        assertEq(_validate(_resign(op)), SIG_FAIL);
    }

    function test_refuses_a_gas_price_above_the_ceiling() public {
        PackedUserOperation memory op = _op(1_000e6);
        op.gasFees = bytes32((uint256(1) << 128) | (policy.MAX_FEE_PER_GAS() + 1));

        assertEq(_validate(_resign(op)), SIG_FAIL);
    }

    function test_refuses_an_operation_carrying_a_paymaster() public {
        PackedUserOperation memory op = _op(1_000e6);
        op.paymasterAndData = abi.encodePacked(address(0xBEEF), uint128(1), uint128(1));

        assertEq(_validate(_resign(op)), SIG_FAIL);
    }

    /// @dev The drain itself: a one wei trade repeated for its gas. The token budget would allow
    ///      five thousand billion of these; the ether budget allows three.
    function test_the_ether_budget_stops_a_one_wei_trade_repeating_for_its_gas() public {
        for (uint256 i = 0; i < 3; i++) {
            assertEq(_validate(_op(1)), SIG_OK);
        }
        assertEq(policy.remainingToday(account, address(0)), 0);
        assertEq(_validate(_op(1)), SIG_FAIL);

        // The token budget is untouched, which is the point: nothing else was ever going to notice.
        assertEq(policy.remainingToday(account, USDC), DAILY - 3);
    }

    function test_refuses_when_no_ether_budget_was_ever_set() public {
        vm.prank(account);
        policy.setLimits(
            address(0),
            VoicePolicy.Limits({
                perTradeCap: type(uint128).max,
                dailyCap: type(uint128).max,
                biometricThreshold: type(uint128).max,
                allowed: false
            })
        );

        assertEq(_validate(_op(1_000e6)), SIG_FAIL);
    }

    // --- the price -----------------------------------------------------------------------------

    /// @dev CoW's only on-chain guarantee is the limit price written into the order, and the key
    ///      that writes it is the one assumed compromised. Selling the daily cap for one wei is
    ///      inside every other bound.
    function test_refuses_a_sale_below_the_floor_the_owner_set() public {
        vm.prank(account);
        policy.setFloor(USDC, WETH, 1e15); // 0.001 WETH per 1 USDC, in base units per 1e18

        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.buyAmount = 1;

        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    function test_accepts_a_sale_exactly_at_the_floor() public {
        vm.prank(account);
        policy.setFloor(USDC, WETH, 1e15);

        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.buyAmount = (uint256(1_000e6) * 1e15) / 1e18;

        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_OK);
    }

    /// @dev A pair the owner has not priced is not a pair the fence can protect, so it is refused
    ///      rather than waved through at whatever price the model asked for.
    function test_refuses_a_pair_the_owner_never_priced() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, CBBTC, 1_000e6);

        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    // --- the threshold -------------------------------------------------------------------------

    /// @dev The bypass: every order sized at the threshold exactly, so no single one is above it,
    ///      and the whole daily budget leaves without a passkey ever being asked for.
    function test_the_threshold_counts_the_day_and_not_one_order() public {
        assertEq(_validate(_op(FACE_ABOVE)), SIG_OK);

        // Under the old rule this was allowed, and so were eight more after it.
        assertEq(_validate(_op(FACE_ABOVE)), SIG_FAIL);
    }

    function test_the_same_second_trade_goes_through_with_a_face() public {
        assertEq(_validate(_op(FACE_ABOVE)), SIG_OK);

        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, FACE_ABOVE);
        PackedUserOperation memory op =
            Fixtures.userOp(account, Fixtures.placeOrderCall(order), "");
        Assertion memory assertion =
            Passkey.assertionFor(keccak256(abi.encode(order, keccak256("op"))));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, _ethSigned(keccak256("op")));
        op.signature = Fixtures.signature(abi.encodePacked(r, s, v), assertion);

        assertEq(_validate(op), SIG_OK);
    }

    /// @dev The assertion is bound to the operation, not only to the order, so an approval cannot
    ///      be reused for a second operation carrying the same order.
    function test_an_approval_does_not_carry_to_another_operation() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, FACE_ABOVE + 1);
        Assertion memory forThisOp =
            Passkey.assertionFor(keccak256(abi.encode(order, keccak256("op"))));

        PackedUserOperation memory other =
            Fixtures.userOp(account, Fixtures.placeOrderCall(order), "");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, _ethSigned(keccak256("another op")));
        other.signature = Fixtures.signature(abi.encodePacked(r, s, v), forThisOp);

        vm.prank(account);
        assertEq(policy.validateUserOp(other, keccak256("another op")), SIG_FAIL);
    }

    // --- SIG_OK has to mean the call goes through ----------------------------------------------

    function test_refuses_selling_a_token_for_itself() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, USDC, 1_000e6);

        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    function test_refuses_an_order_that_has_already_expired() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.validTo = uint32(block.timestamp);

        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    function test_refuses_an_order_armed_for_longer_than_the_ceiling() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.validTo = uint32(block.timestamp + MAX_ORDER_LIFETIME + 1);

        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    /// @dev The shape rules used to live only on the account, so an operation could pass the fence,
    ///      be charged against the budget, and then revert. Six of those emptied a day for nothing.
    function test_a_shape_the_account_would_reject_never_reaches_it() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.partiallyFillable = true;
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
        assertEq(policy.remainingToday(account, USDC), DAILY, "budget was charged anyway");

        order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.receiver = address(0xBAD);
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);

        order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.kind = keccak256("buy");
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);

        order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.sellTokenBalance = keccak256("external");
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);

        order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.buyTokenBalance = keccak256("internal");
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);

        assertEq(policy.remainingToday(account, USDC), DAILY);
    }

    // --- checks a later check would otherwise hide -----------------------------------------------
    //
    // Each of these exists because the mutation report said the guard survived being deleted. The
    // price floor in particular masks a lot: an unpriced pair is refused before the allowlist, the
    // self-swap rule or the missing floor amount ever get a look.

    function test_refuses_a_sell_token_switched_off_while_everything_else_is_in_order() public {
        vm.startPrank(account);
        policy.setLimits(
            CBBTC,
            VoicePolicy.Limits({
                perTradeCap: type(uint128).max,
                dailyCap: type(uint128).max,
                biometricThreshold: type(uint128).max,
                allowed: false
            })
        );
        policy.setFloor(CBBTC, WETH, 1);
        vm.stopPrank();

        GPv2Order.Data memory order = Fixtures.order(account, CBBTC, WETH, 1_000e6);
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    function test_refuses_a_buy_token_switched_off_while_everything_else_is_in_order() public {
        vm.startPrank(account);
        policy.setLimits(
            CBBTC,
            VoicePolicy.Limits({
                perTradeCap: type(uint128).max,
                dailyCap: type(uint128).max,
                biometricThreshold: type(uint128).max,
                allowed: false
            })
        );
        policy.setFloor(USDC, CBBTC, 1);
        vm.stopPrank();

        GPv2Order.Data memory order = Fixtures.order(account, USDC, CBBTC, 1_000e6);
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    /// @dev One operation asking for more ether than one operation may have, with plenty left in
    ///      the day. The daily check would otherwise be the only thing refusing it.
    function test_refuses_one_operation_asking_for_more_ether_than_a_trade_may_cost() public {
        vm.prank(account);
        policy.setLimits(
            address(0),
            VoicePolicy.Limits({
                perTradeCap: uint128(Fixtures.maxCost() - 1),
                dailyCap: type(uint128).max,
                biometricThreshold: type(uint128).max,
                allowed: true
            })
        );

        assertEq(_validate(_op(1_000e6)), SIG_FAIL);
    }

    /// @dev With a loose floor and a small trade the ratio rounds to zero, so a zero buyAmount
    ///      clears the floor check and only the explicit rule refuses it.
    function test_refuses_a_zero_floor_the_ratio_check_rounds_past() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        order.buyAmount = 0;
        assertEq((uint256(1_000e6) * 1) / 1e18, 0, "the ratio no longer rounds to zero");

        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    function test_refuses_a_token_sold_for_itself_even_when_that_pair_is_priced() public {
        vm.prank(account);
        policy.setFloor(USDC, USDC, 1);

        GPv2Order.Data memory order = Fixtures.order(account, USDC, USDC, 1_000e6);
        assertEq(_validate(_sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""))), SIG_FAIL);
    }

    // --- helpers -------------------------------------------------------------------------------

    function _allow(address token, uint128 face) private {
        policy.setLimits(
            token,
            VoicePolicy.Limits({
                perTradeCap: PER_TRADE,
                dailyCap: DAILY,
                biometricThreshold: face,
                allowed: true
            })
        );
    }

    function _ethSigned(bytes32 opHash) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", opHash));
    }

    function _sign(PackedUserOperation memory op) private view returns (PackedUserOperation memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, _ethSigned(keccak256("op")));
        op.signature = Fixtures.signature(abi.encodePacked(r, s, v));
        return op;
    }

    function _resign(PackedUserOperation memory op)
        private
        view
        returns (PackedUserOperation memory)
    {
        return _sign(op);
    }

    function _op(uint256 amount) private view returns (PackedUserOperation memory) {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, amount);
        return _sign(Fixtures.userOp(account, Fixtures.placeOrderCall(order), ""));
    }

    function _validate(PackedUserOperation memory op) private returns (uint256) {
        vm.prank(op.sender);
        return policy.validateUserOp(op, keccak256("op"));
    }
}
