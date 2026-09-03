// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GPv2Order, PackedUserOperation, SIG_FAIL, SIG_OK} from "../src/Types.sol";
import {Assertion} from "../src/WebAuthn.sol";
import {VoiceOrderGate} from "../src/VoiceOrderGate.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";
import {CBBTC, Fixtures, MockSettlement, PEPE, USDC, WETH} from "./Fixtures.sol";
import {Passkey} from "./Passkey.sol";

/// @notice Every check in validateUserOp has a test here that fails when that check is deleted.
contract VoicePolicyTest is Test {
    VoicePolicy policy;
    VoiceOrderGate gate;
    MockSettlement settlement;

    address account = address(0xA11CE);
    uint256 sessionPk = 0xE1C1A7E;
    address sessionKey;

    uint256 constant PER_TRADE = 5_000e6;
    uint256 constant DAILY = 20_000e6;
    uint256 constant FACE_ABOVE = 2_000e6;

    function setUp() public {
        settlement = new MockSettlement();
        gate = new VoiceOrderGate(settlement);
        policy = new VoicePolicy(gate);
        sessionKey = vm.addr(sessionPk);

        vm.warp(1_700_000_000);
        vm.startPrank(account);
        policy.registerSession(
            sessionKey,
            keccak256("approved image"),
            uint48(block.timestamp + 1 days),
            Passkey.RP_ID_HASH,
            Passkey.PUBKEY_X,
            Passkey.PUBKEY_Y
        );
        _allow(USDC);
        _allow(WETH);
        _allow(CBBTC);
        vm.stopPrank();
    }

    // --- the happy path ---------------------------------------------------------------------

    function test_allows_a_trade_inside_every_limit() public {
        assertEq(_validate(_op(USDC, WETH, 1_000e6)), SIG_OK);
    }

    function test_a_trade_over_the_face_limit_passes_with_an_assertion() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory assertion = Passkey.assertionFor(keccak256(abi.encode(order)));

        assertEq(_validate(_opWithAssertion(order, assertion)), SIG_OK);
    }

    // --- the session ------------------------------------------------------------------------

    function test_refuses_when_the_session_key_was_never_registered() public {
        PackedUserOperation memory op = _op(USDC, WETH, 1_000e6);
        op.sender = address(0xB0B);

        assertEq(_validate(op), SIG_FAIL);
    }

    function test_refuses_after_the_owner_revokes() public {
        vm.prank(account);
        policy.revoke();

        assertEq(_validate(_op(USDC, WETH, 1_000e6)), SIG_FAIL);
    }

    function test_refuses_once_the_session_key_has_aged_out() public {
        vm.warp(block.timestamp + 2 days);

        assertEq(_validate(_op(USDC, WETH, 1_000e6)), SIG_FAIL);
    }

    // --- the target -------------------------------------------------------------------------

    function test_refuses_a_call_to_anything_but_the_gate() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        bytes memory callData = Fixtures.callData(
            address(0xDEAD), abi.encodeCall(VoiceOrderGate.placeOrder, (order))
        );

        assertEq(_validate(_sign(Fixtures.userOp(account, callData, ""))), SIG_FAIL);
    }

    function test_refuses_a_different_function_on_the_gate() public {
        bytes memory callData =
            Fixtures.callData(address(gate), abi.encodeWithSignature("settlement()"));

        assertEq(_validate(_sign(Fixtures.userOp(account, callData, ""))), SIG_FAIL);
    }

    function test_refuses_a_call_that_also_sends_ether() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        bytes memory execution = abi.encodePacked(
            address(gate), uint256(1 ether), abi.encodeCall(VoiceOrderGate.placeOrder, (order))
        );
        bytes memory callData =
            abi.encodeWithSignature("execute(bytes32,bytes)", bytes32(0), execution);

        assertEq(_validate(_sign(Fixtures.userOp(account, callData, ""))), SIG_FAIL);
    }

    function test_refuses_calldata_too_short_to_be_a_call() public {
        assertEq(_validate(_sign(Fixtures.userOp(account, hex"1234", ""))), SIG_FAIL);
    }

    // --- the allowlist and the caps ---------------------------------------------------------

    function test_refuses_a_token_that_is_not_on_the_allowlist() public {
        assertEq(_validate(_op(PEPE, WETH, 1_000e6)), SIG_FAIL);
    }

    function test_refuses_buying_a_token_that_is_not_on_the_allowlist() public {
        assertEq(_validate(_op(USDC, PEPE, 1_000e6)), SIG_FAIL);
    }

    function test_refuses_a_trade_over_the_single_trade_cap() public {
        assertEq(_validate(_op(USDC, WETH, PER_TRADE + 1)), SIG_FAIL);
    }

    /// @dev Ten trades at the face limit exactly, which is DAILY, then one more unit.
    function test_refuses_the_trade_that_would_cross_the_daily_cap() public {
        for (uint256 i = 0; i < 10; i++) {
            assertEq(_validate(_op(USDC, WETH, FACE_ABOVE)), SIG_OK);
        }
        assertEq(policy.remainingToday(account, USDC), 0);
        assertEq(_validate(_op(USDC, WETH, 1)), SIG_FAIL);
    }

    function test_the_daily_budget_comes_back_the_next_day() public {
        assertEq(_validate(_op(USDC, WETH, FACE_ABOVE)), SIG_OK);
        assertEq(policy.remainingToday(account, USDC), DAILY - FACE_ABOVE);

        vm.warp(block.timestamp + 1 days + 1);
        assertEq(policy.remainingToday(account, USDC), DAILY);
    }

    function test_each_token_has_its_own_daily_budget() public {
        assertEq(_validate(_op(USDC, WETH, FACE_ABOVE)), SIG_OK);

        assertEq(policy.remainingToday(account, USDC), DAILY - FACE_ABOVE);
        assertEq(policy.remainingToday(account, CBBTC), DAILY);
    }

    /// @dev The threshold is exclusive: at the limit no face is asked for, one unit over it is.
    function test_the_face_limit_is_the_first_unit_above_it() public {
        assertEq(_validate(_op(USDC, WETH, FACE_ABOVE)), SIG_OK);
        assertEq(_validate(_op(USDC, WETH, FACE_ABOVE + 1)), SIG_FAIL);
    }

    // --- the signatures ---------------------------------------------------------------------

    function test_refuses_a_signature_from_a_key_that_is_not_the_session_key() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        PackedUserOperation memory op =
            Fixtures.userOp(account, Fixtures.placeOrderCall(address(gate), order), "");
        bytes32 opHash = keccak256("op");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBADBEEF, _ethSigned(opHash));
        op.signature = Fixtures.signature(abi.encodePacked(r, s, v));

        vm.prank(account);
        assertEq(policy.validateUserOp(op, opHash), SIG_FAIL);
    }

    function test_refuses_an_empty_signature() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        PackedUserOperation memory op = Fixtures.userOp(
            account, Fixtures.placeOrderCall(address(gate), order), Fixtures.signature("")
        );

        vm.prank(account);
        assertEq(policy.validateUserOp(op, keccak256("op")), SIG_FAIL);
    }

    function test_refuses_a_malleable_signature() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        PackedUserOperation memory op =
            Fixtures.userOp(account, Fixtures.placeOrderCall(address(gate), order), "");
        bytes32 opHash = keccak256("op");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, _ethSigned(opHash));

        // The same signature, reflected into the upper half of the curve.
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 flipped = bytes32(n - uint256(s));
        op.signature = Fixtures.signature(abi.encodePacked(r, flipped, v == 27 ? uint8(28) : uint8(27)));

        vm.prank(account);
        assertEq(policy.validateUserOp(op, opHash), SIG_FAIL);
    }

    // --- the passkey ------------------------------------------------------------------------

    function test_refuses_a_trade_over_the_face_limit_with_no_assertion() public {
        assertEq(_validate(_op(USDC, WETH, FACE_ABOVE + 1)), SIG_FAIL);
    }

    function test_refuses_an_assertion_made_for_a_different_order() public {
        GPv2Order.Data memory cheap = Fixtures.order(account, USDC, WETH, 2_500e6);
        GPv2Order.Data memory expensive = Fixtures.order(account, USDC, WETH, 5_000e6);
        Assertion memory forCheap = Passkey.assertionFor(keccak256(abi.encode(cheap)));

        assertEq(_validate(_opWithAssertion(expensive, forCheap)), SIG_FAIL);
    }

    function test_refuses_an_assertion_signed_for_another_site() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory elsewhere = Passkey.assertionFor(
            keccak256(abi.encode(order)), keccak256("evil.example"), Passkey.UP | Passkey.UV
        );

        assertEq(_validate(_opWithAssertion(order, elsewhere)), SIG_FAIL);
    }

    function test_refuses_a_tap_without_a_face() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory tapped =
            Passkey.assertionFor(keccak256(abi.encode(order)), Passkey.RP_ID_HASH, Passkey.UP);

        assertEq(_validate(_opWithAssertion(order, tapped)), SIG_FAIL);
    }

    function test_refuses_an_assertion_the_curve_does_not_verify() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory assertion = Passkey.assertionFor(keccak256(abi.encode(order)));
        assertion.r = bytes32(uint256(1)); // no mock answers for this input

        assertEq(_validate(_opWithAssertion(order, assertion)), SIG_FAIL);
    }

    function test_refuses_authenticator_data_too_short_to_hold_flags() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory assertion = Passkey.assertionFor(keccak256(abi.encode(order)));
        assertion.authenticatorData = hex"00";

        assertEq(_validate(_opWithAssertion(order, assertion)), SIG_FAIL);
    }

    /// @dev Pins the encoder the challenge check depends on, against a value computed outside
    ///      Solidity: base64url(0x11 * 32).
    function test_base64url_matches_a_known_vector() public pure {
        assertEq(
            Passkey.base64url(abi.encodePacked(bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111)))),
            "ERERERERERERERERERERERERERERERERERERERERERE"
        );
    }

    // --- checks that a later check would otherwise hide ---------------------------------------
    //
    // Each of these exists because the mutation report said the guard survived being deleted: some
    // other check was catching the same case by accident. A guard nothing tests is not a guard.

    function test_refuses_a_token_switched_off_while_its_caps_stay_generous() public {
        vm.prank(account);
        policy.setLimits(
            PEPE,
            VoicePolicy.Limits({
                allowed: false,
                perTradeCap: type(uint256).max,
                dailyCap: type(uint256).max,
                biometricThreshold: type(uint256).max
            })
        );

        assertEq(_validate(_op(PEPE, WETH, 1_000e6)), SIG_FAIL);
    }

    function test_refuses_over_the_single_trade_cap_even_with_a_good_assertion() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, PER_TRADE + 1);
        Assertion memory assertion = Passkey.assertionFor(keccak256(abi.encode(order)));

        assertEq(_validate(_opWithAssertion(order, assertion)), SIG_FAIL);
    }

    function test_refuses_an_assertion_attached_but_declared_absent() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory assertion = Passkey.assertionFor(keccak256(abi.encode(order)));

        PackedUserOperation memory op =
            Fixtures.userOp(account, Fixtures.placeOrderCall(address(gate), order), "");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, _ethSigned(keccak256("op")));
        op.signature =
            Fixtures.signatureClaimingNoAssertion(abi.encodePacked(r, s, v), assertion);

        assertEq(_validate(op), SIG_FAIL);
    }

    function test_refuses_a_valid_signature_with_a_byte_stuck_on_the_end() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 1_000e6);
        PackedUserOperation memory op =
            Fixtures.userOp(account, Fixtures.placeOrderCall(address(gate), order), "");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, _ethSigned(keccak256("op")));
        op.signature = Fixtures.signature(abi.encodePacked(r, s, v, hex"00"));

        assertEq(_validate(op), SIG_FAIL);
    }

    function test_refuses_an_assertion_from_an_authenticator_nobody_touched() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory untouched = Passkey.assertionFor(
            keccak256(abi.encode(order)), Passkey.RP_ID_HASH, Passkey.UV
        );

        assertEq(_validate(_opWithAssertion(order, untouched)), SIG_FAIL);
    }

    function test_refuses_client_data_too_short_to_hold_a_challenge() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 3_000e6);
        Assertion memory assertion = Passkey.assertionFor(keccak256(abi.encode(order)));
        assertion.clientDataJSON = "{}";

        assertEq(_validate(_opWithAssertion(order, assertion)), SIG_FAIL);
    }

    // --- helpers ----------------------------------------------------------------------------

    function _allow(address token) private {
        policy.setLimits(
            token,
            VoicePolicy.Limits({
                allowed: true,
                perTradeCap: PER_TRADE,
                dailyCap: DAILY,
                biometricThreshold: FACE_ABOVE
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

    function _op(address sellToken, address buyToken, uint256 amount)
        private
        view
        returns (PackedUserOperation memory)
    {
        GPv2Order.Data memory order = Fixtures.order(account, sellToken, buyToken, amount);
        return _sign(Fixtures.userOp(account, Fixtures.placeOrderCall(address(gate), order), ""));
    }

    function _opWithAssertion(GPv2Order.Data memory order, Assertion memory assertion)
        private
        view
        returns (PackedUserOperation memory op)
    {
        op = Fixtures.userOp(account, Fixtures.placeOrderCall(address(gate), order), "");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, _ethSigned(keccak256("op")));
        op.signature = Fixtures.signature(abi.encodePacked(r, s, v), assertion);
    }

    /// @dev As the account, which is the only caller the policy will answer.
    function _validate(PackedUserOperation memory op) private returns (uint256) {
        vm.prank(op.sender);
        return policy.validateUserOp(op, keccak256("op"));
    }
}
