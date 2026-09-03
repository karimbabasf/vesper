// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GPv2Order} from "../src/Types.sol";
import {VoiceOrderGate} from "../src/VoiceOrderGate.sol";
import {BASE_DOMAIN_SEPARATOR, Fixtures, MockSettlement, USDC, WETH} from "./Fixtures.sol";

contract VoiceOrderGateTest is Test {
    MockSettlement settlement;
    VoiceOrderGate gate;
    address account = address(0xA11CE);

    function setUp() public {
        settlement = new MockSettlement();
        gate = new VoiceOrderGate(settlement);
    }

    function test_reads_its_domain_separator_from_the_settlement_contract() public view {
        assertEq(gate.domainSeparator(), BASE_DOMAIN_SEPARATOR);
    }

    /// @dev The type hash is the one recomputed against Base in docs/venue.md. If this changes,
    ///      every digest this contract produces is for an order CoW will never recognise.
    function test_order_type_hash_matches_the_deployed_protocol() public pure {
        assertEq(
            GPv2Order.TYPE_HASH,
            0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489
        );
        assertEq(
            GPv2Order.TYPE_HASH,
            keccak256(
                "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,"
                "uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,"
                "bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
            )
        );
    }

    function test_presigns_the_order_with_the_account_as_owner() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 2000e6);

        vm.prank(account);
        bytes32 digest = gate.placeOrder(order);

        assertEq(settlement.calls(), 1);
        assertTrue(settlement.lastSigned());
        // uid is digest(32) || owner(20) || validTo(4)
        assertEq(settlement.lastUid(), abi.encodePacked(digest, account, order.validTo));
    }

    function test_the_digest_is_the_eip712_hash_of_the_order() public view {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 2000e6);

        assertEq(
            GPv2Order.hash(order, BASE_DOMAIN_SEPARATOR),
            keccak256(
                abi.encodePacked(
                    hex"1901",
                    BASE_DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            GPv2Order.TYPE_HASH,
                            order.sellToken,
                            order.buyToken,
                            order.receiver,
                            order.sellAmount,
                            order.buyAmount,
                            order.validTo,
                            order.appData,
                            order.feeAmount,
                            order.kind,
                            order.partiallyFillable,
                            order.sellTokenBalance,
                            order.buyTokenBalance
                        )
                    )
                )
            )
        );
    }

    function test_refuses_an_order_whose_proceeds_go_somewhere_else() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 2000e6);
        order.receiver = address(0xBAD);

        vm.prank(account);
        vm.expectRevert(VoiceOrderGate.ReceiverMustBeTheAccount.selector);
        gate.placeOrder(order);
    }

    function test_refuses_an_order_with_no_floor() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 2000e6);
        order.buyAmount = 0;

        vm.prank(account);
        vm.expectRevert(VoiceOrderGate.NoFloor.selector);
        gate.placeOrder(order);
    }

    function test_refuses_a_buy_order() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 2000e6);
        order.kind = keccak256("buy");

        vm.prank(account);
        vm.expectRevert(VoiceOrderGate.NotASale.selector);
        gate.placeOrder(order);
    }

    function test_refuses_a_partially_fillable_order() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 2000e6);
        order.partiallyFillable = true;

        vm.prank(account);
        vm.expectRevert(VoiceOrderGate.PartialFillsNotSupported.selector);
        gate.placeOrder(order);
    }

    function test_refuses_balances_that_are_not_plain_erc20() public {
        GPv2Order.Data memory order = Fixtures.order(account, USDC, WETH, 2000e6);
        order.sellTokenBalance = keccak256("external");

        vm.prank(account);
        vm.expectRevert(VoiceOrderGate.NotErc20Balances.selector);
        gate.placeOrder(order);
    }
}
