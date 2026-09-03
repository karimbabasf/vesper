// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GPv2Order, ISettlement} from "./Types.sol";

/// @title VoiceOrderGate
/// @notice The only address VoicePolicy will let the account call.
///
/// `setPreSignature` takes an order uid, and a uid is a hash. A validator handed one cannot see the
/// token, the amount or the floor, so it cannot enforce anything. This contract exists so the full
/// order struct travels in the calldata where the validator can read it, and only then becomes a
/// uid. It holds no funds, has no owner and stores nothing.
contract VoiceOrderGate {
    using GPv2Order for GPv2Order.Data;

    ISettlement public immutable settlement;

    /// @dev Read from the settlement contract at deploy time rather than hardcoded, so it cannot
    ///      drift from the chain this is deployed on.
    bytes32 public immutable domainSeparator;

    error NotASale();
    error NotErc20Balances();
    error PartialFillsNotSupported();
    error ReceiverMustBeTheAccount();
    error NoFloor();

    event OrderPlaced(address indexed account, bytes32 indexed orderDigest, uint256 sellAmount);

    constructor(ISettlement settlement_) {
        settlement = settlement_;
        domainSeparator = settlement_.domainSeparator();
    }

    /// @notice Presign one order on behalf of the calling account.
    /// @dev The account is the owner in the uid, so an account can only ever presign its own order.
    function placeOrder(GPv2Order.Data calldata order) external returns (bytes32 orderDigest) {
        if (order.kind != GPv2Order.KIND_SELL) revert NotASale();
        if (order.partiallyFillable) revert PartialFillsNotSupported();
        if (
            order.sellTokenBalance != GPv2Order.BALANCE_ERC20
                || order.buyTokenBalance != GPv2Order.BALANCE_ERC20
        ) revert NotErc20Balances();

        // Proceeds must land in the account the validator checked, never an address the model chose.
        if (order.receiver != msg.sender) revert ReceiverMustBeTheAccount();

        // buyAmount is the floor spoken out loud. Zero would let a solver fill at any price.
        if (order.buyAmount == 0) revert NoFloor();

        orderDigest = GPv2Order.hash(order, domainSeparator);
        settlement.setPreSignature(
            abi.encodePacked(orderDigest, msg.sender, order.validTo), true
        );

        emit OrderPlaced(msg.sender, orderDigest, order.sellAmount);
    }
}
