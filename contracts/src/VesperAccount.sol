// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GPv2Order, ISettlement, IValidator, IVesperAccount, PackedUserOperation} from "./Types.sol";

/// @title VesperAccount
/// @notice The smallest account that can hold funds and be fenced by VoicePolicy.
///
/// The design called for Kernel v3, chosen for bundler and paymaster ergonomics. Neither is needed:
/// `EntryPoint.handleOps` is permissionless, so the operator submits its own user operations. What
/// is left is this, which has the advantage of being readable in one sitting.
///
/// The account presigns its own orders. An earlier version routed them through a helper contract so
/// the validator could read the order struct, and that cannot work: GPv2Settlement requires the
/// caller to be the address encoded inside the order uid, so only the order's owner can presign it.
/// The helper reverted with "GPv2: cannot presign order" on Base. Folding the call in here fixes it
/// and takes the general `execute` entry point away at the same time, which is the larger win: a
/// user operation can now do exactly one thing, and that is true even if the validator is wrong.
contract VesperAccount is IVesperAccount {
    address public immutable entryPoint;
    IValidator public immutable validator;
    address public immutable owner;
    ISettlement public immutable settlement;

    /// @dev Read from the settlement at deploy time rather than hardcoded, so it cannot drift from
    ///      the chain this is deployed on.
    bytes32 public immutable domainSeparator;

    error NotEntryPoint();
    error NotOwner();
    error NotASale();
    error NotErc20Balances();
    error PartialFillsNotSupported();
    error ReceiverMustBeTheAccount();
    error NoFloor();
    error FeeMustBeZero();
    error ArmedTooLong();
    error CallFailed(bytes reason);

    /// @dev The uid is emitted whole because it is what cancelling takes, and this is the only
    ///      place it exists. To disarm an order: ownerCall(settlement, 0, setPreSignature(uid,
    ///      false)). Revoking the session key stops new orders and does nothing to armed ones.
    event OrderPlaced(
        bytes orderUid, address sellToken, uint256 sellAmount, uint256 floor, uint32 validTo
    );

    /// @dev A presignature is an armed instruction that a solver may act on at any point before
    ///      validTo, and the fence meters orders as they are created rather than as they settle.
    ///      Without a ceiling, a day's worth of caps can be armed and then all settled at once,
    ///      and a uint32 validTo reaches the year 2106. Thirty minutes is six times the deadline
    ///      the enclave asks for, so nothing legitimate touches it.
    uint256 public constant MAX_ORDER_LIFETIME = 30 minutes;

    constructor(address entryPoint_, IValidator validator_, address owner_, ISettlement settlement_) {
        entryPoint = entryPoint_;
        validator = validator_;
        owner = owner_;
        settlement = settlement_;
        domainSeparator = settlement_.domainSeparator();
    }

    receive() external payable {}

    /// @notice ERC-4337 v0.7. The account forwards the decision and keeps none of it.
    function validateUserOp(
        PackedUserOperation calldata op,
        bytes32 opHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        if (msg.sender != entryPoint) revert NotEntryPoint();

        validationData = validator.validateUserOp(op, opHash);

        if (missingAccountFunds > 0) {
            // Failure here is the EntryPoint's problem to report, not ours to mask.
            (bool paid,) = payable(msg.sender).call{value: missingAccountFunds}("");
            paid;
        }
    }

    /// @notice Presign one CoW order. The only thing a user operation can reach.
    ///
    /// The EntryPoint is the sole caller, which means VoicePolicy has already returned SIG_OK for
    /// this exact calldata: the EntryPoint hashes the operation, hands the same bytes to the
    /// validator, and then executes those same bytes. The checks below are not the fence, they are
    /// the shape rules the fence assumes, restated where they cannot be skipped.
    ///
    /// The owner is deliberately not a caller here. `ownerCall` already reaches the settlement, so
    /// a second privileged path would add surface and no ability.
    function placeOrder(GPv2Order.Data calldata order)
        external
        override
        returns (bytes memory orderUid)
    {
        if (msg.sender != entryPoint) revert NotEntryPoint();

        if (order.kind != GPv2Order.KIND_SELL) revert NotASale();
        if (order.partiallyFillable) revert PartialFillsNotSupported();
        if (
            order.sellTokenBalance != GPv2Order.BALANCE_ERC20
                || order.buyTokenBalance != GPv2Order.BALANCE_ERC20
        ) revert NotErc20Balances();

        // Proceeds land in the account the validator checked, never an address the model chose.
        if (order.receiver != address(this)) revert ReceiverMustBeTheAccount();

        // buyAmount is the floor spoken out loud. Zero would let a solver fill at any price.
        if (order.buyAmount == 0) revert NoFloor();

        // The settlement takes sellAmount + feeAmount from this account for a fill-or-kill sale,
        // and the fence only ever counted sellAmount. A fee is therefore sell-side value leaving
        // that nothing quoted, nothing capped and no face approved. CoW takes its fee inside the
        // price now and refuses an order that carries one, so zero is also the only value that
        // gets filled.
        if (order.feeAmount != 0) revert FeeMustBeZero();

        if (order.validTo > block.timestamp + MAX_ORDER_LIFETIME) revert ArmedTooLong();

        orderUid = abi.encodePacked(GPv2Order.hash(order, domainSeparator), address(this), order.validTo);
        settlement.setPreSignature(orderUid, true);

        emit OrderPlaced(
            orderUid, order.sellToken, order.sellAmount, order.buyAmount, order.validTo
        );
    }

    /// @notice The way out. The validator never sees this, and it is the reason a burner is safe
    ///         to fund: whatever else breaks, the owner can still empty the account.
    function ownerCall(address target, uint256 value, bytes calldata data)
        external
        returns (bytes memory)
    {
        if (msg.sender != owner) revert NotOwner();

        (bool ok, bytes memory result) = target.call{value: value}(data);
        if (!ok) revert CallFailed(result);
        return result;
    }
}
