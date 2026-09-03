// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator, PackedUserOperation} from "./Types.sol";

/// @title VesperAccount
/// @notice The smallest account that can hold funds and be fenced by VoicePolicy.
///
/// The design called for Kernel v3, chosen for bundler and paymaster ergonomics. Neither is needed:
/// `EntryPoint.handleOps` is permissionless, so the operator submits its own user operations. What
/// is left is this, which has the advantage of being readable in one sitting and testable in this
/// repository rather than trusting a factory address and an init encoding.
///
/// The account itself decides nothing. Every user operation is handed to the validator, and the
/// only privileged path is the owner's, which exists so a human can always get the funds out.
contract VesperAccount {
    address public immutable entryPoint;
    IValidator public immutable validator;
    address public immutable owner;

    error NotEntryPoint();
    error NotOwner();
    error NotSelfOrOwner();
    error CallFailed(bytes reason);

    event Executed(address indexed target, uint256 value, bytes data);

    constructor(address entryPoint_, IValidator validator_, address owner_) {
        entryPoint = entryPoint_;
        validator = validator_;
        owner = owner_;
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

    /// @notice ERC-7579 single call. mode is accepted and ignored: this account does one call.
    /// @param executionCalldata target(20) || value(32) || data
    function execute(bytes32, bytes calldata executionCalldata) external {
        if (msg.sender != entryPoint && msg.sender != owner) revert NotSelfOrOwner();

        address target = address(bytes20(executionCalldata[0:20]));
        uint256 value = uint256(bytes32(executionCalldata[20:52]));
        bytes calldata data = executionCalldata[52:];

        (bool ok, bytes memory reason) = target.call{value: value}(data);
        if (!ok) revert CallFailed(reason);
        emit Executed(target, value, data);
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
