// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    GPv2Order,
    IValidator,
    MODULE_TYPE_VALIDATOR,
    PackedUserOperation,
    SIG_FAIL,
    SIG_OK
} from "./Types.sol";
import {Assertion, WebAuthn} from "./WebAuthn.sol";
import {VoiceOrderGate} from "./VoiceOrderGate.sol";

/// @title VoicePolicy
/// @notice The whole security boundary, in one function.
///
/// Everything upstream, the audio and the model and the enclave, exists to make the inputs to
/// `validateUserOp` trustworthy enough to be worth checking. This is the only component that can
/// refuse in a way the enclave cannot influence, because the enclave does not run it.
contract VoicePolicy is IValidator {
    struct Session {
        address key; // the enclave's session key, dead on restart
        bytes32 attestationHash; // the image the owner approved
        uint48 expiry;
        bytes32 rpIdHash; // the origin the passkey belongs to
        bytes32 passkeyX;
        bytes32 passkeyY;
    }

    struct Limits {
        bool allowed;
        uint256 perTradeCap; // token units
        uint256 dailyCap; // token units, rolling 24h
        uint256 biometricThreshold; // above this the passkey is required
    }

    struct Spend {
        uint256 amount;
        uint48 windowStart;
    }

    /// @notice The one address an account may call through this validator.
    VoiceOrderGate public immutable gate;

    mapping(address account => Session) public sessions;
    mapping(address account => mapping(address token => Limits)) public limits;
    mapping(address account => mapping(address token => Spend)) internal spends;
    mapping(address account => bool) public installed;

    event SessionRegistered(address indexed account, address key, bytes32 attestationHash);
    event SessionRevoked(address indexed account);
    event LimitsSet(address indexed account, address indexed token, Limits limits);

    constructor(VoiceOrderGate gate_) {
        gate = gate_;
    }

    // --- owner controls, always callable by the account itself -----------------------------

    /// @notice Authorise one enclave session key under one approved image.
    function registerSession(
        address key,
        bytes32 attestationHash,
        uint48 expiry,
        bytes32 rpIdHash,
        bytes32 passkeyX,
        bytes32 passkeyY
    ) external {
        sessions[msg.sender] =
            Session(key, attestationHash, expiry, rpIdHash, passkeyX, passkeyY);
        emit SessionRegistered(msg.sender, key, attestationHash);
    }

    /// @notice The kill switch. One transaction, independent of everything else working.
    function revoke() external {
        delete sessions[msg.sender];
        emit SessionRevoked(msg.sender);
    }

    function setLimits(address token, Limits calldata newLimits) external {
        limits[msg.sender][token] = newLimits;
        emit LimitsSet(msg.sender, token, newLimits);
    }

    /// @notice What is left of today's budget for one token.
    function remainingToday(address account, address token) external view returns (uint256) {
        Limits memory limit = limits[account][token];
        uint256 spent = _spentToday(account, token);
        return spent >= limit.dailyCap ? 0 : limit.dailyCap - spent;
    }

    // --- the boundary ----------------------------------------------------------------------

    function validateUserOp(PackedUserOperation calldata op, bytes32 opHash)
        external
        override
        returns (uint256)
    {
        Session memory session = sessions[op.sender];
        // Revoked, or never registered. Redundant with the signature check below, since ecrecover
        // cannot recover to address(0); it is here so the revoked case reads plainly.
        if (session.key == address(0)) return SIG_FAIL;
        if (block.timestamp > session.expiry) return SIG_FAIL; // the key has aged out

        (address target, bytes calldata callData) = _decodeSingleCall(op.callData);
        if (target != address(gate)) return SIG_FAIL; // one address in the world
        if (bytes4(callData) != VoiceOrderGate.placeOrder.selector) return SIG_FAIL;

        GPv2Order.Data memory order = abi.decode(callData[4:], (GPv2Order.Data));

        Limits memory sellLimits = limits[op.sender][order.sellToken];
        if (!sellLimits.allowed) return SIG_FAIL;
        if (!limits[op.sender][order.buyToken].allowed) return SIG_FAIL;

        if (order.sellAmount > sellLimits.perTradeCap) return SIG_FAIL;
        if (_spentToday(op.sender, order.sellToken) + order.sellAmount > sellLimits.dailyCap) {
            return SIG_FAIL;
        }

        (bytes memory sessionSig, bool hasAssertion, Assertion memory assertion) =
            _decodeSignature(op.signature);

        if (!_validSessionSignature(opHash, sessionSig, session.key)) return SIG_FAIL;

        if (order.sellAmount > sellLimits.biometricThreshold) {
            if (!hasAssertion) return SIG_FAIL;
            if (
                !WebAuthn.verify(
                    assertion,
                    keccak256(abi.encode(order)), // binds the face to THIS order
                    session.rpIdHash,
                    session.passkeyX,
                    session.passkeyY
                )
            ) return SIG_FAIL;
        }

        _recordSpend(op.sender, order.sellToken, order.sellAmount);
        return SIG_OK;
    }

    // --- internals -------------------------------------------------------------------------

    /// @dev ERC-7579 single call: execute(bytes32 mode, bytes executionCalldata) where
    ///      executionCalldata is target(20) || value(32) || data.
    function _decodeSingleCall(bytes calldata opCallData)
        internal
        pure
        returns (address target, bytes calldata data)
    {
        // 4 selector + 32 mode + 32 offset + 32 length is the shortest possible encoding.
        if (opCallData.length < 100) return (address(0), opCallData[0:0]);

        bytes calldata execution;
        assembly {
            // args begin after the 4 byte selector: (bytes32 mode, bytes executionCalldata)
            let args := add(opCallData.offset, 4)
            let start := add(args, calldataload(add(args, 32)))
            execution.length := calldataload(start)
            execution.offset := add(start, 32)
        }
        if (execution.length < 52) return (address(0), opCallData[0:0]);

        target = address(bytes20(execution[0:20]));
        // execution[20:52] is msg.value, which must be zero: this account never sends ether.
        if (uint256(bytes32(execution[20:52])) != 0) return (address(0), opCallData[0:0]);
        data = execution[52:];
    }

    function _decodeSignature(bytes calldata signature)
        internal
        pure
        returns (bytes memory sessionSig, bool hasAssertion, Assertion memory assertion)
    {
        if (signature.length == 0) return (sessionSig, false, assertion);
        (sessionSig, hasAssertion, assertion) = abi.decode(signature, (bytes, bool, Assertion));
    }

    function _validSessionSignature(bytes32 opHash, bytes memory signature, address key)
        internal
        pure
        returns (bool)
    {
        if (signature.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        // Reject the high half of the curve, so one signature cannot be replayed as two.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }
        bytes32 digest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", opHash));
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == key;
    }

    function _spentToday(address account, address token) internal view returns (uint256) {
        Spend memory spend = spends[account][token];
        if (block.timestamp >= spend.windowStart + 1 days) return 0;
        return spend.amount;
    }

    function _recordSpend(address account, address token, uint256 amount) internal {
        Spend storage spend = spends[account][token];
        if (block.timestamp >= spend.windowStart + 1 days) {
            spend.windowStart = uint48(block.timestamp);
            spend.amount = amount;
        } else {
            spend.amount += amount;
        }
    }

    // --- ERC-7579 plumbing -----------------------------------------------------------------

    function onInstall(bytes calldata) external override {
        installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external override {
        delete installed[msg.sender];
        delete sessions[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return installed[account];
    }

    /// @notice This module never validates a plain signature. Orders go through userOps only.
    function isValidSignatureWithSender(address, bytes32, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return 0xffffffff;
    }
}
