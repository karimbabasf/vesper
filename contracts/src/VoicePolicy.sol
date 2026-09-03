// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    GPv2Order,
    IValidator,
    IVesperAccount,
    MODULE_TYPE_VALIDATOR,
    PackedUserOperation,
    SIG_FAIL,
    SIG_OK
} from "./Types.sol";
import {Assertion, WebAuthn} from "./WebAuthn.sol";

/// @title VoicePolicy
/// @notice The whole security boundary, in one function.
///
/// Everything upstream, the audio and the model and the enclave, exists to make the inputs to
/// `validateUserOp` trustworthy enough to be worth checking. This is the only component that can
/// refuse in a way the enclave cannot influence, because the enclave does not run it.
///
/// There is no assembly here. An earlier version hand-decoded an ERC-7579 execute envelope to find
/// the order, read one offset from the wrong base, and would have decoded a different order from
/// the one the EntryPoint went on to execute. The account now takes the order as a plain external
/// argument, so both sides read it through the compiler's decoder and cannot disagree.
contract VoicePolicy is IValidator {
    /// @dev key and expiry share slot 0, and the hot path reads nothing else. The three passkey
    ///      fields are only loaded above the biometric threshold, which is the uncommon case.
    struct Session {
        address key; // the enclave's session key, dead on restart
        uint48 expiry;
        bytes32 attestationHash; // recorded, not verified: see the note on registerSession
        bytes32 rpIdHash; // the origin the passkey belongs to
        bytes32 passkeyX;
        bytes32 passkeyY;
    }

    /// @dev Two slots rather than four. uint128 holds 3.4e38, and the largest token amount that
    ///      exists anywhere is around 1e30, so nothing real truncates. Anything that would is
    ///      rejected by the ABI decoder at `setLimits` before it can be stored.
    struct Limits {
        uint128 perTradeCap; // token units
        uint128 dailyCap; // token units, rolling 24h
        uint128 biometricThreshold; // above this the passkey is required
        bool allowed;
    }

    /// @dev One slot. amount is bounded by dailyCap, which is a uint128.
    struct Spend {
        uint128 amount;
        uint48 windowStart;
    }

    mapping(address account => Session) public sessions;
    mapping(address account => mapping(address token => Limits)) public limits;
    mapping(address account => mapping(address token => Spend)) internal spends;

    event SessionRegistered(address indexed account, address key, bytes32 attestationHash);
    event SessionRevoked(address indexed account);
    event LimitsSet(address indexed account, address indexed token, Limits limits);

    // --- owner controls, always callable by the account itself -----------------------------

    /// @notice Authorise one enclave session key.
    ///
    /// `attestationHash` is the enclave image the owner says they approved. It is a record and not
    /// a check: verifying a TDX quote on chain is not affordable, so nothing here can confirm the
    /// key was really generated inside that image. Whoever registers the key is trusted to have
    /// checked the quote off chain. Written down here so the claim is not read as stronger.
    function registerSession(
        address key,
        bytes32 attestationHash,
        uint48 expiry,
        bytes32 rpIdHash,
        bytes32 passkeyX,
        bytes32 passkeyY
    ) external {
        sessions[msg.sender] =
            Session(key, expiry, attestationHash, rpIdHash, passkeyX, passkeyY);
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
        uint256 cap = limits[account][token].dailyCap;
        uint256 spent = _spentToday(account, token);
        return spent >= cap ? 0 : cap - spent;
    }

    // --- the boundary ----------------------------------------------------------------------

    function validateUserOp(PackedUserOperation calldata op, bytes32 opHash)
        external
        override
        returns (uint256)
    {
        // Only the account may ask about its own operation. Without this anyone can call in with
        // a signature they watched go by and any op fields they like, and burn the daily budget
        // without ever executing anything. The EntryPoint binds op to opHash; a direct caller does
        // not, so the binding has to be re-established here by refusing direct callers.
        if (msg.sender != op.sender) return SIG_FAIL;

        // The free checks first, so a malformed operation costs no storage reads.
        //
        // Exactly one call, of exactly one shape. GPv2Order.Data is twelve static fields, so a
        // well formed call is the selector and nothing but the struct. Any other length is either
        // a different function or the same one with something appended, and both are refused here
        // rather than reasoned about.
        if (op.callData.length != 4 + GPv2Order.ENCODED_LENGTH) return SIG_FAIL;
        if (bytes4(op.callData) != IVesperAccount.placeOrder.selector) return SIG_FAIL;

        // The EntryPoint calls op.sender with these exact bytes, so naming the target is not
        // needed: the target is the sender, and the sender is the account that just called in.
        GPv2Order.Data memory order = abi.decode(op.callData[4:], (GPv2Order.Data));

        (address key, uint48 expiry) = _sessionKey(op.sender);
        // Revoked, or never registered. Redundant with the signature check below, since ecrecover
        // cannot recover to address(0); it is here so the revoked case reads plainly.
        if (key == address(0)) return SIG_FAIL;
        if (block.timestamp > expiry) return SIG_FAIL; // the key has aged out

        Limits memory sellLimits = limits[op.sender][order.sellToken];
        if (!sellLimits.allowed) return SIG_FAIL;
        if (!limits[op.sender][order.buyToken].allowed) return SIG_FAIL;

        // Per trade before daily, and not only for readability: passing this bounds sellAmount by
        // a uint128, which is what keeps the sum on the next line from overflowing.
        if (order.sellAmount > sellLimits.perTradeCap) return SIG_FAIL;
        if (_spentToday(op.sender, order.sellToken) + order.sellAmount > sellLimits.dailyCap) {
            return SIG_FAIL;
        }

        (bytes memory sessionSig, bool hasAssertion, Assertion memory assertion) =
            _decodeSignature(op.signature);

        if (!_validSessionSignature(opHash, sessionSig, key)) return SIG_FAIL;

        if (order.sellAmount > sellLimits.biometricThreshold) {
            if (!hasAssertion) return SIG_FAIL;
            Session storage session = sessions[op.sender];
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

        _recordSpend(op.sender, order.sellToken, uint128(order.sellAmount));
        return SIG_OK;
    }

    // --- internals -------------------------------------------------------------------------

    /// @dev Reads slot 0 of the session and stops. Loading the whole struct would pull three
    ///      passkey words the common trade never looks at.
    function _sessionKey(address account) internal view returns (address key, uint48 expiry) {
        Session storage session = sessions[account];
        key = session.key;
        expiry = session.expiry;
    }

    /// @dev A malformed blob reverts here rather than returning SIG_FAIL. Only the account can
    ///      reach this line, and the account only ever carries what its own signer produced, so
    ///      the difference is visible to the operator and to nobody else.
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
        if (block.timestamp >= uint256(spend.windowStart) + 1 days) return 0;
        return spend.amount;
    }

    function _recordSpend(address account, address token, uint128 amount) internal {
        Spend storage spend = spends[account][token];
        if (block.timestamp >= uint256(spend.windowStart) + 1 days) {
            spends[account][token] = Spend(amount, uint48(block.timestamp));
        } else {
            spend.amount += amount;
        }
    }

    // --- ERC-7579 plumbing -----------------------------------------------------------------

    /// @dev This account binds its validator at construction rather than installing it, so these
    ///      two exist for the interface and answer about the session, which is the thing that
    ///      actually makes the module usable for an account.
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {
        delete sessions[msg.sender];
        emit SessionRevoked(msg.sender);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return sessions[account].key != address(0);
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
