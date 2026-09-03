// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    GPv2Order,
    IValidator,
    IVesperAccount,
    MAX_ORDER_LIFETIME,
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

    /// @notice Gas is ETH leaving the account, so it is budgeted like any other token.
    ///
    /// Every input to the EntryPoint's prefund is chosen by whoever signs the operation, and
    /// `preVerificationGas` in particular is charged in full and paid to a beneficiary the
    /// submitter names. A stolen session key can therefore carry a one wei trade, ask for four
    /// million gas at ten gwei, name itself the beneficiary, and take the ether. Nothing about the
    /// token caps touches that: the WETH budget barely moves.
    ///
    /// So the operation's own worst case cost is metered against `limits[account][ETH]`. The
    /// ceilings below exist as well, because a budget is a bound on the day and a ceiling is a
    /// bound on one operation, and because they are what keep the multiplication in range.
    address public constant ETH = address(0);

    uint256 public constant MAX_VERIFICATION_GAS = 500_000;
    uint256 public constant MAX_CALL_GAS = 500_000;
    /// @dev Every unit of this is paid in full to whoever submits the bundle, whatever the L1 cost
    ///      turned out to be, and the submitter of a stolen operation names itself. The operator
    ///      asks for 60,000 and is its own beneficiary, so for honest use the number is a wash.
    uint256 public constant MAX_PRE_VERIFICATION_GAS = 100_000;
    /// @dev Base runs around 0.006 gwei. This is over a hundred times that.
    uint256 public constant MAX_FEE_PER_GAS = 1 gwei;

    mapping(address account => Session) public sessions;
    mapping(address account => mapping(address token => Limits)) public limits;
    mapping(address account => mapping(address token => Spend)) internal spends;

    /// @notice The worst price the owner will accept for a pair, as buy units per 1e18 sell units.
    ///
    /// The caps bound how much leaves. Without this they say nothing about what comes back, and a
    /// stolen key can sell the whole daily budget for one wei by writing its own `buyAmount`: CoW's
    /// only on-chain guarantee is the limit price in the order, and solver competition is off
    /// chain. Zero means the owner has not priced this pair and the contract does not pretend to
    /// know one. It goes stale, which is the owner's to manage, and stale here refuses trades
    /// rather than allowing bad ones.
    mapping(address account => mapping(address sell => mapping(address buy => uint256)))
        public minBuyPerSell;

    event SessionRegistered(address indexed account, address key, bytes32 attestationHash);
    event SessionRevoked(address indexed account);
    event LimitsSet(address indexed account, address indexed token, Limits limits);
    event FloorSet(address indexed account, address indexed sell, address indexed buy, uint256 ratio);

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

    /// @param ratio Buy token base units per 1e18 sell token base units. Zero switches it off.
    function setFloor(address sell, address buy, uint128 ratio) external {
        minBuyPerSell[msg.sender][sell][buy] = ratio;
        emit FloorSet(msg.sender, sell, buy, ratio);
    }

    /// @notice What is left of today's budget for one token.
    function remainingToday(address account, address token) external view returns (uint256) {
        uint256 cap = limits[account][token].dailyCap;
        uint256 spent = _spentToday(account, token, cap);
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

        // A paymaster would change who pays and add two more gas fields to the prefund. This
        // account has no paymaster, so the field is required to be absent rather than reasoned
        // about, and the cost below is then the whole cost.
        if (op.paymasterAndData.length != 0) return SIG_FAIL;

        (bool gasFieldsOk, uint256 maxCost) = _maxCost(op);
        if (!gasFieldsOk) return SIG_FAIL;

        // The EntryPoint calls op.sender with these exact bytes, so naming the target is not
        // needed: the target is the sender, and the sender is the account that just called in.
        GPv2Order.Data memory order = abi.decode(op.callData[4:], (GPv2Order.Data));

        // Every shape rule placeOrder enforces, enforced here too. They were only over there, which
        // made SIG_OK a weaker statement than it looks: an operation could pass the fence, be
        // charged against the budget, and then revert on a rule the fence never checked. Six of
        // those in a row emptied a day's budget with nothing armed.
        if (!_wellFormed(order, op.sender)) return SIG_FAIL;

        (address key, uint48 expiry) = _sessionKey(op.sender);
        // Revoked, or never registered. Redundant with the signature check below, since ecrecover
        // cannot recover to address(0); it is here so the revoked case reads plainly.
        if (key == address(0)) return SIG_FAIL;
        if (block.timestamp > expiry) return SIG_FAIL; // the key has aged out

        Limits memory sellLimits = limits[op.sender][order.sellToken];
        if (!sellLimits.allowed) return SIG_FAIL;
        if (!limits[op.sender][order.buyToken].allowed) return SIG_FAIL;

        // Per trade before daily, and not only for readability: passing this bounds sellAmount by
        // a uint128, which is what keeps the sums below from overflowing.
        if (order.sellAmount > sellLimits.perTradeCap) return SIG_FAIL;
        // Read once and carried to _recordSpend below, rather than loading the same slot twice.
        uint256 spent = _spentToday(op.sender, order.sellToken, sellLimits.dailyCap);
        if (spent + order.sellAmount > sellLimits.dailyCap) return SIG_FAIL;

        {
            uint256 floor = minBuyPerSell[op.sender][order.sellToken][order.buyToken];
            // An unpriced pair is not a tradeable pair: without a floor the caps bound how much
            // leaves and say nothing about what comes back, and a stolen key writes buyAmount.
            if (floor == 0) return SIG_FAIL;
            // Cross multiplied rather than divided. Written as buyAmount < sellAmount * floor / 1e18
            // the requirement rounds down, and it rounds all the way to zero whenever the product
            // is under 1e18: a floor that was set would quietly mean "any buyAmount at all" for
            // every trade under some size, and nothing would say which of the two it was doing.
            //
            // In range on both sides: sellAmount and floor are each bounded by a uint128, so their
            // product is at most 2^256 - 2^129 + 1, and buyAmount is bounded to a uint128 by
            // _wellFormed, so its product with 1e18 is under 2^188.
            if (order.buyAmount * 1e18 < order.sellAmount * floor) return SIG_FAIL;
        }

        Limits memory gasLimits = limits[op.sender][ETH];
        uint256 gasSpent = _spentToday(op.sender, ETH, gasLimits.dailyCap);
        {
            if (!gasLimits.allowed) return SIG_FAIL;
            if (maxCost > gasLimits.perTradeCap) return SIG_FAIL;
            if (gasSpent + maxCost > gasLimits.dailyCap) return SIG_FAIL;
        }

        // Cumulative, not per order. Asking about one order lets a stolen key sit just under the
        // threshold and move the whole daily budget without a face ever being asked for.
        //
        // Be exact about what "cumulative" buys, because it is not a hard limit and it is not a
        // day. It reads the same draining ledger the daily cap does, so twice the threshold moves
        // per rolling day without a face, for the reason set out on _spentToday. And it is kept per
        // sell token, because the caps are and there is no price on chain to normalise across them,
        // so N allowed tokens give N independent allowances. **Set the threshold to what you want
        // to approve by hand, divided by twice the number of allowed tokens.**
        bool needsFace = spent + order.sellAmount > sellLimits.biometricThreshold;
        if (!_signaturesOk(op, opHash, key, order, needsFace)) return SIG_FAIL;

        _recordSpend(op.sender, order.sellToken, spent, uint128(order.sellAmount));
        _recordSpend(op.sender, ETH, gasSpent, uint128(maxCost));
        return SIG_OK;
    }

    // --- internals -------------------------------------------------------------------------

    /// @dev The worst this operation can cost the account in ether, and whether it is even asking
    ///      for a plausible amount of gas. The ceilings are what keep the multiply in range as
    ///      well as bounding one operation.
    function _maxCost(PackedUserOperation calldata op)
        internal
        pure
        returns (bool ok, uint256 maxCost)
    {
        uint256 verificationGas = uint256(op.accountGasLimits) >> 128;
        uint256 callGas = uint128(uint256(op.accountGasLimits));
        uint256 maxFee = uint128(uint256(op.gasFees));

        if (verificationGas > MAX_VERIFICATION_GAS) return (false, 0);
        if (callGas > MAX_CALL_GAS) return (false, 0);
        if (op.preVerificationGas > MAX_PRE_VERIFICATION_GAS) return (false, 0);
        if (maxFee > MAX_FEE_PER_GAS) return (false, 0);
        // The priority word, which this used to ignore. The reservation is computed from
        // maxFeePerGas, but the EntryPoint pays the beneficiary at
        // min(maxFeePerGas, basefee + maxPriorityFeePerGas), so the priority word is what decides
        // how much of the reservation becomes a real transfer to whoever submitted the bundle.
        // Leaving it unbounded made the realisable loss ninety six times the honest cost while the
        // reservation stayed the same. This does not change the bound; it closes the gap between
        // the bound and what an attacker can actually collect.
        if (uint256(op.gasFees) >> 128 > MAX_FEE_PER_GAS) return (false, 0);

        // At most 1.2e6 gas times 1e9 wei. Nowhere near overflowing, and it fits a uint128.
        return (true, (verificationGas + callGas + op.preVerificationGas) * maxFee);
    }

    /// @dev The order rules that do not depend on any stored limit. The same list VesperAccount
    ///      enforces, so that SIG_OK means the call will actually go through.
    function _wellFormed(GPv2Order.Data memory order, address account)
        internal
        view
        returns (bool)
    {
        if (order.kind != GPv2Order.KIND_SELL) return false;
        if (order.partiallyFillable) return false;
        if (
            order.sellTokenBalance != GPv2Order.BALANCE_ERC20
                || order.buyTokenBalance != GPv2Order.BALANCE_ERC20
        ) return false;
        if (order.receiver != account) return false;
        // Selling nothing clears the per-trade cap, the daily cap and the floor, and still arms
        // an order and charges the ether budget. Nothing to gain and something to grief.
        if (order.sellAmount == 0) return false;
        if (order.buyAmount == 0) return false;
        // No real token has this many base units, and bounding it is what keeps the price
        // comparison from overflowing.
        if (order.buyAmount > type(uint128).max) return false;
        // address(0) is the key the ether budget is kept under, so an order naming it as a token
        // would have its token spend and its gas spend written to the same slot, and the second
        // write would erase the first. It is not an ERC-20 either way.
        if (order.sellToken == ETH || order.buyToken == ETH) return false;
        // The settlement takes sellAmount + feeAmount from the account for a fill-or-kill sale, so
        // a cap that reads only sellAmount is not a cap. Refused rather than added to the total:
        // a non-zero fee is never legitimate, and a comparison cannot overflow.
        if (order.feeAmount != 0) return false;
        // Selling a token for itself passes every other check and burns the difference.
        if (order.sellToken == order.buyToken) return false;
        // Already expired: it would arm nothing and still be charged in full.
        if (order.validTo <= block.timestamp) return false;
        if (order.validTo > block.timestamp + MAX_ORDER_LIFETIME) return false;
        return true;
    }

    /// @dev The session key always, and the passkey when the day's spend crosses the threshold.
    function _signaturesOk(
        PackedUserOperation calldata op,
        bytes32 opHash,
        address key,
        GPv2Order.Data memory order,
        bool needsFace
    ) internal view returns (bool) {
        (bytes memory sessionSig, bool hasAssertion, Assertion memory assertion) =
            _decodeSignature(op.signature);

        if (!_validSessionSignature(opHash, sessionSig, key)) return false;
        if (!needsFace) return true;
        if (!hasAssertion) return false;

        Session storage session = sessions[op.sender];
        return WebAuthn.verify(
            assertion,
            // Binds the face to this order inside this operation. The order alone would let one
            // approval be replayed for as long as the order stays valid; opHash carries the chain,
            // the EntryPoint, the account and the nonce, so it can be used exactly once.
            keccak256(abi.encode(order, opHash)),
            session.rpIdHash,
            session.passkeyX,
            session.passkeyY
        );
    }

    /// @dev Reads slot 0 of the session and stops. Loading the whole struct would pull three
    ///      passkey words the common trade never looks at.
    function _sessionKey(address account) internal view returns (address key, uint48 expiry) {
        Session storage session = sessions[account];
        key = session.key;
        expiry = session.expiry;
    }

    /// @dev A malformed blob reverts here rather than returning SIG_FAIL. handleOps is
    ///      permissionless, so a stranger can make that happen by submitting a deliberately
    ///      broken operation, and it costs them their own gas to revert their own transaction.
    ///      Nothing is recorded and nothing executes, so the two outcomes differ only in how the
    ///      failure is reported.
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

    uint256 internal constant WINDOW = 1 days;

    /// @dev A bucket of size dailyCap that refills at a constant rate, not a counter that resets.
    ///
    /// Be exact about what this promises, because the obvious reading is wrong. It is **not** "at
    /// most dailyCap leaves in any twenty four hours". Spend the whole bucket, wait a day while it
    /// refills, spend it again: that is 2x dailyCap in a hair over a day, and every O(1) rate
    /// limiter with capacity D has the same property, including the window that resets and the
    /// token bucket. Bounding a rolling day to exactly D needs per-trade history, which is
    /// unbounded storage.
    ///
    /// What it does promise: at any instant no more than dailyCap is available, and the budget only
    /// returns as fast as time passes. That is what stops a stolen key emptying the account in two
    /// seconds at a window boundary, which the version this replaced allowed.
    ///
    /// **Set dailyCap to half of what you are willing to lose in a day.**
    ///
    /// The refill is `dailyCap` per window in absolute terms, not a fraction of what is recorded.
    /// That distinction is the whole reason this is written the way it is. Draining proportionally
    /// meant every write re-based the decay from the amount left at that moment, so an attacker
    /// holding the session key could keep the owner's budget suppressed indefinitely by spamming
    /// operations that spend nothing: each one restarted the decay from a smaller number and the
    /// budget never came back. Leaking at a fixed rate makes a write cost nothing, because the
    /// amount leaked between two moments depends only on the time between them.
    function _spentToday(address account, address token, uint256 dailyCap)
        internal
        view
        returns (uint256)
    {
        Spend memory spend = spends[account][token];
        uint256 elapsed = block.timestamp - spend.windowStart;
        if (elapsed >= WINDOW) return 0;
        // dailyCap is a uint128 and elapsed is under 2^17, so this cannot overflow.
        uint256 leaked = (dailyCap * elapsed) / WINDOW;
        return spend.amount > leaked ? spend.amount - leaked : 0;
    }

    /// @param drained What _spentToday already said, passed in so the slot is read once.
    function _recordSpend(address account, address token, uint256 drained, uint128 amount)
        internal
    {
        // The remainder that has not drained yet, plus what was just spent. Bounded by dailyCap
        // plus one trade, both uint128, so the sum fits and the cast cannot truncate.
        spends[account][token] = Spend(uint128(drained) + amount, uint48(block.timestamp));
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
