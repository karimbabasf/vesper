// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GPv2Order, ISettlement, IVesperAccount, PackedUserOperation} from "../src/Types.sol";
import {Assertion} from "../src/WebAuthn.sol";
import {VesperAccount} from "../src/VesperAccount.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";

interface IEntryPoint {
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
    function getUserOpHash(PackedUserOperation calldata op) external view returns (bytes32);
    function getNonce(address sender, uint192 key) external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice The whole path, against the real contracts on Base.
///
/// This suite exists because the unit tests were all green while the design could not work. The
/// mock settlement let anybody presign; the real one does not. The user operation struct was a
/// field short; nothing local noticed. Both cost a reverted transaction on mainnet to find, and
/// both would have been free to find here.
///
/// Rule from here on: nothing gets deployed with real money until it has passed on a fork.
contract LiveTest is Test {
    address constant SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant VAULT_RELAYER = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;
    address constant WETH = 0x4200000000000000000000000000000000000006;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    /// @dev Pinned so the fork caches and the result does not move under us.
    uint256 constant BLOCK = 50_822_000;

    VesperAccount account;
    VoicePolicy policy;

    address owner = address(0x0BE1);
    uint256 sessionPk = 0xE1C1A7E;

    /// @dev Test-only P-256 key. Its public half is read back from script/p256.py.
    uint256 constant PASSKEY = 0xc0ffee01;
    bytes32 passkeyX;
    bytes32 passkeyY;
    bytes32 constant RP_ID_HASH = keccak256("vesper.local");

    uint128 constant PER_TRADE = 0.002 ether;
    uint128 constant DAILY = 0.005 ether;
    uint128 constant FACE_ABOVE = 0.001 ether;

    function setUp() public {
        vm.createSelectFork("https://mainnet.base.org", BLOCK);

        (passkeyX, passkeyY) = _publicKey(PASSKEY);

        vm.startPrank(owner);
        policy = new VoicePolicy();
        account = new VesperAccount(ENTRY_POINT, policy, owner, ISettlement(SETTLEMENT));
        vm.stopPrank();

        deal(WETH, address(account), 0.01 ether);
        vm.deal(address(account), 0.05 ether); // gas prefund for the EntryPoint

        vm.startPrank(address(account));
        IERC20(WETH).approve(VAULT_RELAYER, type(uint256).max);
        policy.registerSession(
            vm.addr(sessionPk),
            keccak256("no enclave yet, step 5"),
            uint48(block.timestamp + 30 days),
            RP_ID_HASH,
            passkeyX,
            passkeyY
        );
        policy.setLimits(WETH, _limits());
        policy.setLimits(USDC, _limits());
        vm.stopPrank();
    }

    // --- step 3: a trade the EntryPoint actually executes --------------------------------------

    function test_the_domain_separator_matches_the_deployed_settlement() public view {
        assertEq(account.domainSeparator(), ISettlement(SETTLEMENT).domainSeparator());
    }

    function test_a_trade_under_the_threshold_lands_through_the_real_entry_point() public {
        GPv2Order.Data memory order = _order(FACE_ABOVE);
        bytes memory uid = _uid(order);

        assertEq(ISettlement(SETTLEMENT).preSignature(uid), 0, "presigned before we started");

        _run(order, "");

        assertTrue(ISettlement(SETTLEMENT).preSignature(uid) != 0, "settlement did not accept it");
        assertEq(policy.remainingToday(address(account), WETH), DAILY - FACE_ABOVE);
    }

    /// @dev The bug that killed the first design, kept as a test so nobody rebuilds it. The real
    ///      settlement reads the owner out of the uid and refuses anyone else, so a helper
    ///      contract can never presign on an account's behalf.
    function test_a_helper_contract_cannot_presign_for_the_account() public {
        Helper helper = new Helper();
        bytes memory uid =
            GPv2Order.uid(_order(FACE_ABOVE), account.domainSeparator(), address(account));

        vm.expectRevert(bytes("GPv2: cannot presign order"));
        helper.presign(uid);
    }

    function test_the_entry_point_refuses_an_operation_the_fence_says_no_to() public {
        // Over the per-trade cap. The fence returns SIG_FAIL and the EntryPoint will not execute.
        PackedUserOperation[] memory ops = _ops(_order(PER_TRADE + 1), "");

        vm.expectRevert();
        IEntryPoint(ENTRY_POINT).handleOps(ops, payable(owner));
    }

    // --- step 4: the passkey, against the real precompile --------------------------------------

    /// @dev Base answers 1 for a signature we just made, and nothing at all for the same
    ///      signature over a different message. Both answers come from the deployed precompile.
    function test_the_precompile_on_base_agrees_with_our_signer() public {
        bytes32 message = keccak256("a message nobody has signed before");
        (bytes32 r, bytes32 s) = _sign(PASSKEY, message);

        assertEq(
            abi.decode(_askBase(abi.encodePacked(message, r, s, passkeyX, passkeyY)), (uint256)),
            1,
            "base rejected a signature we just made"
        );
        assertEq(
            _askBase(abi.encodePacked(keccak256("a different message"), r, s, passkeyX, passkeyY))
                .length,
            0,
            "base accepted a signature over the wrong message"
        );
    }

    function test_a_trade_above_the_threshold_is_refused_without_a_face() public {
        PackedUserOperation[] memory ops = _ops(_order(FACE_ABOVE + 1), "");

        vm.expectRevert();
        IEntryPoint(ENTRY_POINT).handleOps(ops, payable(owner));
    }

    function test_the_same_trade_goes_through_with_one() public {
        GPv2Order.Data memory order = _order(FACE_ABOVE + 1);
        bytes memory uid = _uid(order);

        _run(order, abi.encode(_assertionFor(keccak256(abi.encode(order)))));

        assertTrue(ISettlement(SETTLEMENT).preSignature(uid) != 0, "settlement did not accept it");
    }

    function test_a_face_for_one_order_does_not_authorise_another() public {
        GPv2Order.Data memory signed = _order(FACE_ABOVE + 1);
        GPv2Order.Data memory other = _order(FACE_ABOVE + 2);
        PackedUserOperation[] memory ops =
            _ops(other, abi.encode(_assertionFor(keccak256(abi.encode(signed)))));

        vm.expectRevert();
        IEntryPoint(ENTRY_POINT).handleOps(ops, payable(owner));
    }

    // --- helpers ------------------------------------------------------------------------------

    function _limits() private pure returns (VoicePolicy.Limits memory) {
        return VoicePolicy.Limits({
            perTradeCap: PER_TRADE,
            dailyCap: DAILY,
            biometricThreshold: FACE_ABOVE,
            allowed: true
        });
    }

    function _order(uint256 sellAmount) private view returns (GPv2Order.Data memory) {
        return GPv2Order.Data({
            sellToken: WETH,
            buyToken: USDC,
            receiver: address(account),
            sellAmount: sellAmount,
            buyAmount: 1,
            validTo: uint32(block.timestamp + 600),
            appData: bytes32(0),
            feeAmount: 0,
            kind: GPv2Order.KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: GPv2Order.BALANCE_ERC20,
            buyTokenBalance: GPv2Order.BALANCE_ERC20
        });
    }

    function _uid(GPv2Order.Data memory order) private view returns (bytes memory) {
        return GPv2Order.uid(order, account.domainSeparator(), address(account));
    }

    function _run(GPv2Order.Data memory order, bytes memory encodedAssertion) private {
        IEntryPoint(ENTRY_POINT).handleOps(_ops(order, encodedAssertion), payable(owner));
    }

    /// @dev Builds the operation, asks the real EntryPoint for its hash, signs it with the session
    ///      key, and attaches the assertion if there is one. Kept separate from submitting it so a
    ///      test that expects a revert can put the expectation on handleOps and nothing else.
    function _ops(GPv2Order.Data memory order, bytes memory encodedAssertion)
        private
        returns (PackedUserOperation[] memory ops)
    {
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(account),
            nonce: IEntryPoint(ENTRY_POINT).getNonce(address(account), 0),
            initCode: "",
            callData: abi.encodeCall(IVesperAccount.placeOrder, (order)),
            accountGasLimits: bytes32((uint256(400_000) << 128) | uint256(600_000)),
            preVerificationGas: 120_000,
            gasFees: bytes32((uint256(2_000_000) << 128) | uint256(200_000_000)),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 opHash = IEntryPoint(ENTRY_POINT).getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            sessionPk, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", opHash))
        );
        bytes memory sessionSig = abi.encodePacked(r, s, v);

        Assertion memory assertion;
        bool hasAssertion = encodedAssertion.length > 0;
        if (hasAssertion) assertion = abi.decode(encodedAssertion, (Assertion));
        op.signature = abi.encode(sessionSig, hasAssertion, assertion);

        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    /// @dev A real assertion: a real clientDataJSON, and a real P-256 signature over it that the
    ///      RIP-7212 precompile on this fork has to accept.
    function _assertionFor(bytes32 challenge) private returns (Assertion memory assertion) {
        assertion = _unsignedAssertion(challenge);
        bytes32 message = sha256(
            abi.encodePacked(assertion.authenticatorData, sha256(bytes(assertion.clientDataJSON)))
        );
        (assertion.r, assertion.s) = _sign(PASSKEY, message);
        _teachTheForkWhatBaseSays(message, assertion.r, assertion.s);
    }

    /// @dev foundry 1.7.1 has no RIP-7212 precompile, so a fork of Base does not carry the one
    ///      thing that makes the passkey path work on Base. Rather than mock a verdict, or
    ///      reimplement the curve and then have to trust the reimplementation, the fork asks the
    ///      deployed precompile over RPC and replays exactly what it said. A wrong signature gets
    ///      the empty answer Base gives it, which the library reads as a refusal.
    function _teachTheForkWhatBaseSays(bytes32 message, bytes32 r, bytes32 s) private {
        bytes memory input = abi.encodePacked(message, r, s, passkeyX, passkeyY);
        vm.mockCall(address(0x100), input, _askBase(input));
    }

    function _askBase(bytes memory input) private returns (bytes memory) {
        string[] memory command = new string[](6);
        command[0] = "cast";
        command[1] = "call";
        command[2] = "0x0000000000000000000000000000000000000100";
        command[3] = "--data";
        command[4] = vm.toString(input);
        command[5] = "--rpc-url=https://mainnet.base.org";
        return vm.ffi(command);
    }

    function _unsignedAssertion(bytes32 challenge) private pure returns (Assertion memory assertion) {
        assertion.authenticatorData =
            abi.encodePacked(RP_ID_HASH, bytes1(uint8(0x05)), bytes4(uint32(1)));
        assertion.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                _base64url(challenge),
                '","origin":"https://vesper.local","crossOrigin":false}'
            )
        );
        assertion.typeIndex = 1;
        assertion.challengeIndex = 23;
    }

    function _publicKey(uint256 privateKey) private returns (bytes32 x, bytes32 y) {
        string[] memory command = new string[](4);
        command[0] = "python3";
        command[1] = "script/p256.py";
        command[2] = "pubkey";
        command[3] = vm.toString(bytes32(privateKey));
        bytes memory out = vm.ffi(command);
        (x, y) = abi.decode(out, (bytes32, bytes32));
    }

    function _sign(uint256 privateKey, bytes32 message) private returns (bytes32 r, bytes32 s) {
        string[] memory command = new string[](5);
        command[0] = "python3";
        command[1] = "script/p256.py";
        command[2] = "sign";
        command[3] = vm.toString(bytes32(privateKey));
        command[4] = vm.toString(message);
        bytes memory out = vm.ffi(command);
        (r, s) = abi.decode(out, (bytes32, bytes32));
    }

    bytes constant ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    function _base64url(bytes32 value) private pure returns (string memory) {
        bytes memory data = abi.encodePacked(value);
        bytes memory out = new bytes(43);
        for (uint256 i = 0; i < 43; i++) {
            uint256 bitOffset = i * 6;
            uint256 byteIndex = bitOffset / 8;
            uint256 shift = bitOffset % 8;
            uint256 chunk = uint256(uint8(data[byteIndex])) << 8;
            if (byteIndex + 1 < data.length) chunk |= uint256(uint8(data[byteIndex + 1]));
            out[i] = ALPHABET[(chunk >> (10 - shift)) & 0x3f];
        }
        return string(out);
    }
}

/// @dev Stands in for the deleted VoiceOrderGate.
contract Helper {
    function presign(bytes calldata uid) external {
        ISettlement(0x9008D19f58AAbD9eD0D60971565AA8510560ab41).setPreSignature(uid, true);
    }
}
