// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GPv2Order, ISettlement, PackedUserOperation} from "../src/Types.sol";
import {Assertion} from "../src/WebAuthn.sol";
import {VoiceOrderGate} from "../src/VoiceOrderGate.sol";

address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
address constant WETH = 0x4200000000000000000000000000000000000006;
address constant CBBTC = 0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf;
address constant PEPE = 0x6982508145454Ce325dDbE47a25d4ec3d2311933;

/// @dev The real Base separator, read from GPv2Settlement on 2026-09-03. See docs/venue.md.
bytes32 constant BASE_DOMAIN_SEPARATOR =
    0xd72ffa789b6fae41254d0b5a13e6e1e92ed947ec6a251edf1cf0b6c02c257b4b;

contract MockSettlement is ISettlement {
    bytes public lastUid;
    bool public lastSigned;
    uint256 public calls;

    function domainSeparator() external pure override returns (bytes32) {
        return BASE_DOMAIN_SEPARATOR;
    }

    function setPreSignature(bytes calldata orderUid, bool signed) external override {
        lastUid = orderUid;
        lastSigned = signed;
        calls++;
    }
}

/// @notice Builders shared by the gate and policy suites.
library Fixtures {
    function order(address account, address sellToken, address buyToken, uint256 sellAmount)
        internal
        pure
        returns (GPv2Order.Data memory)
    {
        return GPv2Order.Data({
            sellToken: sellToken,
            buyToken: buyToken,
            receiver: account,
            sellAmount: sellAmount,
            buyAmount: 1, // any non-zero floor
            validTo: 2_000_000_000,
            appData: bytes32(0),
            feeAmount: 0,
            kind: GPv2Order.KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: GPv2Order.BALANCE_ERC20,
            buyTokenBalance: GPv2Order.BALANCE_ERC20
        });
    }

    /// @dev ERC-7579 single call: execute(mode, target || value || data).
    function callData(address target, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeWithSignature(
            "execute(bytes32,bytes)",
            bytes32(0),
            abi.encodePacked(target, uint256(0), data)
        );
    }

    function placeOrderCall(address gate, GPv2Order.Data memory data)
        internal
        pure
        returns (bytes memory)
    {
        return callData(gate, abi.encodeCall(VoiceOrderGate.placeOrder, (data)));
    }

    function userOp(address sender, bytes memory opCallData, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: "",
            callData: opCallData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            signature: signature
        });
    }

    function signature(bytes memory sessionSig) internal pure returns (bytes memory) {
        Assertion memory empty;
        return abi.encode(sessionSig, false, empty);
    }

    function signature(bytes memory sessionSig, Assertion memory assertion)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(sessionSig, true, assertion);
    }

    /// @dev A perfectly good assertion, attached with the flag that says there is none.
    function signatureClaimingNoAssertion(bytes memory sessionSig, Assertion memory assertion)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(sessionSig, false, assertion);
    }
}
