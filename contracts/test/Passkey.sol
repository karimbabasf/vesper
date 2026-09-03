// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {Assertion} from "../src/WebAuthn.sol";

/// @notice Builds passkey assertions for tests, and makes the P256 precompile answer for them.
///
/// The local EVM has no RIP-7212 precompile, so the curve arithmetic is mocked for one exact input
/// and nothing else: a corrupted signature produces a different input, finds no mock, hits the
/// absent precompile and comes back empty, which the library reads as a failure. Everything except
/// the arithmetic is therefore still under test. The real precompile was confirmed working on Base
/// and Base Sepolia in docs/venue.md.
library Passkey {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 internal constant RP_ID_HASH = keccak256("vesper.local");
    bytes32 internal constant PUBKEY_X = bytes32(uint256(0xAAAA));
    bytes32 internal constant PUBKEY_Y = bytes32(uint256(0xBBBB));
    bytes32 internal constant R = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant S = bytes32(uint256(0xDECAF));

    uint8 internal constant UP = 0x01;
    uint8 internal constant UV = 0x04;

    function assertionFor(bytes32 challenge) internal returns (Assertion memory) {
        return assertionFor(challenge, RP_ID_HASH, UP | UV);
    }

    function assertionFor(bytes32 challenge, bytes32 rpIdHash, uint8 flags)
        internal
        returns (Assertion memory assertion)
    {
        assertion.authenticatorData =
            abi.encodePacked(rpIdHash, bytes1(flags), bytes4(uint32(1)));
        assertion.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                base64url(abi.encodePacked(challenge)),
                '","origin":"https://vesper.local"}'
            )
        );
        // '{' then '"type":"webauthn.get"' (21 bytes) then ','.
        assertion.typeIndex = 1;
        assertion.challengeIndex = 23;
        assertion.r = R;
        assertion.s = S;

        bytes32 message = sha256(
            abi.encodePacked(assertion.authenticatorData, sha256(bytes(assertion.clientDataJSON)))
        );
        vm.mockCall(
            address(0x100),
            abi.encodePacked(message, R, S, PUBKEY_X, PUBKEY_Y),
            abi.encode(uint256(1))
        );
    }

    /// @dev The same ceremony with a different `type`. A registration signature must not place a
    ///      trade, and the only thing separating the two is that field.
    function assertionOfType(bytes32 challenge, string memory ceremony)
        internal
        returns (Assertion memory assertion)
    {
        assertion.authenticatorData =
            abi.encodePacked(RP_ID_HASH, bytes1(UP | UV), bytes4(uint32(1)));
        bytes memory json = abi.encodePacked(
            '{"type":"', ceremony, '","challenge":"',
            base64url(abi.encodePacked(challenge)),
            '","origin":"https://vesper.local"}'
        );
        assertion.clientDataJSON = string(json);
        assertion.typeIndex = 1;
        // '{' + '"type":"' (8) + ceremony + '"' then ','.
        assertion.challengeIndex = 1 + 8 + bytes(ceremony).length + 1 + 1;
        assertion.r = R;
        assertion.s = S;
        _teachPrecompile(assertion);
    }

    /// @dev A well formed ceremony carrying a challenge that is not the one being asked about.
    function assertionForTheWrongChallenge(bytes32 signedChallenge)
        internal
        returns (Assertion memory)
    {
        return assertionFor(signedChallenge);
    }

    function _teachPrecompile(Assertion memory assertion) private {
        bytes32 message = sha256(
            abi.encodePacked(assertion.authenticatorData, sha256(bytes(assertion.clientDataJSON)))
        );
        vm.mockCall(
            address(0x100),
            abi.encodePacked(message, R, S, PUBKEY_X, PUBKEY_Y),
            abi.encode(uint256(1))
        );
    }

    bytes private constant ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// @dev Written independently of the library's encoder on purpose. If the two ever disagree the
    ///      challenge check stops matching and the suite says so.
    function base64url(bytes memory data) internal pure returns (string memory) {
        uint256 length = (data.length * 8 + 5) / 6;
        bytes memory out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            uint256 bit = i * 6;
            uint256 index = bit / 8;
            uint256 shift = bit % 8;
            uint256 chunk = uint256(uint8(data[index])) << 8;
            if (index + 1 < data.length) chunk |= uint256(uint8(data[index + 1]));
            out[i] = ALPHABET[(chunk >> (10 - shift)) & 0x3f];
        }
        return string(out);
    }
}
