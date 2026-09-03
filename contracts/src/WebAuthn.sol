// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice One passkey assertion, as the browser produces it.
struct Assertion {
    bytes authenticatorData;
    string clientDataJSON;
    bytes32 r;
    bytes32 s;
}

/// @title WebAuthn
/// @notice Verify a passkey signature the way the specification says to, in order.
///
/// Every check here exists because skipping it has a name. Skipping the user-verification flag
/// accepts a tap without a face. Skipping the rpIdHash accepts a signature made on another site.
/// Skipping the challenge accepts a signature the holder made for a different order.
library WebAuthn {
    /// @dev RIP-7212. Live on Base and Base Sepolia, confirmed in docs/venue.md.
    address internal constant P256_VERIFIER = address(0x100);

    uint8 internal constant FLAG_USER_PRESENT = 0x01;
    uint8 internal constant FLAG_USER_VERIFIED = 0x04;

    function verify(
        Assertion memory assertion,
        bytes32 challenge,
        bytes32 rpIdHash,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bool) {
        // authenticatorData is rpIdHash(32) || flags(1) || signCount(4), then optional extensions.
        if (assertion.authenticatorData.length < 37) return false;

        if (bytes32(_slice(assertion.authenticatorData, 0, 32)) != rpIdHash) return false;

        uint8 flags = uint8(assertion.authenticatorData[32]);
        if (flags & FLAG_USER_PRESENT == 0) return false;
        // The check people forget: without this a passkey unlocked by a tap counts as a face.
        if (flags & FLAG_USER_VERIFIED == 0) return false;

        if (!_challengeMatches(assertion.clientDataJSON, challenge)) return false;

        bytes32 message =
            sha256(abi.encodePacked(assertion.authenticatorData, sha256(bytes(assertion.clientDataJSON))));

        return _p256(message, assertion.r, assertion.s, pubKeyX, pubKeyY);
    }

    /// @dev clientDataJSON carries the challenge as base64url with no padding.
    function _challengeMatches(string memory clientDataJSON, bytes32 challenge)
        private
        pure
        returns (bool)
    {
        bytes memory needle = abi.encodePacked('"challenge":"', _base64url(abi.encodePacked(challenge)), '"');
        return _contains(bytes(clientDataJSON), needle);
    }

    /// @dev Returns false rather than reverting when the precompile is absent, so a chain without
    ///      RIP-7212 fails closed instead of appearing to verify.
    function _p256(bytes32 message, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        private
        view
        returns (bool)
    {
        (bool ok, bytes memory out) =
            P256_VERIFIER.staticcall(abi.encodePacked(message, r, s, x, y));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    function _slice(bytes memory data, uint256 start, uint256 length)
        private
        pure
        returns (bytes memory out)
    {
        out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            out[i] = data[start + i];
        }
    }

    function _contains(bytes memory haystack, bytes memory needle) private pure returns (bool) {
        if (needle.length > haystack.length) return false;
        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool same = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    same = false;
                    break;
                }
            }
            if (same) return true;
        }
        return false;
    }

    bytes internal constant ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// @dev 32 bytes encodes to 43 base64url characters with no padding.
    function _base64url(bytes memory data) private pure returns (string memory) {
        uint256 encodedLength = (data.length * 8 + 5) / 6;
        bytes memory out = new bytes(encodedLength);

        for (uint256 i = 0; i < encodedLength; i++) {
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
