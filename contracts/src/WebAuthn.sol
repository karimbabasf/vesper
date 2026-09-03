// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice One passkey assertion, as the browser produces it.
///
/// The two indices say where in `clientDataJSON` the `type` and `challenge` fields begin. The
/// browser knows them and passing them costs two words; the alternative is searching the string,
/// which is both slower and weaker. See the note on `verify`.
struct Assertion {
    bytes authenticatorData;
    string clientDataJSON;
    uint256 challengeIndex;
    uint256 typeIndex;
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

    bytes internal constant EXPECTED_TYPE = '"type":"webauthn.get"';

    /// @param challenge What the authenticator was asked to sign over. Here, the order digest.
    function verify(
        Assertion memory assertion,
        bytes32 challenge,
        bytes32 rpIdHash,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bool) {
        // authenticatorData is rpIdHash(32) || flags(1) || signCount(4), then optional extensions.
        if (assertion.authenticatorData.length < 37) return false;

        // The first word, read directly. Copying it out byte by byte cost 8,397 gas to learn
        // something one MLOAD knows, and the length check above already proves 32 bytes are there.
        bytes memory authenticatorData = assertion.authenticatorData;
        bytes32 signedRpIdHash;
        assembly {
            signedRpIdHash := mload(add(authenticatorData, 32))
        }
        if (signedRpIdHash != rpIdHash) return false;

        uint8 flags = uint8(assertion.authenticatorData[32]);
        if (flags & FLAG_USER_PRESENT == 0) return false;
        // The check people forget: without this a passkey unlocked by a tap counts as a face.
        if (flags & FLAG_USER_VERIFIED == 0) return false;

        bytes memory clientData = bytes(assertion.clientDataJSON);

        // A signature made for registration, or for any ceremony that is not an assertion, must
        // not count as one.
        if (!_equalAt(clientData, assertion.typeIndex, EXPECTED_TYPE)) return false;

        // Compared at the offset the caller names, not searched for anywhere in the string.
        //
        // Being exact about what this buys, because it is easy to overstate: the index is supplied
        // by the caller, so anchoring alone does not stop someone who points it at a copy of the
        // expected text. What stops that is that no authenticator will ever produce such a copy.
        // Every field the browser writes into clientDataJSON is a fixed keyword, a base64url value
        // or an origin, and none of those can contain the quote character the needle starts with.
        // Anchoring earns its place by turning an O(n*m) scan into an O(m) compare and by not
        // asking the reader to make that argument about a search.
        bytes memory expected =
            abi.encodePacked('"challenge":"', _base64url(abi.encodePacked(challenge)), '"');
        if (!_equalAt(clientData, assertion.challengeIndex, expected)) return false;

        bytes32 message = sha256(abi.encodePacked(authenticatorData, sha256(clientData)));

        return _p256(message, assertion.r, assertion.s, pubKeyX, pubKeyY);
    }

    /// @dev True when `needle` sits in `haystack` starting exactly at `offset`. Out of range is
    ///      false, never a revert: this is one of several reasons an assertion can be refused and
    ///      they should all look the same from outside.
    function _equalAt(bytes memory haystack, uint256 offset, bytes memory needle)
        private
        pure
        returns (bool)
    {
        unchecked {
            if (offset > haystack.length || needle.length > haystack.length - offset) return false;
            for (uint256 i = 0; i < needle.length; i++) {
                if (haystack[offset + i] != needle[i]) return false;
            }
        }
        return true;
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

    bytes internal constant ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// @dev 32 bytes encodes to 43 base64url characters with no padding.
    ///
    /// The alphabet is copied into memory once. Reading it straight off the constant looks
    /// identical and is not: solidity re-materialises the whole 64 byte constant on every index,
    /// so forty three characters cost 38,770 gas. This costs about a fortieth of that and encodes
    /// the same string, which a fuzz test pins against vm.toBase64URL.
    function _base64url(bytes memory data) private pure returns (string memory) {
        bytes memory alphabet = ALPHABET;
        uint256 encodedLength = (data.length * 8 + 5) / 6;
        bytes memory out = new bytes(encodedLength);

        for (uint256 i = 0; i < encodedLength; i++) {
            uint256 bitOffset = i * 6;
            uint256 byteIndex = bitOffset / 8;
            uint256 shift = bitOffset % 8;

            uint256 chunk = uint256(uint8(data[byteIndex])) << 8;
            if (byteIndex + 1 < data.length) chunk |= uint256(uint8(data[byteIndex + 1]));

            out[i] = alphabet[(chunk >> (10 - shift)) & 0x3f];
        }
        return string(out);
    }
}
