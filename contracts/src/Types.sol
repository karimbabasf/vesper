// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice ERC-4337 v0.7. Field order matters: it is what the EntryPoint hashes.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes signature;
}

// ERC-7579 module type ids. Only the validator is used here.
uint256 constant MODULE_TYPE_VALIDATOR = 1;

// ERC-4337 validation return values.
uint256 constant SIG_OK = 0;
uint256 constant SIG_FAIL = 1;

interface IModule {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256);

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}

interface ISettlement {
    function domainSeparator() external view returns (bytes32);
    function setPreSignature(bytes calldata orderUid, bool signed) external;
}

/// @notice A CoW order, exactly as GPv2Settlement hashes it.
library GPv2Order {
    /// @dev keccak256 of the Order type string. Verified against Base in docs/venue.md.
    bytes32 internal constant TYPE_HASH =
        0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489;

    bytes32 internal constant KIND_SELL = keccak256("sell");
    bytes32 internal constant BALANCE_ERC20 = keccak256("erc20");

    struct Data {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        bytes32 kind;
        bool partiallyFillable;
        bytes32 sellTokenBalance;
        bytes32 buyTokenBalance;
    }

    /// @notice The EIP-712 digest the settlement contract will look for.
    function hash(Data memory order, bytes32 domainSeparator) internal pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                TYPE_HASH,
                order.sellToken,
                order.buyToken,
                order.receiver,
                order.sellAmount,
                order.buyAmount,
                order.validTo,
                order.appData,
                order.feeAmount,
                order.kind,
                order.partiallyFillable,
                order.sellTokenBalance,
                order.buyTokenBalance
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    /// @notice orderDigest || owner || validTo, the 56 bytes setPreSignature takes.
    function uid(Data memory order, bytes32 domainSeparator, address owner)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(hash(order, domainSeparator), owner, order.validTo);
    }
}
