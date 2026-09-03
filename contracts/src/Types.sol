// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice ERC-4337 v0.7. Field order matters: it is what the EntryPoint hashes.
///
/// Nine fields. An earlier version of this file had eight, missing paymasterAndData, and every
/// operation built from it was laid out wrong: the EntryPoint read the signature as the paymaster
/// field and ran off the end looking for a signature. It cost a reverted transaction on Base to
/// notice. The shape here is pinned by selector rather than by memory:
///
///   handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)
///     -> 0x765e827f, which is present in the deployed bytecode at
///        0x0000000071727De22E5E9d8BAf0edAc6f37da032 on Base.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

// ERC-7579 module type ids. Only the validator is used here.
uint256 constant MODULE_TYPE_VALIDATOR = 1;

// ERC-4337 validation return values.
uint256 constant SIG_OK = 0;
uint256 constant SIG_FAIL = 1;

// How long a presigned order may stay armed.
//
// A presignature is an instruction a solver may act on at any point before validTo, and the fence
// meters orders as they are created rather than as they settle. Without a ceiling a week of daily
// budgets can be armed and then all settled in one block, and validTo is a uint32 that reaches
// 2106. Thirty minutes is six times the deadline the enclave asks for, so nothing legitimate
// touches it. Shared rather than read off the account, because the validator asking the account a
// question during validation is a call it does not need to make.
uint256 constant MAX_ORDER_LIFETIME = 30 minutes;

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
    function preSignature(bytes calldata orderUid) external view returns (uint256);
}

/// @notice The one thing a user operation is allowed to do.
///
/// Declared as an interface so VoicePolicy can name the selector without importing the account,
/// which would import the validator back. The account implements it.
interface IVesperAccount {
    function placeOrder(GPv2Order.Data calldata order) external returns (bytes memory orderUid);
}

/// @notice A CoW order, exactly as GPv2Settlement hashes it.
library GPv2Order {
    /// @dev keccak256 of the Order type string. Verified against Base in docs/venue.md.
    bytes32 internal constant TYPE_HASH =
        0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489;

    bytes32 internal constant KIND_SELL = keccak256("sell");
    bytes32 internal constant BALANCE_ERC20 = keccak256("erc20");

    /// @dev Twelve static fields, so an encoded Data is always exactly this many bytes and never
    ///      carries an offset. VoicePolicy leans on that to reject anything of another shape.
    uint256 internal constant ENCODED_LENGTH = 384;

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
