// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {VesperAccount} from "../src/VesperAccount.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";

interface IWETH {
    function deposit() external payable;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice Fund the account, set the fence, and register the session key.
///
///     forge script script/Setup.s.sol --rpc-url https://mainnet.base.org --broadcast
///
/// Everything here is signed by the owner. The session key can do none of it: it can only place
/// orders, and only inside the limits this script writes.
contract Setup is Script {
    address constant WETH = 0x4200000000000000000000000000000000000006;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant VAULT_RELAYER = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;

    /// @dev Deliberately above anything this wallet can afford to trade, so the first end to end
    ///      run needs no passkey. Lowered later to demonstrate the biometric path.
    uint256 constant WETH_PER_TRADE = 0.002 ether;
    uint256 constant WETH_DAILY = 0.005 ether;
    uint256 constant WETH_FACE_ABOVE = 0.002 ether;

    function run() external {
        uint256 ownerPk = vm.envUint("PRIVATE_KEY");
        VesperAccount account = VesperAccount(payable(vm.envAddress("ACCOUNT")));
        VoicePolicy policy = VoicePolicy(vm.envAddress("POLICY"));
        address sessionKey = vm.addr(vm.envUint("SESSION_PRIVATE_KEY"));

        uint256 toAccount = vm.envUint("FUND_WEI");
        uint256 toWrap = vm.envUint("WRAP_WEI");

        vm.startBroadcast(ownerPk);

        payable(address(account)).transfer(toAccount);

        // Wrap, then let CoW's relayer move the WETH when a solver fills.
        account.ownerCall(WETH, toWrap, abi.encodeCall(IWETH.deposit, ()));
        account.ownerCall(
            WETH, 0, abi.encodeCall(IWETH.approve, (VAULT_RELAYER, type(uint256).max))
        );

        account.ownerCall(
            address(policy),
            0,
            abi.encodeCall(
                VoicePolicy.setLimits,
                (
                    WETH,
                    VoicePolicy.Limits({
                        allowed: true,
                        perTradeCap: WETH_PER_TRADE,
                        dailyCap: WETH_DAILY,
                        biometricThreshold: WETH_FACE_ABOVE
                    })
                )
            )
        );
        account.ownerCall(
            address(policy),
            0,
            abi.encodeCall(
                VoicePolicy.setLimits,
                (
                    USDC,
                    VoicePolicy.Limits({
                        allowed: true,
                        perTradeCap: 5_000000,
                        dailyCap: 20_000000,
                        biometricThreshold: 2_000000
                    })
                )
            )
        );

        account.ownerCall(
            address(policy),
            0,
            abi.encodeCall(
                VoicePolicy.registerSession,
                (
                    sessionKey,
                    keccak256("no enclave yet, step 5"),
                    uint48(block.timestamp + 30 days),
                    keccak256("vesper.local"),
                    bytes32(0),
                    bytes32(0)
                )
            )
        );

        vm.stopBroadcast();

        console.log("account eth  ", address(account).balance);
        console.log("account weth ", IWETH(WETH).balanceOf(address(account)));
        console.log("session key  ", sessionKey);
    }
}
