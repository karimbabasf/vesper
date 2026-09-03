// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ISettlement} from "../src/Types.sol";
import {VesperAccount} from "../src/VesperAccount.sol";
import {VoiceOrderGate} from "../src/VoiceOrderGate.sol";
import {VoicePolicy} from "../src/VoicePolicy.sol";

/// @notice Deploy the fence and one account behind it.
///
///     forge script script/Deploy.s.sol --rpc-url https://mainnet.base.org --broadcast
///
/// Addresses come from docs/venue.md, where each one was read off the chain rather than copied
/// from documentation.
contract Deploy is Script {
    address constant SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        uint256 ownerPk = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(ownerPk);

        vm.startBroadcast(ownerPk);

        VoiceOrderGate gate = new VoiceOrderGate(ISettlement(SETTLEMENT));
        VoicePolicy policy = new VoicePolicy(gate);
        VesperAccount account = new VesperAccount(ENTRY_POINT, policy, owner);

        vm.stopBroadcast();

        console.log("owner    ", owner);
        console.log("gate     ", address(gate));
        console.log("policy   ", address(policy));
        console.log("account  ", address(account));
        console.log("separator");
        console.logBytes32(gate.domainSeparator());
    }
}
