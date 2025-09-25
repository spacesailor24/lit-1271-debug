// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../src/SimpleEIP1271.sol";

contract DeploySimpleEIP1271 is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("FORGE_DEPLOYMENT_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Whitelisted signer addresses for Lit Protocol EIP-1271 testing
        address[] memory signerAddresses = new address[](3);
        signerAddresses[0] = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        signerAddresses[1] = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        signerAddresses[2] = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

        // Deploy the contract (no threshold needed - simple whitelist check)
        SimpleEIP1271 simpleContract = new SimpleEIP1271(signerAddresses);

        console.log("SimpleEIP1271 deployed at:", address(simpleContract));
        console.log("Whitelisted signers:");
        for (uint256 i = 0; i < signerAddresses.length; i++) {
            console.log("  -", signerAddresses[i]);
        }

        vm.stopBroadcast();
    }
}