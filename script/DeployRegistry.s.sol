// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/NominalRegistry.sol";

contract DeployRegistryScript is Script {
    function run() external returns (address) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        address deployerAddress = vm.addr(deployerPrivateKey);
        
        console.log("Deploying NominalRegistry with deployer:", deployerAddress);
        console.log("Deployer balance:", deployerAddress.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        NominalRegistry registry = new NominalRegistry();
        
        vm.stopBroadcast();
        
        console.log("NominalRegistry deployed at:", address(registry));
        return address(registry);
    }
}
