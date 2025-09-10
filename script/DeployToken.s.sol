// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/MockERC20.sol";
import "../src/NominalRegistry.sol";

contract DeployNominalToken is Script {
    function run() external returns (address tokenAddress, address registryAddress) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying Nominal Token with deployer:", deployer);
        console.log("Deployer balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy Nominal Token with 1 million initial supply (18 decimals)
        MockERC20 nominalToken = new MockERC20(
            "Nominal",
            "NMNL", 
            1_000_000 * 10**18  // 1 million tokens
        );
        
        // Connect to the already deployed registry
        NominalRegistry registry = NominalRegistry(0x529AE0a40932f028198a58264636De72AdC674F4);
        
        // Add token as allowed and set fees
        uint256 registrationFee = 4 * 10**18;  // 4 NMNL tokens
        uint256 referralFee = 4 * 10**17;      // 0.4 NMNL tokens (10% of registration fee)
        
        registry.setAllowedToken(address(nominalToken), true);
        registry.setRegistrationFeeForToken(address(nominalToken), registrationFee);
        registry.setReferralFeeAmountInToken(address(nominalToken), referralFee);
        
        vm.stopBroadcast();
        
        console.log("Nominal Token (NMNL) deployed at:", address(nominalToken));
        console.log("Token added to registry with:");
        console.log("  - Registration fee: 4 NMNL");
        console.log("  - Referral fee: 0.4 NMNL");
        console.log("  - Total supply:", nominalToken.totalSupply() / 10**18, "NMNL");
        
        return (address(nominalToken), address(registry));
    }
}
