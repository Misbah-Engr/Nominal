// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/NominalRegistryV2.sol";
import "../src/MockERC20.sol";

contract DeployBaseSepolia is Script {
    
    // Base Sepolia chain ID: 84532
    uint256 constant TARGET_CHAIN_ID = 84532;
    
    // Deployment configuration
    uint256 constant ETH_FEE = 0.001 ether; // 0.001 ETH
    uint256 constant TOKEN_FEE = 5 * 10**18; // 5 tokens
    uint256 constant REFERRER_FEE_BPS = 2000; // 20%
    
    function run() external {
        // Ensure we're on the correct chain
        require(block.chainid == TARGET_CHAIN_ID, "Must deploy on Base Sepolia");
        
        uint256 deployerPrivateKey = vm.envUint("DEPLOY_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying contracts with deployer:", deployer);
        console.log("Deployer balance:", deployer.balance);
        console.log("Chain ID:", block.chainid);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy the faucet token first
        console.log("\n=== Deploying NominalUSD Faucet Token ===");
        NominalUSDFaucet faucetToken = new NominalUSDFaucet();
        console.log("NominalUSD Faucet deployed at:", address(faucetToken));
        console.log("Token name:", faucetToken.name());
        console.log("Token symbol:", faucetToken.symbol());
        console.log("Claim amount:", faucetToken.CLAIM_AMOUNT());
        console.log("Cooldown period:", faucetToken.COOLDOWN_PERIOD());
        
        // Deploy the registry
        console.log("\n=== Deploying Nominal Registry V2 ===");
        NominalRegistryV2 registry = new NominalRegistryV2(ETH_FEE);
        console.log("NominalRegistryV2 deployed at:", address(registry));
        console.log("ETH registration fee:", registry.ethFee());
        console.log("Registry owner:", registry.contractOwner());
        
        // Configure the registry
        console.log("\n=== Configuring Registry ===");
        
        // Add the faucet token as supported payment method
        registry.setAllowedToken(address(faucetToken), true, TOKEN_FEE);
        console.log("Added NominalUSD as supported token with fee:", TOKEN_FEE);
        
        // Authorize the deployer as a wallet provider with referral fee
        registry.authorizeWalletProvider(deployer, REFERRER_FEE_BPS);
        console.log("Authorized deployer as wallet provider with", REFERRER_FEE_BPS, "bps referral fee");
        
        vm.stopBroadcast();
        
        // Verification info
        console.log("\n=== Deployment Summary ===");
        console.log("NominalUSD Faucet:", address(faucetToken));
        console.log("NominalRegistryV2:", address(registry));
        console.log("ETH Fee:", ETH_FEE);
        console.log("Token Fee:", TOKEN_FEE);
        console.log("Referrer Fee:", REFERRER_FEE_BPS, "bps (20%)");
        
        console.log("\n=== Next Steps ===");
        console.log("1. Verify contracts on Basescan");
        console.log("2. Test faucet token claiming");
        console.log("3. Test registry name registration");
        
        console.log("\n=== Verification Commands ===");
        console.log("NominalUSD Faucet verification:");
        console.log(string(abi.encodePacked("forge verify-contract ", vm.toString(address(faucetToken)), " src/MockERC20.sol:NominalUSDFaucet --chain base-sepolia")));
        
        console.log("Registry verification:");
        console.log(string(abi.encodePacked("forge verify-contract ", vm.toString(address(registry)), " src/NominalRegistryV2.sol:NominalRegistryV2 --chain base-sepolia")));
        console.log(string(abi.encodePacked("Constructor args: ", vm.toString(ETH_FEE))));
    }
}