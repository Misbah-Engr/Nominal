// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../lib/forge-std/src/Script.sol";
import "../src/NominalRegistryV2.sol";
import "../src/MockERC20.sol";

contract DeployBaseSepolia is Script {
    
    // Base Sepolia chain ID: 84532
    uint256 constant TARGET_CHAIN_ID = 84532;
    // Default deployed faucet token address (can be overridden by FAUCET_TOKEN_ADDRESS env var)
    address constant DEFAULT_FAUCET_TOKEN_ADDRESS = 0x2C6645f308C83ae1d00842069C78844B361A426C;
    
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
        
        // Resolve faucet token from env (if provided) or fallback to default constant
        address faucetAddress = vm.envOr("FAUCET_TOKEN_ADDRESS", DEFAULT_FAUCET_TOKEN_ADDRESS);
        require(faucetAddress != address(0), "Faucet token address not set");
        NominalUSDFaucet faucetToken = NominalUSDFaucet(faucetAddress);

        vm.startBroadcast(deployerPrivateKey);

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
        console.log("Added NominalUSD (faucet) as supported token:", address(faucetToken));
        console.log("Token fee:", TOKEN_FEE);
        
        // Authorize the deployer as a wallet provider with referral fee
        registry.authorizeWalletProvider(deployer, REFERRER_FEE_BPS);
        console.log("Authorized deployer as wallet provider with", REFERRER_FEE_BPS, "bps referral fee");
        
        vm.stopBroadcast();
        
        // Verification info
        console.log("\n=== Deployment Summary ===");
        console.log("NominalUSD Faucet (pre-deployed):", address(faucetToken));
        console.log("NominalRegistryV2 (new):", address(registry));
        console.log("ETH Fee:", ETH_FEE);
        console.log("Token Fee:", TOKEN_FEE);
        console.log("Referrer Fee:", REFERRER_FEE_BPS, "bps (20%)");

        // Display faucet token metadata from the existing deployment
        console.log("\n=== Faucet Token Details ===");
        console.log("Name:", faucetToken.name());
        console.log("Symbol:", faucetToken.symbol());
        console.log("Claim amount:", faucetToken.CLAIM_AMOUNT());
        console.log("Cooldown period:", faucetToken.COOLDOWN_PERIOD());

        console.log("\n=== Verification Commands (manual) ===");
        // Simple verification (uses etherscan key from foundry.toml via ${ES_KEY})
        console.log(
            string(
                abi.encodePacked(
                    "forge verify-contract ",
                    vm.toString(address(registry)),
                    " src/NominalRegistryV2.sol:NominalRegistryV2 --chain base-sepolia --watch"
                )
            )
        );
        // If constructor args are needed explicitly:
        console.log(
            string(
                abi.encodePacked(
                    "# If needed: cast abi-encode \"constructor(uint256)\" ",
                    vm.toString(ETH_FEE)
                )
            )
        );

        // Optional: auto-verify using vm.ffi if enabled
        // Set ENABLE_FFI=1 and AUTO_VERIFY=1 and ensure ES_KEY is set in the environment.
        bool enableFfi = vm.envOr("ENABLE_FFI", false);
        bool autoVerify = vm.envOr("AUTO_VERIFY", false);
        if (enableFfi && autoVerify) {
            string memory apiKey = vm.envString("ES_KEY");
            if (bytes(apiKey).length == 0) {
                console.log("Skipping auto-verify: ES_KEY not set");
            } else {
                console.log("\n=== Auto-verifying on Basescan (Etherscan v2) ===");
                string[] memory cmds = new string[](9);
                cmds[0] = "forge";
                cmds[1] = "verify-contract";
                cmds[2] = vm.toString(address(registry));
                cmds[3] = "src/NominalRegistryV2.sol:NominalRegistryV2";
                cmds[4] = "--chain";
                cmds[5] = "base-sepolia";
                cmds[6] = "--etherscan-api-key";
                cmds[7] = apiKey;
                cmds[8] = "--watch";
                bytes memory out = vm.ffi(cmds);
                console.log("Verification output:", string(out));
            }
        } else {
            console.log("\nTip: Set ENABLE_FFI=1 and AUTO_VERIFY=1 to auto-verify from the script. ES_KEY must be set.");
        }
    }
}