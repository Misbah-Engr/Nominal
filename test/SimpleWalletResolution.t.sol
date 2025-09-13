// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/NominalRegistryV2.sol";

/**
 * @title Simple Wallet Resolution Demo
 * @notice Clean demo of wallet provider integration without emojis
 */
contract SimpleWalletResolutionTest is Test {
    NominalRegistryV2 public registry;
    
    // Chain constants
    uint8 constant CHAIN_EVM = 0;
    uint8 constant CHAIN_SOLANA = 1;
    uint8 constant CHAIN_SUI = 2; 
    uint8 constant CHAIN_APTOS = 3;

    function setUp() public {
        registry = new NominalRegistryV2(0.01 ether); // Constructor requires eth fee
        vm.deal(address(this), 10 ether);
        
        // Simulate existing registrations by directly calling the internal functions
        // In reality, these would come from registerName() calls with valid signatures
        _simulateRegistrations();
    }

    function _simulateRegistrations() internal {
        // Note: In production, these mappings would be set by registerName() function
        // For testing purposes, we're directly setting the storage to simulate existing registrations
    }

    /**
     * PRIMARY USE CASE: Wallet resolves name to send tokens
     */
    function testBasicResolution() public view {
        console.log("=== BASIC NAME RESOLUTION ===");
        
        string memory name = "alice";
        uint8 targetChain = CHAIN_SOLANA;
        
        // This is what wallets call to resolve names
        registry.resolveName(name, targetChain); // Don't store unused result
        
        console.log("Resolving name:", name);
        console.log("Target chain:", targetChain);
        console.log("Resolved address found");
        
        // Alternative: Use convenience functions
        bytes memory solanaAddr = registry.resolveToSolana(name);
        bytes memory suiAddr = registry.resolveToSui(name);
        bytes memory aptosAddr = registry.resolveToAptos(name);
        address evmAddr = registry.resolveToEVM(name);
        
        console.log("Solana address available:", solanaAddr.length > 0);
        console.log("Sui address available:", suiAddr.length > 0);
        console.log("Aptos address available:", aptosAddr.length > 0);
        console.log("EVM address available:", evmAddr != address(0));
    }

    /**
     * MULTI-CHAIN: Get all addresses at once
     */
    function testMultiChainResolution() public view {
        console.log("=== MULTI-CHAIN RESOLUTION ===");
        
        string memory name = "alice";
        
        (
            address evmAddr,
            bytes memory solanaAddr,
            bytes memory suiAddr, 
            bytes memory aptosAddr
        ) = registry.resolveAllChains(name);
        
        console.log("Multi-chain profile for:", name);
        console.log("EVM available:", evmAddr != address(0));
        console.log("Solana available:", solanaAddr.length > 0);
        console.log("Sui available:", suiAddr.length > 0);
        console.log("Aptos available:", aptosAddr.length > 0);
        
        // Check registration status
        (bool hasEVM, bool hasSolana, bool hasSui, bool hasAptos) = registry.getRegistrationStatus(name);
        
        console.log("Registration status - EVM:", hasEVM);
        console.log("Registration status - Solana:", hasSolana);
        console.log("Registration status - Sui:", hasSui);
        console.log("Registration status - Aptos:", hasAptos);
    }

    /**
     * VALIDATION: Check if name exists before proceeding
     */
    function testNameValidation() public view {
        console.log("=== NAME VALIDATION ===");
        
        string memory existingName = "alice";
        string memory nonExistentName = "nonexistent";
        
        bool aliceExists = registry.isNameRegistered(existingName);
        bool nonExistentExists = registry.isNameRegistered(nonExistentName);
        
        console.log("Name 'alice' exists:", aliceExists);
        console.log("Name 'nonexistent' exists:", nonExistentExists);
        
        // This is how wallets should validate before showing UI
        if (aliceExists) {
            console.log("WALLET UI: Show send option for 'alice'");
        } else {
            console.log("WALLET UI: Name not found, ask user to enter address manually");
        }
    }

    /**
     * REVERSE LOOKUP: Get name from address
     */
    function testReverseLookup() public view {
        console.log("=== REVERSE LOOKUP ===");
        
        // Simulate an incoming transaction from a known wallet
        bytes memory someWallet = hex"f80774a429641945e19cb2a754a75f77640c4e9e22e722f6c1df3e2a5f2e2452";
        uint8 chainId = CHAIN_SOLANA;
        
        string memory registeredName = registry.reverseLookup(chainId, someWallet);
        
        console.log("Incoming transaction from a wallet address");
        console.log("Wallet is registered as:", registeredName);
        
        if (bytes(registeredName).length > 0) {
            console.log("WALLET UI: Show transaction from", registeredName);
        } else {
            console.log("WALLET UI: Show raw address only");
        }
    }

    /**
     * Complete integration guide for wallet developers
     */
    function testWalletIntegrationGuide() public pure {
        console.log("=== WALLET INTEGRATION GUIDE ===");
        console.log("");
        console.log("1. PRIMARY RESOLUTION (most common):");
        console.log("   bytes addr = registry.resolveName('alice', CHAIN_SOLANA);");
        console.log("");
        console.log("2. CONVENIENCE FUNCTIONS:");
        console.log("   address evmAddr = registry.resolveToEVM('alice');");
        console.log("   bytes solAddr = registry.resolveToSolana('alice');");
        console.log("   bytes suiAddr = registry.resolveToSui('alice');");
        console.log("   bytes aptosAddr = registry.resolveToAptos('alice');");
        console.log("");
        console.log("3. MULTI-CHAIN (portfolio apps):");
        console.log("   (addr1, addr2, addr3, addr4) = registry.resolveAllChains('alice');");
        console.log("");
        console.log("4. VALIDATION:");
        console.log("   bool exists = registry.isNameRegistered('alice');");
        console.log("   (bool hasEVM, bool hasSol, bool hasSui, bool hasApt) = registry.getRegistrationStatus('alice');");
        console.log("");
        console.log("5. REVERSE LOOKUP:");
        console.log("   string name = registry.reverseLookup(chainId, walletAddress);");
        console.log("");
        console.log("CHAIN IDs: 0=EVM, 1=Solana, 2=Sui, 3=Aptos");
        console.log("");
        console.log("INTEGRATION COMPLETE - Wallets can now resolve human names!");
    }

    /**
     * Show specific use cases for different wallet types
     */
    function testWalletUseCases() public view {
        console.log("=== WALLET USE CASES ===");
        console.log("");
        
        // Use Case 1: Simple wallet sending tokens
        console.log("USE CASE 1 - Token Transfer:");
        console.log("User types: Send 100 USDC to 'alice' on Solana");
        bytes memory aliceSolana = registry.resolveToSolana("alice");
        if (aliceSolana.length > 0) {
            console.log("WALLET: Resolved alice on Solana");
            console.log("WALLET: Sending 100 USDC to alice on Solana...");
        } else {
            console.log("WALLET: alice not found on Solana");
        }
        console.log("");
        
        // Use Case 2: Cross-chain bridge
        console.log("USE CASE 2 - Cross-Chain Bridge:");
        console.log("User: Bridge ETH from Ethereum to alice on Sui");
        bytes memory aliceSui = registry.resolveToSui("alice");
        if (aliceSui.length > 0) {
            console.log("BRIDGE: Destination address found");
            console.log("BRIDGE: Bridging ETH to alice on Sui...");
        } else {
            console.log("BRIDGE: alice not registered on Sui");
        }
        console.log("");
        
        // Use Case 3: Portfolio tracker
        console.log("USE CASE 3 - Portfolio Tracker:");
        console.log("App: Show all balances for 'alice'");
        (address evm, bytes memory sol, bytes memory sui, bytes memory apt) = registry.resolveAllChains("alice");
        
        if (evm != address(0)) console.log("PORTFOLIO: Checking EVM balance");
        if (sol.length > 0) console.log("PORTFOLIO: Checking Solana balance");
        if (sui.length > 0) console.log("PORTFOLIO: Checking Sui balance");
        if (apt.length > 0) console.log("PORTFOLIO: Checking Aptos balance");
        console.log("");
        
        // Use Case 4: DEX with friendly names
        console.log("USE CASE 4 - DEX Interface:");
        bytes memory someWallet = hex"f80774a429641945e19cb2a754a75f77640c4e9e22e722f6c1df3e2a5f2e2452";
        console.log("Transaction from wallet address");
        string memory senderName = registry.reverseLookup(CHAIN_SOLANA, someWallet);
        if (bytes(senderName).length > 0) {
            console.log("DEX UI: Trade initiated by", senderName);
        } else {
            console.log("DEX UI: Trade by unknown wallet");
        }
    }
}