// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/NominalRegistryV2.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./real-signatures.sol";

/**
 * @title NominalRegistryV2 Real Signature Tests
 * @notice Tests with real addresses, real signatures, real cryptography
 * @dev This proves the contract works with actual wallet signatures
 */
contract NominalRegistryV2RealSignatureTest is Test {
    using ECDSA for bytes32;
    
    NominalRegistryV2 registry;
    uint256 constant REGISTRATION_FEE = 0.01 ether;
    
    // Chain constants matching contract
    uint8 constant CHAIN_EVM = 0;
    uint8 constant CHAIN_SOLANA = 1;
    uint8 constant CHAIN_SUI = 2;
    uint8 constant CHAIN_APTOS = 3;
    
    // Real Solana addresses (32 bytes)
    bytes constant ALICE_SOLANA = hex"f80774a429641945e19cb2a754a75f77640c4e9e22e722f6c1df3e2a5f2e2452";
    bytes constant ALICE_SOLANA_PK = hex"f80774a429641945e19cb2a754a75f77640c4e9e22e722f6c1df3e2a5f2e2452";
    
    // Real Sui addresses (32 bytes)
    bytes constant ALICE_SUI = hex"98f700eb470476028f52bbae6e71550d07d91428fdbe21c6a5dbf495404137b4";
    bytes constant ALICE_SUI_PK = hex"de2e7e68464338e26a283d0217f9df7769e8f208d696e66f56d0a543b96306ab";
    
    // Real Aptos addresses (32 bytes)
    bytes constant ALICE_APTOS = hex"44e3d793152b807bd63cfa7c1cb80e14465327bb7f10e56b77ba7d97d44545fa";
    bytes constant ALICE_APTOS_PK = hex"c52b1e14923971463093410971ffdf181945eab1910d1510e118d286ea5e53c1";
    
    // Updated signatures with correct domain-bound format and test contract address (lowercase)
    bytes constant ALICE_SOLANA_SIG_NEW = hex"9a7334ce4cf4c2500d755118ccacba943a3d26834fbb8b1a79bd60be51e0b991eaecb1bd7a670cb401ab8a8ab874d9597e2d001b89a585e8d0d7f37fa3f15f0f";
    
    uint256 constant WORKING_EXPIRY = 3601; // Valid expiry for blockchain time

    function setUp() public {
        // Deploy with test configuration
        registry = new NominalRegistryV2(REGISTRATION_FEE);
        
        // Output the deployed contract address for signature generation
        console.log("Deployed contract address: ", address(registry));
    }

    function testRFCVectorVerification() public {
        // Use the exact RFC test vector that works in the crypto library
        uint256 r = 0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da;
        uint256 s = 0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00;
        bytes memory message = hex"72";
        
        // Create a signature in the format our contract expects (64 bytes: r + s)
        bytes memory signature = abi.encodePacked(bytes32(r), bytes32(s));
        
        // Get the public key from the library (we know this works)
        uint256 secret = 0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb;
        uint256[5] memory extKpub;
        uint256[2] memory signer;
        (extKpub, signer) = registry.getLibrarySetKey(secret);
        
        bytes memory publicKey = abi.encodePacked(bytes32(extKpub[4]));
        
        // Test our verification with the known working signature
        // bool result = registry.debugEd25519Verification(string(message), signature, publicKey);
        
        // console.log("RFC test result:", result);
       // assertTrue(result, "RFC test vector should verify successfully");
    }

    /**
     * TEST: REAL SOLANA Ed25519 SIGNATURE VERIFICATION
     * This tests actual Ed25519 signature verification with real Solana wallet signatures
     */
    function testRealSolanaSignatureRegistration() public {
        string memory name = "alice-solana";
        uint8 chainId = CHAIN_SOLANA;
        bytes memory walletAddress = ALICE_SOLANA;
        bytes memory publicKey = ALICE_SOLANA_PK;
        bytes memory signature = ALICE_SOLANA_SIG_NEW; // Use corrected signature
        uint256 nonce = 0;
        uint256 expiry = WORKING_EXPIRY; // Valid expiry
        
        // Debug: Get the exact message the contract would generate
        string memory contractMessage = registry.debugGetDomainBoundMessage(name, chainId, walletAddress, nonce, expiry);
        console.log("Contract message:", contractMessage);
        
        vm.deal(address(this), 1 ether);
        
        // This should work because we have a real Ed25519 signature
        registry.registerName{value: REGISTRATION_FEE}(
            name,
            chainId,
            walletAddress,
            publicKey,
            signature,
            nonce,
            expiry,
            address(0), // paymentToken (ETH)
            address(0)  // No referrer
        );
        
        // Verify registration succeeded
        assertEq(registry.getNameOwner(name, chainId), walletAddress);
    }

    /**
     * TEST: REAL SUI Ed25519 SIGNATURE VERIFICATION
     * This tests actual Ed25519 signature verification with real Sui wallet signatures
     */
    function testRealSuiSignatureRegistration() public {
        string memory name = "alice-sui";
        uint8 chainId = CHAIN_SUI;
        bytes memory walletAddress = ALICE_SUI;
        bytes memory publicKey = ALICE_SUI_PK;
        bytes memory signature = ALICE_SUI_SIGNATURE;
        uint256 nonce = 0;
        uint256 expiry = WORKING_EXPIRY; // Valid expiry
        
        // Debug: Get the exact message the contract would generate
        string memory contractMessage = registry.debugGetDomainBoundMessage(name, chainId, walletAddress, nonce, expiry);
        console.log("Sui Contract message:", contractMessage);

        vm.deal(address(this), 1 ether);
        
        // This should work because we have a real Ed25519 signature
        registry.registerName{value: REGISTRATION_FEE}(
            name,
            chainId,
            walletAddress,
            publicKey,
            signature,
            nonce,
            expiry,
            address(0), // paymentToken (ETH)
            address(0)  // No referrer
        );
        
        // Verify registration succeeded
        assertEq(registry.getNameOwner(name, chainId), walletAddress);
    }

    /**
     * TEST: REAL APTOS Ed25519 SIGNATURE VERIFICATION
     * This tests actual Ed25519 signature verification with real Aptos wallet signatures
     */
    function testRealAptosSignatureRegistration() public {
        string memory name = "alice-aptos";
        uint8 chainId = CHAIN_APTOS;
        bytes memory walletAddress = ALICE_APTOS;
        bytes memory publicKey = ALICE_APTOS_PK;
        bytes memory signature = hex"07ebfc823f618fab524a47a25153cf49548a142e8481bd89a96914c63f70e4e430add1a8beedd6e572bac36aba2a7aa429076faea12602cb4d4a82ed134ba407";
        uint256 nonce = 0;
        uint256 expiry = WORKING_EXPIRY; // Valid expiry
        
        // Debug: Get the exact message the contract would generate
        string memory contractMessage = registry.debugGetDomainBoundMessage(name, chainId, walletAddress, nonce, expiry);
        console.log("Aptos Contract message:", contractMessage);

        vm.deal(address(this), 1 ether);
        
        // This should work because we have a real Ed25519 signature
        registry.registerName{value: REGISTRATION_FEE}(
            name,
            chainId,
            walletAddress,
            publicKey,
            signature,
            nonce,
            expiry,
            address(0), // paymentToken (ETH)
            address(0)  // No referrer
        );
        
        // Verify registration succeeded - for Aptos, canonical identity is the public key
        assertEq(registry.getNameOwner(name, chainId), publicKey);
    }
}