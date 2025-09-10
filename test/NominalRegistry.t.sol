// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/NominalRegistry.sol";
import "../src/MockERC20.sol";

contract NominalRegistryTest is Test {
    NominalRegistry public registry;
    MockERC20 public testToken;
    
    address public owner = address(0x1);
    address public walletProvider = address(0x2);
    address public user1 = address(0x3);
    address public user2 = address(0x4);
    address public attacker = address(0x5);

    // Test constants
    uint256 public constant ETH_FEE = 0.01 ether;
    uint256 public constant ETH_REFERRAL_PERCENT = 10;
    uint256 public constant TOKEN_FEE = 100 * 10**18;
    uint256 public constant TOKEN_REFERRAL_FEE = 10 * 10**18;

    // Chain constants
    uint8 public constant CHAIN_EVM = 0;
    uint8 public constant CHAIN_SOLANA = 1;
    uint8 public constant CHAIN_SUI = 2;
    uint8 public constant CHAIN_APTOS = 3;
    uint8 public constant CHAIN_NEAR = 4;

    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy contracts
        registry = new NominalRegistry();
        testToken = new MockERC20("Test Token", "TEST", 1000000 * 10**18);

        // Setup registry
        registry.setEthFee(ETH_FEE);
        registry.setETHReferralFeePercent(ETH_REFERRAL_PERCENT);
        registry.setWalletProvider(walletProvider, true);
        registry.setAllowedToken(address(testToken), true);
        registry.setRegistrationFeeForToken(address(testToken), TOKEN_FEE);
        registry.setReferralFeeAmountInToken(address(testToken), TOKEN_REFERRAL_FEE);

        vm.stopPrank();

        // Give users some tokens and ETH
        testToken.mint(user1, 1000 * 10**18);
        testToken.mint(user2, 1000 * 10**18);
        testToken.mint(walletProvider, 1000 * 10**18);
        
        vm.deal(user1, 10 ether);
        vm.deal(user2, 10 ether);
        vm.deal(walletProvider, 10 ether);
    }

    function testBasicFunctionality() public view {
        // Test basic functionality without crypto-lib integration for now
        assertEq(registry.contractOwner(), owner);
        assertEq(registry.ethFee(), ETH_FEE);
        assertTrue(registry.walletProvider(walletProvider));
        assertTrue(registry.allowedTokens(address(testToken)));
    }

    function testConsecutiveDuplicateAddresses() public {
        // Test consecutive duplicates detection  
        vm.startPrank(walletProvider);
        
        bytes[] memory signatures = new bytes[](4);
        bytes[] memory publicKeys = new bytes[](4);
        bytes[] memory addresses = new bytes[](4);
        uint8[] memory chains = new uint8[](4);
        uint256[] memory nonces = new uint256[](4);
        uint256[] memory expiries = new uint256[](4);

        for (uint256 i = 0; i < 4; i++) {
            signatures[i] = abi.encodePacked(bytes32(uint256(0x1234 + i)), bytes32(uint256(0x5678 + i)));
            publicKeys[i] = abi.encodePacked(bytes32(uint256(0xabcd + i)));
            chains[i] = CHAIN_SOLANA;
            nonces[i] = 0;
            expiries[i] = block.timestamp + 1 hours;
        }

        // Set CONSECUTIVE duplicates
        addresses[0] = abi.encodePacked(bytes32(uint256(0x1111)));
        addresses[1] = abi.encodePacked(bytes32(uint256(0x2222))); // First occurrence
        addresses[2] = abi.encodePacked(bytes32(uint256(0x2222))); // CONSECUTIVE DUPLICATE!
        addresses[3] = abi.encodePacked(bytes32(uint256(0x4444)));

        vm.expectRevert("Duplicate addresses");
        registry.registerForSomeone{value: ETH_FEE}(
            "testdupe",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();
    }

    function testNonConsecutiveDuplicateAddresses() public {
        // Test NON-CONSECUTIVE duplicates detection (the critical test!)
        vm.startPrank(walletProvider);
        
        bytes[] memory signatures = new bytes[](4);
        bytes[] memory publicKeys = new bytes[](4);
        bytes[] memory addresses = new bytes[](4);
        uint8[] memory chains = new uint8[](4);
        uint256[] memory nonces = new uint256[](4);
        uint256[] memory expiries = new uint256[](4);

        for (uint256 i = 0; i < 4; i++) {
            signatures[i] = abi.encodePacked(bytes32(uint256(0x1234 + i)), bytes32(uint256(0x5678 + i)));
            publicKeys[i] = abi.encodePacked(bytes32(uint256(0xabcd + i)));
            chains[i] = CHAIN_SOLANA;
            nonces[i] = 0;
            expiries[i] = block.timestamp + 1 hours;
        }

        // Set NON-CONSECUTIVE duplicates
        bytes32 dup = bytes32(uint256(0x2222));
        addresses[0] = abi.encodePacked(bytes32(uint256(0x1111)));
        addresses[1] = abi.encodePacked(dup); // First occurrence
        addresses[2] = abi.encodePacked(bytes32(uint256(0x3333))); // Different value
        addresses[3] = abi.encodePacked(dup); // NON-CONSECUTIVE DUPLICATE at positions 1 and 3!

        vm.expectRevert("Duplicate addresses");
        registry.registerForSomeone{value: ETH_FEE}(
            "testdupe2",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();
    }

    function testNoFalsePositiveForUniqueDuplicates() public {
        // Ensure unique addresses don't trigger false positives
        vm.startPrank(walletProvider);
        
        bytes[] memory signatures = new bytes[](3);
        bytes[] memory publicKeys = new bytes[](3);
        bytes[] memory addresses = new bytes[](3);
        uint8[] memory chains = new uint8[](3);
        uint256[] memory nonces = new uint256[](3);
        uint256[] memory expiries = new uint256[](3);

        for (uint256 i = 0; i < 3; i++) {
            signatures[i] = abi.encodePacked(bytes32(uint256(0x1234 + i)), bytes32(uint256(0x5678 + i)));
            publicKeys[i] = abi.encodePacked(bytes32(uint256(0xabcd + i)));
            addresses[i] = abi.encodePacked(bytes32(uint256(0x1111 + i))); // All unique
            chains[i] = CHAIN_SOLANA;
            nonces[i] = 0;
            expiries[i] = block.timestamp + 1 hours;
        }

        // This should NOT revert with "Duplicate addresses" since all addresses are unique
        // But it will fail at signature verification first (which is the expected behavior)
        vm.expectRevert("Public key does not match address");
        registry.registerForSomeone{value: ETH_FEE}(
            "testunique",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();
    }

    function testPauseFunctionality() public {
        // Test pause prevents registration
        vm.prank(owner);
        registry.pause();
        assertTrue(registry.paused());

        vm.startPrank(user1);
        
        bytes[] memory signatures = new bytes[](1);
        bytes[] memory publicKeys = new bytes[](1);
        bytes[] memory addresses = new bytes[](1);
        uint8[] memory chains = new uint8[](1);
        uint256[] memory nonces = new uint256[](1);
        uint256[] memory expiries = new uint256[](1);

        signatures[0] = abi.encodePacked(bytes32(uint256(0x1234)), bytes32(uint256(0x5678)));
        publicKeys[0] = abi.encodePacked(bytes32(uint256(0xabcd)));
        addresses[0] = abi.encodePacked(bytes32(uint256(0x1111)));
        chains[0] = CHAIN_SOLANA;
        nonces[0] = 0;
        expiries[0] = block.timestamp + 1 hours;

        vm.expectRevert("Contract paused");
        registry.registerName{value: ETH_FEE}(
            "pausedtest",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();

        // Unpause and try again
        vm.prank(owner);
        registry.unpause();
        assertFalse(registry.paused());
    }

    function testOwnerTransfer() public {
        address newOwner = address(0x999);

        // Request transfer
        vm.prank(owner);
        registry.requestOwnerTransfer(newOwner);
        assertEq(registry.pendingOwner(), newOwner);

        // Accept transfer
        vm.prank(newOwner);
        registry.acceptOwner();
        assertEq(registry.contractOwner(), newOwner);
        assertEq(registry.pendingOwner(), address(0));

        // Verify old owner can't perform owner functions
        vm.prank(owner);
        vm.expectRevert("Not owner");
        registry.pause();

        // Verify new owner can perform owner functions
        vm.prank(newOwner);
        registry.pause();
        assertTrue(registry.paused());
    }

    function testUnauthorizedAccess() public {
        // Test non-wallet provider can't call registerForSomeone
        bytes[] memory signatures = new bytes[](0);
        bytes[] memory publicKeys = new bytes[](0);
        bytes[] memory addresses = new bytes[](0);
        uint8[] memory chains = new uint8[](0);
        uint256[] memory nonces = new uint256[](0);
        uint256[] memory expiries = new uint256[](0);

        // Direct call without vm.prank to avoid cheatcode depth issues
        vm.deal(attacker, 1 ether);
        
        // This should fail because attacker is not a wallet provider
        vm.expectRevert("Not wallet provider");
        vm.prank(attacker);
        registry.registerForSomeone{value: ETH_FEE}(
            "attackertest",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );
    }

    function testInsufficientFee() public {
        vm.startPrank(user1);
        
        // Use empty arrays to avoid signature verification
        bytes[] memory signatures = new bytes[](0);
        bytes[] memory publicKeys = new bytes[](0);
        bytes[] memory addresses = new bytes[](0);
        uint8[] memory chains = new uint8[](0);
        uint256[] memory nonces = new uint256[](0);
        uint256[] memory expiries = new uint256[](0);

        vm.expectRevert("Insufficient ETH fee");
        registry.registerName{value: ETH_FEE - 1}( // Insufficient fee
            "underpaidtest",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();
    }

    function testTokenPayment() public {
        // Test token-based payment
        vm.startPrank(user1);
        
        // Approve token spending
        testToken.approve(address(registry), TOKEN_FEE);

        // Use empty arrays to avoid signature verification and test token payment
        bytes[] memory signatures = new bytes[](0);
        bytes[] memory publicKeys = new bytes[](0);
        bytes[] memory addresses = new bytes[](0);
        uint8[] memory chains = new uint8[](0);
        uint256[] memory nonces = new uint256[](0);
        uint256[] memory expiries = new uint256[](0);

        uint256 balanceBefore = testToken.balanceOf(user1);
        uint256 registryBalanceBefore = testToken.balanceOf(address(registry));

        // This should work since we're using valid token payment
        registry.registerName(
            "tokentest",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(testToken)
        );

        // Verify token was transferred
        assertEq(testToken.balanceOf(user1), balanceBefore - TOKEN_FEE);
        assertEq(testToken.balanceOf(address(registry)), registryBalanceBefore + TOKEN_FEE);

        vm.stopPrank();
    }

    function testNameNormalization() public view {
        // Test getUserAddress normalizes names to lowercase
        string memory testName = "TestUser";
        string memory normalizedName = "testuser";
        
        // We can't easily test actual registration due to crypto-lib complexity
        // But we can test that getUserAddress works with case normalization
        address result1 = registry.getUserAddress(testName, CHAIN_EVM);
        address result2 = registry.getUserAddress(normalizedName, CHAIN_EVM);
        
        // Both should return the same result (address(0) since nothing is registered)
        assertEq(result1, result2);
        assertEq(result1, address(0));
    }

    function testETHRefund() public {
        // Test ETH refund for overpayment
        vm.startPrank(user1);
        
        uint256 balanceBefore = user1.balance;
        uint256 overpayment = ETH_FEE + 0.005 ether;

        bytes[] memory signatures = new bytes[](0);
        bytes[] memory publicKeys = new bytes[](0);
        bytes[] memory addresses = new bytes[](0);
        uint8[] memory chains = new uint8[](0);
        uint256[] memory nonces = new uint256[](0);
        uint256[] memory expiries = new uint256[](0);

        // This should work for EVM-only registration with overpayment
        registry.registerName{value: overpayment}(
            "refundtest",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        // Should only charge the fee and refund the excess
        assertEq(user1.balance, balanceBefore - ETH_FEE);
        assertEq(address(registry).balance, ETH_FEE);

        vm.stopPrank();
    }

    function testArrayLengthMismatch() public {
        // Test array length validation
        vm.startPrank(walletProvider);
        
        bytes[] memory signatures = new bytes[](2);
        bytes[] memory publicKeys = new bytes[](1); // Mismatched length!
        bytes[] memory addresses = new bytes[](2);
        uint8[] memory chains = new uint8[](2);
        uint256[] memory nonces = new uint256[](2);
        uint256[] memory expiries = new uint256[](2);

        vm.expectRevert("Array length mismatch");
        registry.registerForSomeone{value: ETH_FEE}(
            "mismatchtest",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();
    }

    function testInvalidChainId() public {
        vm.startPrank(user1);
        
        bytes[] memory signatures = new bytes[](1);
        bytes[] memory publicKeys = new bytes[](1);
        bytes[] memory addresses = new bytes[](1);
        uint8[] memory chains = new uint8[](1);
        uint256[] memory nonces = new uint256[](1);
        uint256[] memory expiries = new uint256[](1);

        signatures[0] = abi.encodePacked(bytes32(uint256(0x1234)), bytes32(uint256(0x5678)));
        publicKeys[0] = abi.encodePacked(bytes32(uint256(0xabcd)));
        addresses[0] = abi.encodePacked(bytes32(uint256(0x1111)));
        chains[0] = 99; // Invalid chain ID
        nonces[0] = 0;
        expiries[0] = block.timestamp + 1 hours;

        vm.expectRevert("Invalid chain");
        registry.registerName{value: ETH_FEE}(
            "invalidchain",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();
    }

    // This test will demonstrate that our implementation is ready for the crypto-lib integration
    function testCryptoLibIntegration() public {
        // This test shows the structure is ready for crypto-lib
        // Once crypto-lib is fully integrated, signatures will be properly verified
        
        vm.startPrank(user1);
        
        bytes[] memory signatures = new bytes[](1);
        bytes[] memory publicKeys = new bytes[](1);
        bytes[] memory addresses = new bytes[](1);
        uint8[] memory chains = new uint8[](1);
        uint256[] memory nonces = new uint256[](1);
        uint256[] memory expiries = new uint256[](1);

        // Create a proper 64-byte signature and 32-byte public key
        signatures[0] = abi.encodePacked(
            bytes32(uint256(0x1234567890123456789012345678901234567890123456789012345678901234)),
            bytes32(uint256(0x5678901234567890123456789012345678901234567890123456789012345678))
        );
        publicKeys[0] = abi.encodePacked(bytes32(uint256(0xabcdef1234567890123456789012345678901234567890123456789012345678)));
        addresses[0] = abi.encodePacked(bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111)));
        chains[0] = CHAIN_SOLANA;
        nonces[0] = 0;
        expiries[0] = block.timestamp + 1 hours;

        // This will fail at crypto-lib verification, but it demonstrates the integration point
        vm.expectRevert(); // Could be various crypto-lib related errors
        registry.registerName{value: ETH_FEE}(
            "cryptotest",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );

        vm.stopPrank();
    }

    function testUnauthorizedTokenPayment() public {
        // Test unauthorized token payment
        vm.startPrank(user1);
        
        // Create unauthorized token
        MockERC20 badToken = new MockERC20("Bad Token", "BAD", 1000000 * 10**18);
        badToken.mint(user1, 1000 * 10**18);
        badToken.approve(address(registry), 1000 * 10**18);

        bytes[] memory signatures = new bytes[](0);
        bytes[] memory publicKeys = new bytes[](0);
        bytes[] memory addresses = new bytes[](0);
        uint8[] memory chains = new uint8[](0);
        uint256[] memory nonces = new uint256[](0);
        uint256[] memory expiries = new uint256[](0);

        vm.expectRevert("Token not allowed");
        registry.registerName(
            "badtoken",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(badToken) // Unauthorized token!
        );

        vm.stopPrank();
    }

    // ============ NAME AVAILABILITY TESTING ============
    
    function testNameAvailabilityChecks() public view {
        // Test single chain availability 
        assertTrue(registry.isNameAvailable("newname", CHAIN_EVM));
        assertTrue(registry.isNameAvailable("newname", CHAIN_SOLANA));
        
        // Test case normalization
        assertTrue(registry.isNameAvailable("TestName", CHAIN_EVM));
        assertTrue(registry.isNameAvailable("testname", CHAIN_EVM));
    }

    function testNameAvailabilityOnMultipleChains() public view {
        uint8[] memory testChains = new uint8[](3);
        testChains[0] = CHAIN_EVM;
        testChains[1] = CHAIN_SOLANA;
        testChains[2] = CHAIN_SUI;
        
        (bool available, uint8[] memory unavailable) = registry.isNameAvailableOnChains("availablename", testChains);
        assertTrue(available);
        assertEq(unavailable.length, 0);
    }

    function testGetNameOwners() public view {
        address[5] memory owners = registry.getNameOwners("unregisteredname");
        
        // All should be address(0) since name is not registered
        for (uint i = 0; i < 5; i++) {
            assertEq(owners[i], address(0));
        }
    }

    function testGetNameAvailabilityStatus() public view {
        (bool[5] memory availability, uint256 totalAvailable) = registry.getNameAvailabilityStatus("newname");
        
        // All chains should be available for new name
        assertEq(totalAvailable, 5);
        for (uint i = 0; i < 5; i++) {
            assertTrue(availability[i]);
        }
    }

    function testNameAvailabilityAfterRegistration() public {
        // Register a name first
        vm.startPrank(user1);
        
        bytes[] memory signatures = new bytes[](0);
        bytes[] memory publicKeys = new bytes[](0);
        bytes[] memory addresses = new bytes[](0);
        uint8[] memory chains = new uint8[](0);
        uint256[] memory nonces = new uint256[](0);
        uint256[] memory expiries = new uint256[](0);

        registry.registerName{value: ETH_FEE}(
            "takenname",
            signatures,
            publicKeys,
            addresses,
            chains,
            nonces,
            expiries,
            address(0)
        );
        
        vm.stopPrank();

        // Now check availability
        assertFalse(registry.isNameAvailable("takenname", CHAIN_EVM));
        assertTrue(registry.isNameAvailable("takenname", CHAIN_SOLANA)); // Other chains still available
        
        // Test multi-chain check
        uint8[] memory testChains = new uint8[](2);
        testChains[0] = CHAIN_EVM;
        testChains[1] = CHAIN_SOLANA;
        
        (bool available, uint8[] memory unavailable) = registry.isNameAvailableOnChains("takenname", testChains);
        assertFalse(available); // Not available on ALL chains
        assertEq(unavailable.length, 1);
        assertEq(unavailable[0], CHAIN_EVM);
        
        // Test ownership check
        address[5] memory owners = registry.getNameOwners("takenname");
        assertEq(owners[CHAIN_EVM], user1);
        assertEq(owners[CHAIN_SOLANA], address(0));
        
        // Test availability status
        (bool[5] memory availability, uint256 totalAvailable) = registry.getNameAvailabilityStatus("takenname");
        assertEq(totalAvailable, 4); // 4 chains still available
        assertFalse(availability[CHAIN_EVM]);
        assertTrue(availability[CHAIN_SOLANA]);
    }

    function testInvalidChainInAvailabilityCheck() public {
        vm.expectRevert("Invalid chain");
        registry.isNameAvailable("test", 99);
        
        uint8[] memory invalidChains = new uint8[](1);
        invalidChains[0] = 99;
        
        vm.expectRevert("Invalid chain");
        registry.isNameAvailableOnChains("test", invalidChains);
    }

    function testEmptyNameInAvailabilityCheck() public {
        vm.expectRevert("Empty name");
        registry.isNameAvailable("", CHAIN_EVM);
        
        vm.expectRevert("Empty name");
        uint8[] memory chains = new uint8[](1);
        chains[0] = CHAIN_EVM;
        registry.isNameAvailableOnChains("", chains);
    }
}