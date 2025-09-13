// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/NominalRegistryV2.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockToken is ERC20 {
    constructor() ERC20("MockToken", "MTK") {
        _mint(msg.sender, 1_000_000 ether);
    }
}

contract NominalRegistryV2BusinessLogicTest is Test {
    NominalRegistryV2 registry;
    MockToken token;
    address admin = address(0xA11CE);
    address provider = address(0xBEEF);
    address user = address(0xCAFE);
    // provider is also the referrer for referral tests
    uint256 constant REGISTRATION_FEE = 0.01 ether;

    function setUp() public {
        vm.deal(admin, 10 ether);
        vm.deal(user, 10 ether);
        vm.startPrank(admin);
        registry = new NominalRegistryV2(REGISTRATION_FEE);
        token = new MockToken();
    registry.authorizeWalletProvider(provider, 100); // 1% referral fee
    // registry.setAllowedToken(address(token), true, 1);
        vm.stopPrank();
    }

    function testReferralFeeETH() public {
        vm.deal(user, 1 ether);
        uint256 providerBalanceBefore = provider.balance;
        
        // Create a proper EIP-712 signature for EVM chain
        uint256 userPrivateKey = 0xCAFE;
        address userAddr = vm.addr(userPrivateKey);
        bytes memory walletAddress = abi.encodePacked(userAddr);
        
        // Create EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Registration(string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry)"),
                keccak256(bytes("bob")),
                uint8(0),
                keccak256(walletAddress),
                uint256(0),
                block.timestamp + 30 minutes
            )
        );
        
        bytes32 domainSeparator = registry.getDomainSeparator();
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        vm.prank(user);
        registry.registerName{value: REGISTRATION_FEE}(
            "bob",
            0,
            walletAddress,
            abi.encodePacked(userAddr), // publicKey (not used for EVM)
            signature,
            0,
            block.timestamp + 30 minutes,
            address(0), // ETH
            provider
        );
        
        uint256 providerBalanceAfter = provider.balance;
        assertGt(providerBalanceAfter, providerBalanceBefore, "Provider should receive ETH referral fee");
        
        // Calculate expected referral amount: 1% of 0.01 ether = 0.0001 ether
        uint256 expectedReferral = (REGISTRATION_FEE * 100) / 10000; // 100 basis points = 1%
        assertEq(providerBalanceAfter - providerBalanceBefore, expectedReferral, "Referral amount should be 1% of registration fee");
    }

    function testAdminWithdrawETH() public {
        // First, generate some revenue
        vm.deal(user, 1 ether);
        
        // Create a proper EIP-712 signature for EVM chain
        uint256 userPrivateKey = 0xCAFE;
        address userAddr = vm.addr(userPrivateKey);
        bytes memory walletAddress = abi.encodePacked(userAddr);
        
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Registration(string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry)"),
                keccak256(bytes("alice")),
                uint8(0),
                keccak256(walletAddress),
                uint256(0),
                block.timestamp + 30 minutes
            )
        );
        
        bytes32 domainSeparator = registry.getDomainSeparator();
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Register without referrer so full fee goes to contract
        vm.prank(user);
        registry.registerName{value: REGISTRATION_FEE}(
            "alice",
            0,
            walletAddress,
            abi.encodePacked(userAddr),
            signature,
            0,
            block.timestamp + 30 minutes,
            address(0), // ETH
            address(0)  // No referrer
        );
        
        // Check contract balance
        uint256 contractBalance = address(registry).balance;
        assertEq(contractBalance, REGISTRATION_FEE, "Contract should have registration fee");
        
        // Admin withdraws
        uint256 adminBalanceBefore = admin.balance;
        vm.prank(admin);
        registry.withdraw();
        
        uint256 adminBalanceAfter = admin.balance;
        assertEq(adminBalanceAfter - adminBalanceBefore, REGISTRATION_FEE, "Admin should receive full registration fee");
        assertEq(address(registry).balance, 0, "Contract balance should be zero after withdrawal");
    }

    function testAdminWithdrawToken() public {
        // Set up token payment
        vm.prank(admin);
        registry.setAllowedToken(address(token), true, 100 ether);
        
        // Give user tokens and approve
        vm.startPrank(admin);
        token.transfer(user, 1000 ether);
        vm.stopPrank();
        
        vm.prank(user);
        token.approve(address(registry), 1000 ether);
        
        // Create signature for token payment registration
        uint256 userPrivateKey = 0xCAFE;
        address userAddr = vm.addr(userPrivateKey);
        bytes memory walletAddress = abi.encodePacked(userAddr);
        
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Registration(string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry)"),
                keccak256(bytes("charlie")),
                uint8(0),
                keccak256(walletAddress),
                uint256(0),
                block.timestamp + 30 minutes
            )
        );
        
        bytes32 domainSeparator = registry.getDomainSeparator();
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Register with token payment
        vm.prank(user);
        registry.registerName(
            "charlie",
            0,
            walletAddress,
            abi.encodePacked(userAddr),
            signature,
            0,
            block.timestamp + 30 minutes,
            address(token), // Token payment
            address(0)      // No referrer
        );
        
        // Check contract token balance
        uint256 contractTokenBalance = token.balanceOf(address(registry));
        assertEq(contractTokenBalance, 100 ether, "Contract should have token fee");
        
        // Admin withdraws tokens
        uint256 adminTokenBalanceBefore = token.balanceOf(admin);
        vm.prank(admin);
        registry.withdrawAllTokens(address(token));
        
        uint256 adminTokenBalanceAfter = token.balanceOf(admin);
        assertEq(adminTokenBalanceAfter - adminTokenBalanceBefore, 100 ether, "Admin should receive token fee");
        assertEq(token.balanceOf(address(registry)), 0, "Contract token balance should be zero");
    }

    function testUnauthorizedWithdrawFails() public {
        // Non-admin tries to withdraw ETH
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.withdraw();
        
        // Non-admin tries to withdraw tokens
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.withdrawAllTokens(address(token));
    }

    function testWalletProviderManagement() public {
        address newProvider = address(0x1234567890123456789012345678901234567890);
        
        // Admin authorizes new provider with 3% fee
        vm.prank(admin);
        registry.authorizeWalletProvider(newProvider, 300); // 300 = 3%
        
        // Check provider is authorized
        assertTrue(registry.authorizedWalletProviders(newProvider), "Provider should be authorized");
        assertEq(registry.walletProviderReferralFee(newProvider), 300, "Referral fee should be 3%");
        
        // Admin updates provider fee to 2%
        vm.prank(admin);
        registry.updateWalletProviderFee(newProvider, 200);
        assertEq(registry.walletProviderReferralFee(newProvider), 200, "Updated referral fee should be 2%");
        
        // Admin removes provider
        vm.prank(admin);
        registry.removeWalletProvider(newProvider);
        assertFalse(registry.authorizedWalletProviders(newProvider), "Provider should no longer be authorized");
        assertEq(registry.walletProviderReferralFee(newProvider), 0, "Referral fee should be reset to 0");
    }

    function testWalletProviderFeeLimits() public {
        address newProvider = address(0x2234567890123456789012345678901234567890);
        
        // Try to set fee higher than 5% (500 basis points) - should fail
        vm.expectRevert("Fee too high");
        vm.prank(admin);
        registry.authorizeWalletProvider(newProvider, 600); // 6% > 5% max
        
        // Setting exactly 5% should work
        vm.prank(admin);
        registry.authorizeWalletProvider(newProvider, 500); // 5% exactly
        assertEq(registry.walletProviderReferralFee(newProvider), 500, "5% fee should be allowed");
        
        // Try to update fee higher than 5% - should fail
        vm.expectRevert("Fee too high");
        vm.prank(admin);
        registry.updateWalletProviderFee(newProvider, 501); // 5.01% > 5% max
    }

    function testUnauthorizedProviderManagement() public {
        address newProvider = address(0x3234567890123456789012345678901234567890);
        
        // Non-admin tries to authorize provider
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.authorizeWalletProvider(newProvider, 300);
        
        // Non-admin tries to remove provider  
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.removeWalletProvider(provider);
        
        // Non-admin tries to update provider fee
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.updateWalletProviderFee(provider, 200);
    }

    function testTokenConfiguration() public {
        // Admin sets allowed token with fee
        vm.prank(admin);
        registry.setAllowedToken(address(token), true, 50 ether);
        
        assertTrue(registry.allowedTokens(address(token)), "Token should be allowed");
        assertEq(registry.tokenFees(address(token)), 50 ether, "Token fee should be set correctly");
        
        // Admin disables token
        vm.prank(admin);
        registry.setAllowedToken(address(token), false, 0);
        
        assertFalse(registry.allowedTokens(address(token)), "Token should no longer be allowed");
        assertEq(registry.tokenFees(address(token)), 0, "Token fee should be reset to 0");
    }

    function testTokenConfigurationValidation() public {
        // Try to set zero address as token - should fail
        vm.expectRevert("Invalid token address");
        vm.prank(admin);
        registry.setAllowedToken(address(0), true, 50 ether);
        
        // Try to set allowed token with zero fee - should fail
        vm.expectRevert("Fee must be greater than zero");
        vm.prank(admin);
        registry.setAllowedToken(address(token), true, 0);
        
        // Setting disabled token with zero fee should work
        vm.prank(admin);
        registry.setAllowedToken(address(token), false, 0); // This should work
    }

    function testPauseFunctionality() public {
        // Admin pauses contract
        vm.prank(admin);
        registry.pause();
        assertTrue(registry.paused(), "Contract should be paused");
        
        // Try to register while paused - should fail
        vm.expectRevert(abi.encodeWithSignature("Paused()"));
        vm.prank(user);
        registry.registerName{value: REGISTRATION_FEE}(
            "testname",
            0,
            abi.encodePacked(user),
            abi.encodePacked(user),
            hex"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            0,
            block.timestamp + 30 minutes,
            address(0),
            address(0)
        );
        
        // Admin unpauses
        vm.prank(admin);
        registry.unpause();
        assertFalse(registry.paused(), "Contract should no longer be paused");
        
        // Emergency pause should also work
        vm.prank(admin);
        registry.emergencyPause();
        assertTrue(registry.paused(), "Contract should be paused via emergency");
    }

    function testUnauthorizedPause() public {
        // Non-admin tries to pause
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.pause();
        
        // Non-admin tries to unpause
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.unpause();
        
        // Non-admin tries emergency pause
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.emergencyPause();
    }

    function testOwnershipTransfer() public {
        address newOwner = address(0x4234567890123456789012345678901234567890);
        
        // Admin initiates ownership transfer
        vm.prank(admin);
        registry.transferOwnership(newOwner);
        assertEq(registry.pendingOwner(), newOwner, "Pending owner should be set");
        assertEq(registry.contractOwner(), admin, "Current owner should still be admin");
        
        // New owner accepts ownership
        vm.prank(newOwner);
        registry.acceptOwnership();
        assertEq(registry.contractOwner(), newOwner, "Owner should be transferred");
        assertEq(registry.pendingOwner(), address(0), "Pending owner should be reset");
        
        // Old admin should no longer have access
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(admin);
        registry.pause();
    }

    function testOwnershipTransferValidation() public {
        address newOwner = address(0x5234567890123456789012345678901234567890);
        
        // Admin initiates ownership transfer
        vm.prank(admin);
        registry.transferOwnership(newOwner);
        
        // Random user tries to accept ownership - should fail
        vm.expectRevert("Not pending owner");
        vm.prank(user);
        registry.acceptOwnership();
        
        // Non-admin tries to transfer ownership - should fail
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(user);
        registry.transferOwnership(user);
    }

    function testExcessETHRefund() public {
        vm.deal(user, 1 ether);
        
        // Create signature for registration
        uint256 userPrivateKey = 0xCAFE;
        address userAddr = vm.addr(userPrivateKey);
        bytes memory walletAddress = abi.encodePacked(userAddr);
        
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Registration(string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry)"),
                keccak256(bytes("excess")),
                uint8(0),
                keccak256(walletAddress),
                uint256(0),
                block.timestamp + 30 minutes
            )
        );
        
        bytes32 domainSeparator = registry.getDomainSeparator();
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        uint256 userBalanceBefore = user.balance;
        uint256 excessAmount = 0.02 ether; // Send 2x the required fee
        
        // Register with excess ETH
        vm.prank(user);
        registry.registerName{value: REGISTRATION_FEE + excessAmount}(
            "excess",
            0,
            walletAddress,
            abi.encodePacked(userAddr),
            signature,
            0,
            block.timestamp + 30 minutes,
            address(0), // ETH payment
            address(0)  // No referrer
        );
        
        uint256 userBalanceAfter = user.balance;
        
        // User should only lose the registration fee, excess should be refunded
        assertEq(userBalanceBefore - userBalanceAfter, REGISTRATION_FEE, "User should only lose registration fee amount");
    }

    function testInsufficientFeeReverts() public {
        vm.deal(user, 1 ether);
        
        // Try to register with insufficient ETH
        vm.expectRevert(abi.encodeWithSignature("InsufficientFee()"));
        vm.prank(user);
        registry.registerName{value: REGISTRATION_FEE - 1}( // 1 wei short
            "insufficient",
            0,
            abi.encodePacked(user),
            abi.encodePacked(user),
            hex"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            0,
            block.timestamp + 30 minutes,
            address(0),
            address(0)
        );
    }

    function testTokenPaymentValidation() public {
        // Set up token
        vm.prank(admin);
        registry.setAllowedToken(address(token), true, 100 ether);
        
        // Try to register with disallowed token
        address fakeToken = address(0x9999999999999999999999999999999999999999);
        vm.expectRevert("Token not allowed");
        vm.prank(user);
        registry.registerName(
            "fake",
            0,
            abi.encodePacked(user),
            abi.encodePacked(user),
            hex"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            0,
            block.timestamp + 30 minutes,
            fakeToken, // Not allowed
            address(0)
        );
        
        // Try to send ETH with token payment - should fail
        vm.expectRevert("No ETH needed for token payment");
        vm.prank(user);
        registry.registerName{value: 1 wei}(
            "mixed",
            0,
            abi.encodePacked(user),
            abi.encodePacked(user),
            hex"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            0,
            block.timestamp + 30 minutes,
            address(token), // Token payment
            address(0)
        );
    }

    // More tests for admin withdrawal, token payments, provider management, pause, and ownership transfer will be added here.
}
