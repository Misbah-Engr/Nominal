// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {SCL_EIP6565} from "../lib/crypto-lib/src/lib/libSCL_EIP6565.sol";

contract NominalRegistry is ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // Chain enumeration
    enum Chain { EVM, SOLANA, SUI, APTOS, NEAR }
    uint8 public constant MAX_CHAINS = 5;
    
    // Chain constants
    uint8 public constant CHAIN_EVM = 0;
    uint8 public constant CHAIN_SOLANA = 1;
    uint8 public constant CHAIN_SUI = 2;
    uint8 public constant CHAIN_APTOS = 3;
    uint8 public constant CHAIN_NEAR = 4;

    // State variables
    address public contractOwner;
    uint256 public ethFee;
    uint256 public ETHreferralFeePercent;
    mapping(string => mapping(uint8 => address)) public nameOf;
    mapping(address => bool) public walletProvider;
    mapping(address => bool) public allowedTokens;
    mapping(address => uint256) public registrationFeeForToken;
    mapping(address => uint256) public referralFeeAmountInToken;
    bool public paused;
    address public pendingOwner;

    // Chain identifiers mapping
    mapping(uint8 => string) public chainIdentifier;

    // Nonce management for replay protection
    mapping(address => uint256) public nonces;

    // EIP-712 domain separator
    bytes32 private DOMAIN_SEPARATOR;
    bytes32 private constant NAME_REGISTRATION_TYPEHASH = keccak256(
        "NameRegistration(string domain,address contract,string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry,string purpose)"
    );

    // Crypto lib interface for non-EVM chains
        // Struct to hold signature data for non-EVM chains
    struct ChainSignature {
        uint8 chain;
        bytes signature;
        bytes publicKey;
        bytes walletAddress;
        uint256 nonce;
        uint256 expiry;
    }

    // Address derivation functions (chain-specific)
    function _deriveAddressFromPublicKey(uint8 chain, bytes memory publicKey) internal pure returns (bytes memory) {
        if (chain == uint8(Chain.SOLANA)) {
            // For Solana, the address is the public key itself (32 bytes base58 encoded)
            require(publicKey.length == 32, "Invalid Solana public key length");
            return publicKey;
        } else if (chain == uint8(Chain.SUI)) {
            // For Sui, address is derived from public key + flag
            require(publicKey.length == 32, "Invalid Sui public key length");
            return abi.encodePacked(keccak256(abi.encodePacked(publicKey, uint8(0x00))));
        } else if (chain == uint8(Chain.APTOS)) {
            // For Aptos, address is derived from public key + scheme identifier
            require(publicKey.length == 32, "Invalid Aptos public key length");
            return abi.encodePacked(keccak256(abi.encodePacked(publicKey, uint8(0x00))));
        } else if (chain == uint8(Chain.NEAR)) {
            // For Near, the address is the public key itself (account ID)
            return publicKey;
        }
        revert("Unsupported chain for address derivation");
    }

    // Events
    event NameRegistered(address indexed registrar, string name, uint8[] chains, address[] addresses);
    event NameReleased(address indexed owner, string name, uint8 chain, address indexed wallet);
    event OwnerTransferRequested(address indexed currentOwner, address indexed pendingOwner);
    event OwnerTransferAccepted(address indexed oldOwner, address indexed newOwner);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Not owner");
        _;
    }

    modifier onlyWalletProvider() {
        require(walletProvider[msg.sender], "Not wallet provider");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    constructor() {
        contractOwner = msg.sender;
        
        // Initialize chain identifiers
        chainIdentifier[uint8(Chain.EVM)] = "EVM";
        chainIdentifier[uint8(Chain.SOLANA)] = "SOLANA";
        chainIdentifier[uint8(Chain.SUI)] = "SUI";
        chainIdentifier[uint8(Chain.APTOS)] = "APTOS";
        chainIdentifier[uint8(Chain.NEAR)] = "NEAR";

        // Setup EIP-712 domain separator
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Nominal Registry"),
            keccak256("v1"),
            block.chainid,
            address(this)
        ));
    }

    // Owner transfer flow
    function requestOwnerTransfer(address _pendingOwner) external onlyOwner {
        require(_pendingOwner != address(0), "Invalid pending owner");
        pendingOwner = _pendingOwner;
        emit OwnerTransferRequested(contractOwner, _pendingOwner);
    }

    function acceptOwner() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        address oldOwner = contractOwner;
        contractOwner = pendingOwner;
        pendingOwner = address(0);
        emit OwnerTransferAccepted(oldOwner, contractOwner);
    }

    // Pausability
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // Admin functions
    function setEthFee(uint256 _fee) external onlyOwner {
        ethFee = _fee;
    }

    function setETHReferralFeePercent(uint256 _percent) external onlyOwner {
        require(_percent <= 100, "Invalid percent");
        ETHreferralFeePercent = _percent;
    }

    function setWalletProvider(address _provider, bool _allowed) external onlyOwner {
        walletProvider[_provider] = _allowed;
    }

    function setAllowedToken(address _token, bool _allowed) external onlyOwner {
        allowedTokens[_token] = _allowed;
    }

    function setRegistrationFeeForToken(address _token, uint256 _fee) external onlyOwner {
        registrationFeeForToken[_token] = _fee;
    }

    function setReferralFeeAmountInToken(address _token, uint256 _amount) external onlyOwner {
        referralFeeAmountInToken[_token] = _amount;
    }

    // Utility functions
    function getUserAddress(string memory name, uint8 chain) external view returns (address) {
        string memory normalizedName = _normalizeName(name);
        return nameOf[normalizedName][chain];
    }

    function getChainIdentifier(uint8 chain) external view returns (string memory) {
        return chainIdentifier[chain];
    }

    /**
     * @dev Check if a name is available on a specific chain
     * @param name The name to check (will be normalized to lowercase)
     * @param chain The chain ID to check availability on
     * @return available True if the name is available, false if taken
     */
    function isNameAvailable(string memory name, uint8 chain) external view returns (bool available) {
        require(chain < MAX_CHAINS, "Invalid chain");
        string memory normalizedName = _normalizeName(name);
        return nameOf[normalizedName][chain] == address(0);
    }

    /**
     * @dev Check if a name is available on multiple chains
     * @param name The name to check (will be normalized to lowercase)  
     * @param chains Array of chain IDs to check availability on
     * @return available True if the name is available on ALL specified chains, false otherwise
     * @return unavailableChains Array of chain IDs where the name is NOT available
     */
    function isNameAvailableOnChains(string memory name, uint8[] memory chains) 
        external view returns (bool available, uint8[] memory unavailableChains) {
        string memory normalizedName = _normalizeName(name);
        
        // First pass: count unavailable chains
        uint256 unavailableCount = 0;
        for (uint256 i = 0; i < chains.length; i++) {
            require(chains[i] < MAX_CHAINS, "Invalid chain");
            if (nameOf[normalizedName][chains[i]] != address(0)) {
                unavailableCount++;
            }
        }
        
        // If all chains are available
        if (unavailableCount == 0) {
            return (true, new uint8[](0));
        }
        
        // Second pass: collect unavailable chains
        unavailableChains = new uint8[](unavailableCount);
        uint256 index = 0;
        for (uint256 i = 0; i < chains.length; i++) {
            if (nameOf[normalizedName][chains[i]] != address(0)) {
                unavailableChains[index] = chains[i];
                index++;
            }
        }
        
        return (false, unavailableChains);
    }

    /**
     * @dev Get the current owner of a name on all chains
     * @param name The name to check (will be normalized to lowercase)
     * @return owners Array of addresses owning the name on each chain (address(0) if not registered)
     *               Index 0 = EVM, 1 = SOLANA, 2 = SUI, 3 = APTOS, 4 = NEAR
     */
    function getNameOwners(string memory name) external view returns (address[MAX_CHAINS] memory owners) {
        string memory normalizedName = _normalizeName(name);
        for (uint8 i = 0; i < MAX_CHAINS; i++) {
            owners[i] = nameOf[normalizedName][i];
        }
    }

    /**
     * @dev Check name availability status across all chains
     * @param name The name to check (will be normalized to lowercase)
     * @return availability Array of booleans indicating availability on each chain
     *                      Index 0 = EVM, 1 = SOLANA, 2 = SUI, 3 = APTOS, 4 = NEAR
     * @return totalAvailable Total number of chains where the name is available
     */
    function getNameAvailabilityStatus(string memory name) 
        external view returns (bool[MAX_CHAINS] memory availability, uint256 totalAvailable) {
        string memory normalizedName = _normalizeName(name);
        totalAvailable = 0;
        
        for (uint8 i = 0; i < MAX_CHAINS; i++) {
            availability[i] = (nameOf[normalizedName][i] == address(0));
            if (availability[i]) {
                totalAvailable++;
            }
        }
    }

    // Name normalization - convert to lowercase and validate format
    function _normalizeName(string memory name) internal pure returns (string memory) {
        bytes memory nameBytes = bytes(name);
        require(nameBytes.length > 0, "Empty name");
        require(nameBytes.length <= 32, "Name too long");

        // Convert to lowercase and validate format
        for (uint256 i = 0; i < nameBytes.length; i++) {
            bytes1 char = nameBytes[i];
            
            // Convert uppercase to lowercase
            if (char >= 0x41 && char <= 0x5A) {
                nameBytes[i] = bytes1(uint8(char) + 32);
            }
            // Allow lowercase letters, numbers, and hyphens (but not at start/end)
            else if (!((char >= 0x61 && char <= 0x7A) || // a-z
                      (char >= 0x30 && char <= 0x39) || // 0-9
                      (char == 0x2D && i > 0 && i < nameBytes.length - 1))) { // hyphen only in middle
                revert("Invalid character in name");
            }
        }

        return string(nameBytes);
    }

    // Check if arrays have duplicates
    function _hasDuplicateAddresses(address[] memory addresses) internal pure returns (bool) {
        for (uint256 i = 0; i < addresses.length; i++) {
            for (uint256 j = i + 1; j < addresses.length; j++) {
                if (addresses[i] == addresses[j]) {
                    return true;
                }
            }
        }
        return false;
    }

    // Check if name is available across requested chains
    function _checkNameAvailability(string memory normalizedName, uint8[] memory chains) internal view {
        for (uint256 i = 0; i < chains.length; i++) {
            require(chains[i] < MAX_CHAINS, "Invalid chain");
            require(nameOf[normalizedName][chains[i]] == address(0), "Name already taken on chain");
        }
    }

    // Verify EVM wallet signature
    function _verifyEVMWallet(
        address walletAddress,
        bytes memory signature,
        string memory name,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (bool) {
        require(block.timestamp <= expiry, "Signature expired");
        require(nonce == nonces[walletAddress], "Invalid nonce");

        bytes32 structHash = keccak256(abi.encode(
            NAME_REGISTRATION_TYPEHASH,
            keccak256("Nominal Registry-v1"),
            address(this),
            keccak256(bytes(name)),
            uint8(Chain.EVM),
            abi.encode(walletAddress),
            nonce,
            expiry,
            keccak256("bind-name")
        ));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = hash.recover(signature);
        return recovered == walletAddress;
    }

    // Create canonical message for non-EVM chains
    function _createCanonicalMessage(
        string memory name,
        uint8 chain,
        bytes memory walletAddress,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            "Nominal Registry-v1",
            address(this),
            name,
            chain,
            walletAddress,
            nonce,
            expiry,
            "bind-name"
        );
    }

        // Verify Solana wallet signature  
    function _verifySolWallet(
        bytes memory walletAddress,
        bytes memory signature,
        bytes memory publicKey,
        string memory name,
        uint256 nonce,
        uint256 expiry,
        address signerAddress
    ) internal view returns (bool) {
        require(block.timestamp <= expiry, "Signature expired");
        require(nonce == nonces[signerAddress], "Invalid nonce");
        require(walletAddress.length == 32, "Invalid Solana address length");
        require(signature.length == 64, "Invalid Solana signature length");
        require(publicKey.length == 32, "Invalid Solana public key length");

        // Verify the provided public key corresponds to the wallet address
        bytes memory derivedAddress = _deriveAddressFromPublicKey(CHAIN_SOLANA, publicKey);
        require(keccak256(derivedAddress) == keccak256(walletAddress), "Public key does not match address");

        bytes memory message = _createCanonicalMessage(name, CHAIN_SOLANA, walletAddress, nonce, expiry);
        
        // Extract r and s from 64-byte signature
        require(signature.length == 64, "Invalid signature length");
        uint256 r;
        uint256 s;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        
        // Convert 32-byte public key to extended format for Ed25519
        // extKpub = [x, y, x2p128, y2p128, compressed]
        uint256 pubX = uint256(bytes32(publicKey));
        uint256[5] memory extKpub;
        extKpub[0] = pubX;
        extKpub[1] = 0; // Will be derived from compressed form
        extKpub[2] = 0; // Precomputed value
        extKpub[3] = 0; // Precomputed value  
        extKpub[4] = pubX; // Compressed form
        
        // Use crypto-lib Ed25519 verification
        return SCL_EIP6565.Verify(string(message), r, s, extKpub);
    }

    // Verify SUI wallet signature
    function _verifySUIWallet(
        bytes memory walletAddress,
        bytes memory signature,
        bytes memory publicKey,
        string memory name,
        uint256 nonce,
        uint256 expiry,
        address signerAddress
    ) internal view returns (bool) {
        require(block.timestamp <= expiry, "Signature expired");
        require(nonce == nonces[signerAddress], "Invalid nonce");
        require(walletAddress.length == 32, "Invalid SUI address length");
        require(publicKey.length == 32, "Invalid SUI public key length");

        // Verify the provided public key corresponds to the wallet address
        bytes memory derivedAddress = _deriveAddressFromPublicKey(CHAIN_SUI, publicKey);
        require(keccak256(derivedAddress) == keccak256(walletAddress), "Public key does not match address");

        bytes memory message = _createCanonicalMessage(name, CHAIN_SUI, walletAddress, nonce, expiry);
        
        // Extract r and s from signature
        require(signature.length == 64, "Invalid SUI signature length");
        uint256 r;
        uint256 s;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        
        // Convert public key to extended format for Ed25519
        uint256 pubX = uint256(bytes32(publicKey));
        uint256[5] memory extKpub;
        extKpub[0] = pubX;
        extKpub[1] = 0;
        extKpub[2] = 0;
        extKpub[3] = 0;
        extKpub[4] = pubX;
        
        // Use crypto-lib Ed25519 verification
        return SCL_EIP6565.Verify(string(message), r, s, extKpub);
    }

        // Verify Aptos wallet signature
    function _verifyAptosWallet(
        bytes memory walletAddress,
        bytes memory signature,
        bytes memory publicKey,
        string memory name,
        uint256 nonce,
        uint256 expiry,
        address signerAddress
    ) internal view returns (bool) {
        require(block.timestamp <= expiry, "Signature expired");
        require(nonce == nonces[signerAddress], "Invalid nonce");
        require(walletAddress.length == 32, "Invalid Aptos address length");
        require(publicKey.length == 32, "Invalid Aptos public key length");

        // Verify the provided public key corresponds to the wallet address
        bytes memory derivedAddress = _deriveAddressFromPublicKey(CHAIN_APTOS, publicKey);
        require(keccak256(derivedAddress) == keccak256(walletAddress), "Public key does not match address");

        bytes memory message = _createCanonicalMessage(name, CHAIN_APTOS, walletAddress, nonce, expiry);
        
        // Extract r and s from signature
        require(signature.length == 64, "Invalid Aptos signature length");
        uint256 r;
        uint256 s;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        
        // Convert public key to extended format for Ed25519
        uint256 pubX = uint256(bytes32(publicKey));
        uint256[5] memory extKpub;
        extKpub[0] = pubX;
        extKpub[1] = 0;
        extKpub[2] = 0;
        extKpub[3] = 0;
        extKpub[4] = pubX;
        
        // Use crypto-lib Ed25519 verification
        return SCL_EIP6565.Verify(string(message), r, s, extKpub);
    }

    // Verify Near wallet signature
    function _verifyNearWallet(
        bytes memory walletAddress,
        bytes memory signature,
        bytes memory publicKey,
        string memory name,
        uint256 nonce,
        uint256 expiry,
        address signerAddress
    ) internal view returns (bool) {
        require(block.timestamp <= expiry, "Signature expired");
        require(nonce == nonces[signerAddress], "Invalid nonce");
        require(publicKey.length == 32, "Invalid Near public key length");

        // Verify the provided public key corresponds to the wallet address
        bytes memory derivedAddress = _deriveAddressFromPublicKey(uint8(Chain.NEAR), publicKey);
        require(keccak256(derivedAddress) == keccak256(walletAddress), "Public key does not match address");

        bytes memory message = _createCanonicalMessage(name, uint8(Chain.NEAR), walletAddress, nonce, expiry);
        
        // Near uses Ed25519, so we use the same verification
        require(signature.length == 64, "Invalid Ed25519 signature length");
        uint256 r;
        uint256 s;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        
        uint256 pubKeyX;
        assembly {
            pubKeyX := mload(add(publicKey, 0x20))
        }
        uint256[5] memory extKpub = [pubKeyX, 0, 0, 0, pubKeyX];
        
        return SCL_EIP6565.Verify(string(message), r, s, extKpub);
    }

    // Handle fee collection
    function _collectFee(address tokenToPay) internal {
        if (tokenToPay == address(0)) {
            // ETH payment
            require(msg.value >= ethFee, "Insufficient ETH fee");
            
            // Refund excess
            if (msg.value > ethFee) {
                (bool success, ) = msg.sender.call{value: msg.value - ethFee}("");
                require(success, "ETH refund failed");
            }
        } else {
            // ERC20 token payment
            require(allowedTokens[tokenToPay], "Token not allowed");
            uint256 fee = registrationFeeForToken[tokenToPay];
            require(fee > 0, "Fee not set for token");
            
            IERC20(tokenToPay).safeTransferFrom(msg.sender, address(this), fee);
        }
    }

    // Pay referral fee to wallet provider
    function _payReferralFee(address tokenToPay, address provider) internal {
        if (tokenToPay == address(0)) {
            // ETH referral
            uint256 referralAmount = (ethFee * ETHreferralFeePercent) / 100;
            if (referralAmount > 0) {
                (bool success, ) = provider.call{value: referralAmount}("");
                require(success, "ETH referral payment failed");
            }
        } else {
            // ERC20 referral
            uint256 referralAmount = referralFeeAmountInToken[tokenToPay];
            if (referralAmount > 0) {
                IERC20(tokenToPay).safeTransfer(provider, referralAmount);
            }
        }
    }

    // Self-registration flow
    function registerName(
        string memory name,
        bytes[] memory signaturesForOtherChains,
        bytes[] memory publicKeysForOtherChains,
        bytes[] memory otherChainAddresses,
        uint8[] memory otherChains,
        uint256[] memory noncesForOtherChains,
        uint256[] memory expiriesForOtherChains,
        address tokenToPay
    ) external payable nonReentrant whenNotPaused {
        // Normalize name
        string memory normalizedName = _normalizeName(name);
        
        // Validate input arrays
        require(
            signaturesForOtherChains.length == publicKeysForOtherChains.length &&
            publicKeysForOtherChains.length == otherChainAddresses.length &&
            otherChainAddresses.length == otherChains.length &&
            otherChains.length == noncesForOtherChains.length &&
            noncesForOtherChains.length == expiriesForOtherChains.length,
            "Array length mismatch"
        );

        // Create full arrays including EVM
        uint8[] memory allChains = new uint8[](otherChains.length + 1);
        address[] memory allAddresses = new address[](otherChains.length + 1);
        
        allChains[0] = uint8(Chain.EVM);
        allAddresses[0] = msg.sender;
        
        for (uint256 i = 0; i < otherChains.length; i++) {
            allChains[i + 1] = otherChains[i];
            // Convert bytes to address for storage (simplified for EVM compatibility)
            allAddresses[i + 1] = address(uint160(uint256(keccak256(otherChainAddresses[i]))));
        }

        // Check for duplicates
        require(!_hasDuplicateAddresses(allAddresses), "Duplicate addresses");

        // Check name availability
        _checkNameAvailability(normalizedName, allChains);

        // Verify signatures for other chains
        for (uint256 i = 0; i < otherChains.length; i++) {
            bool verified = false;
            
            if (otherChains[i] == uint8(Chain.SOLANA)) {
                verified = _verifySolWallet(
                    otherChainAddresses[i],
                    signaturesForOtherChains[i],
                    publicKeysForOtherChains[i],
                    normalizedName,
                    noncesForOtherChains[i],
                    expiriesForOtherChains[i],
                    allAddresses[i + 1]
                );
            } else if (otherChains[i] == uint8(Chain.SUI)) {
                verified = _verifySUIWallet(
                    otherChainAddresses[i],
                    signaturesForOtherChains[i],
                    publicKeysForOtherChains[i],
                    normalizedName,
                    noncesForOtherChains[i],
                    expiriesForOtherChains[i],
                    allAddresses[i + 1]
                );
            } else if (otherChains[i] == uint8(Chain.APTOS)) {
                verified = _verifyAptosWallet(
                    otherChainAddresses[i],
                    signaturesForOtherChains[i],
                    publicKeysForOtherChains[i],
                    normalizedName,
                    noncesForOtherChains[i],
                    expiriesForOtherChains[i],
                    allAddresses[i + 1]
                );
            } else if (otherChains[i] == uint8(Chain.NEAR)) {
                verified = _verifyNearWallet(
                    otherChainAddresses[i],
                    signaturesForOtherChains[i],
                    publicKeysForOtherChains[i],
                    normalizedName,
                    noncesForOtherChains[i],
                    expiriesForOtherChains[i],
                    allAddresses[i + 1]
                );
            }
            
            require(verified, "Invalid signature for chain");
        }

        // Collect fee
        _collectFee(tokenToPay);

        // Update nonces for all addresses
        nonces[msg.sender]++;
        for (uint256 i = 0; i < allAddresses.length - 1; i++) {
            nonces[allAddresses[i + 1]]++;
        }

        // Set name mappings (Effects)
        for (uint256 i = 0; i < allChains.length; i++) {
            nameOf[normalizedName][allChains[i]] = allAddresses[i];
        }

        // Emit event (Interactions)
        emit NameRegistered(msg.sender, normalizedName, allChains, allAddresses);
    }

    // Wallet provider registration flow
    function registerForSomeone(
        string memory name,
        bytes[] memory signatures,
        bytes[] memory publicKeys,
        bytes[] memory addresses,
        uint8[] memory chains,
        uint256[] memory noncesForChains,
        uint256[] memory expiriesForChains,
        address tokenToPay
    ) external payable onlyWalletProvider nonReentrant whenNotPaused {
        // Normalize name
        string memory normalizedName = _normalizeName(name);
        
        // Validate input arrays
        require(
            signatures.length == publicKeys.length &&
            publicKeys.length == addresses.length &&
            addresses.length == chains.length &&
            chains.length == noncesForChains.length &&
            noncesForChains.length == expiriesForChains.length,
            "Array length mismatch"
        );
        require(signatures.length > 0, "Empty arrays");

        // Convert bytes addresses to address array for duplicate checking
        address[] memory addressesForDuplicateCheck = new address[](addresses.length);
        for (uint256 i = 0; i < addresses.length; i++) {
            addressesForDuplicateCheck[i] = address(uint160(uint256(keccak256(addresses[i]))));
        }

        // Check for duplicates
        require(!_hasDuplicateAddresses(addressesForDuplicateCheck), "Duplicate addresses");

        // Check name availability
        _checkNameAvailability(normalizedName, chains);

        // Verify all signatures
        for (uint256 i = 0; i < chains.length; i++) {
            bool verified = false;
            
            if (chains[i] == uint8(Chain.EVM)) {
                address evmAddress = address(uint160(bytes20(addresses[i])));
                verified = _verifyEVMWallet(
                    evmAddress,
                    signatures[i],
                    normalizedName,
                    noncesForChains[i],
                    expiriesForChains[i]
                );
            } else if (chains[i] == uint8(Chain.SOLANA)) {
                verified = _verifySolWallet(
                    addresses[i],
                    signatures[i],
                    publicKeys[i],
                    normalizedName,
                    noncesForChains[i],
                    expiriesForChains[i],
                    addressesForDuplicateCheck[i]
                );
            } else if (chains[i] == uint8(Chain.SUI)) {
                verified = _verifySUIWallet(
                    addresses[i],
                    signatures[i],
                    publicKeys[i],
                    normalizedName,
                    noncesForChains[i],
                    expiriesForChains[i],
                    addressesForDuplicateCheck[i]
                );
            } else if (chains[i] == uint8(Chain.APTOS)) {
                verified = _verifyAptosWallet(
                    addresses[i],
                    signatures[i],
                    publicKeys[i],
                    normalizedName,
                    noncesForChains[i],
                    expiriesForChains[i],
                    addressesForDuplicateCheck[i]
                );
            } else if (chains[i] == uint8(Chain.NEAR)) {
                verified = _verifyNearWallet(
                    addresses[i],
                    signatures[i],
                    publicKeys[i],
                    normalizedName,
                    noncesForChains[i],
                    expiriesForChains[i],
                    addressesForDuplicateCheck[i]
                );
            }
            
            require(verified, "Invalid signature for chain");
        }

        // Collect fee
        _collectFee(tokenToPay);

        // Pay referral fee
        _payReferralFee(tokenToPay, msg.sender);

        // Update nonces
        for (uint256 i = 0; i < addressesForDuplicateCheck.length; i++) {
            nonces[addressesForDuplicateCheck[i]]++;
        }

        // Set name mappings (Effects)
        for (uint256 i = 0; i < chains.length; i++) {
            nameOf[normalizedName][chains[i]] = addressesForDuplicateCheck[i];
        }

        // Emit event (Interactions)
        emit NameRegistered(msg.sender, normalizedName, chains, addressesForDuplicateCheck);
    }

    // Release name (optional functionality)
    function releaseName(string memory name, uint8 chain) external whenNotPaused {
        string memory normalizedName = _normalizeName(name);
        address currentOwner = nameOf[normalizedName][chain];
        require(currentOwner == msg.sender, "Not owner of name");
        
        nameOf[normalizedName][chain] = address(0);
        emit NameReleased(msg.sender, normalizedName, chain, currentOwner);
    }

    // Withdraw functions for owner
    function withdrawETH(uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "Insufficient balance");
        (bool success, ) = contractOwner.call{value: amount}("");
        require(success, "ETH withdrawal failed");
    }

    function withdrawToken(address token, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(contractOwner, amount);
    }
}
