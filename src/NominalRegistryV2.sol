// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {SCL_EIP6565} from "../lib/crypto-lib/src/lib/libSCL_EIP6565.sol";
import {SCL_sha512} from "../lib/crypto-lib/src/hash/SCL_sha512.sol";
import {ModInv} from "../lib/crypto-lib/src/modular/SCL_modular.sol";
import {SqrtMod} from "../lib/crypto-lib/src/modular/SCL_sqrtMod_5mod8.sol";
import {p, n, d} from "../lib/crypto-lib/src/fields/SCL_wei25519.sol";

/**
 * @title NominalRegistryV2
 * @notice A multi-chain naming registry with cryptographic verification for wallet ownership
 */
contract NominalRegistryV2 is ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    enum Chain { EVM, SOLANA, SUI, APTOS }
    uint8 public constant MAX_CHAINS = 4;

    enum SignatureFormat { UTF8 }
    uint8 public constant CHAIN_EVM    = 0;
    uint8 public constant CHAIN_SOLANA = 1;
    uint8 public constant CHAIN_SUI    = 2;
    uint8 public constant CHAIN_APTOS  = 3;

    // Sui multi-scheme support
    uint8 private constant SUI_FLAG_ED25519 = 0x00;
    uint8 private constant SUI_FLAG_K1      = 0x01;
    uint8 private constant SUI_FLAG_R1      = 0x02;

    address public contractOwner;
    uint256 public ethFee;
    bool public paused;
    address public pendingOwner;

    // For Aptos, wallets must convert public key to wallet address off-chain
    mapping(string => mapping(uint8 => bytes)) public nameToChainAddress;
    mapping(bytes32 => string) public addressToName;

    mapping(string => address) public nameToEvmAddress;
    mapping(address => string) public evmAddressToName;

    // Nonces keyed by canonical identity (EVM: 20B addr; Solana: 32B pubkey; Sui: 32B addr; Aptos: 32B pubkey)
    mapping(uint8 => mapping(bytes => uint256)) public chainNonces;

    mapping(address => bool) public authorizedWalletProviders;
    mapping(address => uint256) public walletProviderReferralFee; // bps

    uint256 public registrationFee;
    mapping(address => bool) public allowedTokens;
    mapping(address => uint256) public tokenFees;

    bytes32 private DOMAIN_SEPARATOR;
    bytes32 private constant REGISTRATION_TYPEHASH = keccak256(
        "Registration(string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry)"
    );

    event NameRegistered(string indexed name, uint8 indexed chainId, bytes walletAddress, address indexed registrant);

    error InvalidChain();
    error InvalidSignature();
    error NameNotAvailable();
    error Unauthorized();
    error InsufficientFee();
    error ExpiredSignature();
    error InvalidNonce();
    error Paused();
    error InvalidAddress();
    error InvalidName();

    modifier onlyOwner() {
        if (msg.sender != contractOwner) revert Unauthorized();
        _;
    }
    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }
    modifier validChain(uint8 chainId) {
        if (chainId >= MAX_CHAINS) revert InvalidChain();
        _;
    }

    constructor(uint256 _ethFee) {
        contractOwner = msg.sender;
        ethFee = _ethFee;
        registrationFee = _ethFee;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("NominalRegistryV2"),
                keccak256("2"),
                block.chainid,
                address(this)
            )
        );
    }

    function getDomainSeparator() external view returns (bytes32) { return DOMAIN_SEPARATOR; }

    // Core

    function registerName(
        string memory name,
        uint8 chainId,
        bytes memory walletAddress,
        bytes memory publicKey,
        bytes memory signature,
        uint256 nonceVal,
        uint256 expiry,
        address paymentToken,
        address referrer
    ) external payable whenNotPaused validChain(chainId) nonReentrant {
    
        name = _normalizeNameStrict(name);

        _validateRegistrationInput(name, walletAddress, expiry);
        if (nameToChainAddress[name][chainId].length > 0) revert NameNotAvailable();

        _processPayment(paymentToken, referrer);

        // Constrain stack by scoping temps
        bytes memory canonical;
        {
            canonical = _canonicalAccountBytesOrRevert(chainId, walletAddress, publicKey);
            _verifySignatureAndNonce(name, chainId, walletAddress, publicKey, signature, nonceVal, expiry, canonical);
            _storeRegistrationCanonical(name, chainId, walletAddress, canonical);
        }

        // Emit after temp scope is gone
        emit NameRegistered(name, chainId, nameToChainAddress[name][chainId], msg.sender);
    }

    function _validateRegistrationInput(
        string memory name,
        bytes memory walletAddress,
        uint256 expiry
    ) internal view {
        if (bytes(name).length == 0 || bytes(name).length > 64) revert InvalidName();
        if (walletAddress.length == 0) revert InvalidAddress();
        if (expiry <= block.timestamp) revert ExpiredSignature();
        if (expiry > block.timestamp + 5 hours) revert ExpiredSignature();
    }

    // Payments

    function _processPayment(address paymentToken, address referrer) internal {
        if (paymentToken == address(0)) {
            if (msg.value < registrationFee) revert InsufficientFee();
            _calculateAndPayReferral(referrer, registrationFee, true);
            if (msg.value > registrationFee) {
                (bool ok, ) = payable(msg.sender).call{value: (msg.value - registrationFee)}("");
                require(ok, "ETH refund failed");
            }
        } else {
            if (!allowedTokens[paymentToken]) revert("Token not allowed");
            if (msg.value > 0) revert("No ETH needed for token payment");
            uint256 fee = tokenFees[paymentToken];
            if (fee == 0) revert("Token fee not set");
            uint256 r = _calculateReferralAmount(referrer, fee);
            if (r > 0) {
                IERC20(paymentToken).safeTransferFrom(msg.sender, referrer, r);
                IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), fee - r);
            } else {
                IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), fee);
            }
        }
    }

    function _calculateAndPayReferral(address referrer, uint256 totalFee, bool isETH) internal returns (uint256 r) {
        if (referrer == address(0) || !authorizedWalletProviders[referrer]) return 0;
        uint256 bps = walletProviderReferralFee[referrer];
        if (bps == 0) return 0;
        r = (totalFee * bps) / 10000;
        if (r > 0 && isETH) {
            (bool ok, ) = payable(referrer).call{value: r}("");
            require(ok, "ETH referral failed");
        }
    }

    function _calculateReferralAmount(address referrer, uint256 totalFee) internal view returns (uint256) {
        if (referrer == address(0) || !authorizedWalletProviders[referrer]) return 0;
        uint256 bps = walletProviderReferralFee[referrer];
        if (bps == 0) return 0;
        return (totalFee * bps) / 10000;
    }

    function _verifySignatureAndNonce(
        string memory name,
        uint8 chainId,
        bytes memory walletAddress,
        bytes memory publicKey,
        bytes memory signature,
        uint256 nonceVal,
        uint256 expiry,
        bytes memory canonical
    ) internal {
        if (chainId == CHAIN_EVM) {
            _verifyEVMSignature(name, chainId, walletAddress, nonceVal, expiry, signature);
        } else if (chainId == CHAIN_SUI) {
            _verifySuiMultiScheme(name, chainId, canonical, publicKey, signature, nonceVal, expiry, walletAddress);
        } else if (chainId == CHAIN_APTOS) {
            _verifyAptos(name, chainId, canonical, publicKey, signature, nonceVal, expiry);
        } else {
            // SOLANA (raw Ed25519 over our domain-bound message)
            string memory message = _createDomainBoundMessage(name, chainId, canonical, nonceVal, expiry);
            _verifyEd25519Strict(message, signature, publicKey);
        }
        uint256 expected = chainNonces[chainId][canonical];
        if (nonceVal != expected) revert InvalidNonce();
        chainNonces[chainId][canonical] = expected + 1;
    }

    function _verifyEVMSignature(
        string memory name,
        uint8 chainId,
        bytes memory walletAddress,
        uint256 nonceVal,
        uint256 expiry,
        bytes memory signature
    ) internal view {
        bytes32 structHash = keccak256(
            abi.encode(
                REGISTRATION_TYPEHASH,
                keccak256(bytes(name)),
                chainId,
                keccak256(walletAddress),
                nonceVal,
                expiry
            )
        );
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = hash.recover(signature);
        if (signer != bytesToAddress(walletAddress)) revert InvalidSignature();
    }

    function _verifyEd25519Strict(
        string memory message,
        bytes memory signature,
        bytes memory publicKey
    ) internal returns (bool) {
        if (signature.length != 64 || publicKey.length != 32) revert InvalidSignature();

        // Pass R and S as loaded; lib Verify_LE handles LE semantics internally.
        uint256 r; uint256 s;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        // No Swap256 on r/s, and no numeric S<n check (endianness mismatch).
        
        uint256[5] memory extKpub;
        if (!_setupExtKpubFromCompressedKey(publicKey, extKpub)) revert InvalidSignature();
        if (!SCL_EIP6565.Verify_LE(message, r, s, extKpub)) revert InvalidSignature();
        return true;
    }

    // Non-reverting Ed25519 verifier used for trying alternate encodings (e.g., Sui/Aptos intent messages).
    function _ed25519VerifyNoRevert(
        string memory message,
        bytes memory signature,
        bytes memory publicKey
    ) internal returns (bool) {
        if (signature.length != 64 || publicKey.length != 32) return false;
        uint256 r; uint256 s;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        uint256[5] memory extKpub;
        if (!_setupExtKpubFromCompressedKey(publicKey, extKpub)) return false;
        return SCL_EIP6565.Verify_LE(message, r, s, extKpub);
    }

    function debugGetDomainBoundMessage(
        string memory name,
        uint8 chainId,
        bytes memory canonicalAccount,
        uint256 nonceVal,
        uint256 expiry
    ) external view returns (string memory) {
        return _createDomainBoundMessage(name, chainId, canonicalAccount, nonceVal, expiry);
    }

    function _createDomainBoundMessage(
        string memory name,
        uint8 chainId,
        bytes memory canonicalAccount,
        uint256 nonceVal,
        uint256 expiry
    ) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                "NominalRegistryV2 on ",
                Strings.toString(block.chainid),
                " @ ",
                _addrToHex(address(this)),
                " | name: ",
                name,
                " | chain: ",
                Strings.toString(chainId),
                " | acct: ",
                _bytesToHexString(canonicalAccount),
                " | nonce: ",
                Strings.toString(nonceVal),
                " | exp: ",
                Strings.toString(expiry)
            )
        );
    }

    // ===== Aptos (AIP-62 "fullMessage" support) =====
    function _verifyAptos(
        string memory name,
        uint8 chainId,
        bytes memory canonical,   // 32B ed25519 pubkey (canonical for Aptos)
        bytes memory publicKey,   // 32B ed25519
        bytes memory signature,   // 64B ed25519 (R||S)
        uint256 nonceVal,
        uint256 expiry
    ) internal {
        // Base message we show to users and expose via debugGetDomainBoundMessage
        string memory base = _createDomainBoundMessage(name, chainId, canonical, nonceVal, expiry);

        // 0) Some dev setups may sign raw `base`
        if (_ed25519VerifyNoRevert(base, signature, publicKey)) return;

        // 1) AIP-62 canonical (common): "APTOS\nmessage: <base>\nnonce: <nonce>"
        string memory fm1 = string(
            abi.encodePacked("APTOS\nmessage: ", base, "\nnonce: ", Strings.toString(nonceVal))
        );
        if (_ed25519VerifyNoRevert(fm1, signature, publicKey)) return;

        // 2) Variant: "APTOS\nnonce: <nonce>\nmessage: <base>"
        string memory fm2 = string(
            abi.encodePacked("APTOS\nnonce: ", Strings.toString(nonceVal), "\nmessage: ", base)
        );
        if (_ed25519VerifyNoRevert(fm2, signature, publicKey)) return;

        // 3) Space-separated legacy seen in some adapters
        string memory fm3 = string(
            abi.encodePacked("APTOS nonce: ", Strings.toString(nonceVal), " message: ", base)
        );
        if (_ed25519VerifyNoRevert(fm3, signature, publicKey)) return;

        revert InvalidSignature();
    }

    // ============= Canonical Identity & Storage =============

    function _canonicalAccountBytesOrRevert(
        uint8 chainId,
        bytes memory walletAddress,
        bytes memory publicKey
    ) internal view returns (bytes memory) {
        if (chainId == CHAIN_EVM) {
            if (walletAddress.length != 20) revert InvalidAddress();
            return walletAddress;
        }
        if (chainId == CHAIN_SOLANA) {
            if (publicKey.length != 32 || walletAddress.length != 32) revert InvalidAddress();
            if (keccak256(publicKey) != keccak256(walletAddress)) revert InvalidSignature();
            return publicKey; // canonical = pubkey
        }
        if (chainId == CHAIN_SUI) {
            if (walletAddress.length != 32) revert InvalidAddress();
            // We accept Ed25519 (32B) or secp (64/65B) pubkeys; equality to walletAddress
            // is enforced inside _verifySuiMultiScheme. Canonical for Sui is the 32B address digest.
            return walletAddress;
        }
        if (chainId == CHAIN_APTOS) {
            if (publicKey.length != 32) revert InvalidAddress();
            return publicKey; // canonical = pubkey
        }
        revert InvalidChain();
    }

    function _storeRegistration(
        string memory name,
        uint8 chainId,
        bytes memory walletAddress
    ) internal {
        nameToChainAddress[name][chainId] = walletAddress;
        addressToName[keccak256(abi.encodePacked(chainId, walletAddress))] = name;
        if (chainId == CHAIN_EVM) {
            address evmAddr = bytesToAddress(walletAddress);
            nameToEvmAddress[name] = evmAddr;
            evmAddressToName[evmAddr] = name;
        }
    }

    function _storeRegistrationCanonical(
        string memory name,
        uint8 chainId,
        bytes memory walletAddress,
        bytes memory canonical
    ) internal {
        if (chainId == CHAIN_APTOS || chainId == CHAIN_SUI) {
            nameToChainAddress[name][chainId] = canonical;
            addressToName[keccak256(abi.encodePacked(chainId, canonical))] = name;
            if (chainId == CHAIN_EVM) { /* none */ }
        } else {
            _storeRegistration(name, chainId, walletAddress);
        }
    }

    // Ed25519 Key Utils
    function _setupExtKpubFromCompressedKey(
        bytes memory publicKey,
        uint256[5] memory extKpub
    ) internal returns (bool) {
        if (publicKey.length != 32) return false;
        uint256 compressedKey = uint256(bytes32(publicKey));
        uint256 compressedKeyLE = SCL_sha512.Swap256(compressedKey);
        (uint256 edX, uint256 edY) = _decompressEd25519Point(compressedKeyLE);
        (extKpub[0], extKpub[1]) = SCL_EIP6565.Edwards2WeierStrass(edX, edY);
        (extKpub[2], extKpub[3]) = SCL_EIP6565.ecPow128(extKpub[0], extKpub[1], 1, 1);
        uint256[2] memory edPoint = [edX, edY];
        uint256 recompressedKey = SCL_EIP6565.edCompress(edPoint);
        extKpub[4] = SCL_sha512.Swap256(recompressedKey);
        return true;
    }

    function _decompressEd25519Point(uint256 compressedKey) internal returns (uint256 x, uint256 y) {
        uint256 sign = (compressedKey >> 255) & 1;
        y = compressedKey & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        if (y >= p) revert InvalidSignature();

        uint256 y2 = mulmod(y, y, p);
        uint256 numerator = addmod(y2, p - 1, p);
        uint256 denominator = addmod(mulmod(d, y2, p), 1, p);
        uint256 denominatorInv = ModInv(denominator, p);
        uint256 x2 = mulmod(numerator, denominatorInv, p);
        x = SqrtMod(x2);
        if ((x & 1) != sign) { x = p - x; }
    }

    // SUI (BLAKE2b-256 via EIP-152)

    function _suiAddressFromPubkey(bytes memory pubkey) internal view returns (bytes32) {
        if (pubkey.length != 32) revert InvalidAddress();
        bytes memory inBuf = new bytes(33);
        inBuf[0] = 0x00; // Ed25519 flag
        // copy 32B pubkey
        for (uint256 i = 0; i < 32; i++) { inBuf[i+1] = pubkey[i]; }
        return _blake2b256_singleBlock(inBuf);
    }

    function _verifySuiMultiScheme(
        string memory name,
        uint8 chainId,
        bytes memory canonical,         // 32B Sui addr digest (already chosen as canonical)
        bytes memory publicKey,         // Ed: 32B; secp: 64/65B uncompressed
        bytes memory signature,         // Ed: 64B (R||S); secp: 64B (r||s)
        uint256 nonceVal,
        uint256 expiry,
        bytes memory providedWalletAddr // 32B address the UI passed
    ) internal {
        string memory message = _createDomainBoundMessage(name, chainId, canonical, nonceVal, expiry);
        // Build message encodings once for Ed25519 path. For secp path we compute inside a helper
        // to reduce stack pressure.
        bytes memory rawBytes = bytes(message);
        bytes memory intentBytes = abi.encodePacked(bytes1(0x00), bytes1(0x00), bytes1(0x00), _bcsVecU8(rawBytes));
        bytes memory simpleIntent = abi.encodePacked(bytes1(0x00), bytes1(0x00), bytes1(0x00), rawBytes);

        // Try Ed25519 first (32B pubkey)
        if (publicKey.length == 32) {
            bytes32 addr = _suiAddressFromEd25519(publicKey);
            if (keccak256(abi.encodePacked(addr)) != keccak256(providedWalletAddr)) revert InvalidSignature();
            // Accept raw, BCS intent-wrapped, or simple intent-wrapped encodings
            if (_ed25519VerifyNoRevert(message, signature, publicKey)) return;
            string memory intentMsg = string(intentBytes);
            if (_ed25519VerifyNoRevert(intentMsg, signature, publicKey)) return;
            string memory simpleIntentMsg = string(simpleIntent);
            if (_ed25519VerifyNoRevert(simpleIntentMsg, signature, publicKey)) return;
            revert InvalidSignature();
        }

        // Secp path is moved into a helper to avoid stack-too-deep while keeping via-ir disabled.
        if (_verifySuiSecp(message, publicKey, signature, providedWalletAddr)) return;
        revert InvalidSignature();
    }

    // Refactored secp verifier for Sui: tries raw, BCS intent, and simple intent encodings
    function _verifySuiSecp(
        string memory message,
        bytes memory publicKey,
        bytes memory signature,
        bytes memory providedWalletAddr
    ) private view returns (bool) {
        (bytes32 Qx, bytes32 Qy, uint8 yParity, bool ok) = _parseSecpUncompressed(publicKey);
        if (!ok) return false;
        bytes memory comp33 = _compressSecpXYTo33(Qx, yParity);

        bytes memory rawBytes = bytes(message);
        bytes memory intentBytes = abi.encodePacked(bytes1(0x00), bytes1(0x00), bytes1(0x00), _bcsVecU8(rawBytes));
        bytes memory simpleIntent = abi.encodePacked(bytes1(0x00), bytes1(0x00), bytes1(0x00), rawBytes);

        bytes32 hRaw = sha256(rawBytes);
        bytes32 hIntent = sha256(intentBytes);
        bytes32 hSimple = sha256(simpleIntent);

        // k1
        if (_verifySecp256k1_ByRecover(hRaw, signature, Qx, Qy)) {
            bytes32 addrK1 = _suiAddressFromFlagAndCompressed(SUI_FLAG_K1, comp33);
            if (keccak256(abi.encodePacked(addrK1)) != keccak256(providedWalletAddr)) return false;
            return true;
        }
        if (_verifySecp256k1_ByRecover(hIntent, signature, Qx, Qy)) {
            bytes32 addrK1b = _suiAddressFromFlagAndCompressed(SUI_FLAG_K1, comp33);
            if (keccak256(abi.encodePacked(addrK1b)) != keccak256(providedWalletAddr)) return false;
            return true;
        }
        if (_verifySecp256k1_ByRecover(hSimple, signature, Qx, Qy)) {
            bytes32 addrK1c = _suiAddressFromFlagAndCompressed(SUI_FLAG_K1, comp33);
            if (keccak256(abi.encodePacked(addrK1c)) != keccak256(providedWalletAddr)) return false;
            return true;
        }

        // r1
        if (_verifyP256_RIP7212(hRaw, signature, Qx, Qy)) {
            bytes32 addrR1 = _suiAddressFromFlagAndCompressed(SUI_FLAG_R1, comp33);
            if (keccak256(abi.encodePacked(addrR1)) != keccak256(providedWalletAddr)) return false;
            return true;
        }
        if (_verifyP256_RIP7212(hIntent, signature, Qx, Qy)) {
            bytes32 addrR1b = _suiAddressFromFlagAndCompressed(SUI_FLAG_R1, comp33);
            if (keccak256(abi.encodePacked(addrR1b)) != keccak256(providedWalletAddr)) return false;
            return true;
        }
        if (_verifyP256_RIP7212(hSimple, signature, Qx, Qy)) {
            bytes32 addrR1c = _suiAddressFromFlagAndCompressed(SUI_FLAG_R1, comp33);
            if (keccak256(abi.encodePacked(addrR1c)) != keccak256(providedWalletAddr)) return false;
            return true;
        }
        return false;
    }

    // ======= Sui IntentMessage helpers (BCS encoding) =======

    // Encodes a uint as BCS ULEB128
    function _bcsUleb128(uint256 v) private pure returns (bytes memory out) {
        // Max 10 bytes for 64-bit values; our messages are much smaller but keep generic.
        bytes memory tmp = new bytes(10);
        uint256 i = 0;
        while (true) {
            uint8 b = uint8(v & 0x7f);
            v >>= 7;
            if (v != 0) { tmp[i] = bytes1(b | 0x80); }
            else { tmp[i] = bytes1(b); break; }
            unchecked { i++; }
        }
        out = new bytes(i + 1);
        for (uint256 j = 0; j <= i; j++) { out[j] = tmp[j]; }
    }

    // Encodes a bytes payload as BCS Vec<u8>: ULEB128(len) || bytes
    function _bcsVecU8(bytes memory b) private pure returns (bytes memory out) {
        bytes memory lenEnc = _bcsUleb128(b.length);
        out = new bytes(lenEnc.length + b.length);
        uint256 o = 0;
        for (uint256 i = 0; i < lenEnc.length; i++) { out[o++] = lenEnc[i]; }
        for (uint256 j = 0; j < b.length; j++) { out[o++] = b[j]; }
    }

    function _suiAddressFromEd25519(bytes memory pub32) private view returns (bytes32) {
        if (pub32.length != 32) revert InvalidAddress();
        bytes memory inBuf = new bytes(33);
        inBuf[0] = bytes1(uint8(SUI_FLAG_ED25519));
        for (uint256 i=0;i<32;i++){ inBuf[i+1]=pub32[i]; }
        return _blake2b256_singleBlock(inBuf);
    }

    function _suiAddressFromFlagAndCompressed(uint8 flag, bytes memory comp33) private view returns (bytes32) {
        if (comp33.length != 33) revert InvalidAddress();
        bytes memory inBuf = new bytes(34);
        inBuf[0] = bytes1(flag);
        for (uint256 i=0;i<33;i++){ inBuf[i+1]=comp33[i]; }
        return _blake2b256_singleBlock(inBuf);
    }

    function _parseSecpUncompressed(bytes memory pubkey) private pure returns (bytes32 Qx, bytes32 Qy, uint8 yParity, bool ok) {
        if (pubkey.length == 65) {
            if (pubkey[0] != 0x04) return (Qx,Qy,0,false);
            assembly {
                Qx := mload(add(pubkey, 0x21))
                Qy := mload(add(pubkey, 0x41))
            }
            yParity = uint8(uint256(Qy) & 1);
            return (Qx,Qy,yParity,true);
        } else if (pubkey.length == 64) {
            assembly {
                Qx := mload(add(pubkey, 0x20))
                Qy := mload(add(pubkey, 0x40))
            }
            yParity = uint8(uint256(Qy) & 1);
            return (Qx,Qy,yParity,true);
        }
        return (Qx,Qy,0,false);
    }

    function _compressSecpXYTo33(bytes32 Qx, uint8 yParity) private pure returns (bytes memory out33) {
        out33 = new bytes(33);
        out33[0] = (yParity == 0) ? bytes1(0x02) : bytes1(0x03);
        assembly { mstore(add(out33, 0x21), Qx) }
    }

    // Verify k1 with ecrecover; bind to pubkey by recomputing the Ethereum addr from 0x04||X||Y
    function _verifySecp256k1_ByRecover(bytes32 h, bytes memory sig64, bytes32 Qx, bytes32 Qy) private pure returns (bool) {
        if (sig64.length != 64) return false;
        bytes32 r; bytes32 s;
        assembly {
            r := mload(add(sig64, 0x20))
            s := mload(add(sig64, 0x40))
        }
        bytes memory uncompressed = new bytes(65);
        uncompressed[0] = 0x04;
        assembly {
            mstore(add(uncompressed, 0x21), Qx)
            mstore(add(uncompressed, 0x41), Qy)
        }

        bytes memory xy = new bytes(64);
        assembly {
            mstore(add(xy, 0x20), Qx)
            mstore(add(xy, 0x40), Qy)
        }
        address expected = address(uint160(uint256(keccak256(xy))));

        bytes memory sig65 = new bytes(65);
        assembly {
            mstore(add(sig65, 0x20), r)
            mstore(add(sig65, 0x40), s)
        }
        sig65[64] = 0x1b;
        if (ECDSA.recover(h, sig65) == expected) return true;
        sig65[64] = 0x1c;
        return (ECDSA.recover(h, sig65) == expected);
    }

    // Verify r1 via RIP-7212 precompile (0x0100). Input: [hash|r|s|Qx|Qy] -> 1 on success
    function _verifyP256_RIP7212(bytes32 h, bytes memory sig64, bytes32 Qx, bytes32 Qy) private view returns (bool ok) {
        if (sig64.length != 64) return false;
        bytes32 r; bytes32 s;
        assembly {
            r := mload(add(sig64, 0x20))
            s := mload(add(sig64, 0x40))
        }
        bytes memory input = new bytes(160);
        assembly {
            mstore(add(input, 0x20), h)
            mstore(add(input, 0x40), r)
            mstore(add(input, 0x60), s)
            mstore(add(input, 0x80), Qx)
            mstore(add(input, 0xa0), Qy)
        }
        bytes32 out;
        bool success;
        assembly {
            success := staticcall(gas(), 0x0100, add(input, 0x20), 160, out, 0x20)
        }
        return (success && out == bytes32(uint256(1)));
    }

    // Computes blake2b-256 over input (<=128 bytes) in one block with f=true.
    function _blake2b256_singleBlock(bytes memory input) internal view returns (bytes32 out32) {
        if (input.length > 128) revert InvalidAddress();

        // IV (8 * u64)
        uint64[8] memory IV = [
            uint64(0x6a09e667f3bcc908), uint64(0xbb67ae8584caa73b),
            uint64(0x3c6ef372fe94f82b), uint64(0xa54ff53a5f1d36f1),
            uint64(0x510e527fade682d1), uint64(0x9b05688c2b3e6c1f),
            uint64(0x1f83d9abfb41bd6b), uint64(0x5be0cd19137e2179)
        ];

        // h state with param block for digestLen=32, fanout=1, depth=1 -> xor 0x01010020 into h0 (LE)
        uint64[8] memory hState;
        hState[0] = IV[0] ^ uint64(0x01010020);
        hState[1] = IV[1]; hState[2] = IV[2]; hState[3] = IV[3];
        hState[4] = IV[4]; hState[5] = IV[5]; hState[6] = IV[6]; hState[7] = IV[7];

        // Build precompile payload (213 bytes)
        bytes memory payload = new bytes(4 + 64 + 128 + 8 + 8 + 1);
        uint256 o = 0;

        _storeU32BE(payload, o, 12); o += 4; // rounds

        for (uint256 i = 0; i < 8; i++) { _storeU64LE(payload, o, hState[i]); o += 8; }

        // message block (128B)
        for (uint256 j = 0; j < 128; j++) {
            payload[o + j] = (j < input.length) ? input[j] : bytes1(0);
        }
        o += 128;

        _storeU64LE(payload, o, uint64(input.length)); o += 8; // t0
        _storeU64LE(payload, o, 0);                     o += 8; // t1
        payload[o] = 0x01; // f=true

        bytes32[2] memory outState;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x09, add(payload, 0x20), mload(payload), outState, 0x40)
        }
        require(ok, "blake2b precompile failed");
        out32 = outState[0]; // digest = first 32B (LE) of final state
    }

    function _storeU32BE(bytes memory buf, uint256 off, uint32 v) private pure {
        buf[off+0] = bytes1(uint8(v >> 24));
        buf[off+1] = bytes1(uint8(v >> 16));
        buf[off+2] = bytes1(uint8(v >> 8));
        buf[off+3] = bytes1(uint8(v));
    }

    function _storeU64LE(bytes memory buf, uint256 off, uint64 v) private pure {
        buf[off+0] = bytes1(uint8(v));
        buf[off+1] = bytes1(uint8(v >> 8));
        buf[off+2] = bytes1(uint8(v >> 16));
        buf[off+3] = bytes1(uint8(v >> 24));
        buf[off+4] = bytes1(uint8(v >> 32));
        buf[off+5] = bytes1(uint8(v >> 40));
        buf[off+6] = bytes1(uint8(v >> 48));
        buf[off+7] = bytes1(uint8(v >> 56));
    }

    // Views 

    function getNameOwner(string memory name, uint8 chainId) external view returns (bytes memory) {
        return nameToChainAddress[_normalizeNameView(name)][chainId];
    }

    function resolveName(string memory name, uint8 chainId) external view returns (bytes memory) {
        return nameToChainAddress[_normalizeNameView(name)][chainId];
    }

    function resolveToEVM(string memory name) external view returns (address) {
        return nameToEvmAddress[_normalizeNameView(name)];
    }

    function resolveToSolana(string memory name) external view returns (bytes memory) {
        return nameToChainAddress[_normalizeNameView(name)][CHAIN_SOLANA];
    }

    function resolveToSui(string memory name) external view returns (bytes memory) {
        return nameToChainAddress[_normalizeNameView(name)][CHAIN_SUI];
    }

    // WARNING: Aptos addresses are derived off-chain from the public key. This function returns the registered public key.
    function resolveToAptos(string memory name) external view returns (bytes memory) {
        return nameToChainAddress[_normalizeNameView(name)][CHAIN_APTOS];
    }

    function resolveAllChains(string memory name) external view returns (
        address evmAddr,
        bytes memory solanaAddr,
        bytes memory suiAddr,
        bytes memory aptosPubKey
    ) {
        string memory nm = _normalizeNameView(name);
        evmAddr = nameToEvmAddress[nm];
        solanaAddr = nameToChainAddress[nm][CHAIN_SOLANA];
        suiAddr = nameToChainAddress[nm][CHAIN_SUI];
        aptosPubKey = nameToChainAddress[nm][CHAIN_APTOS];
    }

    function reverseLookup(uint8 chainId, bytes memory walletAddress) external view returns (string memory) {
        return addressToName[keccak256(abi.encodePacked(chainId, walletAddress))];
    }

    function isNameRegistered(string memory name) external view returns (bool) {
        string memory nm = _normalizeNameView(name);
        return (nameToEvmAddress[nm] != address(0) ||
                nameToChainAddress[nm][CHAIN_SOLANA].length > 0 ||
                nameToChainAddress[nm][CHAIN_SUI].length > 0 ||
                nameToChainAddress[nm][CHAIN_APTOS].length > 0);
    }

    function getRegistrationStatus(string memory name) external view returns (bool, bool, bool, bool) {
        string memory nm = _normalizeNameView(name);
        return (
            nameToEvmAddress[nm] != address(0),
            nameToChainAddress[nm][CHAIN_SOLANA].length > 0,
            nameToChainAddress[nm][CHAIN_SUI].length > 0,
            nameToChainAddress[nm][CHAIN_APTOS].length > 0
        );
    }

    function isNameAvailable(string memory name, uint8 chainId) external view returns (bool) {
        return nameToChainAddress[_normalizeNameView(name)][chainId].length == 0;
    }

    function getNonce(uint8 chainId, bytes memory walletAddress) external view returns (uint256) {
        return chainNonces[chainId][walletAddress];
    }
    function getNextNonce(uint8 chainId, bytes memory walletAddress) external view returns (uint256) {
        return chainNonces[chainId][walletAddress];
    }

    // =================== Owner/Admin ===================

    function setRegistrationFee(uint256 _fee) external onlyOwner { registrationFee = _fee; ethFee = _fee; }
    function pause() external onlyOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }

    function withdraw() external onlyOwner {
        (bool ok, ) = payable(contractOwner).call{value: address(this).balance}("");
        require(ok, "ETH withdraw failed");
    }
    function withdrawToken(address token, uint256 amount) external onlyOwner {
        require(allowedTokens[token], "Token not supported");
        IERC20(token).safeTransfer(contractOwner, amount);
    }
    function withdrawAllTokens(address token) external onlyOwner {
        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal > 0) IERC20(token).safeTransfer(contractOwner, bal);
    }

    function transferOwnership(address newOwner) external onlyOwner { pendingOwner = newOwner; }
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        contractOwner = pendingOwner; pendingOwner = address(0);
    }

    function authorizeWalletProvider(address provider, uint256 referralFeeBasisPoints) external onlyOwner {
        require(provider != address(0), "Invalid provider");
        require(referralFeeBasisPoints <= 5000, "Fee too high");
        authorizedWalletProviders[provider] = true;
        walletProviderReferralFee[provider] = referralFeeBasisPoints;
    }
    function removeWalletProvider(address provider) external onlyOwner {
        authorizedWalletProviders[provider] = false;
        walletProviderReferralFee[provider] = 0;
    }
    function updateWalletProviderFee(address provider, uint256 referralFeeBasisPoints) external onlyOwner {
        require(authorizedWalletProviders[provider], "Provider not authorized");
        require(referralFeeBasisPoints <= 5000, "Fee too high");
        walletProviderReferralFee[provider] = referralFeeBasisPoints;
    }

    function setAllowedToken(address token, bool allowed, uint256 fee) external onlyOwner {
        require(token != address(0), "Invalid token address");
        allowedTokens[token] = allowed;
        if (allowed) {
            require(fee > 0, "Fee must be greater than zero");
            tokenFees[token] = fee;
        } else {
            tokenFees[token] = 0;
        }
    }

    function emergencyPause() external onlyOwner { paused = true; }
    function getContractBalance() external view onlyOwner returns (uint256) { return address(this).balance; }
    function getTokenBalance(address token) external view onlyOwner returns (uint256) { return IERC20(token).balanceOf(address(this)); }

    // =================== Helpers ===================

    function _bytesToHexString(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0"; str[1] = "x";
        for (uint256 i = 0; i < data.length; i++) {
            str[2 + i * 2] = alphabet[uint8(data[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
    function _addrToHex(address a) internal pure returns (string memory) { return _bytesToHexString(abi.encodePacked(a)); }

    function bytesToAddress(bytes memory data) public pure returns (address) {
        if (data.length != 20) revert InvalidAddress();
        address addr;
        assembly { addr := shr(96, mload(add(data, 32))) }
        return addr;
    }

    // Name normalization (ASCII lower + [a-z0-9-_.], no leading/trailing '-' or '.')
    function _normalizeNameStrict(string memory name) internal pure returns (string memory) {
        bytes memory b = bytes(name);
        if (b.length == 0) revert InvalidName();
        for (uint256 i = 0; i < b.length; i++) {
            uint8 c = uint8(b[i]);
            if (c >= 65 && c <= 90) { b[i] = bytes1(c + 32); }
            else {
                bool okChar = (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c == 45 || c == 95 || c == 46;
                if (!okChar) revert InvalidName();
            }
        }
        if (b[0] == "-" || b[0] == "." || b[b.length-1] == "-" || b[b.length-1] == ".") revert InvalidName();
        return string(b);
    }
    function _normalizeNameView(string memory name) internal pure returns (string memory) { return _normalizeNameStrict(name); }
}
