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
import {p, d} from "../lib/crypto-lib/src/fields/SCL_wei25519.sol";

library SuiIntent {
    function _uleb128(uint256 v) internal pure returns (bytes memory out) {
        while (true) {
            uint8 b = uint8(v & 0x7f);
            v >>= 7;
            if (v != 0) b |= 0x80;
            out = abi.encodePacked(out, bytes1(b));
            if (v == 0) break;
        }
    }
    // PersonalMessage scope: 0x03 00 00
    function wrap(bytes memory raw) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0x03), bytes1(0x00), bytes1(0x00), _uleb128(raw.length), raw);
    }
    function wrapSimple(bytes memory raw) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0x03), bytes1(0x00), bytes1(0x00), raw);
    }
}

/**
 * @title NominalRegistryV2 (clean)
 * @notice Multi-chain naming registry w/ EVM, Solana (ed25519), Sui (ed25519, compact msg), Aptos (ed25519)
 */
contract NominalRegistryV2 is ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    uint8 public constant MAX_CHAINS = 4;
    uint8 public constant CHAIN_EVM    = 0;
    uint8 public constant CHAIN_SOLANA = 1;
    uint8 public constant CHAIN_SUI    = 2;
    uint8 public constant CHAIN_APTOS  = 3;

    address public contractOwner;
    bool public paused;
    address public pendingOwner;

    // name → chain → canonical bytes (EVM:20, Sol:32 pubkey, Sui:32 digest, Aptos:32 pubkey)
    mapping(string => mapping(uint8 => bytes)) public nameToChainAddress;
    mapping(bytes32 => string) public addressToName;

    // Fast path for EVM
    mapping(string => address) public nameToEvmAddress;
    mapping(address => string) public evmAddressToName;

    // Nonces keyed by canonical identity
    mapping(uint8 => mapping(bytes => uint256)) public chainNonces;

    // Providers & fees
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

    modifier onlyOwner() { if (msg.sender != contractOwner) revert Unauthorized(); _; }
    modifier whenNotPaused() { if (paused) revert Paused(); _; }
    modifier validChain(uint8 chainId) { if (chainId >= MAX_CHAINS) revert InvalidChain(); _; }

    constructor(uint256 _registrationFee) {
        contractOwner = msg.sender;
        registrationFee = _registrationFee;
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

    // -------- Core --------

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

        bytes memory canonical = _canonicalAccountBytesOrRevert(chainId, walletAddress, publicKey);
        _verifySignatureAndNonce(name, chainId, walletAddress, publicKey, signature, nonceVal, expiry, canonical);
        _storeRegistrationCanonical(name, chainId, walletAddress, canonical);

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

    // -------- Payments --------

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

    // -------- Signature Verification & Nonces --------

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
            // SUI ONLY: compact message (<=128B) + intent variants + optional single-block blake2b digests
            bytes memory raw = bytes(_createDomainBoundMessageSuiCompact(canonical, nonceVal, expiry));
            bool ok = _verifySuiAll(raw, signature, publicKey);
            if (!ok) revert InvalidSignature();
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

        uint256 r; uint256 s;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }

        uint256[5] memory extKpub;
        if (!_setupExtKpubFromCompressedKey(publicKey, extKpub)) revert InvalidSignature();
        if (!SCL_EIP6565.Verify_LE(message, r, s, extKpub)) revert InvalidSignature();
        return true;
    }

    // Non-reverting Ed25519 verifier
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
        if (chainId == CHAIN_SUI) {
            return _createDomainBoundMessageSuiCompact(canonicalAccount, nonceVal, expiry);
        }
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
        bytes memory canonical,   // 32B ed25519 pubkey
        bytes memory publicKey,   // 32B ed25519
        bytes memory signature,   // 64B ed25519 (R||S)
        uint256 nonceVal,
        uint256 expiry
    ) internal {
        string memory base = _createDomainBoundMessage(name, chainId, canonical, nonceVal, expiry);

        if (_ed25519VerifyNoRevert(base, signature, publicKey)) return;

        string memory fm1 = string(
            abi.encodePacked("APTOS\nmessage: ", base, "\nnonce: ", Strings.toString(nonceVal))
        );
        if (_ed25519VerifyNoRevert(fm1, signature, publicKey)) return;

        string memory fm2 = string(
            abi.encodePacked("APTOS\nnonce: ", Strings.toString(nonceVal), "\nmessage: ", base)
        );
        if (_ed25519VerifyNoRevert(fm2, signature, publicKey)) return;

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
            return walletAddress; // canonical = 32B Sui address digest
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
        } else {
            _storeRegistration(name, chainId, walletAddress);
        }
    }

    // -------- Ed25519 Key Utils --------
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

    // -------- Sui (ed25519) --------

    function _verifySuiAll(bytes memory raw, bytes memory sig64, bytes memory pubkey32) internal returns (bool) {
        // Preimage candidates
        if (_ed25519VerifyNoRevert(string(raw), sig64, pubkey32)) return true;
        bytes memory intent = SuiIntent.wrap(raw);          // 0x03 00 00 + ULEB + raw
        if (_ed25519VerifyNoRevert(string(intent), sig64, pubkey32)) return true;
        bytes memory simple = SuiIntent.wrapSimple(raw);    // 0x03 00 00 + raw
        if (_ed25519VerifyNoRevert(string(simple), sig64, pubkey32)) return true;

        // Digest candidates (only valid when ≤128 bytes because of single-block hasher)
        if (raw.length <= 128) {
            bytes memory hRaw = abi.encodePacked(_blake2b256_singleBlock(raw));
            if (_ed25519VerifyNoRevert(string(hRaw), sig64, pubkey32)) return true;
        }
        if (intent.length <= 128) {
            bytes memory hIntent = abi.encodePacked(_blake2b256_singleBlock(intent));
            if (_ed25519VerifyNoRevert(string(hIntent), sig64, pubkey32)) return true;
        }
        if (simple.length <= 128) {
            bytes memory hSimple = abi.encodePacked(_blake2b256_singleBlock(simple));
            if (_ed25519VerifyNoRevert(string(hSimple), sig64, pubkey32)) return true;
        }
        return false;
    }

    // single-block BLAKE2b-256 (limit 128B input)
    function _blake2b256_singleBlock(bytes memory input) internal view returns (bytes32 out32) {
        if (input.length > 128) revert InvalidAddress();

        uint64[8] memory IV = [
            uint64(0x6a09e667f3bcc908), uint64(0xbb67ae8584caa73b),
            uint64(0x3c6ef372fe94f82b), uint64(0xa54ff53a5f1d36f1),
            uint64(0x510e527fade682d1), uint64(0x9b05688c2b3e6c1f),
            uint64(0x1f83d9abfb41bd6b), uint64(0x5be0cd19137e2179)
        ];

        uint64[8] memory hState;
        hState[0] = IV[0] ^ uint64(0x01010020);
        hState[1] = IV[1]; hState[2] = IV[2]; hState[3] = IV[3];
        hState[4] = IV[4]; hState[5] = IV[5]; hState[6] = IV[6]; hState[7] = IV[7];

        bytes memory payload = new bytes(4 + 64 + 128 + 8 + 8 + 1);
        uint256 o = 0;

        _storeU32BE(payload, o, 12); o += 4;

        for (uint256 i = 0; i < 8; i++) { _storeU64LE(payload, o, hState[i]); o += 8; }

        for (uint256 j = 0; j < 128; j++) {
            payload[o + j] = (j < input.length) ? input[j] : bytes1(0);
        }
        o += 128;

        _storeU64LE(payload, o, uint64(input.length)); o += 8;
        _storeU64LE(payload, o, 0);                     o += 8;
        payload[o] = 0x01;

        bytes32[2] memory outState;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x09, add(payload, 0x20), mload(payload), outState, 0x40)
        }
        require(ok, "blake2b precompile failed");
        out32 = outState[0];
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

    // -------- Views --------

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

    // -------- Owner/Admin --------

    function setRegistrationFee(uint256 _fee) external onlyOwner { registrationFee = _fee; }
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

    function getContractBalance() external view returns (uint256) { return address(this).balance; }
    function getTokenBalance(address token) external view returns (uint256) { return IERC20(token).balanceOf(address(this)); }

    // -------- Helpers --------

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

    // Compact message used ONLY for SUI (keep under 128B)
    function _createDomainBoundMessageSuiCompact(
        bytes memory canonicalAccount,
        uint256 nonceVal,
        uint256 expiry
    ) internal view returns (string memory) {
        // Example: "NRV2|a:0x..|n:123|e:1700000000"
        return string(
            abi.encodePacked(
                "NRV2|a:",
                _bytesToHexString(canonicalAccount),
                "|n:",
                Strings.toString(nonceVal),
                "|e:",
                Strings.toString(expiry)
            )
        );
    }

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
