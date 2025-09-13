#!/usr/bin/env node

/**
 * Generate signatures for specific test cases
 */

const { Keypair } = require('@solana/web3.js');
const { Ed25519Keypair } = require('@mysten/sui.js/keypairs/ed25519');
const { ethers } = require('ethers');
const crypto = require('crypto');
const fs = require('fs');
const nacl = require('tweetnacl');

// Simple base58 decoder for Solana addresses
function base58Decode(s) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let decoded = BigInt(0);
    let multi = BigInt(1);
    
    for (let i = s.length - 1; i >= 0; i--) {
        const char = s[i];
        const index = alphabet.indexOf(char);
        if (index === -1) throw new Error('Invalid base58 character');
        decoded += BigInt(index) * multi;
        multi *= BigInt(58);
    }
    
    // Convert to buffer
    const bytes = [];
    while (decoded > 0) {
        bytes.unshift(Number(decoded % BigInt(256)));
        decoded = decoded / BigInt(256);
    }
    
    // Add leading zeros
    for (let i = 0; i < s.length && s[i] === '1'; i++) {
        bytes.unshift(0);
    }
    
    return Buffer.from(bytes);
}

// Load addresses
const addressData = JSON.parse(fs.readFileSync('./test/real-addresses.json', 'utf8'));

// Extract user data from the chain structure
function extractUserData(chainData, index) {
    const wallet = chainData.wallets[index];
    if (!wallet) return null;
    
    // Handle different chain formats
    if (chainData.name === 'EVM') {
        return {
            address: wallet.address,
            privateKey: wallet.privateKey,
            publicKey: wallet.publicKey
        };
    } else if (chainData.name === 'SOLANA') {
        // Solana has array for private key
        const privateKeyBytes = Array.isArray(wallet.privateKey) ? 
            Buffer.from(wallet.privateKey) : 
            Buffer.from(wallet.privateKey, 'hex');
            
        return {
            address: wallet.address,
            privateKey: privateKeyBytes.toString('hex'),
            privateKeyBytes: privateKeyBytes,
            publicKey: Array.isArray(wallet.publicKey) ? Buffer.from(wallet.publicKey) : wallet.publicKey
        };
    } else if (chainData.name === 'SUI') {
        // Sui has array for private key and public key
        return {
            address: wallet.address,
            privateKey: wallet.privateKey, // Keep as array
            privateKeyBytes: Buffer.from(wallet.privateKey),
            publicKey: wallet.publicKey, // Keep as array
            publicKeyBytes: Buffer.from(wallet.publicKey)
        };
    } else if (chainData.name === 'APTOS') {
        // Aptos has array for private key
        return {
            address: wallet.address,
            privateKey: wallet.privateKey, // Keep as array
            privateKeyBytes: Buffer.from(wallet.privateKey),
            publicKey: wallet.publicKey, // Keep as array 
            publicKeyBytes: Buffer.from(wallet.publicKey)
        };
    }
}

const userData = {
    alice: {
        evm: extractUserData(addressData.chains[0], 0),
        solana: extractUserData(addressData.chains[1], 0),
        sui: extractUserData(addressData.chains[2], 0),
        aptos: extractUserData(addressData.chains[3], 0)
    },
    bob: {
        evm: extractUserData(addressData.chains[0], 1),
        solana: extractUserData(addressData.chains[1], 1), 
        sui: extractUserData(addressData.chains[2], 1),
        aptos: extractUserData(addressData.chains[3], 1)
    }
};

// Contract parameters - these MUST match the test setup
const CONTRACT_ADDRESS = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"; // From test traces
const CHAIN_ID = 31337; // Anvil default
const EXPIRY = 3601; // WORKING_EXPIRY from tests

// Test cases that need signatures
const TEST_CASES = [
    { name: "alice-solana", chain: 1, userType: "alice" },
    { name: "alice-sui", chain: 2, userType: "alice" },
    { name: "alice-aptos", chain: 3, userType: "alice" },
    { name: "alice-event-test", chain: 0, userType: "alice" },
    { name: "alice-nonce-test", chain: 0, userType: "alice" },
    { name: "alice-payment-test", chain: 0, userType: "alice" },
    { name: "bob", chain: 0, userType: "bob" }
];

/**
 * Create EIP-712 domain separator (matches contract exactly)
 */
function createDomainSeparator(chainId, verifyingContract) {
    return ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
            [
                ethers.keccak256(ethers.toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
                ethers.keccak256(ethers.toUtf8Bytes('NominalRegistryV2')), // MUST match contract
                ethers.keccak256(ethers.toUtf8Bytes('2')), // MUST match contract
                chainId,
                verifyingContract
            ]
        )
    );
}

/**
 * Create EIP-712 struct hash
 */
function createStructHash(name, chainId, walletAddress, nonce, expiry) {
    const REGISTRATION_TYPEHASH = ethers.keccak256(
        ethers.toUtf8Bytes('Registration(string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry)')
    );
    
    return ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32', 'uint8', 'bytes32', 'uint256', 'uint256'],
            [
                REGISTRATION_TYPEHASH,
                ethers.keccak256(ethers.toUtf8Bytes(name)),
                chainId,
                ethers.keccak256(walletAddress),
                nonce,
                expiry
            ]
        )
    );
}

/**
 * Create wallet-compatible message for Ed25519 chains
 */
function createWalletMessage(name, chainId, walletAddress, nonce, expiry) {
    const addressHex = '0x' + Buffer.from(walletAddress).toString('hex');
    return `Register ${name} on chain ${chainId} for ${addressHex} (nonce: ${nonce}, expires: ${expiry})`;
}

/**
 * Generate EVM signature
 */
function generateEVMSignature(privateKey, name, chainId, walletAddress, nonce, expiry) {
    const domainSeparator = createDomainSeparator(CHAIN_ID, CONTRACT_ADDRESS);
    const structHash = createStructHash(name, chainId, walletAddress, nonce, expiry);
    const messageHash = ethers.keccak256(
        ethers.solidityPacked(['string', 'bytes32', 'bytes32'], ['\x19\x01', domainSeparator, structHash])
    );
    
    const wallet = new ethers.Wallet(privateKey);
    const signature = wallet.signingKey.sign(messageHash);
    
    return {
        signature: signature.r + signature.s.slice(2) + (signature.v).toString(16).padStart(2, '0'),
        messageHash,
        domainSeparator,
        structHash
    };
}

/**
 * Generate Ed25519 signature
 */
function generateEd25519Signature(chainId, privateKeyData, message) {
    let privateKeyBytes;
    
    console.log(`Debug: Chain ${chainId}, input private key type: ${typeof privateKeyData}`);
    console.log(`Debug: Chain ${chainId}, input private key: ${privateKeyData}`);
    
    if (chainId === 1) { // Solana
        if (Array.isArray(privateKeyData)) {
            privateKeyBytes = new Uint8Array(privateKeyData);
        } else {
            privateKeyBytes = new Uint8Array(Buffer.from(privateKeyData, 'hex'));
        }
        console.log(`Debug: Chain ${chainId}, private key length: ${privateKeyBytes.length}`);
        console.log(`Debug: Chain ${chainId}, private key is Uint8Array: ${privateKeyBytes instanceof Uint8Array}`);
    } else if (chainId === 2) { // Sui - 32 byte seed, need to expand to 64 bytes
        let seed;
        if (Array.isArray(privateKeyData)) {
            seed = new Uint8Array(privateKeyData);
        } else {
            seed = new Uint8Array(Buffer.from(privateKeyData, 'hex'));
        }
        console.log(`Debug: Chain ${chainId}, seed length: ${seed.length}`);
        
        // Generate the full keypair from the 32-byte seed
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        privateKeyBytes = keypair.secretKey; // This will be 64 bytes
        console.log(`Debug: Chain ${chainId}, expanded private key length: ${privateKeyBytes.length}`);
    } else if (chainId === 3) { // Aptos
        let seed;
        if (Array.isArray(privateKeyData)) {
            seed = new Uint8Array(privateKeyData);
        } else {
            seed = new Uint8Array(Buffer.from(privateKeyData, 'hex'));
        }
        console.log(`Debug: Chain ${chainId}, seed length: ${seed.length}`);
        
        if (seed.length === 32) {
            // Generate the full keypair from the 32-byte seed
            const keypair = nacl.sign.keyPair.fromSeed(seed);
            privateKeyBytes = keypair.secretKey; // This will be 64 bytes
        } else {
            privateKeyBytes = seed; // Already 64 bytes
        }
        console.log(`Debug: Chain ${chainId}, final private key length: ${privateKeyBytes.length}`);
    }
    
    const messageBytes = new Uint8Array(new TextEncoder().encode(message));
    const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
    
    console.log(`Debug: Generated signature bytes (length=${signature.length}):`, Buffer.from(signature).toString('hex'));
    
    // Extract R and S for debugging
    const r = signature.slice(0, 32);
    const s = signature.slice(32, 64);
    console.log(`Debug: R (32 bytes):`, Buffer.from(r).toString('hex'));
    console.log(`Debug: S (32 bytes):`, Buffer.from(s).toString('hex'));
    console.log(`Debug: R as uint256:`, BigInt('0x' + Buffer.from(r).toString('hex')));
    console.log(`Debug: S as uint256:`, BigInt('0x' + Buffer.from(s).toString('hex')));
    
    return Buffer.from(signature).toString('hex');
}

async function main() {
    console.log('Generating test signatures...');
    console.log('Contract address:', CONTRACT_ADDRESS);
    console.log('Chain ID:', CHAIN_ID);
    console.log('Expiry:', EXPIRY);
    
    const results = {};
    
    for (const testCase of TEST_CASES) {
        console.log(`\nGenerating signature for: ${testCase.name} (chain ${testCase.chain})`);
        
        const userInfo = userData[testCase.userType];
        if (!userInfo) {
            console.error(`No data for user: ${testCase.userType}`);
            continue;
        }
        
        if (testCase.chain === 0) { // EVM
            const walletAddress = Buffer.from(userInfo.evm.address.slice(2), 'hex');
            const result = generateEVMSignature(
                userInfo.evm.privateKey,
                testCase.name,
                testCase.chain,
                walletAddress,
                0, // nonce
                EXPIRY
            );
            
            results[testCase.name] = {
                chain: testCase.chain,
                walletAddress: userInfo.evm.address,
                signature: result.signature,
                messageHash: result.messageHash,
                nonce: 0,
                expiry: EXPIRY
            };
            
            console.log('  Address:', userInfo.evm.address);
            console.log('  Signature:', result.signature);
            
        } else { // Ed25519 chains
            let chainData, privateKeyBytes, walletAddressBytes;
            
            if (testCase.chain === 1) { // Solana
                chainData = userInfo.solana;
                privateKeyBytes = chainData.privateKeyBytes;
                walletAddressBytes = base58Decode(chainData.address);
                
                // Extract public key from private key (last 32 bytes of 64-byte private key)
                if (!chainData.publicKeyBytes) {
                    const keypair = nacl.sign.keyPair.fromSecretKey(privateKeyBytes);
                    chainData.publicKeyBytes = keypair.publicKey;
                    console.log(`Debug: Generated public key for Solana: ${Buffer.from(keypair.publicKey).toString('hex')}`);
                    console.log(`Debug: Address bytes: ${walletAddressBytes.toString('hex')}`);
                    console.log(`Debug: Public key equals address: ${Buffer.from(keypair.publicKey).equals(walletAddressBytes)}`);
                }
            } else if (testCase.chain === 2) { // Sui  
                chainData = userInfo.sui;
                // Sui private key is 70 bytes, extract first 32 bytes for Ed25519 seed
                privateKeyBytes = chainData.privateKeyBytes.slice(0, 32);
                walletAddressBytes = Buffer.from(chainData.address.replace('0x', ''), 'hex');
            } else if (testCase.chain === 3) { // Aptos
                chainData = userInfo.aptos;
                // Ensure we use exactly 32 bytes for Ed25519 seed
                privateKeyBytes = chainData.privateKeyBytes.slice(0, 32);
                walletAddressBytes = Buffer.from(chainData.address.replace('0x', ''), 'hex');
            }
            
            console.log(`Debug: Chain ${testCase.chain}, private key length: ${privateKeyBytes.length}`);
            
            const message = `Register ${testCase.name} on chain ${testCase.chain} for 0x${walletAddressBytes.toString('hex')} (nonce: 0, expires: ${EXPIRY})`;
            const signature = generateEd25519Signature(testCase.chain, privateKeyBytes, message);
            
            results[testCase.name] = {
                chain: testCase.chain,
                walletAddress: chainData.address,
                walletAddressHex: '0x' + walletAddressBytes.toString('hex'),
                publicKeyHex: chainData.publicKeyBytes ? ('0x' + Buffer.from(chainData.publicKeyBytes).toString('hex')) : null,
                signature: '0x' + signature,
                message: message,
                nonce: 0,
                expiry: EXPIRY
            };
            
            console.log('  Address:', chainData.address);
            console.log('  Address (hex):', '0x' + walletAddressBytes.toString('hex'));
            if (chainData.publicKeyBytes) {
                console.log('  Public Key (hex):', '0x' + chainData.publicKeyBytes.toString('hex'));
            }
            console.log('  Signature:', signature);
            console.log('  Message:', message);
        }
    }
    
    // Save results
    fs.writeFileSync('./test/test-signatures.json', JSON.stringify(results, null, 2));
    console.log('\nSignatures saved to ./test/test-signatures.json');
}

main().catch(console.error);