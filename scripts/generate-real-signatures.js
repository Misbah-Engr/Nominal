#!/usr/bin/env node

/**
 * Generate real signatures for multi-chain wallet testing
 * This script creates production-ready signatures for Nominal Registry
 */

const { Keypair } = require('@solana/web3.js');
const { Ed25519Keypair } = require('@mysten/sui.js/keypairs/ed25519');
const { ethers } = require('ethers');
const crypto = require('crypto');
const fs = require('fs');

// Load generated addresses
const addressData = JSON.parse(fs.readFileSync('./test/real-addresses.json', 'utf8'));

// Chain constants
const CHAINS = {
    EVM: 0,
    SOLANA: 1,
    SUI: 2,
    APTOS: 3
};

/**
 * Create the same message format as the contract _createDomainBoundMessage
 * Format: "NominalRegistryV2 on [chainId] @ [contractAddress] | name: [name] | chain: [chainId] | acct: [hexString] | nonce: [nonce] | exp: [expiry]"
 */
function createDomainBoundMessage(name, chainId, walletAddress, nonce, expiry, contractChainId, contractAddress) {
    // Convert walletAddress bytes to hex string like the contract does
    const addressHex = '0x' + Buffer.from(walletAddress).toString('hex');
    
    return `NominalRegistryV2 on ${contractChainId} @ ${contractAddress} | name: ${name} | chain: ${chainId} | acct: ${addressHex} | nonce: ${nonce} | exp: ${expiry}`;
}

/**
 * Create EIP-712 domain separator (matches contract)
 */
function createDomainSeparator(chainId, verifyingContract) {
    return ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
            [
                ethers.keccak256(ethers.toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
                ethers.keccak256(ethers.toUtf8Bytes('NominalRegistryV2')),
                ethers.keccak256(ethers.toUtf8Bytes('2')),
                chainId,
                verifyingContract
            ]
        )
    );
}

/**
 * Create EIP-712 typed data hash (matches contract)
 */
function createEIP712Hash(name, chainId, walletAddress, nonce, expiry, domainSeparator) {
    const REGISTRATION_TYPEHASH = ethers.keccak256(
        ethers.toUtf8Bytes('Registration(string name,uint8 chain,bytes walletAddress,uint256 nonce,uint256 expiry)')
    );
    
    const structHash = ethers.keccak256(
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
    
    return ethers.keccak256(
        ethers.concat([
            ethers.toUtf8Bytes('\x19\x01'),
            domainSeparator,
            structHash
        ])
    );
}

/**
 * Generate real EVM signature using EIP-712
 */
function generateEVMSignature(privateKey, name, chainId, walletAddressBytes, nonce, expiry, contractAddress) {
    try {
        const wallet = new ethers.Wallet(privateKey);
        
        // Convert address bytes object to proper bytes array
        const addressArray = Object.values(walletAddressBytes);
        const walletAddress = new Uint8Array(addressArray);
        
        // Create domain separator (simulating mainnet for now)
        const domainSeparator = createDomainSeparator(1, contractAddress);
        
        // Create EIP-712 hash
        const hash = createEIP712Hash(name, chainId, walletAddress, nonce, expiry, domainSeparator);
        
        // Sign the hash
        const signature = wallet.signingKey.sign(hash);
        
        return {
            signature: signature.serialized,
            hash: hash,
            signer: wallet.address,
            message: `EIP-712 registration for ${name}`,
            valid: true
        };
    } catch (error) {
        console.error('EVM signature generation failed:', error);
        return {
            signature: '0x' + '00'.repeat(65),
            hash: '0x' + '00'.repeat(32),
            signer: '0x' + '00'.repeat(20),
            message: 'Failed to generate EVM signature',
            valid: false
        };
    }
}

/**
 * Generate real Ed25519 signature for non-EVM chains
 */
function generateEd25519Signature(privateKeyArray, publicKeyArray, name, chainId, walletAddressArray, nonce, expiry, contractChainId, contractAddress) {
    try {
        // Create the message in the same format as the contract
        const addressBytes = Array.isArray(walletAddressArray) 
            ? walletAddressArray 
            : Object.values(walletAddressArray);
        const message = createDomainBoundMessage(name, chainId, addressBytes, nonce, expiry, contractChainId, contractAddress);
        const messageBytes = Buffer.from(message, 'utf8');
        
        // Use tweetnacl for Ed25519 signing
        const nacl = require('tweetnacl');
        
        // Create proper 32-byte seed from private key array
        const privateKeyBytes = Array.isArray(privateKeyArray) 
            ? privateKeyArray 
            : Object.values(privateKeyArray);
        const seed = new Uint8Array(privateKeyBytes.slice(0, 32));
        
        // Generate keypair from seed
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        
        // Sign the message
        const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
        
        return {
            signature: '0x' + Buffer.from(signature).toString('hex'),
            message: message,
            publicKey: '0x' + Buffer.from(keypair.publicKey).toString('hex'),
            signer: '0x' + Buffer.from(keypair.publicKey).toString('hex'),
            valid: true
        };
    } catch (error) {
        console.error(`Ed25519 signature generation failed for chain ${chainId}:`, error);
        return {
            signature: '0x' + '00'.repeat(64),
            message: `Failed to generate Ed25519 signature for chain ${chainId}`,
            publicKey: '0x' + '00'.repeat(32),
            signer: '0x' + '00'.repeat(32),
            valid: false
        };
    }
}

/**
 * Generate real Sui signature (special handling for bech32 private keys)
 */
function generateSuiSignature(privateKeyArray, publicKeyArray, name, chainId, walletAddressArray, nonce, expiry, contractChainId, contractAddress) {
    try {
        const nacl = require('tweetnacl');
        const bech32 = require('bech32');
        
        // Create the message in the same format as the contract
        const addressBytes = Array.isArray(walletAddressArray) 
            ? walletAddressArray 
            : Object.values(walletAddressArray);
        const message = createDomainBoundMessage(name, chainId, addressBytes, nonce, expiry, contractChainId, contractAddress);
        const messageBytes = Buffer.from(message, 'utf8');
        
        // For Sui, the private key is stored as a bech32 string
        const suiPrivKeyString = privateKeyArray.join('');
        
        // Decode the bech32 private key
        const decoded = bech32.bech32.decode(suiPrivKeyString);
        const bytes = bech32.bech32.fromWords(decoded.words);
        
        // Sui private keys have a flag byte at the beginning, so we skip it
        const seed = new Uint8Array(bytes.slice(1));
        
        // Generate keypair from seed
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        
        // Sign the message
        const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
        
        return {
            signature: '0x' + Buffer.from(signature).toString('hex'),
            message: message,
            publicKey: '0x' + Buffer.from(keypair.publicKey).toString('hex'),
            signer: '0x' + Buffer.from(keypair.publicKey).toString('hex'),
            valid: true
        };
    } catch (error) {
        console.error(`Sui signature generation failed:`, error);
        return {
            signature: '0x' + '00'.repeat(64),
            message: `Failed to generate Sui signature`,
            publicKey: '0x' + '00'.repeat(32),
            signer: '0x' + '00'.repeat(32),
            valid: false
        };
    }
}

/**
 * Generate test signatures for all users and chains
 */
function generateTestSignatures() {
    console.log('🖊️  Generating real signatures for all chains...\n');
    
    const contractChainId = 31337; // Test chain ID (matches test environment)
    const contractAddress = '0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f'; // Test contract address
    
    const signatures = {
        timestamp: new Date().toISOString(),
        contractChainId: contractChainId,
        contractAddress: contractAddress,
        testCases: {}
    };
    
    const users = ['alice', 'bob', 'charlie'];
    const nonce = 0;
    const expiry = 3601; // Fixed expiry for testing (matches test file)
    
    users.forEach(user => {
        console.log(`👤 Generating signatures for ${user}...`);
        const userData = addressData.users[user];
        signatures.testCases[user] = {};
        
        // EVM signature
        console.log(`  📱 EVM signature...`);
        const evmWallet = userData.evm;
        signatures.testCases[user].evm = generateEVMSignature(
            evmWallet.privateKey,
            user,
            CHAINS.EVM,
            evmWallet.addressBytes,
            nonce,
            expiry,
            contractAddress
        );
        
        // Solana signature
        console.log(`  ☀️ Solana signature...`);
        const solanaWallet = userData.solana;
        signatures.testCases[user].solana = generateEd25519Signature(
            solanaWallet.privateKey,
            solanaWallet.publicKey,
            user,
            CHAINS.SOLANA,
            solanaWallet.addressBytes,
            nonce,
            expiry,
            contractChainId,
            contractAddress
        );
        
        // Sui signature
        console.log(`  🌊 Sui signature...`);
        const suiWallet = userData.sui;
        signatures.testCases[user].sui = generateSuiSignature(
            suiWallet.privateKey,
            suiWallet.publicKey,
            user,
            CHAINS.SUI,
            suiWallet.addressBytes,
            nonce,
            expiry,
            contractChainId,
            contractAddress
        );
        
        // Aptos signature
        console.log(`  🔥 Aptos signature...`);
        const aptosWallet = userData.aptos;
        signatures.testCases[user].aptos = generateEd25519Signature(
            aptosWallet.privateKey,
            aptosWallet.publicKey,
            user,
            CHAINS.APTOS,
            aptosWallet.addressBytes,
            nonce,
            expiry,
            contractChainId,
            contractAddress
        );
        
        console.log('');
    });
    
    return signatures;
}

/**
 * Display signature summary
 */
function displaySignatureSummary(signatures) {
    console.log('📋 Generated Signatures Summary:\n');
    
    Object.entries(signatures.testCases).forEach(([user, chains]) => {
        console.log(`👤 ${user.toUpperCase()}:`);
        
        Object.entries(chains).forEach(([chain, sigData]) => {
            const status = sigData.valid ? '✅' : '❌';
            console.log(`  ${chain.toUpperCase()}: ${status} ${sigData.signature.slice(0, 20)}...`);
        });
        
        console.log('');
    });
}

/**
 * Save signatures to JSON file
 */
function saveSignatures(signatures) {
    const outputPath = './test/real-signatures.json';
    fs.writeFileSync(outputPath, JSON.stringify(signatures, null, 2));
    console.log(`💾 Signatures saved to: ${outputPath}`);
}

/**
 * Generate Solidity test data
 */
function generateSolidityTestData(signatures) {
    console.log('\n🔧 Generating Solidity test data...');
    
    let solidityCode = '// SPDX-License-Identifier: MIT\n';
    solidityCode += '// Auto-generated test data with real signatures\n\n';
    
    Object.entries(signatures.testCases).forEach(([user, chains]) => {
        solidityCode += `// ${user.toUpperCase()} test data\n`;
        
        Object.entries(chains).forEach(([chain, sigData]) => {
            const varName = `${user}_${chain}_signature`;
            solidityCode += `bytes constant ${varName.toUpperCase()} = hex"${sigData.signature.slice(2)}";\n`;
        });
        
        solidityCode += '\n';
    });
    
    fs.writeFileSync('./test/real-signatures.sol', solidityCode);
    console.log('💾 Solidity test data saved to: ./test/real-signatures.sol');
}

// Main execution
async function main() {
    try {
        console.log('🔑 Generating real signatures for production testing...\n');
        
        const signatures = generateTestSignatures();
        displaySignatureSummary(signatures);
        saveSignatures(signatures);
        generateSolidityTestData(signatures);
        
        console.log('\n✅ Real signature generation completed successfully!');
        console.log('\n🔍 Next steps:');
        console.log('1. Update test files with these real signatures');
        console.log('2. Run comprehensive tests with real wallet data');
        console.log('3. Verify all signature verification logic works correctly');
        
    } catch (error) {
        console.error('❌ Error generating signatures:', error);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = {
    generateEVMSignature,
    generateEd25519Signature,
    createDomainBoundMessage,
    CHAINS
};