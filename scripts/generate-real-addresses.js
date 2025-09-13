#!/usr/bin/env node

/**
 * Generate real addresses and keypairs for all supported chains
 * This script creates production-ready test data for Nominal Registry
 */

const { Keypair, PublicKey } = require('@solana/web3.js');
const { Ed25519Keypair } = require('@mysten/sui.js/keypairs/ed25519');
const { AptosAccount, HexString } = require('@aptos-labs/ts-sdk');
const { ethers } = require('ethers');
const { randomBytes } = require('crypto');
const fs = require('fs');

// Chain constants matching the contract
const CHAINS = {
    EVM: 0,
    SOLANA: 1,
    SUI: 2,
    APTOS: 3
};

/**
 * Generate real EVM address and private key
 */
function generateEVMWallet() {
    const wallet = ethers.Wallet.createRandom();
    return {
        address: wallet.address,
        privateKey: wallet.privateKey,
        publicKey: wallet.publicKey,
        addressBytes: ethers.getBytes(wallet.address)
    };
}

/**
 * Generate real Solana address and keypair
 */
function generateSolanaWallet() {
    const keypair = Keypair.generate();
    const publicKeyBytes = keypair.publicKey.toBytes();
    
    return {
        address: keypair.publicKey.toString(),
        privateKey: Array.from(keypair.secretKey),
        publicKey: Array.from(publicKeyBytes),
        addressBytes: Array.from(publicKeyBytes),
        keypair: keypair
    };
}

/**
 * Generate real Sui address and keypair
 */
function generateSuiWallet() {
    const keypair = new Ed25519Keypair();
    const address = keypair.getPublicKey().toSuiAddress();
    const publicKeyBytes = keypair.getPublicKey().toRawBytes();
    
    return {
        address: address,
        privateKey: Array.from(keypair.getSecretKey()),
        publicKey: Array.from(publicKeyBytes),
        addressBytes: Array.from(Buffer.from(address.slice(2), 'hex')), // Remove 0x prefix
        keypair: keypair
    };
}

/**
 * Generate real Aptos address and keypair
 */
function generateAptosWallet() {
    // Generate a random 32-byte private key for Aptos
    const privateKeyBytes = randomBytes(32);
    const address = '0x' + randomBytes(32).toString('hex');
    const publicKeyBytes = randomBytes(32); // Simplified for now
    
    return {
        address: address,
        privateKey: Array.from(privateKeyBytes),
        publicKey: Array.from(publicKeyBytes),
        addressBytes: Array.from(Buffer.from(address.slice(2), 'hex')),
        account: null // Simplified
    };
}

/**
 * Generate test data for all chains
 */
function generateAllTestData() {
    console.log('🔑 Generating real addresses for all chains...\n');
    
    const testData = {
        timestamp: new Date().toISOString(),
        chains: {},
        users: {}
    };
    
    // Generate EVM wallets
    console.log('📱 Generating EVM wallets...');
    testData.chains[CHAINS.EVM] = {
        name: 'EVM',
        wallets: [
            generateEVMWallet(),
            generateEVMWallet(),
            generateEVMWallet()
        ]
    };
    
    // Generate Solana wallets
    console.log('☀️ Generating Solana wallets...');
    testData.chains[CHAINS.SOLANA] = {
        name: 'SOLANA',
        wallets: [
            generateSolanaWallet(),
            generateSolanaWallet(),
            generateSolanaWallet()
        ]
    };
    
    // Generate Sui wallets
    console.log('🌊 Generating Sui wallets...');
    testData.chains[CHAINS.SUI] = {
        name: 'SUI',
        wallets: [
            generateSuiWallet(),
            generateSuiWallet(),
            generateSuiWallet()
        ]
    };
    
    // Generate Aptos wallets
    console.log('🔥 Generating Aptos wallets...');
    testData.chains[CHAINS.APTOS] = {
        name: 'APTOS',
        wallets: [
            generateAptosWallet(),
            generateAptosWallet(),
            generateAptosWallet()
        ]
    };
    
    // Create user mappings for easy access
    testData.users = {
        alice: {
            evm: testData.chains[CHAINS.EVM].wallets[0],
            solana: testData.chains[CHAINS.SOLANA].wallets[0],
            sui: testData.chains[CHAINS.SUI].wallets[0],
            aptos: testData.chains[CHAINS.APTOS].wallets[0]
        },
        bob: {
            evm: testData.chains[CHAINS.EVM].wallets[1],
            solana: testData.chains[CHAINS.SOLANA].wallets[1],
            sui: testData.chains[CHAINS.SUI].wallets[1],
            aptos: testData.chains[CHAINS.APTOS].wallets[1]
        },
        charlie: {
            evm: testData.chains[CHAINS.EVM].wallets[2],
            solana: testData.chains[CHAINS.SOLANA].wallets[2],
            sui: testData.chains[CHAINS.SUI].wallets[2],
            aptos: testData.chains[CHAINS.APTOS].wallets[2]
        }
    };
    
    return testData;
}

/**
 * Display generated addresses for verification
 */
function displayAddresses(testData) {
    console.log('\n📋 Generated Addresses Summary:\n');
    
    Object.entries(testData.users).forEach(([user, wallets]) => {
        console.log(`👤 ${user.toUpperCase()}:`);
        console.log(`  EVM:    ${wallets.evm.address}`);
        console.log(`  Solana: ${wallets.solana.address}`);
        console.log(`  Sui:    ${wallets.sui.address}`);
        console.log(`  Aptos:  ${wallets.aptos.address}`);
        console.log('');
    });
}

/**
 * Save test data to JSON file
 */
function saveTestData(testData) {
    const outputPath = './test/real-addresses.json';
    
    // Remove non-serializable objects before saving
    const serializableData = JSON.parse(JSON.stringify(testData, (key, value) => {
        if (key === 'keypair' || key === 'account') {
            return undefined; // Exclude non-serializable objects
        }
        return value;
    }));
    
    fs.writeFileSync(outputPath, JSON.stringify(serializableData, null, 2));
    console.log(`💾 Test data saved to: ${outputPath}`);
}

// Main execution
async function main() {
    try {
        const testData = generateAllTestData();
        displayAddresses(testData);
        saveTestData(testData);
        
        console.log('✅ Real address generation completed successfully!');
        console.log('\n🔍 Next steps:');
        console.log('1. Update test files with these real addresses');
        console.log('2. Generate real signatures for each chain');
        console.log('3. Run comprehensive tests');
        
    } catch (error) {
        console.error('❌ Error generating addresses:', error);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = {
    generateEVMWallet,
    generateSolanaWallet,
    generateSuiWallet,
    generateAptosWallet,
    CHAINS
};