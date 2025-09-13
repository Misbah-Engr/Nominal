#!/usr/bin/env node

/**
 * Simple Ed25519 signer for the exact message from the contract
 * Usage: node sign-exact-message.js "message" privateKeyHex
 */

const nacl = require('tweetnacl');

if (process.argv.length < 4) {
    console.log('Usage: node sign-exact-message.js "message" privateKeyHex');
    process.exit(1);
}

const message = process.argv[2];
const privateKeyHex = process.argv[3];

try {
    // Convert message to bytes
    const messageBytes = Buffer.from(message, 'utf8');
    
    // Convert private key hex to bytes (32 bytes)
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    if (privateKeyBytes.length !== 32) {
        throw new Error(`Private key must be 32 bytes, got ${privateKeyBytes.length}`);
    }
    
    // Generate keypair from seed
    const keypair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
    
    // Sign the message
    const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
    
    // Output hex signature (64 bytes)
    console.log(Buffer.from(signature).toString('hex'));
    
} catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
}