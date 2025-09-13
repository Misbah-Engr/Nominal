#!/usr/bin/env node

/**
 * Decode Sui private key and generate correct signature
 */

const nacl = require('tweetnacl');
const bech32 = require('bech32');

// Load the address data
const addressData = require('../test/real-addresses.json');

async function decodeSuiKey() {
    try {
        // Get the Sui private key string
        const suiPrivKeyString = addressData.users.alice.sui.privateKey.join('');
        console.log('Sui private key string:', suiPrivKeyString);
        
        // Decode the bech32 private key
        const decoded = bech32.bech32.decode(suiPrivKeyString);
        console.log('Decoded bech32:', decoded);
        
        // Convert 5-bit words to bytes
        const bytes = bech32.bech32.fromWords(decoded.words);
        console.log('Bytes from bech32:', bytes.length, Buffer.from(bytes).toString('hex'));
        
        // Sui private keys have a flag byte at the beginning, so we skip it
        if (bytes.length === 33) {
            // Skip the first byte (flag) and take the next 32 bytes as the Ed25519 seed
            const seed = new Uint8Array(bytes.slice(1));
            console.log('Ed25519 seed (skipping flag byte):', Buffer.from(seed).toString('hex'));
            
            // Create keypair from seed
            const naclKeypair = nacl.sign.keyPair.fromSeed(seed);
            console.log('Nacl public key:', Buffer.from(naclKeypair.publicKey).toString('hex'));
            
            // Expected public key from test data
            const expectedPubKey = Buffer.from(addressData.users.alice.sui.publicKey).toString('hex');
            console.log('Expected public key:', expectedPubKey);
            
            if (Buffer.from(naclKeypair.publicKey).toString('hex') === expectedPubKey) {
                console.log('✅ Public keys match!');
                
                // Sign the message
                const message = 'NominalRegistryV2 on 31337 @ 0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f | name: alice-sui | chain: 2 | acct: 0x98f700eb470476028f52bbae6e71550d07d91428fdbe21c6a5dbf495404137b4 | nonce: 0 | exp: 3601';
                const messageBytes = Buffer.from(message, 'utf8');
                const signature = nacl.sign.detached(messageBytes, naclKeypair.secretKey);
                
                console.log('\n🔑 Sui signature for the exact message:');
                console.log(Buffer.from(signature).toString('hex'));
                return;
            } else {
                console.log('❌ Public keys do not match');
            }
        } else if (bytes.length === 32) {
            // This should be the Ed25519 seed
            const seed = new Uint8Array(bytes);
            console.log('Ed25519 seed:', Buffer.from(seed).toString('hex'));
            
            // Create keypair from seed
            const naclKeypair = nacl.sign.keyPair.fromSeed(seed);
            console.log('Nacl public key:', Buffer.from(naclKeypair.publicKey).toString('hex'));
            
            // Expected public key from test data
            const expectedPubKey = Buffer.from(addressData.users.alice.sui.publicKey).toString('hex');
            console.log('Expected public key:', expectedPubKey);
            
            if (Buffer.from(naclKeypair.publicKey).toString('hex') === expectedPubKey) {
                console.log('✅ Public keys match!');
                
                // Sign the message
                const message = 'NominalRegistryV2 on 31337 @ 0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f | name: alice-sui | chain: 2 | acct: 0x98f700eb470476028f52bbae6e71550d07d91428fdbe21c6a5dbf495404137b4 | nonce: 0 | exp: 3601';
                const messageBytes = Buffer.from(message, 'utf8');
                const signature = nacl.sign.detached(messageBytes, naclKeypair.secretKey);
                
                console.log('\n🔑 Sui signature for the exact message:');
                console.log(Buffer.from(signature).toString('hex'));
                return;
            } else {
                console.log('❌ Public keys do not match');
            }
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

decodeSuiKey();