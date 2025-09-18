#!/bin/bash
cd /workspaces/Nominal/frontend

echo "Cleaning up..."
rm -rf node_modules package-lock.json

echo "Installing core dependencies..."
npm install viem@^2.21.0 js-sha3@^0.8.0 bs58@^5.0.0

echo "Installing Solana dependencies..."
npm install @solana/web3.js@^1.95.0 @solana/wallet-adapter-base@^0.9.23

echo "Installing blake2b..."
npm install blake2b-wasm@^2.4.0

echo "Installing other dependencies..."
npm install

echo "Starting development server..."
npm run dev