#!/bin/bash
set -e

echo "=== Nominal Frontend Build Test ==="
cd /workspaces/Nominal/frontend

echo "Step 1: Cleaning up..."
rm -rf node_modules package-lock.json .next

echo "Step 2: Installing dependencies..."
npm install

echo "Step 3: Building project..."
npm run build

echo "Step 4: Starting development server..."
npm run dev