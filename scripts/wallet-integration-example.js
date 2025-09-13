/**
 * @title Wallet Provider Integration Guide
 * @notice Complete example of how wallet providers integrate with NominalRegistry
 */

import { ethers } from 'ethers';

// Contract ABI (excerpt - only resolution functions)
const NOMINAL_REGISTRY_ABI = [
    "function resolveName(string name, uint8 chainId) view returns (bytes)",
    "function resolveToEVM(string name) view returns (address)",
    "function resolveToSolana(string name) view returns (bytes)",
    "function resolveToSui(string name) view returns (bytes)",
    "function resolveToAptos(string name) view returns (bytes)",
    "function resolveAllChains(string name) view returns (address, bytes, bytes, bytes)",
    "function reverseLookup(uint8 chainId, bytes walletAddress) view returns (string)",
    "function isNameRegistered(string name) view returns (bool)",
    "function getRegistrationStatus(string name) view returns (bool, bool, bool, bool)"
];

// Chain IDs
const CHAINS = {
    EVM: 0,
    SOLANA: 1,
    SUI: 2,
    APTOS: 3
};

// Deployed contract address (example)
const REGISTRY_ADDRESS = "0x..."; // Replace with actual deployed address

class WalletNameResolver {
    constructor(provider, registryAddress = REGISTRY_ADDRESS) {
        this.provider = provider;
        this.registry = new ethers.Contract(registryAddress, NOMINAL_REGISTRY_ABI, provider);
    }

    /**
     * 🎯 PRIMARY USE CASE: Resolve name to address for token transfers
     */
    async resolveForTransfer(name, chainId) {
        try {
            console.log(`🔍 Resolving "${name}" for chain ${chainId}...`);
            
            const addressBytes = await this.registry.resolveName(name, chainId);
            
            if (addressBytes === '0x' || addressBytes.length <= 2) {
                throw new Error(`Name "${name}" not registered on chain ${chainId}`);
            }
            
            // Convert bytes to appropriate format for each chain
            let formattedAddress;
            switch (chainId) {
                case CHAINS.EVM:
                    // For EVM, convert bytes to address format
                    formattedAddress = ethers.getAddress('0x' + addressBytes.slice(-40));
                    break;
                case CHAINS.SOLANA:
                case CHAINS.SUI:
                case CHAINS.APTOS:
                    // For other chains, keep as hex string (32 bytes)
                    formattedAddress = addressBytes;
                    break;
                default:
                    throw new Error(`Unsupported chain ID: ${chainId}`);
            }
            
            console.log(`✅ Resolved to: ${formattedAddress}`);
            return formattedAddress;
            
        } catch (error) {
            console.error(`❌ Resolution failed:`, error.message);
            throw error;
        }
    }

    /**
     * 💼 MULTI-CHAIN WALLET: Get all addresses for portfolio view
     */
    async getMultiChainProfile(name) {
        try {
            console.log(`📊 Getting multi-chain profile for "${name}"...`);
            
            const [evmAddr, solanaAddr, suiAddr, aptosAddr] = await this.registry.resolveAllChains(name);
            
            const profile = {
                name: name,
                addresses: {
                    evm: evmAddr !== ethers.ZeroAddress ? evmAddr : null,
                    solana: solanaAddr !== '0x' ? solanaAddr : null,
                    sui: suiAddr !== '0x' ? suiAddr : null,
                    aptos: aptosAddr !== '0x' ? aptosAddr : null
                }
            };
            
            console.log(`✅ Profile:`, profile);
            return profile;
            
        } catch (error) {
            console.error(`❌ Profile lookup failed:`, error.message);
            throw error;
        }
    }

    /**
     * 🔄 REVERSE LOOKUP: Get name from wallet address
     */
    async getNameFromAddress(chainId, walletAddress) {
        try {
            console.log(`🔍 Reverse lookup for ${walletAddress} on chain ${chainId}...`);
            
            // Convert address to bytes format for the contract
            let addressBytes;
            if (chainId === CHAINS.EVM) {
                // For EVM, convert address to bytes32
                addressBytes = ethers.zeroPadValue(walletAddress, 32);
            } else {
                // For other chains, address should already be in bytes format
                addressBytes = walletAddress;
            }
            
            const name = await this.registry.reverseLookup(chainId, addressBytes);
            
            if (!name || name === '') {
                console.log(`❌ No name registered for this address`);
                return null;
            }
            
            console.log(`✅ Address belongs to: "${name}"`);
            return name;
            
        } catch (error) {
            console.error(`❌ Reverse lookup failed:`, error.message);
            throw error;
        }
    }

    /**
     * ✅ VALIDATION: Check if name exists before showing UI
     */
    async validateName(name) {
        try {
            const isRegistered = await this.registry.isNameRegistered(name);
            
            if (!isRegistered) {
                return {
                    valid: false,
                    message: `Name "${name}" is not registered on any chain`
                };
            }
            
            const [hasEVM, hasSolana, hasSui, hasAptos] = await this.registry.getRegistrationStatus(name);
            
            return {
                valid: true,
                chains: {
                    evm: hasEVM,
                    solana: hasSolana,
                    sui: hasSui,
                    aptos: hasAptos
                }
            };
            
        } catch (error) {
            return {
                valid: false,
                message: `Validation failed: ${error.message}`
            };
        }
    }

    /**
     * 🌉 CROSS-CHAIN BRIDGE: Find destination address
     */
    async getBridgeDestination(name, targetChain) {
        try {
            console.log(`🌉 Finding bridge destination for "${name}" on chain ${targetChain}...`);
            
            const destinationAddress = await this.resolveForTransfer(name, targetChain);
            
            return {
                name: name,
                targetChain: targetChain,
                destinationAddress: destinationAddress,
                canBridge: true
            };
            
        } catch (error) {
            console.log(`❌ Cannot bridge to ${name} on chain ${targetChain}: ${error.message}`);
            
            // Suggest alternative chains
            const profile = await this.getMultiChainProfile(name);
            const availableChains = Object.keys(profile.addresses).filter(
                chain => profile.addresses[chain] !== null
            );
            
            return {
                name: name,
                targetChain: targetChain,
                destinationAddress: null,
                canBridge: false,
                availableChains: availableChains
            };
        }
    }
}

/**
 * 📱 EXAMPLE WALLET INTEGRATION
 */
class ExampleWallet {
    constructor(provider) {
        this.resolver = new WalletNameResolver(provider);
    }

    /**
     * User wants to send tokens to "alice" on Solana
     */
    async sendTokens(recipientName, amount, tokenAddress, chainId = CHAINS.SOLANA) {
        try {
            console.log(`💸 Sending ${amount} tokens to "${recipientName}" on chain ${chainId}...`);
            
            // Step 1: Resolve name to address
            const recipientAddress = await this.resolver.resolveForTransfer(recipientName, chainId);
            
            // Step 2: Prepare transaction (chain-specific logic)
            let transaction;
            switch (chainId) {
                case CHAINS.EVM:
                    transaction = {
                        to: tokenAddress,
                        data: this.encodeERC20Transfer(recipientAddress, amount)
                    };
                    break;
                case CHAINS.SOLANA:
                    transaction = {
                        type: 'solana_token_transfer',
                        recipient: recipientAddress,
                        amount: amount,
                        tokenMint: tokenAddress
                    };
                    break;
                // Add other chains...
            }
            
            console.log(`✅ Transaction prepared for ${recipientAddress}`);
            return transaction;
            
        } catch (error) {
            console.error(`❌ Send failed:`, error.message);
            throw error;
        }
    }

    /**
     * Show transaction history with human names
     */
    async getTransactionHistory(userAddress, chainId) {
        // Get raw transaction history from blockchain
        const rawTransactions = await this.getRawTransactions(userAddress, chainId);
        
        // Enhance with human names
        const enhancedTransactions = await Promise.all(
            rawTransactions.map(async (tx) => {
                try {
                    const fromName = await this.resolver.getNameFromAddress(chainId, tx.from);
                    const toName = await this.resolver.getNameFromAddress(chainId, tx.to);
                    
                    return {
                        ...tx,
                        fromName: fromName || tx.from,
                        toName: toName || tx.to,
                        displayFrom: fromName ? `${fromName} (${tx.from.slice(0,6)}...)` : tx.from,
                        displayTo: toName ? `${toName} (${tx.to.slice(0,6)}...)` : tx.to
                    };
                } catch (error) {
                    return tx; // Return original if name lookup fails
                }
            })
        );
        
        return enhancedTransactions;
    }

    // Helper methods...
    encodeERC20Transfer(to, amount) {
        const iface = new ethers.Interface(["function transfer(address,uint256)"]);
        return iface.encodeFunctionData("transfer", [to, amount]);
    }

    async getRawTransactions(address, chainId) {
        // Implementation depends on chain and data provider
        return [];
    }
}

/**
 * 🚀 USAGE EXAMPLES
 */
async function examples() {
    // Setup (you need an Ethereum provider)
    const provider = new ethers.JsonRpcProvider("https://eth-mainnet.alchemyapi.io/v2/YOUR-API-KEY");
    const wallet = new ExampleWallet(provider);
    
    try {
        // Example 1: Send tokens by name
        await wallet.sendTokens("alice", "100", "0xTokenAddress...", CHAINS.SOLANA);
        
        // Example 2: Multi-chain profile
        const resolver = new WalletNameResolver(provider);
        const profile = await resolver.getMultiChainProfile("alice");
        
        // Example 3: Validate before sending
        const validation = await resolver.validateName("alice");
        if (validation.valid) {
            console.log("✅ Name is valid, user can send");
        }
        
        // Example 4: Cross-chain bridge
        const bridgeInfo = await resolver.getBridgeDestination("alice", CHAINS.SUI);
        if (bridgeInfo.canBridge) {
            console.log(`✅ Can bridge to ${bridgeInfo.destinationAddress}`);
        }
        
    } catch (error) {
        console.error("Example failed:", error);
    }
}

export {
    WalletNameResolver,
    ExampleWallet,
    CHAINS,
    NOMINAL_REGISTRY_ABI,
    examples
};