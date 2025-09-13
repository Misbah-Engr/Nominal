# Wallet Provider Integration Guide

## Overview

The Nominal Registry enables wallet providers to resolve human-readable names (like "alice") to wallet addresses across multiple blockchains. Users can register their wallet addresses under a single name and wallet providers can then resolve this name to the appropriate address for any supported chain.

## Supported Chains

- **EVM** (Chain ID: 0) - Ethereum, Polygon, BSC, etc.
- **Solana** (Chain ID: 1) 
- **Sui** (Chain ID: 2)
- **Aptos** (Chain ID: 3)

## Integration Methods

### 1. Basic Resolution (Most Common)

```solidity
// Resolve a name to an address on a specific chain
bytes memory address = registry.resolveName("alice", CHAIN_SOLANA);
if (address.length > 0) {
    // Send tokens to this address
} else {
    // Name not registered on this chain, ask user for address
}
```

### 2. Chain-Specific Convenience Functions

```solidity
// Direct resolution for each chain
address evmAddr = registry.resolveToEVM("alice");
bytes memory solanaAddr = registry.resolveToSolana("alice");
bytes memory suiAddr = registry.resolveToSui("alice");
bytes memory aptosAddr = registry.resolveToAptos("alice");
```

### 3. Multi-Chain Resolution (Portfolio Apps)

```solidity
// Get all addresses for a name across all chains
(address evm, bytes memory sol, bytes memory sui, bytes memory apt) = 
    registry.resolveAllChains("alice");

// Check which chains are available
if (evm != address(0)) {
    // User has EVM address
}
if (sol.length > 0) {
    // User has Solana address  
}
// etc.
```

### 4. Name Validation

```solidity
// Check if a name is registered at all
bool exists = registry.isNameRegistered("alice");

// Check specific chain availability
(bool hasEVM, bool hasSolana, bool hasSui, bool hasAptos) = 
    registry.getRegistrationStatus("alice");
```

### 5. Reverse Lookup

```solidity
// Get the human name for a wallet address
string memory name = registry.reverseLookup(bob);
string memory chainSpecificName = registry.reverseLookup(CHAIN_SOLANA, solanaAddress);
```

## Use Cases

### Token Transfers
```
User Input: "Send 100 USDC to alice on Solana"
1. Call registry.resolveToSolana("alice")
2. If result.length > 0, use that address
3. If empty, prompt user to enter address manually
```

### Cross-Chain Bridges
```
User Input: "Bridge ETH to alice on Sui"
1. Call registry.resolveToSui("alice")
2. Use resolved address as bridge destination
3. Handle failure gracefully if name not found
```

### Portfolio Tracking
```
User Input: "Show balances for alice"
1. Call registry.resolveAllChains("alice")
2. Query balances on each chain where address exists
3. Display consolidated portfolio
```

### Transaction History
```
Incoming Transaction: from 0x1234...
1. Call registry.reverseLookup(address)
2. If name found, display "from alice" instead of raw address
3. Improves UX with human-readable names
```

### DEX Interfaces
```
Trade Event: User traded with 0x1234...
1. Call registry.reverseLookup(address)
2. Display "Trade with alice" if name found
3. Fall back to truncated address if not
```

## JavaScript/TypeScript Integration

```typescript
// Contract interaction example
const registry = new ethers.Contract(REGISTRY_ADDRESS, REGISTRY_ABI, provider);

async function resolveNameToAddress(name: string, chainId: number): Promise<string | null> {
    try {
        const address = await registry.resolveName(name, chainId);
        return address.length > 0 ? address : null;
    } catch (error) {
        console.error('Resolution failed:', error);
        return null;
    }
}

async function sendTokensToName(recipientName: string, amount: string, chainId: number) {
    const address = await resolveNameToAddress(recipientName, chainId);
    
    if (address) {
        // Proceed with token transfer to resolved address
        await tokenContract.transfer(address, amount);
        console.log(`Sent ${amount} tokens to ${recipientName} at ${address}`);
    } else {
        // Prompt user to enter address manually
        console.log(`Name ${recipientName} not found on chain ${chainId}`);
    }
}

async function showPortfolio(userName: string) {
    const addresses = await registry.resolveAllChains(userName);
    
    const portfolio = {};
    if (addresses[0] !== ethers.constants.AddressZero) {
        portfolio.ethereum = await getEthereumBalance(addresses[0]);
    }
    if (addresses[1].length > 0) {
        portfolio.solana = await getSolanaBalance(addresses[1]);
    }
    // ... etc for other chains
    
    return portfolio;
}
```

## Error Handling

Always handle these cases gracefully:

1. **Name not found**: Prompt user to enter address manually
2. **Chain not supported**: Show available chains for the name
3. **Network errors**: Retry with exponential backoff
4. **Invalid names**: Validate before calling contract

## Gas Optimization

- Cache resolution results for recent lookups
- Use `getRegistrationStatus()` to check availability before calling individual chain resolvers
- Batch multiple lookups when possible

## Security Considerations

- Always verify the registry contract address
- The registry is immutable - names and addresses cannot be changed once registered
- Consider the payment requirements for registration when building registration flows
- Validate that resolved addresses are correctly formatted for the target chain

## Contract Address

The Nominal Registry is deployed at: `[TO BE FILLED WHEN DEPLOYED]`

## Support

For integration support, please contact the Nominal team or refer to the full documentation.