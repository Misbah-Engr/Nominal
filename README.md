# Nominal

Wrong address transfer. Copying address everytime you want to receive payment in a wallet like it is necessary. Ever tried to remember all your wallet addresses across different blockchains? You can't. That's exactly why Nominal exists.

## What is this?

Nominal is a cross-chain naming service that lets you register one simple name (like "alice") and link it to your wallet addresses across multiple blockchains - Ethereum, Solana, Sui, Aptos, and NEAR. It is your universal crypto identity. Non-custodial wallets will integrate soon.

Instead of sharing `0x742d35Cc6F4F4F4F...` or `DRiP2Ln2P2P2P2P...`, you just tell people "send it to alice on Solana." and they're good to go.

## What's deployed?

We're live on Base Sepolia testnet:

- **NominalRegistryV2**: `0xBA038a80273c1B68148B95B70eC06C5567C05aD9` - Multi-chain naming registry
- **NominalUSD Faucet**: `0x7016FcE7411CE7759c516B8E2d6Fcc40910d2017` - Test token (NUSD) with 5-hour cooldown faucet

we will release the testnet webpage soon.

## How it works

1. **Register your name** - Pick something memorable 
2. **Link your wallets** - Connect addresses from any supported chain with cryptographic proof
3. **Share one name** - People can find all your addresses through one simple name

You can pay with ETH (0.001 ETH) or NominalUSD tokens (5 NUSD) on Base Sepolia. The faucet gives you 20 NUSD every 5 hours for testing.

## Tech stuff

- Built with Solidity 0.8.30
- Uses Foundry for development  
- On-chain Ed25519 signature verification for non-EVM chains using crypto-lib
- Cross-chain signature verification with crypto-lib (A library audited by Veridise and Crypto Experts. We want to get the part we used reaudited again before mainnet)
- EIP-712 signatures for EVM chains
- Multi-chain canonical account derivation (Sui uses blake2b, others use direct addressing)
- Supports referral fees (20% configurable for wallet providers)

## Supported chains

- Ethereum (and EVM chains)
- Solana  
- Sui
- Aptos
- NEAR

## Getting started

```bash
# Clone and setup
git clone https://github.com/Misbah-Engr/Nominal.git
cd Nominal
forge install

# Test it out
forge test

# Deploy (if you want your own instance)
forge script script/DeployBaseSepolia.s.sol --broadcast --verify
```


## Security

Every wallet signature is verified using the appropriate cryptographic scheme for each blockchain. We don't mess around with security - all validations are preserved even after optimization. 

**Important:** The contract only uses the safe verification functions from the crypto library. Dangerous functions that handle secret keys are excluded from production code, following the library's security guidelines. We will get audits soon.

## Contributing

Found a bug? Want to add a new chain? PRs welcome. Just keep it simple and don't break anything.

## License

MIT - do whatever you want with it.

---

*Built because managing multiple wallet addresses shouldn't be this hard.*
