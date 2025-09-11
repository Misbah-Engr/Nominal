# Nominal

Wrong address transfer. Copying address everytime you want to receive payment in a wallet like it is necessary. Ever tried to remember all your wallet addresses across different blockchains? You can't. That's exactly why Nominal exists.

## What is this?

Nominal is a cross-chain naming service that lets you register one simple name (like "alice") and link it to your wallet addresses across multiple blockchains - Ethereum, Solana, Sui, Aptos, and NEAR. It is your universal crypto identity. Non-custodial wallets will integrate soon.

Instead of sharing `0x742d35Cc6F4F4F4F...` or `DRiP2Ln2P2P2P2P...`, you just tell people "send it to alice on Solana." and they're good to go.

## What's deployed?

We're live on Base Sepolia testnet:

- **Registry Contract**: `0xa30481F5624247e0e532502D79C05B46bD41ad33`
- **NMNL Token**: `0xf3dEceEa57A2335930902d40b77bB60c055e4CA7`
we will release the testnet webpage soon.

## How it works

1. **Register your name** - Pick something memorable 
2. **Link your wallets** - Connect addresses from any supported chain
3. **Share one name** - People can find all your addresses through one simple name

You can pay with ETH or any supported ERC20 token on Base.

## Tech stuff

- Built with Solidity 0.8.19
- Uses Foundry for development
- Cross-chain signature verification with crypto-lib (A library audited by Veridise and Crypto Experts. We want to get the part we used reaudited again before mainnet)
- EIP-712 signatures for security
- Supports referral fees (because why not share the love?)

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
forge script script/DeployRegistry.s.sol --broadcast --verify
```


## Security

Every wallet signature is verified using the appropriate cryptographic scheme for each blockchain. We don't mess around with security - all validations are preserved even after optimization. We will get audits soon.

## Contributing

Found a bug? Want to add a new chain? PRs welcome. Just keep it simple and don't break anything.

## License

MIT - do whatever you want with it.

---

*Built because managing multiple wallet addresses shouldn't be this hard.*
