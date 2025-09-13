// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import "lib/openzeppelin-contracts/contracts/access/Ownable.sol";

/**
 * @title NominalUSDFaucet
 * @dev Faucet token for testing purposes with cooldown mechanism
 */
contract NominalUSDFaucet is ERC20, Ownable {
    
    uint256 public constant CLAIM_AMOUNT = 20 * 10**18; // 20 tokens
    uint256 public constant COOLDOWN_PERIOD = 5 hours;
    
    mapping(address => uint256) public lastClaimTime;
    
    event TokensClaimed(address indexed user, uint256 amount);
    
    constructor() ERC20("Nominal USD", "NUSD") Ownable(msg.sender) {
        // Mint initial supply to owner for distribution
        _mint(msg.sender, 1000000 * 10**18); // 1M tokens to owner
    }

    /**
     * @dev Faucet function - allows users to claim tokens with cooldown
     */
    function claimTokens() external {
        require(
            lastClaimTime[msg.sender] + COOLDOWN_PERIOD <= block.timestamp,
            "Cooldown period not met"
        );
        
        lastClaimTime[msg.sender] = block.timestamp;
        _mint(msg.sender, CLAIM_AMOUNT);
        
        emit TokensClaimed(msg.sender, CLAIM_AMOUNT);
    }
    
    /**
     * @dev Check time remaining until next claim
     */
    function timeUntilNextClaim(address user) external view returns (uint256) {
        uint256 nextClaimTime = lastClaimTime[user] + COOLDOWN_PERIOD;
        if (nextClaimTime <= block.timestamp) {
            return 0;
        }
        return nextClaimTime - block.timestamp;
    }
    
    /**
     * @dev Check if user can claim tokens
     */
    function canClaim(address user) external view returns (bool) {
        return lastClaimTime[user] + COOLDOWN_PERIOD <= block.timestamp;
    }

    /**
     * @dev Owner can mint tokens for initial distribution or emergencies
     */
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /**
     * @dev Burn function for testing
     */
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /**
     * @dev Burn from specific address for testing
     */
    function burnFrom(address from, uint256 amount) external {
        _burn(from, amount);
    }
}
