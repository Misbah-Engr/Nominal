// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/NominalRegistry.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * Post-deployment configuration script.
 * Usage (example):
 *  forge script script/ConfigureRegistry.s.sol:ConfigureRegistryScript \
 *    --rpc-url $BASE_SEPOLIA_RPC --broadcast \
 *    --verify --etherscan-api-key $BASESCAN_API_KEY \
 *    -vvvv \
 *    -s "run(<registryAddress>,<tokenAddress>)"
 */
contract ConfigureRegistryScript is Script {
    function run(address registryAddr, address tokenAddr) external {
        uint256 pk = vm.envUint("DEPLOYER_KEY");
        vm.startBroadcast(pk);
        NominalRegistry reg = NominalRegistry(payable(registryAddr));

        // Set ETH fee = 0.001 ether
        reg.setEthFee(0.001 ether);
        // Allow token
        reg.setAllowedToken(tokenAddr, true);
        // Set token registration fee = 4 * 10^decimals (assume 18 decimals)
        reg.setRegistrationFeeForToken(tokenAddr, 4 ether);
        // Set referral fee percent for ETH (10%)
        reg.setETHReferralFeePercent(10);
        // Set referral fee amount in token (10% of 4 tokens = 0.4). Simpler to store an absolute amount.
        reg.setReferralFeeAmountInToken(tokenAddr, 4 ether / 10);

        vm.stopBroadcast();
    }
}
