/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  networks: {
    hardhat: {
      hardfork: "osaka",
      chainId: 2025,
      blockGasLimit: 16777216,
      gasPrice: 0,
      initialBaseFeePerGas: 0,
      throwOnTransactionFailures: false,
      throwOnCallFailures: false,
      allowBlocksWithSameTimestamp: true
    },
  },
  solidity: "0.8.23",
};
