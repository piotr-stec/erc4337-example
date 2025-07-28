require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  defaultNetwork: "localhost",
  // networks: {
  //   arb: {
  //     url: process.env.RPC_URL,
  //     accounts: [process.env.PRIVATE_KEY],
  //   },
  // },
  solidity: {
    compilers: [
      {
        version: "0.8.19",
        settings: {
          optimizer: {
            enabled: true,
            runs: 1000,
          },
        },
      },
      {
        version: "0.8.21", 
        settings: {
          optimizer: {
            enabled: true,
            runs: 1000,
          },
        },
      },
      {
        version: "0.8.27",
        settings: {
          optimizer: {
            enabled: true,
            runs: 1000,
          },
        },
      }
    ]
  },
};
