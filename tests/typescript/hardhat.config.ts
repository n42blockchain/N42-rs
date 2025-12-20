import "hardhat-jest";
import 'dotenv/config'; // Loads .env file
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: "0.6.11",
      },
      {
        version: "0.8.28"
      }
    ]
  },
  networks: {
    localdevnet: {
      url: "http://127.0.0.1:8545",
      accounts: [process.env.PRIVATE_KEY],
      chainId: 1143,
    },

    localtestnet: {
      url: "http://127.0.0.1:8545",
      accounts: [process.env.PRIVATE_KEY],
      chainId: 1142,
    },

    testnet1: {
      url: "http://5.161.252.59:8545/",
      accounts: [process.env.PRIVATE_KEY],
      chainId: 1142,
    },
  },
};

export default config;
