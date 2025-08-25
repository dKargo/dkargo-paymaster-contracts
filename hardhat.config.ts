import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import "@nomicfoundation/hardhat-foundry";
import { ethers } from 'ethers';
import dotenv from 'dotenv';
dotenv.config();

let privateKey = ethers.keccak256(ethers.toUtf8Bytes('paymaster'));
privateKey = process.env.PRIVATE_KEY || privateKey;

let providerUrl = 'http://127.0.0.1:8545';
providerUrl = process.env.PROVIDER_URL || providerUrl;

function getNetwork(url: string): {
  url: string;
  accounts: string[];
} {
  
  return {
    url,
    accounts: [privateKey],
  };
}

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: '0.8.23',
        settings: { optimizer: { enabled: true, runs: 1000000 },viaIR: true },
      },
      {
        version: '0.8.28',
        settings: { optimizer: { enabled: true, runs: 1000000 }, viaIR: true },
      },
      {
        version: '0.8.20',
      },
      {
        version: '0.8.13',
      },
    ],
    settings: {
      optimizer: { enabled: true, runs: 1000 },
      viaIR: true,
    },
  },
  networks: {
    localhost: getNetwork('http://127.0.0.1:8545'),
    custom: getNetwork(providerUrl),
    hardhat: {
      chainId: 1337,
    },
  },
  mocha: {
    timeout: 10000,
  },
};

export default config;
