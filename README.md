# Dkargo Paymaster Verifying Contracts

[![Foundry](https://img.shields.io/badge/Solidity-e6e6e6?style=for-the-badge-333333&logo=solidity&logoColor=black)]()
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFBD10.svg)](https://getfoundry.sh/)
[![Hardhat](https://img.shields.io/badge/Built%20with-Hardhat-4F00A3.svg)](https://hardhat.org/)

This repository contains an ERC-4337 paymaster implementation that allows a paymaster operator to sponsor the gas fees of users of Dapp or blockchain service using DKA balance.

## Features
- ✅ Sponsors the user`s transaction fees paid to Bundler.
- ✅ Compatible with EntryPoint v0.7.
- ✅ Verifies the paymaster's signature and relays the result to the EntryPoint.
- ✅ Has a paymaster signer & owner roles, only owners are allowed to withdraw the funds from contract / entryPoint.

## Core Contracts
| Contract                   	| Description                                                                                                                                                                                                                        	|
|----------------------------	|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|
| `BasePaymaster`            	| [eth-infinitism's helper class](https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/BasePaymaster.sol) for creating paymaster.                                                                       	|
| `PaymasterSigner`          	| Helper class to verify paymaster ECDSA signatures using [@openzeppelin/ECDSA.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/32e7a6ffbc5af9ab0e6dfdbc58508511d0f0b4a2/contracts/utils/cryptography/ECDSA.sol#L2). 	|
| `DkargoVerifyingPaymaster` 	| Verifying paymaster implementation (for EntryPoint v0.7).                                                                                                                                                                          	|

## Getting Started
### Prerequisites
- Node.js (v22.x or later)
- Foundry (Refer to [Foundry installation instructions](https://getfoundry.sh/introduction/installation))

### Installation
1. Clone the repository:
    ```
    git clone https://github.com/dKargo/dkargo-paymaster-contracts.git

    cd dkargo-paymaster-contracts
    ```
2. Install dependencies:
    ```
    npm i
    ```
3. For Deploy, Set the values shown in `.env.example` as environmental variables. To copy it into a `.env` file:
    ```
    cp .env.example .env
    ```

    <br/>

    You'll still need to edit some variables, i.e., `DEPLOYER_PRIVATE_KEY` and `PROVIDER_URL`.

    ```
    # Your private key
    DEPLOYER_PRIVATE_KEY=

    # The Provider RPC
    PROVIDER_URL=
    ```
4. Deploy Paymaster contract
    ```
    npx hardhat run ./deploy/deploy.ts
    ```

### Test And Coverage
#### Test
```
# run hardhat & foundry test
npm run test

# run foundry test for --verbosity...
npm run test:foundry -- -vvvv
```

#### Coverage
> Achieving Test coverage: 100% - 🚀

```
forge coverage --no-match-coverage test/foundry/base

╭----------------------------------------+-----------------+-----------------+---------------+-----------------╮
| File                                   | % Lines         | % Statements    | % Branches    | % Funcs         |
+==============================================================================================================+
| contracts/DkargoVerifyingPaymaster.sol | 100.00% (19/19) | 100.00% (17/17) | 100.00% (3/3) | 100.00% (5/5)   |
|----------------------------------------+-----------------+-----------------+---------------+-----------------|
| contracts/base/BasePaymaster.sol       | 100.00% (27/27) | 100.00% (17/17) | 100.00% (4/4) | 100.00% (12/12) |
|----------------------------------------+-----------------+-----------------+---------------+-----------------|
| contracts/common/PaymasterSigner.sol   | 100.00% (9/9)   | 100.00% (11/11) | 100.00% (1/1) | 100.00% (3/3)   |
|----------------------------------------+-----------------+-----------------+---------------+-----------------|
| Total                                  | 100.00% (55/55) | 100.00% (45/45) | 100.00% (8/8) | 100.00% (20/20) |
╰----------------------------------------+-----------------+-----------------+---------------+-----------------╯
```

#### Open Coverage Report HTML
```
npm run report
```

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
