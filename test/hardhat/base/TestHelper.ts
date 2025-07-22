import hre from 'hardhat';
import { EntryPoint } from '../../../typechain-types/@account-abstraction/contracts/core/EntryPoint';
import { Create2Factory } from '../../../src/Create2Factory';
import { AbiCoder, concat, ethers, hexlify } from 'ethers';
import { bytecode as EntryPointBytecode } from '@account-abstraction/contracts/artifacts/EntryPoint.json';
import { bytecode as SimpleAccountFactoryBytecode } from '@account-abstraction/contracts/artifacts/SimpleAccountFactory.json';
import {
  DkargoVerifyingPaymaster__factory,
  EntryPoint__factory,
  SimpleAccountFactory,
  SimpleAccountFactory__factory,
} from '../../../typechain-types';
import { ENTRY_POINT_V7 } from './Constant';

export async function setupWallets() {
  const [PAYMASTER_OWNER, PAYMASTER_SIGNER, DAPP_ACCOUNT, USER1, BUNDLER] = await hre.ethers.getSigners();
  return { PAYMASTER_OWNER, PAYMASTER_SIGNER, DAPP_ACCOUNT, USER1, BUNDLER };
}

export async function deployEntryPoint(signer: ethers.Signer): Promise<EntryPoint> {
  const create2factory = new Create2Factory(hre.ethers.provider, signer);
  const addr = await create2factory.deploy(
    EntryPointBytecode,
    '0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3', // slat
    process.env.COVERAGE != null ? 20e6 : 8e6,
  );

  return EntryPoint__factory.connect(addr, signer);
}

export async function deploySimpleAccountFactory(
  signer: ethers.Signer,
): Promise<SimpleAccountFactory> {
  const create2factory = new Create2Factory(hre.ethers.provider, signer);

  // Create bytecode with param
  const abiCoder = AbiCoder.defaultAbiCoder();
  const paramsEncoded = abiCoder.encode(['address'], [ENTRY_POINT_V7]);
  const deployCode = hexlify(concat([SimpleAccountFactoryBytecode, paramsEncoded]));

  const addr = await create2factory.deploy(deployCode, '0x', 6e6);

  return SimpleAccountFactory__factory.connect(addr, signer);
}

export async function deployDkargoVerifyingPaymasterContracts(owner:ethers.Signer, signer: ethers.Signer) {
  const create2factory = new Create2Factory(hre.ethers.provider, owner);
  const code = await hre.ethers.provider.getCode(ENTRY_POINT_V7);

  // for hardhat node
  if (code == '0x') {
    await create2factory.deploy(
      EntryPointBytecode,
      '0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3', // slat
      process.env.COVERAGE != null ? 20e6 : 8e6,
    );
  }

  const factory = await hre.ethers.getContractFactory('DkargoVerifyingPaymaster', owner);
  const _signer = await signer.getAddress();
  const _owner = await owner.getAddress();
  const { data } = await factory.getDeployTransaction(_owner, _signer, ENTRY_POINT_V7);
  const paymaster = await create2factory.deploy(data,"0x0000000000000000000000000000000000000000000000000000000000043371");
  
  return DkargoVerifyingPaymaster__factory.connect(paymaster, owner);
}
