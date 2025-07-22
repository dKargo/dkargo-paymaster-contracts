import { Create2Factory } from '../src/Create2Factory';
import { ENTRY_POINT_V7 } from '../test/hardhat/base/Constant';
import { bytecode as EntryPointBytecode } from '@account-abstraction/contracts/artifacts/EntryPoint.json';
import hre from 'hardhat';

async function main() {
  const [signer] = await hre.ethers.getSigners();

  const {chainId} = await hre.ethers.provider.getNetwork()

  if(chainId == 1337n || chainId == 31337n) {
    const create2factory = new Create2Factory(hre.ethers.provider, signer);
    const code = await hre.ethers.provider.getCode(ENTRY_POINT_V7);
  
    // for hardhat or local node
    if (code == '0x') {
      await create2factory.deploy(
        EntryPointBytecode,
        '0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3', // slat
        process.env.COVERAGE != null ? 20e6 : 8e6,
      );
    }
  }

  
  const factory = await hre.ethers.getContractFactory('DkargoVerifyingPaymaster', signer);
  const paymaster = await factory.deploy(signer.address,signer.address,ENTRY_POINT_V7)
  await paymaster.waitForDeployment()
  const addr = await paymaster.getAddress()

  console.log('==DkargoVerifyingPaymaster addr=', addr)
}

void main();
