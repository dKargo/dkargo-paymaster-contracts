import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import hre from 'hardhat';
import { setupPaymasterTestEnvironment } from './base/TestBase';
import { ENTRY_POINT_V7 } from './base/Constant';
import { getAddress, parseEther, Signer, Wallet } from 'ethers';
import { DkargoVerifyingPaymaster, EntryPoint } from '../../typechain-types';

describe('DkargoVerifyingPaymaster', function () {
  async function setUp() {
    return await setupPaymasterTestEnvironment();
  }

  describe('Deployment', function () {
    it('Should set the right `Owner`', async function () {
      const { PAYMASTER, PAYMASTER_OWNER } = await loadFixture(setUp);
      const owner = await PAYMASTER.owner();
      expect(owner).to.equal(PAYMASTER_OWNER.address);
    });
    it('Should set the right `paymasterSigner`', async function () {
      const { PAYMASTER, PAYMASTER_SIGNER } = await loadFixture(setUp);
      const paymasterSigner = await PAYMASTER.getSigner();
      expect(paymasterSigner).to.equal(PAYMASTER_SIGNER.address);
    });
    it('Should set the right `EntryPoint`', async function () {
      const { PAYMASTER, ENTRYPOINT } = await loadFixture(setUp);
      const entryPoint1 = await PAYMASTER.entryPoint();

      const entryPoint2 = await ENTRYPOINT.getAddress();
      expect(entryPoint1.toLocaleLowerCase()).to.equal(entryPoint2.toLocaleLowerCase());
    });
  });

  describe('Deposit', function () {
    it('Should increase after a `deposit`', async function () {
      const { PAYMASTER, PAYMASTER_OWNER } = await loadFixture(setUp);
      const value = parseEther('1');

      const tx = await PAYMASTER.connect(PAYMASTER_OWNER).deposit({ value });
      await tx.wait();
      const depositAmount = await PAYMASTER.getDeposit();

      expect(depositAmount).to.equal(value);
    });

    it('Should emit event on `Deposited`', async function () {
      const { PAYMASTER, PAYMASTER_OWNER, ENTRYPOINT } = await loadFixture(setUp);
      const value = parseEther('1');
      const addr = await PAYMASTER.getAddress();

      const tx = await PAYMASTER.connect(PAYMASTER_OWNER).deposit({ value });

      await expect(tx).to.emit(ENTRYPOINT, 'Deposited').withArgs(getAddress(addr), value);
    });
  });

  describe('Withdraw', function () {
    let PAYMASTER: DkargoVerifyingPaymaster, PAYMASTER_OWNER: Signer, ENTRYPOINT:EntryPoint;

    before('before', async () => {
      const env = await loadFixture(setUp);
      PAYMASTER = env.PAYMASTER;
      PAYMASTER_OWNER = env.PAYMASTER_OWNER;
      ENTRYPOINT = env.ENTRYPOINT

      const value = parseEther('1');
      const tx = await PAYMASTER.connect(PAYMASTER_OWNER).deposit({ value });
      await tx.wait();
    });

    it('Should decrease after a `withdrawTo`', async function () {
      const amount = parseEther('0.1');
      const withdrawAddress = Wallet.createRandom().address;

      const beforeWithdrawBalance = await PAYMASTER.getDeposit();
      const beforeWithdrawAddressBalance = await hre.ethers.provider.getBalance(withdrawAddress);

      const tx = await PAYMASTER.connect(PAYMASTER_OWNER).withdrawTo(withdrawAddress, amount);
      await tx.wait();
      const afterWithdrawBalance = await PAYMASTER.getDeposit();
      const afterWithdrawAddressBalance = await hre.ethers.provider.getBalance(withdrawAddress);

      expect(afterWithdrawBalance).to.equal(beforeWithdrawBalance - amount);
      expect(afterWithdrawAddressBalance).to.equal(beforeWithdrawAddressBalance + amount);
    });

    it('Should emit event on `Withdraw`', async function () {
      const amount = parseEther('0.1');
      const withdrawAddress = Wallet.createRandom().address;
      const addr = await PAYMASTER.getAddress()

      const tx = await PAYMASTER.connect(PAYMASTER_OWNER).withdrawTo(withdrawAddress, amount);
      await tx.wait();
      await expect(tx).to.emit(ENTRYPOINT, 'Withdrawn').withArgs(getAddress(addr), getAddress(withdrawAddress), amount);
    });
  });

  // describe('Paymaster Signature', function() {
  //   it("verify",async() => {
  //           const { PAYMASTER, PAYMASTER_OWNER } = await loadFixture(setUp);
            
  //     PAYMASTER.validatePaymasterUserOp({},"",null)
  //   })
  // })
});
