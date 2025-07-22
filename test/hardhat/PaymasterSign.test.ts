import { loadFixture, time } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import { setupPaymasterTestEnvironment } from './base/TestBase';
import { AbiCoder, concat, parseEther, toBeArray } from 'ethers';
import {
  generatePackedUserOp,
  paymasterPostOpGasLimit,
  paymasterVerificationGasLimit,
} from './mock/userOp';
import { packUint } from '../../src/utils';
import { SimpleAccount__factory } from '../../typechain-types';

describe('DkargoVerifyingPaymaster', function () {
  async function setUp() {
    const env = await setupPaymasterTestEnvironment();

    const { PAYMASTER, PAYMASTER_OWNER, SIMPLE_ACCOUT_FACTORY, USER1, ENTRYPOINT } = env;

    /**
     * Deposit Paymaster
     */
    const value = parseEther('1');
    const tx = await PAYMASTER.connect(PAYMASTER_OWNER).deposit({ value });
    await tx.wait();

    async function getInitCode() {
      const i = SIMPLE_ACCOUT_FACTORY.getFunction('createAccount');
      const factoryData = await i.populateTransaction(USER1.address, '0');
      const factory = SIMPLE_ACCOUT_FACTORY.target;
      return concat([factory.toString(), factoryData.data]);
    }

    async function getSmartAccountSender() {
      return await SIMPLE_ACCOUT_FACTORY.getFunction('getAddress')(USER1.address, '0');
    }

    async function getSenderNonce(sender: string) {
      return await ENTRYPOINT.getNonce(sender, Date.now());
    }

    async function getExecuteCallData() {
      const i = SimpleAccount__factory.createInterface();
      return i.encodeFunctionData('execute', [USER1.address, 0n, '0x']);
    }

    async function getExecuteBatchCallData() {
      const i = SimpleAccount__factory.createInterface();
      return i.encodeFunctionData('executeBatch', [
        [USER1.address, USER1.address],
        [0n, 0n],
        ['0x', '0x'],
      ]);
    }

    return { getInitCode, getSmartAccountSender, getSenderNonce, getExecuteCallData,getExecuteBatchCallData , ...env };
  }

  describe('Execute UserOp with paymaster', function () {
    it('Should succeed when a UserOp is submitted with a valid Paymaster signature', async () => {
      const {
        PAYMASTER,
        PAYMASTER_SIGNER,
        USER1,
        ENTRYPOINT,
        BUNDLER,
        getInitCode,
        getSmartAccountSender,
        getSenderNonce,
        getExecuteCallData
      } = await loadFixture(setUp);

      const paymaster = PAYMASTER.target.toString();

      const initCode = await getInitCode();      
      const sender = await getSmartAccountSender();
      const nonce = await getSenderNonce(sender);
      const callData =  await getExecuteCallData()
      const { packedUserOp, validAfter, validUntil } = generatePackedUserOp(
        { sender, nonce, initCode, callData },
        paymaster,
        true,
      );

      const hash = await PAYMASTER.getHash(packedUserOp, validUntil, validAfter);
      const sig = await PAYMASTER_SIGNER.signMessage(toBeArray(hash));

      const coder = new AbiCoder();
      const paymasterData = concat([
        coder.encode(['uint48', 'uint48'], [validUntil, validAfter]),
        sig,
      ]);

      const paymasterAndData = concat([
        paymaster,
        packUint(paymasterVerificationGasLimit, paymasterPostOpGasLimit),
        paymasterData,
      ]);
      packedUserOp.paymasterAndData = paymasterAndData;

      const userHash = await ENTRYPOINT.getUserOpHash(packedUserOp);
      const userSig = await USER1.signMessage(toBeArray(userHash));
      packedUserOp.signature = userSig;

      const tx = await ENTRYPOINT.connect(BUNDLER).handleOps([packedUserOp], BUNDLER.address);
      await expect(tx).to.not.be.reverted;
    });
  });
  describe('ExecuteBatch UserOp with paymaster', function () {
    it('Should succeed when a UserOp is submitted with a valid Paymaster signature', async () => {
      const {
        PAYMASTER,
        PAYMASTER_SIGNER,
        USER1,
        ENTRYPOINT,
        BUNDLER,
        getInitCode,
        getSmartAccountSender,
        getSenderNonce,
        getExecuteBatchCallData
      } = await loadFixture(setUp);

      const paymaster = PAYMASTER.target.toString();

      const initCode = await getInitCode();
      const sender = await getSmartAccountSender();
      const nonce = await getSenderNonce(sender);
      const callData =  await getExecuteBatchCallData()
      const { packedUserOp, validAfter, validUntil } = generatePackedUserOp(
        { sender, nonce, initCode, callData },
        paymaster,
        true,
      );

      const hash = await PAYMASTER.getHash(packedUserOp, validUntil, validAfter);
      const sig = await PAYMASTER_SIGNER.signMessage(toBeArray(hash));

      const coder = new AbiCoder();
      const paymasterData = concat([
        coder.encode(['uint48', 'uint48'], [validUntil, validAfter]),
        sig,
      ]);

      const paymasterAndData = concat([
        paymaster,
        packUint(paymasterVerificationGasLimit, paymasterPostOpGasLimit),
        paymasterData,
      ]);
      packedUserOp.paymasterAndData = paymasterAndData;

      const userHash = await ENTRYPOINT.getUserOpHash(packedUserOp);
      const userSig = await USER1.signMessage(toBeArray(userHash));
      packedUserOp.signature = userSig;

      const tx = await ENTRYPOINT.connect(BUNDLER).handleOps([packedUserOp], BUNDLER.address);
      await expect(tx).to.not.be.reverted;
    });
  });
});
