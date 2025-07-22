import { setupWallets, deployEntryPoint, deploySimpleAccountFactory, deployDkargoVerifyingPaymasterContracts } from "./TestHelper";

export async function setupPaymasterTestEnvironment() {
  const { PAYMASTER_OWNER, PAYMASTER_SIGNER, DAPP_ACCOUNT, USER1, BUNDLER } = await setupWallets();

  const ENTRYPOINT = await deployEntryPoint(USER1);
  const SIMPLE_ACCOUT_FACTORY = await deploySimpleAccountFactory(USER1);

  const PAYMASTER = await deployDkargoVerifyingPaymasterContracts(PAYMASTER_OWNER, PAYMASTER_SIGNER)
  return {
    BUNDLER,
      PAYMASTER_OWNER,
      PAYMASTER_SIGNER,
      DAPP_ACCOUNT,
      USER1,
      ENTRYPOINT,
      SIMPLE_ACCOUT_FACTORY,
      PAYMASTER
  };
}
