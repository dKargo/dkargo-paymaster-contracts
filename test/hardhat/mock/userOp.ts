import { AddressLike, concat, toBeHex } from 'ethers';
import { PackedUserOperationStruct } from '../../../typechain-types/contracts/DkargoVerifyingPaymaster';
import { packUint } from '../../../src/utils';

const MOCK_INIT_PACKED_USEROP: PackedUserOperationStruct = {
  sender: '0xa3aBDC7f6334CD3EE466A115f30522377787c024',
  nonce: '32332403905572026968531932282880',
  initCode: '0x',
  callData:
    '0x',
  accountGasLimits: '0x00000000000000000000000000035c9c00000000000000000000000000002bb8',
  preVerificationGas: '50652',
  gasFees: '0x000000000000000000000000001e8480000000000000000000000000001e8490',
  paymasterAndData: '0x',
  signature: '0x',
};

export const paymasterPostOpGasLimit = toBeHex(40000);
export const paymasterVerificationGasLimit = toBeHex(30000);

export function generatePackedUserOp(
  _packedUserOp: Pick<PackedUserOperationStruct, 'sender' | 'nonce' | 'initCode'| 'callData'>,
  paymaster: AddressLike,
  isInit: boolean,
) {
  const date = new Date();
  const validUntil = Number((date.valueOf() / 1000).toFixed(0)) + 600;
  const validAfter = Number((date.valueOf() / 1000).toFixed(0)) - 60;

  let packedUserOp: PackedUserOperationStruct = {
    ...MOCK_INIT_PACKED_USEROP,
    ..._packedUserOp,
    initCode: isInit ? _packedUserOp.initCode : '0x',
    paymasterAndData: concat([
      paymaster.toString(),
      packUint(paymasterVerificationGasLimit, paymasterPostOpGasLimit),
    ]),
  };


  return {
    packedUserOp,
    validUntil,
    validAfter,
  };
}

