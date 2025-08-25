// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {BasePaymaster} from "./base/BasePaymaster.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PaymasterSigner} from "./common/PaymasterSigner.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract DkargoVerifyingPaymaster is BasePaymaster, PaymasterSigner {
    using UserOperationLib for PackedUserOperation;

    uint256 private constant VALID_TIMESTAMP_OFFSET = _PAYMASTER_DATA_OFFSET; // 52
    uint256 private constant SIGNATURE_OFFSET = VALID_TIMESTAMP_OFFSET + 64; // 116

    constructor(address owner, address paymasterSigner, IEntryPoint _entryPoint) BasePaymaster(owner,_entryPoint) {
        _setSigner(paymasterSigner);
    }

    /**
     * return the hash we're going to sign off-chain (and validate on-chain)
     * this method is called by the off-chain service, to sign the request.
     * it is called on-chain from the validatePaymasterUserOp, to validate the signature.
     * note that this signature covers all fields of the UserOperation, except the "paymasterAndData",
     * which will carry the signature itself.
     * 
     * @dev userOp.paymasterAndData for mode 0:
     * - paymaster address (20 bytes)
     * - paymaster validationGasLimit (16 bytes)
     * - paymaster postOpGasLimit (16 bytes)
     */
    function getHash(PackedUserOperation calldata userOp, uint48 validUntil, uint48 validAfter) public view returns (bytes32) {
        //can't use userOp.hash(), since it contains also the paymasterAndData itself.
        address sender = userOp.getSender();
        return
            keccak256(
            abi.encode(
                sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                uint256(bytes32(userOp.paymasterAndData[_PAYMASTER_VALIDATION_GAS_OFFSET : _PAYMASTER_DATA_OFFSET])),
                userOp.preVerificationGas,
                userOp.gasFees,
                block.chainid,
                address(this),
                validUntil,
                validAfter
            )
        );
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 /** userOpHash */, uint256 /** requiredPreFund */) internal view override returns (bytes memory context, uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = parsePaymasterAndData(userOp.paymasterAndData);

        // ECDSA library supports both 64 and 65-byte long signatures.
        // we only "require" it here so that the revert reason on invalid signature will be of "VerifyingPaymaster", and not "ECDSA"
        require(signature.length == 64 || signature.length == 65, "VerifyingPaymaster: invalid signature length in paymasterAndData");
        
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter));

        bool isPaymasterSign = _isPaymasterSign(hash,signature);

        if(isPaymasterSign) {
            return ("", _packValidationData(false, validUntil, validAfter));
        }

        return ("", _packValidationData(true, validUntil, validAfter));
    }


    function parsePaymasterAndData(bytes calldata paymasterAndData) public pure returns (uint48 validUntil, uint48 validAfter, bytes calldata signature) {
        (validUntil, validAfter) = abi.decode(paymasterAndData[VALID_TIMESTAMP_OFFSET :], (uint48, uint48));
        signature = paymasterAndData[SIGNATURE_OFFSET :];
    }

    function setPaymasterSigner(address newPaymasterSigner) external onlyOwner {
        _setSigner(newPaymasterSigner);
    }

    /**
     * @dev Handles post user operation execution logic. The caller must be the entry point.
     *
     * It receives the `context` returned by `_validatePaymasterUserOp`. Function is not called if no context
     * is returned by {validatePaymasterUserOp}.
     */
    // function _postOp(
    //     PostOpMode /* mode */,
    //     bytes calldata /* context */,
    //     uint256 /* actualGasCost */,
    //     uint256 /* actualUserOpFeePerGas */
    // ) internal override virtual {}
}