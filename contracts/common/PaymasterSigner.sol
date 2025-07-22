// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

abstract contract PaymasterSigner {
    
    /**
     * @notice Throws when the paymaster verifiying signer address provided is address(0)
     */
    error PaymasterSignerCanNotBeZero();

    address private paymasterSigner;

    /**
     * @dev Sets the signer with the address of the native signer. This function should be called during construction
     * or through an initializer.
     */
    function _setSigner(address newPaymasterSigner) internal {
        if (newPaymasterSigner == address(0)) {
            revert PaymasterSignerCanNotBeZero();
        }
        paymasterSigner = newPaymasterSigner;
    }

    /// @dev Return the signer's address.
    function getSigner() public view virtual returns (address) {
        return paymasterSigner;
    }


    function _isPaymasterSign(
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual returns (bool) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, signature);
        return getSigner() == recovered && err == ECDSA.RecoverError.NoError;
    }
}