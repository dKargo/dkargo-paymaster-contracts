// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {DkargoVerifyingPaymaster} from "../../contracts/DkargoVerifyingPaymaster.sol";
import {BasePaymaster} from "../../contracts/base/BasePaymaster.sol";
import {PaymasterSigner} from "../../contracts/common/PaymasterSigner.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IStakeManager} from "@account-abstraction/contracts/interfaces/IStakeManager.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import { IPaymaster } from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import "@account-abstraction/contracts/core/UserOperationLib.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {_parseValidationData, ValidationData} from "@account-abstraction/contracts/core/Helpers.sol";


import {TestBase} from "./base/TestBase.sol";
import { console } from "forge-std/Test.sol";

contract TestDkargoVerifyingPaymaster is TestBase {

    DkargoVerifyingPaymaster public paymaster;
    function setUp() public {
        setupTestEnvironment();

        paymaster = new DkargoVerifyingPaymaster(PAYMASTER_OWNER.addr,PAYMASTER_SIGNER.addr,ENTRYPOINT);
    }

    function test_Deployment() external {
        vm.expectEmit();
        emit Ownable.OwnershipTransferred(address(0),PAYMASTER_OWNER.addr);

        DkargoVerifyingPaymaster _paymaster = new DkargoVerifyingPaymaster(PAYMASTER_OWNER.addr,PAYMASTER_SIGNER.addr,ENTRYPOINT);

        assertEq(_paymaster.owner(),PAYMASTER_OWNER.addr);
        assertEq(_paymaster.getSigner(),PAYMASTER_SIGNER.addr);
        assertEq(address(_paymaster.entryPoint()), address(ENTRYPOINT));
    }

    function test_RevertIf_DeploymentWrongEntrypoint() external {
        vm.expectRevert("IEntryPoint interface mismatch");
        new DkargoVerifyingPaymaster(PAYMASTER_OWNER.addr,PAYMASTER_SIGNER.addr,IEntryPoint(address(DUMMY_ERC20)));
    }

    function test_ParsePaymasterAndData() external view {
        uint48 _validUntil = 111;
        uint48 _validAfter = 222;
        bytes memory _paymasterSign = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));
        bytes memory paymasterAndData = abi.encodePacked(address(paymaster),bytes16(uint128(30000)), bytes16(uint128(40000)),uint256(111), uint256(222),_paymasterSign);

        (uint48 validUntil, uint48 validAfter, bytes memory signature) = paymaster.parsePaymasterAndData(paymasterAndData);
        assertEq(_validUntil,validUntil,"!=validUntil");
        assertEq(_validAfter,validAfter,"!=validAfter");
        assertEq(_paymasterSign, signature,"!=signature");
    }

    function test_Deposit() external prankModifier(PAYMASTER_OWNER.addr) {
        uint256 depositAmount = 1 ether;

        vm.expectEmit();
        emit IStakeManager.Deposited(address(paymaster), depositAmount);
        paymaster.deposit{value:depositAmount}();

        assertEq(paymaster.getDeposit(),depositAmount);
    }

    function test_WithdrawTo() external prankModifier(PAYMASTER_OWNER.addr) {
        uint256 depositAmount = 1 ether;
        paymaster.deposit{value:depositAmount}();

        uint256 withdrawAmount = 0.5 ether;

        uint256 initDepositBalance = paymaster.getDeposit();
        uint256 initBobBalance = BOB.addr.balance;

        vm.expectEmit();
        emit IStakeManager.Withdrawn(address(paymaster),BOB.addr, withdrawAmount);
        paymaster.withdrawTo(payable(BOB.addr), withdrawAmount);
        
        

        assertEq(paymaster.getDeposit(),initDepositBalance - withdrawAmount);
        assertEq( address(BOB.addr).balance,initBobBalance + withdrawAmount);
    }

    function test_StakeAndWithdraw() external prankModifier(PAYMASTER_OWNER.addr) {
        uint256 stakeAmount = 1 ether;
        uint32 unstakeDelaySec = 90;

        vm.expectEmit();
        emit IStakeManager.StakeLocked(address(paymaster), stakeAmount,unstakeDelaySec);
        paymaster.addStake{value:stakeAmount}(unstakeDelaySec);

        {
            EntryPoint.DepositInfo memory info = ENTRYPOINT.getDepositInfo(address(paymaster));
            assertEq(info.deposit,0,"!= deposit");
            assertEq(info.staked,true,"!= staked");
            assertEq(info.stake,uint112(stakeAmount),"!= stake");
            assertEq(info.unstakeDelaySec,unstakeDelaySec,"!= unstakeDelaySec");
            assertEq(info.withdrawTime,0,"!= withdrawTime");
        }

        vm.expectEmit();
        uint48 withdrawTime = uint48(block.timestamp) + unstakeDelaySec;
        emit IStakeManager.StakeUnlocked(address(paymaster),withdrawTime);
        paymaster.unlockStake();

        {
            EntryPoint.DepositInfo memory info = ENTRYPOINT.getDepositInfo(address(paymaster));
            assertEq(info.deposit,0,"!= deposit");
            assertEq(info.staked,false,"!= staked");
            assertEq(info.stake,uint112(stakeAmount),"!= stake");
            assertEq(info.unstakeDelaySec,unstakeDelaySec,"!= unstakeDelaySec");
            assertEq(info.withdrawTime,withdrawTime,"!= withdrawTime");
        }

        vm.warp(withdrawTime);
        vm.expectEmit();
        emit IStakeManager.StakeWithdrawn(address(paymaster),PAYMASTER_OWNER.addr,stakeAmount);
        paymaster.withdrawStake(payable(PAYMASTER_OWNER.addr));

        {
            EntryPoint.DepositInfo memory info = ENTRYPOINT.getDepositInfo(address(paymaster));
            assertEq(info.deposit,0,"!= deposit");
            assertEq(info.staked,false,"!= staked");
            assertEq(info.stake,uint112(0),"!= stake");
            assertEq(info.unstakeDelaySec,0,"!= unstakeDelaySec");
            assertEq(info.withdrawTime,0,"!= withdrawTime");
        }
    }

    function test_UnlockStake() external prankModifier(PAYMASTER_OWNER.addr) {
        uint256 stakeAmount = 1 ether;
        uint32 unstakeDelaySec = 90;
        paymaster.addStake{value:stakeAmount}(unstakeDelaySec);


        EntryPoint.DepositInfo memory info = ENTRYPOINT.getDepositInfo(address(paymaster));
        assertEq(info.deposit,0,"!= deposit");
        assertEq(info.staked,true,"!= staked");
        assertEq(info.stake,uint112(stakeAmount),"!= stake");
        assertEq(info.unstakeDelaySec,unstakeDelaySec,"!= unstakeDelaySec");
        assertEq(info.withdrawTime,0,"!= withdrawTime");
    }

    
    /** --------------------------------------------------------------------------------------- */
    /** --------------------------------------------------------------------------------------- */

    function test_SetSigner() external prankModifier(PAYMASTER_OWNER.addr) {
        address beforeSigner = paymaster.getSigner();
        assertEq(beforeSigner,PAYMASTER_SIGNER.addr);

        paymaster.setPaymasterSigner(BOB.addr);
        
        address afterSigner = paymaster.getSigner();
        assertEq(afterSigner,BOB.addr);
    }

    function test_RevartIf_NotOwner_SetSigner() external prankModifier(BOB.addr) {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector,BOB.addr));
        paymaster.setPaymasterSigner(ALICE.addr);

    }

    function test_RevertIf_SetSignerToZeroAddress() external prankModifier(PAYMASTER_OWNER.addr) {
        vm.expectRevert(abi.encodeWithSelector(PaymasterSigner.PaymasterSignerCanNotBeZero.selector));
        paymaster.setPaymasterSigner(address(0));        
    }


    function test_TransferOwner() external prankModifier(PAYMASTER_OWNER.addr) {
        paymaster.transferOwnership(BOB.addr);
        
        address afterOwner = paymaster.owner();
        assertEq(afterOwner,BOB.addr);
    }

    function test_RenounceOwnership() external prankModifier(PAYMASTER_OWNER.addr) {
        paymaster.renounceOwnership();
        
        address afterOwner = paymaster.owner();
        assertEq(afterOwner,address(0x00));
    }

    /** --------------------------------------------------------------------------------------- */
    /** --------------------------------------------------------------------------------------- */


    function test_RevertIf_CallpostOp() external prankModifier(PAYMASTER_OWNER.addr) {
        vm.expectRevert("Sender not EntryPoint");
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded,"0x",0,0);        
    }

    function test_RevertIf_CallpostOpRevert() external prankModifier(address(ENTRYPOINT)) {
        vm.expectRevert("must override");
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded,"0x",0,0);        
    }

    function test_RevertIf_CallValidatePaymasterUserOp() external prankModifier(PAYMASTER_OWNER.addr) {
        PackedUserOperation memory userOp;
        vm.expectRevert("Sender not EntryPoint");
        paymaster.validatePaymasterUserOp(userOp,"0x",0);        
    }

    function test_RevertIf_CallValidatePaymasterUserOpInvaildSignLength() external prankModifier(address(ENTRYPOINT)) {
        PackedUserOperation memory userOp;

        /**
         * @dev for revert signature length invaild, bytes32 -> bytes30
         */
        bytes memory paymasterSign = abi.encodePacked(bytes32(0), bytes30(0), uint8(0));
        userOp.paymasterAndData = abi.encodePacked(address(paymaster),bytes16(uint128(30000)), bytes16(uint128(40000)),uint256(111), uint256(222),paymasterSign);

        vm.expectRevert("VerifyingPaymaster: invalid signature length in paymasterAndData");
        paymaster.validatePaymasterUserOp(userOp,"0x",0);        
    }

    function test_RevertIf_CallValidatePaymasterUserOpInvaildSign() external prankModifier(address(ENTRYPOINT)) {
        PackedUserOperation memory userOp;

        /**
         * @dev for revert signature length invaild, bytes32 -> bytes30
         */
        bytes memory paymasterSign = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));
        userOp.paymasterAndData = abi.encodePacked(address(paymaster),bytes16(uint128(30000)), bytes16(uint128(40000)),uint256(111), uint256(222),paymasterSign);
        (,uint256 validationData) = paymaster.validatePaymasterUserOp(userOp,"0x",0);

        ValidationData memory _validationData = _parseValidationData(validationData);
        assertEq(_validationData.aggregator,address(1) /** address(1) == true */);
    }
}