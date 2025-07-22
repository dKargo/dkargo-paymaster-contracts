// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {DkargoVerifyingPaymaster} from "../../contracts/DkargoVerifyingPaymaster.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IStakeManager} from "@account-abstraction/contracts/interfaces/IStakeManager.sol";

import {TestBase} from "./base/TestBase.sol";

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
}