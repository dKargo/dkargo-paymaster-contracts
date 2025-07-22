// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {DkargoVerifyingPaymaster} from "../../../contracts/DkargoVerifyingPaymaster.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {SimpleAccountFactory} from "@account-abstraction/contracts/samples/SimpleAccountFactory.sol";

import { Test } from "forge-std/Test.sol";
import { Vm } from "forge-std/Vm.sol";

abstract contract TestBase is Test {

    address constant ENTRYPOINT_ADDRESS = address(0x0000000071727De22E5E9d8BAf0edAc6f37da032);

    Vm.Wallet internal PAYMASTER_OWNER;
    Vm.Wallet internal PAYMASTER_SIGNER;
    Vm.Wallet internal BOB;
    Vm.Wallet internal ALICE;

    Vm.Wallet internal BUNDLER;
    Vm.Wallet internal FACTORY_OWNER;
    Vm.Wallet internal DEPLOYER;

    IEntryPoint internal ENTRYPOINT;
    SimpleAccountFactory internal FACTROY;

    // -----------------------------------------
    // Modifiers
    // -----------------------------------------
    modifier prankModifier(address pranker) {
        vm.startPrank(pranker);
        _;
        vm.stopPrank();
    }

    function setupTestEnvironment() internal virtual {
        /// Initializes the testing environment
        setupWallets();
        deployTestContracts();
    }

    function createAndFundWallet(string memory name, uint256 amount) internal returns (Vm.Wallet memory) {
        Vm.Wallet memory wallet = vm.createWallet(name);
        vm.label(wallet.addr, name);
        vm.deal(wallet.addr, amount);
        return wallet;
    }

    function setupWallets() internal {
        PAYMASTER_OWNER = createAndFundWallet("PAYMASTER_OWNER", 1000 ether);
        PAYMASTER_SIGNER = createAndFundWallet("PPAYMASTER_SIGNER", 1000 ether);
        BUNDLER = createAndFundWallet("BUNDLER", 1000 ether);
        BOB = createAndFundWallet("BOB", 1000 ether);
        ALICE = createAndFundWallet("ALICE", 1000 ether);

        DEPLOYER = createAndFundWallet("DEPLOYER", 1000 ether);
        FACTORY_OWNER = createAndFundWallet("FACTORY_OWNER", 1000 ether);
    }

    function deployTestContracts() internal {
        ENTRYPOINT = new EntryPoint(); // for get code
        vm.etch(address(ENTRYPOINT_ADDRESS), address(ENTRYPOINT).code);
        ENTRYPOINT = IEntryPoint(ENTRYPOINT_ADDRESS);

        FACTROY = new SimpleAccountFactory(ENTRYPOINT);
    }
}