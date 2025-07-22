// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {DkargoVerifyingPaymaster} from "../../contracts/DkargoVerifyingPaymaster.sol";
import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

import {TestBase} from "./base/TestBase.sol";
import { Vm } from "forge-std/Vm.sol";

contract TestPaymasterSign is TestBase {
      using UserOperationLib for PackedUserOperation;
  
    DkargoVerifyingPaymaster public paymaster;
    function setUp() public {
        setupTestEnvironment();

        paymaster = new DkargoVerifyingPaymaster(PAYMASTER_OWNER.addr,PAYMASTER_SIGNER.addr,ENTRYPOINT);

        vm.startPrank(PAYMASTER_OWNER.addr);
        paymaster.deposit{value:10 ether}();
        vm.stopPrank();

        // Prevent validAfter overflow (Foundry default timestamp is 1)
        vm.warp( block.timestamp + 10_000 ); 
    }

    function test_ExecuteUserOp() external {
        bytes memory factoryData = abi.encodeWithSelector(FACTROY.createAccount.selector,BOB.addr,0);
        bytes memory initCode = abi.encodePacked(address(FACTROY),factoryData);

        address sender = FACTROY.getAddress(BOB.addr, 0);
        uint256 nonce = ENTRYPOINT.getNonce(sender, 0);

        /**
         * @dev userOp.callData mock data
         * function execute(address,uint256,bytes calldata)
         * - dest: ALICE
         * - value: 0
         * - func: 0x
         */
        bytes memory callData = abi.encodeWithSelector(SimpleAccount.execute.selector,ALICE.addr,0,bytes(""));

        /**
         * @dev userOp.accountGasLimits mock data
         * - verificationGasLimit (bytes16) 0x00000000000000000000000000035c9c (220316)
         * - callGasLimit         (bytes16) 0x00000000000000000000000000002bb8 (11192)
         */
        bytes32 accountGasLimits = bytes32(0x00000000000000000000000000035c9c00000000000000000000000000002bb8);

        /**
         * @dev userOp.preVerificationGas mock data
         */
        uint256 preVerificationGas = 50652;

        /**
         * @dev userOp.gasFees mock data
         * - maxPriorityFeePerGas (bytes16) 0x000000000000000000000000001e8480 (2000000)
         * - maxFeePerGas         (bytes16) 0x000000000000000000000000001e8490 (2000016)
         */
        bytes32 gasFees = 0x000000000000000000000000001e8480000000000000000000000000001e8490;

        /**
         * @dev userOp.paymasterAndData unsigned mock data
         * - paymaster address (20 bytes)
         * - paymaster validationGasLimit (16 bytes) 0x00000000000000000000000000007530 (30000)
         * - paymaster postOpGasLimit (16 bytes)     0x00000000000000000000000000009c40 (40000)
         */
        bytes memory paymasterAndData = abi.encodePacked(address(paymaster),bytes16(uint128(30000)), bytes16(uint128(40000)));

        /**
         * @dev Paymaster signature validity period
         * - validUntil : ~ 6min
         * - validAfter : 1min ~
         */
        uint48 validUntil = uint48(block.timestamp + 600);
        uint48 validAfter = uint48(block.timestamp - 60);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender:sender,
            nonce:nonce,
            initCode:initCode,
            callData:callData,
            accountGasLimits:accountGasLimits,
            preVerificationGas:preVerificationGas,
            gasFees:gasFees,
            paymasterAndData:paymasterAndData,
            signature:bytes("")
        });


        /**
         * @dev userOp.paymasterAndData signed mock data
         * - paymaster address            (20 bytes)
         * - paymaster validationGasLimit (16 bytes) 0x00000000000000000000000000007530 (30000)
         * - paymaster postOpGasLimit     (16 bytes) 0x00000000000000000000000000009c40 (40000)
         * - validUntil                   (32 btyes) 
         * - validAfter                   (32 btyes)
         * - paymaster sign               (32|33 bytes)
         */
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(paymaster.getHash(userOp, validUntil, validAfter));
        (uint8 v,bytes32 r, bytes32 s) = vm.sign(PAYMASTER_SIGNER.privateKey,hash);
        bytes memory paymasterSign = abi.encodePacked(r, s, v);
        bytes memory paymasterData = abi.encodePacked(uint256(validUntil), uint256(validAfter), paymasterSign);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData,paymasterData);


        bytes32 userOpHash =  MessageHashUtils.toEthSignedMessageHash(ENTRYPOINT.getUserOpHash(userOp));
        (uint8 v2,bytes32 r2, bytes32 s2) = vm.sign(BOB.privateKey,userOpHash);
        userOp.signature = abi.encodePacked(r2, s2, v2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.startPrank(BUNDLER.addr);
        ENTRYPOINT.handleOps(ops, payable(BUNDLER.addr));
        vm.stopPrank();

    }

    function test_ExecuteBatchUserOp() external {
        bytes memory factoryData = abi.encodeWithSelector(FACTROY.createAccount.selector,BOB.addr,0);
        bytes memory initCode = abi.encodePacked(address(FACTROY),factoryData);

        address sender = FACTROY.getAddress(BOB.addr, 0);
        uint256 nonce = ENTRYPOINT.getNonce(sender, 0);

        /**
         * @dev userOp.callData mock data
         * function executeBatch(address[],uint256[],bytes calldata[])
         * - dest: ALICE
         * - value: 0
         * - func: 0x
         */
        address[] memory dest = new address[](2);
        dest[0] = 0x1111111111111111111111111111111111111111;
        dest[1] = 0x2222222222222222222222222222222222222222;

        uint256[] memory value = new uint256[](2);
        value[0] = 1;
        value[1] = 2;

        bytes[] memory func = new bytes[](2);
        func[0] = hex"";
        func[1] = hex"";

        bytes memory callData = abi.encodeWithSelector(
                                SimpleAccount.executeBatch.selector,
                                dest,
                                value,
                                func
                            );

        /**
         * @dev userOp.accountGasLimits mock data
         * - verificationGasLimit (bytes16) 0x00000000000000000000000000035c9c (220316)
         * - callGasLimit         (bytes16) 0x00000000000000000000000000002bb8 (11192)
         */
        bytes32 accountGasLimits = bytes32(0x00000000000000000000000000035c9c00000000000000000000000000002bb8);

        /**
         * @dev userOp.preVerificationGas mock data
         */
        uint256 preVerificationGas = 50652;

        /**
         * @dev userOp.gasFees mock data
         * - maxPriorityFeePerGas (bytes16) 0x000000000000000000000000001e8480 (2000000)
         * - maxFeePerGas         (bytes16) 0x000000000000000000000000001e8490 (2000016)
         */
        bytes32 gasFees = 0x000000000000000000000000001e8480000000000000000000000000001e8490;

        /**
         * @dev userOp.paymasterAndData unsigned mock data
         * - paymaster address (20 bytes)
         * - paymaster validationGasLimit (16 bytes) 0x00000000000000000000000000007530 (30000)
         * - paymaster postOpGasLimit (16 bytes)     0x00000000000000000000000000009c40 (40000)
         */
        bytes memory paymasterAndData = abi.encodePacked(address(paymaster),bytes16(uint128(30000)), bytes16(uint128(40000)));

        /**
         * @dev Paymaster signature validity period
         * - validUntil : ~ 6min
         * - validAfter : 1min ~
         */
        uint48 validUntil = uint48(block.timestamp + 600);
        uint48 validAfter = uint48(block.timestamp - 60);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender:sender,
            nonce:nonce,
            initCode:initCode,
            callData:callData,
            accountGasLimits:accountGasLimits,
            preVerificationGas:preVerificationGas,
            gasFees:gasFees,
            paymasterAndData:paymasterAndData,
            signature:bytes("")
        });


        /**
         * @dev userOp.paymasterAndData signed mock data
         * - paymaster address            (20 bytes)
         * - paymaster validationGasLimit (16 bytes) 0x00000000000000000000000000007530 (30000)
         * - paymaster postOpGasLimit     (16 bytes) 0x00000000000000000000000000009c40 (40000)
         * - validUntil                   (32 btyes) 
         * - validAfter                   (32 btyes)
         * - paymaster sign               (32|33 bytes)
         */
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(paymaster.getHash(userOp, validUntil, validAfter));
        (uint8 v,bytes32 r, bytes32 s) = vm.sign(PAYMASTER_SIGNER.privateKey,hash);
        bytes memory paymasterSign = abi.encodePacked(r, s, v);
        bytes memory paymasterData = abi.encodePacked(uint256(validUntil), uint256(validAfter), paymasterSign);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData,paymasterData);


        bytes32 userOpHash =  MessageHashUtils.toEthSignedMessageHash(ENTRYPOINT.getUserOpHash(userOp));
        (uint8 v2,bytes32 r2, bytes32 s2) = vm.sign(BOB.privateKey,userOpHash);
        userOp.signature = abi.encodePacked(r2, s2, v2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.startPrank(BUNDLER.addr);
        ENTRYPOINT.handleOps(ops, payable(BUNDLER.addr));
        vm.stopPrank();

    }
}