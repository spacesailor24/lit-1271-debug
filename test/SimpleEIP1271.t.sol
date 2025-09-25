// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/SimpleEIP1271.sol";

contract SimpleEIP1271Test is Test {
    SimpleEIP1271 public simpleContract;
    address[] signerAddresses;
    uint256[] privateKeys;

    function setUp() public {
        // Generate some test addresses and their private keys
        for (uint i = 0; i < 3; i++) {
            uint256 privateKey = uint256(keccak256(abi.encodePacked("test key", i)));
            address addr = vm.addr(privateKey);
            signerAddresses.push(addr);
            privateKeys.push(privateKey);
        }

        // Deploy simplified contract (no threshold)
        simpleContract = new SimpleEIP1271(signerAddresses);
    }

    function testSignerStatus() public {
        // Test that all configured signers are recognized
        for (uint i = 0; i < signerAddresses.length; i++) {
            assertTrue(simpleContract.isSigner(signerAddresses[i]));
        }
        // Test that a random address is not a signer
        assertFalse(simpleContract.isSigner(address(0xdead)));
    }

    function testSingleSignatureValidation() public {
        bytes32 messageHash = keccak256("Test message");

        // Test with valid whitelisted signer - should succeed
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[0], messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(simpleContract.isValidSignature(messageHash, signature), bytes4(0x1626ba7e));

        // Test with another valid whitelisted signer - should succeed
        (v, r, s) = vm.sign(privateKeys[1], messageHash);
        signature = abi.encodePacked(r, s, v);
        assertEq(simpleContract.isValidSignature(messageHash, signature), bytes4(0x1626ba7e));

        // Test with third valid whitelisted signer - should succeed
        (v, r, s) = vm.sign(privateKeys[2], messageHash);
        signature = abi.encodePacked(r, s, v);
        assertEq(simpleContract.isValidSignature(messageHash, signature), bytes4(0x1626ba7e));
    }

    function testInvalidSignatureLength() public {
        bytes32 messageHash = keccak256("Test message");

        // Test with invalid signature length (too short)
        bytes memory invalidSignature = new bytes(64);
        assertEq(simpleContract.isValidSignature(messageHash, invalidSignature), bytes4(0xffffffff));

        // Test with invalid signature length (too long)
        invalidSignature = new bytes(66);
        assertEq(simpleContract.isValidSignature(messageHash, invalidSignature), bytes4(0xffffffff));

        // Test with multi-signature length (should fail - only single signatures accepted)
        invalidSignature = new bytes(130); // 2 * 65
        assertEq(simpleContract.isValidSignature(messageHash, invalidSignature), bytes4(0xffffffff));
    }

    function testNonWhitelistedSigner() public {
        bytes32 messageHash = keccak256("Test message");
        uint256 nonSignerPrivateKey = uint256(keccak256(abi.encodePacked("non-signer key")));

        // Create signature from non-whitelisted signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonSignerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should fail because signer is not whitelisted
        assertEq(simpleContract.isValidSignature(messageHash, signature), bytes4(0xffffffff));
    }

    function testVValueHandling() public {
        bytes32 messageHash = keccak256("V value test");

        // Test with standard v=27/28 values
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[0], messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(simpleContract.isValidSignature(messageHash, signature), bytes4(0x1626ba7e));

        // Test with v=0/1 values (should be converted to 27/28)
        if (v >= 27) v -= 27; // Convert to 0/1 format
        signature = abi.encodePacked(r, s, v);
        assertEq(simpleContract.isValidSignature(messageHash, signature), bytes4(0x1626ba7e));
    }

    function testZeroAddressRecovery() public {
        bytes32 messageHash = keccak256("Zero address test");

        // Create a signature that recovers to address(0)
        // This is typically an invalid signature
        bytes memory invalidSignature = new bytes(65);
        // Set all bytes to 0 - this should recover to address(0)

        assertEq(simpleContract.isValidSignature(messageHash, invalidSignature), bytes4(0xffffffff));
    }

    function testLitProtocolCompatibility() public {
        // Test with the exact message format that Lit Protocol uses
        string memory siweMessage = "localhost wants you to sign in with your Ethereum account:\n0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n\nThis is a test statement.  You can put anything you want here.\n\nURI: https://localhost/login\nVersion: 1\nChain ID: 1\nNonce: 0x1234567890abcdef\nIssued At: 2024-01-01T00:00:00.000Z\nExpiration Time: 2024-01-02T00:00:00.000Z";

        // This simulates the hash that ethers.utils.hashMessage() creates
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", bytes(siweMessage).length, siweMessage));

        // Test with whitelisted signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[0], prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertEq(simpleContract.isValidSignature(prefixedHash, signature), bytes4(0x1626ba7e));
    }
}