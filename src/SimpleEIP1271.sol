// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleEIP1271 {
    mapping(address => bool) public signers;

    // EIP-1271 magic value
    bytes4 constant internal MAGICVALUE = 0x1626ba7e;

    constructor(address[] memory _signers) {
        require(_signers.length > 0, "Must have at least one signer");

        for (uint256 i = 0; i < _signers.length; i++) {
            require(_signers[i] != address(0), "Invalid signer address");
            signers[_signers[i]] = true;
        }
    }

    function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4) {
        // For Lit Protocol compatibility, we expect a single 65-byte signature
        if (_signature.length != 65) {
            return 0xffffffff;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(add(_signature.offset, 0))
            s := calldataload(add(_signature.offset, 32))
            v := byte(0, calldataload(add(_signature.offset, 64)))
        }

        // Handle both 27/28 and 0/1 v values
        if (v < 27) {
            v += 27;
        }

        // The hash passed here already includes the Ethereum message prefix
        // when created via hashMessage() in ethers
        address recovered = ecrecover(_hash, v, r, s);

        // Simple whitelist check - if the recovered signer is whitelisted, it's valid
        if (recovered != address(0) && signers[recovered]) {
            return MAGICVALUE;
        }

        return bytes4(0xffffffff);
    }

    function isSigner(address _address) external view returns (bool) {
        return signers[_address];
    }
}