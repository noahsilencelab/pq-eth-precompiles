// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract MLDSAWallet {
    uint256 public constant PUBLIC_KEY_LENGTH = 1312;
    address public constant ML_DSA_VERIFY_PRECOMPILE = address(0x1b);

    error InvalidPublicKeyLength(uint256 provided);
    error SignatureVerificationCallFailed();
    error InvalidSignature();
    error Expired(uint256 currentTimestamp, uint256 deadline);
    error CallFailed(bytes revertData);

    mapping(bytes32 => uint256) public nonces;

    receive() external payable {}

    function operationDigest(
        bytes calldata publicKey,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline
    ) public view returns (bytes32) {
        if (publicKey.length != PUBLIC_KEY_LENGTH) {
            revert InvalidPublicKeyLength(publicKey.length);
        }

        bytes32 keyHash = keccak256(publicKey);
        uint256 nonce_ = nonces[keyHash];
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                keyHash,
                nonce_,
                target,
                value,
                keccak256(data),
                deadline
            )
        );
    }

    function execute(
        bytes calldata publicKey,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes calldata signature
    ) external payable returns (bytes memory result) {
        if (block.timestamp > deadline) {
            revert Expired(block.timestamp, deadline);
        }

        if (publicKey.length != PUBLIC_KEY_LENGTH) {
            revert InvalidPublicKeyLength(publicKey.length);
        }

        bytes32 keyHash = keccak256(publicKey);
        uint256 usedNonce = nonces[keyHash];
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                keyHash,
                usedNonce,
                target,
                value,
                keccak256(data),
                deadline
            )
        );
        bytes memory verifyInput =
            abi.encodePacked(publicKey, signature, bytes2(0x0000), digest);

        (bool ok, bytes memory verifyOutput) = ML_DSA_VERIFY_PRECOMPILE.staticcall(verifyInput);
        if (!ok) {
            revert SignatureVerificationCallFailed();
        }
        if (verifyOutput.length != 32 || verifyOutput[31] != 0x01) {
            revert InvalidSignature();
        }

        nonces[keyHash] = usedNonce + 1;

        (ok, result) = target.call{value: value}(data);
        if (!ok) {
            revert CallFailed(result);
        }
    }
}
