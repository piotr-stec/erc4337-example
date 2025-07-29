// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "./MerkleTreeLibrary.sol";
import "lib/poseidon-solidity/contracts/PoseidonT3.sol";

interface IERC20 {
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IVerifier {
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool);
}

contract Account is IAccount {
    using MerkleTreeLib for MerkleTreeLib.Tree;

    // Privacy Pool state
    MerkleTreeLib.Tree private tree;
    mapping(uint256 => bool) public nullifierHashes;

    // Original Account state
    uint256 public count;
    address public owner;
    address public verifier;
    bytes32[] public supportedVerificationKey;

    // Events
    event Deposit(
        uint256 indexed secretNullifierHash,
        uint256 amount,
        address indexed token
    );
    event Withdrawal(
        uint256 indexed nullifier1,
        uint256 indexed nullifier2,
        address recipient
    );

    // Errors
    error TransferFailed();
    error NullifierAlreadyUsed();
    error InvalidRoot();
    error UnsupportedVerificationKey();

    constructor(
        address _owner,
        address _verifier,
        bytes32[] memory _supportedVK
    ) {
        owner = _owner;
        verifier = _verifier;
        supportedVerificationKey = _supportedVK;
        tree.initialize();
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external view returns (uint256 validationData) {
        IVerifier honkVerifier = IVerifier(verifier);
        (bytes memory proof, bytes32[] memory publicInputs) = abi.decode(
            userOp.signature,
            (bytes, bytes32[])
        );

        // Check if VK is supported
        if (!_isVerificationKeySupported(publicInputs)) {
            return 1; // Invalid VK
        }

        if (honkVerifier.verify(proof, publicInputs)) {
            return 0;
        } else {
            return 1; // Invalid proof
        }
    }

    // Privacy Pool Functions
    function deposit(
        uint256 secretNullifierHash,
        uint256 amount,
        address token
    ) external {
        uint256 secretNullifierAmountHash = _poseidonHash(
            secretNullifierHash,
            amount
        );
        uint256 commitment = _poseidonHash(
            secretNullifierAmountHash,
            uint256(uint160(token))
        );

        IERC20 erc20 = IERC20(token);
        bool success = erc20.transferFrom(msg.sender, address(this), amount);
        if (!success) revert TransferFailed();

        // Add to merkle tree
        tree.addLeaf(commitment);
        count++;

        emit Deposit(secretNullifierHash, amount, token);
    }

    function withdraw(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        if (!_isVerificationKeySupported(publicInputs)) {
            revert UnsupportedVerificationKey();
        }

        IVerifier honkVerifier = IVerifier(verifier);
        if (!honkVerifier.verify(proof, publicInputs)) {
            revert("Invalid proof");
        }
        uint256 root_1 = uint256(publicInputs[0]);
        uint256 nullifier_1 = uint256(publicInputs[1]);
        address token_address_1 = address(uint160(uint256(publicInputs[2])));
        uint256 amount = uint256(publicInputs[3]);
        uint256 root_2 = uint256(publicInputs[4]);
        uint256 nullifier_2 = uint256(publicInputs[5]);
        // unused for now
        address token_address_2 = address(uint160(uint256(publicInputs[6])));
        uint256 gas_fee = uint256(publicInputs[7]);
        uint256 refund_commitment_hash = uint256(publicInputs[8]);
        uint256 refund_commitment_hash_fee = uint256(publicInputs[9]);
        address recipient = address(uint160(uint256(publicInputs[10])));

        // Check if VK is supported
        if (!_isVerificationKeySupported(publicInputs)) {
            revert UnsupportedVerificationKey();
        }

        // Check if nullifiers already used
        if (nullifierHashes[nullifier_1]) {
            revert NullifierAlreadyUsed();
        }
        if (nullifierHashes[nullifier_2]) {
            revert NullifierAlreadyUsed();
        }

        // Check if merkle roots are valid
        if (!tree.isValidRoot(root_1)) {
            revert InvalidRoot();
        }
        if (!tree.isValidRoot(root_2)) {
            revert InvalidRoot();
        }

        // Mark nullifiers as used
        nullifierHashes[nullifier_1] = true;
        nullifierHashes[nullifier_2] = true;

        // Add refund commitments to tree
        tree.addLeaf(refund_commitment_hash);
        tree.addLeaf(refund_commitment_hash_fee);

        // Transfer tokens to recipient
        IERC20 erc20_1 = IERC20(token_address_1);
        bool success = erc20_1.transfer(recipient, amount);
        if (!success) revert TransferFailed();
    }

    function _poseidonHash(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256) {
        uint256[2] memory inputs = [a, b];
        return PoseidonT3.hash(inputs);
    }

    function _isVerificationKeySupported(
        bytes32[] memory publicInputs
    ) internal view returns (bool) {
        uint256 VK_SIZE = 112;

        bytes32[] memory extractedVK = new bytes32[](VK_SIZE);
        for (uint256 i = 0; i < VK_SIZE; i++) {
            extractedVK[i] = publicInputs[11 + i];
        }

        if (supportedVerificationKey.length != VK_SIZE) {
            return false;
        }

        for (uint256 i = 0; i < VK_SIZE; i++) {
            if (supportedVerificationKey[i] != extractedVK[i]) {
                return false;
            }
        }

        return true;
    }

    // Getter functions
    function getCurrentRoot() external view returns (uint256) {
        return tree.currentRoot;
    }

    function isValidRoot(uint256 root) external view returns (bool) {
        return tree.isValidRoot(root);
    }

    function execute(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        if (!_isVerificationKeySupported(publicInputs)) {
            revert UnsupportedVerificationKey();
        }

        IVerifier honkVerifier = IVerifier(verifier);
        if (!honkVerifier.verify(proof, publicInputs)) {
            revert("Invalid proof");
        }
        count++;
    }
}

contract AccountFactory {
    function createAccount(
        address owner,
        address verifier,
        bytes32[] memory supportedVK
    ) external returns (address) {
        bytes32 salt = bytes32(uint256(uint160(owner)));
        bytes memory creationCode = type(Account).creationCode;
        bytes memory bytecode = abi.encodePacked(
            creationCode,
            abi.encode(owner, verifier, supportedVK)
        );

        address addr = Create2.computeAddress(salt, keccak256(bytecode));
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return addr;
        }

        return deploy(salt, bytecode);
    }

    function deploy(
        bytes32 salt,
        bytes memory bytecode
    ) internal returns (address addr) {
        require(bytecode.length != 0, "Create2: bytecode length is zero");
        /// @solidity memory-safe-assembly
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Create2: Failed on deploy");
    }
}
