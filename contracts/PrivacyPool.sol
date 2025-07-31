// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

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

struct OfferParams {
    string offerType;
    string currency;
    uint256 cryptoAmount;
    uint256 fiatAmount;
    address tokenAddress;
    uint256 fee;
    string revTag;
}

struct Offer {
    bytes32 id;
    string offerType;
    string currency;
    uint256 cryptoAmount;
    uint256 fiatAmount;
    address tokenAddress;
    uint256 fee;
    string status;
    string revTag;
    uint256 timestamp;
    uint256 secretHash;
}

enum OfferStatus {
    CREATED,
    LOCKED,
    COMPLETED,
    CANCELED,
    EXPIRED
}

struct PendingTransfer {
    bytes32 offerId;
    address buyer;
    uint256 timestamp;
    uint256 timeout;
    PendingState state;
    bytes32 tlsnProofHash;
}

enum PendingState {
    PENDING,
    COMPLETED,
    VOIDED,
    EXPIRED
}

contract PrivacyPool {
    using MerkleTreeLib for MerkleTreeLib.Tree;

    // Privacy Pool state
    MerkleTreeLib.Tree private tree;
    mapping(uint256 => bool) public nullifierHashes;

    // Offer state
    mapping(uint256 => Offer) public offers; // secretHash => Offer
    mapping(bytes32 => PendingTransfer) public pendingTransfers;
    mapping(bytes32 => bool) public completedOffers;
    uint256 public offerCounter;

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
    
    event LeafAdded(
        address indexed caller,
        uint256 indexed commitment,
        uint256 newRoot
    );

    event OfferCreated(
        bytes32 indexed offerId,
        uint256 indexed secretHash,
        address indexed creator,
        string offerType,
        uint256 cryptoAmount,
        uint256 fiatAmount
    );

    // Errors
    error TransferFailed();
    error NullifierAlreadyUsed();
    error InvalidRoot();
    error UnsupportedVerificationKey();
    error OfferNotFound();
    error OfferAlreadyExists();
    error OfferNotActive();
    error UnauthorizedAccess();
    error TransferAlreadyExists();
    error TransferNotFound();
    error TransferExpired();
    error InvalidSecret();

    constructor(
        address _owner,
        address _verifier,
        bytes32[] memory _supportedVK
    ) {
        owner = _owner;
        verifier = _verifier;
        supportedVerificationKey = _supportedVK;
        tree.initialize();
        offerCounter = 0;
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

    function createOffer(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint256 secretHash,
        OfferParams calldata params
    ) external {
        // Check if VK is supported
        if (!_isVerificationKeySupported(publicInputs)) {
            revert UnsupportedVerificationKey();
        }

        // Verify proof
        if (!IVerifier(verifier).verify(proof, publicInputs)) {
            revert("Invalid proof");
        }

        // Validate nullifiers and roots
        _validateNullifiersAndRoots(publicInputs);

        // Validate offer parameters
        _validateOfferParameters(
            publicInputs,
            params.tokenAddress,
            params.cryptoAmount,
            params.fee,
            secretHash
        );

        // Process offer creation
        _processOfferCreation(
            publicInputs,
            secretHash,
            params.offerType,
            params.currency,
            params.cryptoAmount,
            params.fiatAmount,
            params.tokenAddress,
            params.fee,
            params.revTag
        );
    }

    function _validateNullifiersAndRoots(
        bytes32[] calldata publicInputs
    ) internal view {
        uint256 nullifier_1 = uint256(publicInputs[1]);
        uint256 nullifier_2 = uint256(publicInputs[5]);

        if (nullifierHashes[nullifier_1] || nullifierHashes[nullifier_2]) {
            revert NullifierAlreadyUsed();
        }

        if (
            !tree.isValidRoot(uint256(publicInputs[0])) ||
            !tree.isValidRoot(uint256(publicInputs[4]))
        ) {
            revert InvalidRoot();
        }
    }

    function _validateOfferParameters(
        bytes32[] calldata publicInputs,
        address tokenAddress,
        uint256 cryptoAmount,
        uint256 fee,
        uint256 secretHash
    ) internal view {
        address token_address_1 = address(uint160(uint256(publicInputs[2])));
        uint256 amount = uint256(publicInputs[3]);

        require(token_address_1 == tokenAddress, "Token address mismatch");
        require(amount >= cryptoAmount + fee, "Insufficient deposit amount");

        if (offers[secretHash].timestamp != 0) {
            revert OfferAlreadyExists();
        }
    }

    function _processOfferCreation(
        bytes32[] calldata publicInputs,
        uint256 secretHash,
        string calldata offerType,
        string calldata currency,
        uint256 cryptoAmount,
        uint256 fiatAmount,
        address tokenAddress,
        uint256 fee,
        string calldata revTag
    ) internal {
        // Mark nullifiers as used
        nullifierHashes[uint256(publicInputs[1])] = true;
        nullifierHashes[uint256(publicInputs[5])] = true;

        // Add refund commitments to tree
        tree.addLeaf(uint256(publicInputs[8]));
        tree.addLeaf(uint256(publicInputs[9]));

        // Create offer ID
        bytes32 offerId = keccak256(
            abi.encodePacked(block.timestamp, offerCounter, secretHash)
        );
        offerCounter++;

        // Store offer
        offers[secretHash] = Offer({
            id: offerId,
            offerType: offerType,
            currency: currency,
            cryptoAmount: cryptoAmount,
            fiatAmount: fiatAmount,
            tokenAddress: tokenAddress,
            fee: fee,
            status: "CREATED",
            revTag: revTag,
            timestamp: block.timestamp,
            secretHash: secretHash
        });

        // Emit event
        emit OfferCreated(
            offerId,
            secretHash,
            address(0),
            offerType,
            cryptoAmount,
            fiatAmount
        );
    }

    function createTransaction(
        uint256 secretHash,
        string calldata currency,
        uint256 cryptoAmount,
        uint256 fiatAmount,
        address tokenAddress,
        uint256 fee
    ) external {}

    function verifyTransaction(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint256 secretNullifierHash
    ) external {}

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
