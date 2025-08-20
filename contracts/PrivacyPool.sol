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

struct Transaction {
    bytes32 id;
    uint256 cryptoAmount;
    uint256 fiatAmount;
    string currency;
    uint256 expiresAt;
    string status; // "pending", "success", "rejected"
    string randomTitle;
    address tokenAddress;
    string revTag;
    uint256 timestamp;
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

    // Transaction state
    mapping(bytes32 => Transaction) public transactions; // transactionId => Transaction

    uint256 public count;
    address public owner;
    address public verifier;
    address public tlsnTransactionVerifier;
    address public tlsnBinanceVerifier;

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
        string offerType,
        uint256 cryptoAmount,
        uint256 fiatAmount,
        string currency,
        address tokenAddress,
        string revTag
    );

    event OfferCanceled(
        bytes32 indexed offerId,
        uint256 indexed secretHash,
        address indexed canceler
    );

    event PrivateOfferCanceled(
        bytes32 indexed offerId,
        uint256 indexed secretHash,
        uint256 secretNullifierHash,
        uint256 amount,
        address tokenAddress
    );

    event TransactionCreated(
        bytes32 indexed transactionId,
        uint256 indexed cryptoAmount,
        uint256 indexed fiatAmount,
        string currency,
        string revTag
    );

    event TransactionResponse(
        bytes32 indexed transactionId,
        uint256 fiatAmount,
        string currency,
        string randomTitle
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
        address _tlsnTransactionVerifier,
        address _tlsnBinanceVerifier
    ) {
        owner = _owner;
        verifier = _verifier;
        tlsnTransactionVerifier = _tlsnTransactionVerifier;
        tlsnBinanceVerifier = _tlsnBinanceVerifier;
        tree.initialize();
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
            abi.encodePacked(block.timestamp, secretHash)
        );

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
            offerType,
            cryptoAmount,
            fiatAmount,
            currency,
            tokenAddress,
            revTag
        );
    }

    // Public offer cancellation function - funds go back to the user
    function cancelOffer(uint256 secret) external {
        // Hash the secret to get secretHash
        uint256 secretHash = _poseidonHash(secret, secret); // use the same hash that is available in the mobile backend

        // Check if offer exists
        if (offers[secretHash].timestamp == 0) {
            revert OfferNotFound();
        }

        // Check if offer is in CREATED status
        if (
            keccak256(bytes(offers[secretHash].status)) !=
            keccak256(bytes("CREATED"))
        ) {
            revert OfferNotActive();
        }

        // Get offer details before deletion
        bytes32 offerId = offers[secretHash].id;
        uint256 cryptoAmount = offers[secretHash].cryptoAmount;
        address tokenAddress = offers[secretHash].tokenAddress;

        // Update offer status to CANCELED
        offers[secretHash].status = "CANCELED";

        // Refund crypto - fee is not refunded
        IERC20 erc20 = IERC20(tokenAddress);
        bool success = erc20.transfer(msg.sender, cryptoAmount);
        if (!success) revert TransferFailed();

        // Emit event
        emit OfferCanceled(offerId, secretHash, msg.sender);
    }

    function privateCancelOffer(
        uint256 secret,
        uint256 secretNullifierHash
    ) external {
        uint256 secretHash = _poseidonHash(secret, secret);

        // Check if offer exists
        if (offers[secretHash].timestamp == 0) {
            revert OfferNotFound();
        }

        // Check if offer is in CREATED status
        if (
            keccak256(bytes(offers[secretHash].status)) !=
            keccak256(bytes("CREATED"))
        ) {
            revert OfferNotActive();
        }

        // Get offer details before deletion
        bytes32 offerId = offers[secretHash].id;
        uint256 cryptoAmount = offers[secretHash].cryptoAmount;
        address tokenAddress = offers[secretHash].tokenAddress;

        // Update offer status to CANCELED
        offers[secretHash].status = "CANCELED";

        // create new deposit commitment
        uint256 secretNullifierAmountHash = _poseidonHash(
            secretNullifierHash,
            cryptoAmount
        );
        uint256 commitment = _poseidonHash(
            secretNullifierAmountHash,
            uint256(uint160(tokenAddress))
        );
        // Add to merkle tree
        tree.addLeaf(commitment);

        emit PrivateOfferCanceled(
            offerId,
            secretHash,
            secretNullifierHash,
            cryptoAmount,
            tokenAddress
        );
    }

    function createTransaction(
        uint256 offerId,
        uint256 cryptoAmount
    ) external returns (bytes32) {
        // Validate offer exists and is available
        require(offers[offerId].id != bytes32(0), "Offer not found");
        require(
            keccak256(bytes(offers[offerId].status)) ==
                keccak256(bytes("CREATED")),
            "Offer not available"
        );
        require(
            offers[offerId].cryptoAmount >= cryptoAmount,
            "Insufficient offer amount"
        );
        require(cryptoAmount > 0, "Crypto amount must be greater than 0");

        // Generate unique transaction ID
        bytes32 transactionId = keccak256(
            abi.encodePacked(
                block.timestamp,
                msg.sender,
                block.prevrandao,
                offerId
            )
        );

        // Get offer data
        Offer memory offer = offers[offerId];

        // Calculate proportional fiat amount based on crypto amount requested
        uint256 proportionalFiatAmount = (offer.fiatAmount * cryptoAmount) /
            offer.cryptoAmount;

        // Generate random title
        string memory randomTitle = string(
            abi.encodePacked("TX-", uint2str(uint256(transactionId) % 10000))
        );

        // Calculate expiration timestamp (2 hours default)
        uint256 expiresAt = block.timestamp + (120 minutes);

        // Create transaction
        Transaction memory newTransaction = Transaction({
            id: transactionId,
            cryptoAmount: cryptoAmount,
            fiatAmount: proportionalFiatAmount,
            currency: offer.currency,
            expiresAt: expiresAt,
            status: "pending",
            randomTitle: randomTitle,
            tokenAddress: offer.tokenAddress,
            revTag: offer.revTag,
            timestamp: block.timestamp
        });

        // Store transaction
        transactions[transactionId] = newTransaction;

        // Reduce offer's available amount instead of locking entire offer
        offers[offerId].cryptoAmount -= cryptoAmount;
        offers[offerId].fiatAmount -= proportionalFiatAmount;

        // If offer is fully consumed, mark it as completed
        if (offers[offerId].cryptoAmount == 0) {
            offers[offerId].status = "COMPLETED";
        }

        // Emit events
        emit TransactionCreated(
            transactionId,
            cryptoAmount,
            proportionalFiatAmount,
            offer.currency,
            offer.revTag
        );

        emit TransactionResponse(
            transactionId,
            proportionalFiatAmount,
            offer.currency,
            randomTitle
        );

        return transactionId;
    }

    function updateTransactionStatus(
        bytes32 transactionId,
        string calldata newStatus
    ) external {
        // Check if transaction exists
        require(
            transactions[transactionId].timestamp != 0,
            "Transaction not found"
        );

        // Check if transaction hasn't expired
        require(
            block.timestamp <= transactions[transactionId].expiresAt,
            "Transaction expired"
        );

        // Only allow valid status transitions
        require(
            keccak256(bytes(newStatus)) == keccak256(bytes("success")) ||
                keccak256(bytes(newStatus)) == keccak256(bytes("rejected")) ||
                keccak256(bytes(newStatus)) == keccak256(bytes("pending")),
            "Invalid status"
        );

        // Update status
        transactions[transactionId].status = newStatus;
    }

    function getTransaction(
        bytes32 transactionId
    ) external view returns (Transaction memory) {
        require(
            transactions[transactionId].timestamp != 0,
            "Transaction not found"
        );
        return transactions[transactionId];
    }

    function verifyTransaction(
        bytes calldata proofTransaction,
        bytes32[] calldata publicInputsTransaction,
        bytes calldata proofPrice,
        bytes32[] calldata publicInputsPrice,
        bytes32 transactionId,
        uint256 secretNullifierHash
    ) external {
        // // Verify proof
        // IVerifier honkVerifier = IVerifier(tlsnTransactionVerifier);
        // if (!honkVerifier.verify(proofTransaction, publicInputsTransaction)) {
        //     revert("Invalid proof");
        // }

        // Verify proof
        IVerifier honkBinanceVerifier = IVerifier(tlsnBinanceVerifier);
        if (!honkBinanceVerifier.verify(proofPrice, publicInputsPrice)) {
            revert("Invalid proof");
        }

        // Validate transaction exists
        // Transaction storage transaction = transactions[transactionId];
        // require(transaction.timestamp != 0, "Transaction not found");

        // TODO: proof checks

        // uint256 secretNullifierAmountHash = _poseidonHash(
        //     secretNullifierHash,
        //     amount
        // );
        // uint256 commitment = _poseidonHash(
        //     secretNullifierAmountHash,
        //     uint256(uint160(token))
        // );

        // // Add to merkle tree
        // tree.addLeaf(commitment);

        // Update transaction status to success
        // transaction.status = "success";

        // emit TransactionResponse(
        //     transactionId,
        //     transaction.fiatAmount,
        //     transaction.currency,
        //     transaction.randomTitle
        // );
    }

    function _poseidonHash(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256) {
        uint256[2] memory inputs = [a, b];
        return PoseidonT3.hash(inputs);
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
        IVerifier honkVerifier = IVerifier(verifier);
        if (!honkVerifier.verify(proof, publicInputs)) {
            revert("Invalid proof");
        }
        count++;
    }

    // Helper function to convert uint to string
    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - (_i / 10) * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    // Test function to extract and return price and symbol data
    function testExtractPriceData(
        bytes calldata proofPrice,
        bytes32[] calldata publicInputsPrice
    ) external view returns (string memory price, string memory symbol, uint64 mins, uint256 closeTime) {
        // Verify proof first
        IVerifier honkBinanceVerifier = IVerifier(tlsnBinanceVerifier);
        require(honkBinanceVerifier.verify(proofPrice, publicInputsPrice), "Invalid proof");
        
        // Extract data
        price = extractPrice(publicInputsPrice);
        symbol = extractSymbol(publicInputsPrice);
        mins = extractMins(publicInputsPrice);
        closeTime = extractCloseTime(publicInputsPrice);
    }

    // Test function WITHOUT proof verification for debugging
    function testExtractPriceDataNoVerify(
        bytes32[] calldata publicInputsPrice
    ) external pure returns (string memory price, string memory symbol, uint64 mins, uint256 closeTime) {
        // Extract data without proof verification
        price = extractPrice(publicInputsPrice);
        symbol = extractSymbol(publicInputsPrice);
        mins = extractMins(publicInputsPrice);
        closeTime = extractCloseTime(publicInputsPrice);
    }

    // Test function with clean data extraction
    function testExtractCleanPriceData(
        bytes32[] calldata publicInputsPrice
    ) external pure returns (uint256 cleanPrice, string memory cleanSymbol, uint64 mins, uint256 closeTime) {
        // Extract clean data
        cleanPrice = extractCleanPrice(publicInputsPrice);
        cleanSymbol = extractCleanSymbol(publicInputsPrice);
        mins = extractMins(publicInputsPrice);
        closeTime = extractCloseTime(publicInputsPrice);
    }

    // Debug function to see raw bytes
    function debugRawBytes(
        bytes32[] calldata publicInputs, 
        uint256 startIndex, 
        uint256 length
    ) external pure returns (bytes memory) {
        bytes memory rawData = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            rawData[i] = bytes1(uint8(uint256(publicInputs[startIndex + i])));
        }
        return rawData;
    }

    function extractPrice(bytes32[] calldata publicInputs) internal pure returns (string memory) {
        bytes memory priceData = new bytes(20);
        
        // Price.data starts at index 70 (corrected calculation)
        for (uint256 i = 0; i < 20; i++) {
            priceData[i] = bytes1(uint8(uint256(publicInputs[70 + i])));
        }
        
        return string(priceData);
    }

    function extractSymbol(bytes32[] calldata publicInputs) internal pure returns (string memory) {
        bytes memory symbolData = new bytes(14);
        
        // Symbol.data starts at index 108 (corrected calculation)
        for (uint256 i = 0; i < 14; i++) {
            symbolData[i] = bytes1(uint8(uint256(publicInputs[108 + i])));
        }
        
        return string(symbolData);
    }

    // Extract clean price value from JSON format like "price":"3.62596667"
    function extractCleanPrice(bytes32[] calldata publicInputs) internal pure returns (uint256) {
        // Extract raw price data
        bytes memory priceData = new bytes(20);
        for (uint256 i = 0; i < 20; i++) {
            priceData[i] = bytes1(uint8(uint256(publicInputs[70 + i])));
        }
        
        // Find the numeric value between the quotes after ":"
        // Format: "price":"3.62596667"
        // We want to extract "3.62596667" and convert to uint256 with 8 decimal places
        
        uint256 start = 0;
        uint256 end = 0;
        bool foundColon = false;
        bool foundSecondQuote = false;
        
        for (uint256 i = 0; i < 20; i++) {
            if (priceData[i] == 0x3A) { // ':'
                foundColon = true;
            } else if (foundColon && priceData[i] == 0x22) { // '"' after colon
                if (!foundSecondQuote) {
                    start = i + 1; // Start after the quote
                    foundSecondQuote = true;
                } else {
                    end = i; // End at the closing quote
                    break;
                }
            }
        }
        
        // Parse the decimal number
        uint256 result = 0;
        uint256 decimals = 0;
        bool hasDecimal = false;
        
        for (uint256 i = start; i < end; i++) {
            uint8 digit = uint8(priceData[i]);
            if (digit == 0x2E) { // '.'
                hasDecimal = true;
            } else if (digit >= 0x30 && digit <= 0x39) { // '0'-'9'
                result = result * 10 + (digit - 0x30);
                if (hasDecimal) {
                    decimals++;
                }
            }
        }
        
        // Normalize to 8 decimal places
        while (decimals < 8) {
            result *= 10;
            decimals++;
        }
        
        return result;
    }

    // Extract clean symbol from format like "symbol=USDTPLN"
    function extractCleanSymbol(bytes32[] calldata publicInputs) internal pure returns (string memory) {
        bytes memory symbolData = new bytes(14);
        for (uint256 i = 0; i < 14; i++) {
            symbolData[i] = bytes1(uint8(uint256(publicInputs[108 + i])));
        }
        
        // Find the symbol after '='
        uint256 start = 0;
        for (uint256 i = 0; i < 14; i++) {
            if (symbolData[i] == 0x3D) { // '='
                start = i + 1;
                break;
            }
        }
        
        // Extract symbol part
        bytes memory cleanSymbol = new bytes(14 - start);
        for (uint256 i = 0; i < 14 - start; i++) {
            cleanSymbol[i] = symbolData[start + i];
        }
        
        return string(cleanSymbol);
    }

    function extractMins(bytes32[] calldata publicInputs) internal pure returns (uint64) {
        // Mins.data starts at index 1, 8 bytes
        uint64 mins = 0;
        for (uint256 i = 0; i < 8; i++) {
            mins |= uint64(uint8(uint256(publicInputs[1 + i]))) << uint64(8 * (7 - i));
        }
        return mins;
    }

    function extractCloseTime(bytes32[] calldata publicInputs) internal pure returns (uint256) {
        // CloseTime.data starts at index 27, 25 bytes
        uint256 closeTime = 0;
        for (uint256 i = 0; i < 25; i++) {
            closeTime |= uint256(uint8(uint256(publicInputs[27 + i]))) << (8 * (24 - i));
        }
        return closeTime;
    }
}
