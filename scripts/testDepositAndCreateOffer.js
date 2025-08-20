const hre = require("hardhat");

async function main() {
    console.log("=== Testing Deposit → Create Offer Flow ===\n");

    const [deployer] = await hre.ethers.getSigners();
    console.log("Testing with account:", deployer.address);

    // 1. Deploy MockERC20 token
    console.log("1. Deploying MockERC20 token...");
    const MockERC20 = await hre.ethers.getContractFactory("MockERC20");
    const testToken = await MockERC20.deploy(
        "Test Token",
        "TEST", 
        hre.ethers.parseEther("1000000")
    );
    await testToken.waitForDeployment();
    console.log("   Token deployed to:", testToken.target);
    
    // 2. Deploy MockVerifier (for testing logic without ZK verification)
    console.log("2. Deploying MockVerifier for testing...");
    const MockVerifier = await hre.ethers.getContractFactory("MockVerifier");
    const mockVerifier = await MockVerifier.deploy();
    await mockVerifier.waitForDeployment();
    console.log("   MockVerifier deployed to:", mockVerifier.target);

    // 3. Deploy PrivacyPool with MockVerifier
    console.log("3. Deploying PrivacyPool...");
    const MerkleTreeLib = await hre.ethers.getContractFactory("MerkleTreeLib");
    const merkleTreeLib = await MerkleTreeLib.deploy();
    await merkleTreeLib.waitForDeployment();

    const PoseidonT3 = await hre.ethers.getContractFactory("PoseidonT3");
    const poseidonT3 = await PoseidonT3.deploy();
    await poseidonT3.waitForDeployment();

    const PrivacyPool = await hre.ethers.getContractFactory("PrivacyPool", {
        libraries: {
            MerkleTreeLib: merkleTreeLib.target,
            PoseidonT3: poseidonT3.target,
        },
    });

    const privacyPool = await PrivacyPool.deploy(
        deployer.address,
        mockVerifier.target,
        [] // Empty VK for MockVerifier
    );
    await privacyPool.waitForDeployment();
    console.log("   PrivacyPool deployed to:", privacyPool.target);

    // 4. Perform deposit
    console.log("\n4. Performing deposit...");
    const depositAmount = hre.ethers.parseEther("100");
    const secretNullifierHash = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    
    // Approve token transfer
    const approveTx = await testToken.approve(privacyPool.target, depositAmount);
    await approveTx.wait();
    console.log("   Tokens approved");

    // Execute deposit
    const depositTx = await privacyPool.deposit(secretNullifierHash, depositAmount, testToken.target);
    const depositReceipt = await depositTx.wait();
    console.log("   Deposit successful!");

    // Check for LeafAdded events
    const leafAddedEvents = depositReceipt.logs.filter(log => {
        try {
            return log.topics[0] === hre.ethers.id("LeafAdded(address,uint256,uint256)");
        } catch (e) {
            return false;
        }
    });

    let commitment, newRoot;
    for (const log of leafAddedEvents) {
        if (log.fragment && log.fragment.name === 'LeafAdded') {
            commitment = log.args[1];
            newRoot = log.args[2];
            console.log("   Commitment:", commitment.toString());
            console.log("   New Root:", newRoot.toString());
            break;
        }
    }

    // 5. Create offer using the deposit
    console.log("\n5. Creating offer...");
    
    // TODO: Replace with your actual proof data from circuit
    const actualProof = "0x" + "00".repeat(100); // REPLACE WITH YOUR PROOF
    
    // TODO: Replace with your actual public inputs from circuit
    const actualPublicInputs = [
        newRoot.toString(),                    // root_1 - use actual root from your circuit
        "111111111111111111111111111111",     // nullifier_1 - use actual nullifier
        testToken.target,                      // token_address_1
        depositAmount.toString(),              // amount
        newRoot.toString(),                    // root_2 - use actual root
        "222222222222222222222222222222",     // nullifier_2 - use actual nullifier
        testToken.target,                      // token_address_2
        "0",                                   // gas_fee
        "333333333333333333333333333333",     // refund_commitment_hash
        "444444444444444444444444444444",     // refund_commitment_hash_fee  
        deployer.address,                      // recipient
        // TODO: Add your actual VK data (112 bytes32 values)
        ...Array(112).fill("0x" + "ff".repeat(32))
    ];

    // Offer parameters
    const offerParams = {
        offerType: "SELL",
        currency: "USD", 
        cryptoAmount: hre.ethers.parseEther("50"), // Using 50 ETH from 100 ETH deposit
        fiatAmount: hre.ethers.parseEther("100000"), // $100,000
        tokenAddress: testToken.target,
        fee: hre.ethers.parseEther("1"),
        revTag: "user123"
    };

    const secretHash = "99999999999999999999999999999999999999999999999999999999999999999999999999999999";

    try {
        const createOfferTx = await privacyPool.createOffer(
            actualProof,
            actualPublicInputs,
            secretHash,
            offerParams
        );
        
        const createOfferReceipt = await createOfferTx.wait();
        console.log("   Offer created successfully!");
        
        // Check for OfferCreated events
        const offerCreatedEvents = createOfferReceipt.logs.filter(log => {
            try {
                return log.topics[0] === hre.ethers.id("OfferCreated(bytes32,uint256,address,string,uint256,uint256)");
            } catch (e) {
                return false;
            }
        });

        for (const log of offerCreatedEvents) {
            if (log.fragment && log.fragment.name === 'OfferCreated') {
                console.log("   Offer ID:", log.args[0]);
                console.log("   Secret Hash:", log.args[1].toString());
                console.log("   Offer Type:", log.args[3]);
                console.log("   Crypto Amount:", hre.ethers.formatEther(log.args[4]));
                console.log("   Fiat Amount:", hre.ethers.formatEther(log.args[5]));
            }
        }

        // 6. Verify offer is stored
        console.log("\n6. Verifying offer storage...");
        const storedOffer = await privacyPool.offers(secretHash);
        console.log("   Stored offer type:", storedOffer.offerType);
        console.log("   Stored crypto amount:", hre.ethers.formatEther(storedOffer.cryptoAmount));
        console.log("   Stored status:", storedOffer.status);

    } catch (error) {
        console.error("   Create offer failed:", error.message);
    }

    console.log("\n=== Test Complete ===");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});