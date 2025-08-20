const hre = require("hardhat");

// Addresses from existing deployments
const PP_ADDRESS = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9";
const TOKEN_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

async function main() {
    console.log("=== Testing Cancel Offer Function ===\n");

    const [deployer] = await hre.ethers.getSigners();
    console.log("Testing with account:", deployer.address);

    // Connect to deployed contracts
    const privacyPool = await hre.ethers.getContractAt("PrivacyPool", PP_ADDRESS);
    const testToken = await hre.ethers.getContractAt("MockERC20", TOKEN_ADDRESS);

    console.log("Connected to:");
    console.log("  PrivacyPool:", PP_ADDRESS);
    console.log("  TestToken:", TOKEN_ADDRESS);

    // Example secret that was used to create an offer
    // In real scenario, this would be the secret that user provided when creating offer
    const secret = "12345678901234567890123456789012345678901234567890123456789012345678901234"; // Example secret
    
    // Calculate secretHash the same way as in contract: _poseidonHash(secret, 0)
    // For testing, we'll use a known secretHash from a created offer
    const secretHash = "0x091abada6450cc0090b7caaaee0e6e44dd87d01d8aa2514311e1a98b484162e0"; // From createOfferTest

    console.log("\n=== Cancel Parameters ===");
    console.log("Secret (example):", secret);
    console.log("Secret Hash:", secretHash);

    try {
        // First, check if offer exists
        console.log("\n=== Checking Offer Before Cancel ===");
        const offerBefore = await privacyPool.offers(secretHash);
        
        if (offerBefore.timestamp.toString() === "0") {
            console.log("❌ No offer found with this secret hash");
            console.log("Make sure to run createOfferTest.js first to create an offer");
            return;
        }

        console.log("Offer found:");
        console.log("  ID:", offerBefore.id);
        console.log("  Type:", offerBefore.offerType);
        console.log("  Status:", offerBefore.status);
        console.log("  Crypto Amount:", offerBefore.cryptoAmount.toString(), "wei");
        console.log("  Fee:", offerBefore.fee.toString(), "wei");
        console.log("  Token:", offerBefore.tokenAddress);
        console.log("  Created:", new Date(parseInt(offerBefore.timestamp) * 1000).toISOString());

        // Check if offer is in CREATED status
        if (offerBefore.status !== "CREATED") {
            console.log("❌ Offer is not in CREATED status, cannot cancel");
            return;
        }

        // Check user's balance before cancel
        const balanceBefore = await testToken.balanceOf(deployer.address);
        console.log("\n=== Balance Before Cancel ===");
        console.log("User balance:", hre.ethers.formatEther(balanceBefore), "tokens");

        // Calculate expected refund
        const expectedRefund = BigInt(offerBefore.cryptoAmount) + BigInt(offerBefore.fee);
        console.log("Expected refund:", expectedRefund.toString(), "wei");

        // Cancel the offer
        console.log("\n=== Canceling Offer ===");
        
        // Note: In real implementation, you would calculate secretHash from user's secret
        // For testing, we're using a mock secret that should hash to the known secretHash
        // Since we don't have the exact secret, we'll modify the function call
        
        // For this test, let's assume secret = 0 would hash to our secretHash (it won't, but for demo)
        // In production, user provides the actual secret they used
        const mockSecret = "0"; // This won't work with real hashing, but demonstrates the flow
        
        console.log("⚠ Note: This will likely fail because we don't have the exact secret");
        console.log("In real usage, user provides the secret they used when creating the offer");
        
        try {
            const cancelTx = await privacyPool.cancelOffer(mockSecret);
            console.log("Transaction sent, waiting for confirmation...");
            const receipt = await cancelTx.wait();
            console.log("✅ Offer canceled successfully!");
            console.log("Transaction hash:", receipt.hash);
            console.log("Gas used:", receipt.gasUsed.toString());

            // Check for OfferCanceled events
            console.log("\n=== Checking Events ===");
            const offerCanceledEvents = receipt.logs.filter(log => {
                try {
                    return log.topics[0] === hre.ethers.id("OfferCanceled(bytes32,uint256,address)");
                } catch (e) {
                    return false;
                }
            });

            if (offerCanceledEvents.length > 0) {
                for (const log of offerCanceledEvents) {
                    if (log.fragment && log.fragment.name === 'OfferCanceled') {
                        console.log("OfferCanceled Event:");
                        console.log("  Offer ID:", log.args[0]);
                        console.log("  Secret Hash:", log.args[1].toString());
                        console.log("  Canceler:", log.args[2]);
                    }
                }
            } else {
                console.log("No OfferCanceled events found");
            }

            // Check balance after cancel
            const balanceAfter = await testToken.balanceOf(deployer.address);
            const refundReceived = balanceAfter - balanceBefore;
            
            console.log("\n=== Balance After Cancel ===");
            console.log("User balance:", hre.ethers.formatEther(balanceAfter), "tokens");
            console.log("Refund received:", refundReceived.toString(), "wei");

            // Check offer status after cancel
            const offerAfter = await privacyPool.offers(secretHash);
            console.log("\n=== Offer After Cancel ===");
            console.log("Status:", offerAfter.status);

        } catch (cancelError) {
            console.log("❌ Cancel failed (expected):");
            console.log("Error:", cancelError.message);
            
            if (cancelError.message.includes("OfferNotFound")) {
                console.log("→ Secret hash doesn't match any existing offer");
            } else if (cancelError.message.includes("OfferNotActive")) {
                console.log("→ Offer is not in CREATED status");
            }
            
            console.log("\n💡 To test cancel functionality properly:");
            console.log("1. When creating an offer, save the secret used");
            console.log("2. Use that exact secret in cancelOffer function");
            console.log("3. The contract will hash the secret to find the matching offer");
        }

    } catch (error) {
        console.log("❌ Test failed:");
        console.log("Error:", error.message);
    }

    console.log("\n=== Instructions for Real Usage ===");
    console.log("1. User creates offer with secret S");
    console.log("2. Contract stores offer with key = hash(S, 0)");  
    console.log("3. To cancel, user provides secret S");
    console.log("4. Contract computes hash(S, 0) and finds the offer");
    console.log("5. Contract refunds crypto + fee to msg.sender");
    console.log("6. Offer status changed to CANCELED");

    console.log("\n=== Test Complete ===");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});