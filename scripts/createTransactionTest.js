const hre = require("hardhat");

// Addresses from existing deployments
const PP_ADDRESS = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9";
const TOKEN_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const secretHash = 3481040699; 

async function main() {
    console.log("=== Testing Create Transaction Function ===\n");

    const [deployer] = await hre.ethers.getSigners();
    console.log("Testing with account:", deployer.address);

    // Connect to deployed contracts
    const privacyPool = await hre.ethers.getContractAt("PrivacyPool", PP_ADDRESS);

    console.log("\nConnected to:");
    console.log("  PrivacyPool:", PP_ADDRESS);
    console.log("  TestToken:", TOKEN_ADDRESS);

    try {
        const requestedCryptoAmount = "850";
        
        const createTransactionTx = await privacyPool.createTransaction(
            secretHash, 
            requestedCryptoAmount
        );
        
        console.log("Transaction sent, waiting for confirmation...");
        const transactionReceipt = await createTransactionTx.wait();
        console.log("✅ Transaction created successfully!");
        console.log("Gas used:", transactionReceipt.gasUsed.toString());

        // ========== STEP 3: Parse Transaction Events ==========
        console.log("\n=== Step 3: Analyzing Transaction Events ===");
        
        let transactionId = null;
        let transactionCreatedData = null;
        let transactionResponseData = null;

        for (const log of transactionReceipt.logs) {
            try {
                const parsedLog = privacyPool.interface.parseLog(log);
                if (parsedLog) {
                    console.log(`\nFound event: ${parsedLog.name}`);
                    
                    if (parsedLog.name === 'TransactionCreated') {
                        transactionId = parsedLog.args[0];
                        transactionCreatedData = parsedLog.args;
                        console.log("TransactionCreated Event:");
                        console.log("  Transaction ID:", parsedLog.args[0]);
                        console.log("  Crypto Amount:", hre.ethers.formatEther(parsedLog.args[1]), "ETH");
                        console.log("  Fiat Amount:", parsedLog.args[2].toString());
                        console.log("  Currency:", parsedLog.args[3]);
                        console.log("  Rev Tag:", parsedLog.args[4]);
                    }
                    
                    if (parsedLog.name === 'TransactionResponse') {
                        transactionResponseData = parsedLog.args;
                        console.log("TransactionResponse Event:");
                        console.log("  Transaction ID:", parsedLog.args[0]);
                        console.log("  Fiat Amount:", parsedLog.args[1].toString());
                        console.log("  Currency:", parsedLog.args[2]);
                        console.log("  Random Title:", parsedLog.args[3]);
                    }
                }
            } catch (e) {
                // Skip unparseable logs
            }
        }

        // ========== STEP 4: Verify Transaction Storage ==========
        if (transactionId) {
            console.log("\n=== Step 4: Verifying Transaction Storage ===");
            
            const storedTransaction = await privacyPool.getTransaction(transactionId);
            console.log("Stored Transaction Details:");
            console.log("  ID:", storedTransaction.id);
            console.log("  Crypto Amount:", hre.ethers.formatEther(storedTransaction.cryptoAmount), "ETH");
            console.log("  Fiat Amount:", storedTransaction.fiatAmount.toString());
            console.log("  Currency:", storedTransaction.currency);
            console.log("  Status:", storedTransaction.status);
            console.log("  Random Title:", storedTransaction.randomTitle);
            console.log("  Token Address:", storedTransaction.tokenAddress);
            console.log("  Rev Tag:", storedTransaction.revTag);
            console.log("  Created:", new Date(parseInt(storedTransaction.timestamp) * 1000).toISOString());
            console.log("  Expires:", new Date(parseInt(storedTransaction.expiresAt) * 1000).toISOString());


        }

    } catch (error) {
        console.log("❌ Test failed:");
        console.log("Error message:", error.message);
        
        if (error.message.includes("Offer not found")) {
            console.log("→ Issue: Offer lookup using secretHash failed");
        } else if (error.message.includes("Offer not available")) {
            console.log("→ Issue: Offer status problem");
        } else if (error.message.includes("Insufficient offer amount")) {
            console.log("→ Issue: Not enough crypto in offer");
        } else if (error.message.includes("TransferFailed")) {
            console.log("→ Issue: Token transfer failed");
        }
        
        console.log("\nFull error:");
        console.log(error);
    }

    console.log("\n=== Test Complete ===");
}

main().catch((error) => {
    console.error("Script failed:", error);
    process.exitCode = 1;
});