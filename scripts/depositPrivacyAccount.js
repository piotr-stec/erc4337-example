const hre = require("hardhat");

const PP_ADDRESS = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9";
const TOKEN_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Depositing with account:", deployer.address);

    const testToken = await hre.ethers.getContractAt("MockERC20", TOKEN_ADDRESS);


    const privacyPool = await hre.ethers.getContractAt("PrivacyPool", PP_ADDRESS);

    // Deposit 1 data - SN hash 0: low: 206695238856679289309719721270756912533, high: 24719846671636985223041990782682324696
    const deposit1 = {
        secretNullifierHash: "0xb7368d213ea64063936640d5c52b4f8a82524afa716a051e11acd3b6eece1b9",
        amount: "0x3e8",
        tokenAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    };

    // Deposit 2 data - SN hash 1: low: 232139093813905680560086533889701793112, high: 63747943465059982269835692015246825560  
    const deposit2 = {
        secretNullifierHash: "0xa580aadb886e6bb2f77b89ecee76d7e22ca4dedba7562d0e75f22c6c7484b78",
        amount: "0x3e8",
        tokenAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    };


    // address token

    try {
        // Execute first deposit
        const txApprove1 = await testToken.approve(PP_ADDRESS, deposit1.amount);
        await txApprove1.wait();
        console.log("Approved token transfer for Privacy Pool - Deposit 1");

        const tx1 = await privacyPool.connect(deployer).deposit(deposit1.secretNullifierHash, deposit1.amount, TOKEN_ADDRESS);
        const receipt1 = await tx1.wait();
        console.log("Deposit 1 successful!");
        
        // Check for LeafAdded events from Deposit 1
        console.log("\n=== Deposit 1 Events ===");
        const leafAddedEvents1 = receipt1.logs.filter(log => {
            try {
                // LeafAdded event topic hash
                return log.topics[0] === hre.ethers.id("LeafAdded(address,uint256,uint256)");
            } catch (e) {
                return false;
            }
        });
        
        for (const log of leafAddedEvents1) {
            if (log.fragment && log.fragment.name === 'LeafAdded') {
                console.log("LeafAdded Event:");
                console.log("  Address:", log.address);
                console.log("  Caller:", log.args[0]);
                console.log("  Commitment:", log.args[1].toString());
                console.log("  New Root:", log.args[2].toString());
                console.log("  Index:", log.index);
                console.log("");
            }
        }
        
        if (leafAddedEvents1.length === 0) {
            console.log("No LeafAdded events found");
            console.log("All events:", receipt1.logs.map(log => ({
                address: log.address,
                topics: log.topics,
                data: log.data
            })));
        }

        // Execute second deposit
        const txApprove2 = await testToken.approve(PP_ADDRESS, deposit2.amount);
        await txApprove2.wait();
        console.log("\nApproved token transfer for Privacy Pool - Deposit 2");

        const tx2 = await privacyPool.connect(deployer).deposit(deposit2.secretNullifierHash, deposit2.amount, TOKEN_ADDRESS);
        const receipt2 = await tx2.wait();
        console.log("Deposit 2 successful!");
        
        // Check for LeafAdded events from Deposit 2
        console.log("\n=== Deposit 2 Events ===");
        const leafAddedEvents2 = receipt2.logs.filter(log => {
            try {
                return log.topics[0] === hre.ethers.id("LeafAdded(address,uint256,uint256)");
            } catch (e) {
                return false;
            }
        });
        
        for (const log of leafAddedEvents2) {
            if (log.fragment && log.fragment.name === 'LeafAdded') {
                console.log("LeafAdded Event:");
                console.log("  Address:", log.address);
                console.log("  Caller:", log.args[0]);
                console.log("  Commitment:", log.args[1].toString());
                console.log("  New Root:", log.args[2].toString());
                console.log("  Index:", log.index);
                console.log("");
            }
        }
        
        if (leafAddedEvents2.length === 0) {
            console.log("No LeafAdded events found");
        }
    } catch (error) {
        console.error("Deposit failed:", error);
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
