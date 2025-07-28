const hre = require("hardhat");

const PA_ADDRESS = "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c";
const TOKEN_ADDRESS = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853";

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Depositing with account:", deployer.address);

    const testToken = await hre.ethers.getContractAt("MockERC20", TOKEN_ADDRESS);


    const privacyAccount = await hre.ethers.getContractAt("Account", PA_ADDRESS);

    const secretNullifierHash = 123412; // Replace with actual nullifier hash if needed
    const amount = hre.ethers.parseEther("1.0"); // Amount to deposit (1 token)    


    // address token

    try {
        const txApprove = await testToken.approve(PA_ADDRESS, amount);
        await txApprove.wait();
        console.log("Approved token transfer for Privacy Account");


        const tx = await privacyAccount.connect(deployer).deposit(secretNullifierHash, amount, TOKEN_ADDRESS);
        await tx.wait();
        console.log("Deposit successful!");
    } catch (error) {
        console.error("Deposit failed:", error);
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
