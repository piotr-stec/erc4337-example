const hre = require("hardhat");

const PA_ADDRESS = "0x809d550fca64d94Bd9F66E60752A544199cfAC3D";
const TOKEN_ADDRESS = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853";

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Depositing with account:", deployer.address);

    const testToken = await hre.ethers.getContractAt("MockERC20", TOKEN_ADDRESS);

    const balance = await testToken.balanceOf(PA_ADDRESS);
    console.log("Current balance:", hre.ethers.formatEther(balance), "tokens");

    const privacyAccount = await hre.ethers.getContractAt("Account", PA_ADDRESS);
    const counter = await privacyAccount.count();
    console.log("Current counter:", counter.toString());

    // address token

    // try {
    //     const txApprove = await testToken.approve(PA_ADDRESS, amount);
    //     await txApprove.wait();
    //     console.log("Approved token transfer for Privacy Account");

    // } catch (error) {
    //     console.error("Deposit failed:", error);
    // }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
