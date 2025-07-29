const hre = require("hardhat");

const PA_ADDRESS = "0xAA292E8611aDF267e563f334Ee42320aC96D0463";
const TOKEN_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Depositing with account:", deployer.address);

    const testToken = await hre.ethers.getContractAt("MockERC20", TOKEN_ADDRESS);

    const balance = await testToken.balanceOf(PA_ADDRESS);
    console.log("Current balance:", hre.ethers.formatEther(balance), "tokens");

    const privacyAccount = await hre.ethers.getContractAt("Account", PA_ADDRESS);
    const counter = await privacyAccount.count();
    console.log("Current counter:", counter.toString());

}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
