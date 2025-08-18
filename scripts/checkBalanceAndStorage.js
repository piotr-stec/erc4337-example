const hre = require("hardhat");

const PP_ADDRESS = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707";
const TOKEN_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Depositing with account:", deployer.address);

    const testToken = await hre.ethers.getContractAt("MockERC20", TOKEN_ADDRESS);

    const balance = await testToken.balanceOf(PP_ADDRESS);
    console.log("Current balance:", hre.ethers.formatEther(balance), "tokens");


}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
