const hre = require("hardhat");

async function main() {
  console.log("Deploying Test ERC20 Token...");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  // Deploy MockERC20 token with constructor parameters
  const MockERC20 = await hre.ethers.getContractFactory("MockERC20");
  
  try {
    const testToken = await MockERC20.deploy(
      "Test Token",                               // _name
      "TEST",                                     // _symbol  
      hre.ethers.parseEther("1000000")           // _totalSupply (1M tokens)
    );
    await testToken.waitForDeployment();

    console.log("TestToken deployed to:", testToken.target);
    
    // Check balance
    const balance = await testToken.balanceOf(deployer.address);
    console.log("Deployer balance:", hre.ethers.formatEther(balance), "TEST");

    return testToken.target;

  } catch (error) {
    console.error("Deployment failed:", error);
    console.log("\nTo fix this, create contracts/TestToken.sol with:");
    console.log(testTokenCode);
    throw error;
  }
}

main()
  .then((address) => {
    console.log("\nTest Token deployed at:", address);
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });