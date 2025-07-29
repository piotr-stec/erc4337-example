const hre = require("hardhat");

async function main() {
  const honkVerifier = await hre.ethers.deployContract("HonkVerifier");
  await honkVerifier.waitForDeployment();

  console.log(`HonkVerifier deployed to ${honkVerifier.target}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});