const hre = require("hardhat");

async function main() {
  console.log("Fixed deployment approach...");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  // Use existing addresses
  const POSEIDON_T3 = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  const MERKLE_TREE_LIB = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
  const ACCOUNT_FACTORY = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
  const RECURSIVE_VERIFIER = "0x4A679253410272dd5232B3Ff7cF5dbB88f295319";

  try {
    // Deploy Account directly instead of through factory
    console.log("Deploying Account directly...");
    const Account = await hre.ethers.getContractFactory("Account", {
      libraries: {
        PoseidonT3: POSEIDON_T3,
        MerkleTreeLib: MERKLE_TREE_LIB,
      },
    });

    const privacyAccount = await Account.deploy(deployer.address, RECURSIVE_VERIFIER);
    await privacyAccount.waitForDeployment();
    
    console.log("Privacy Account deployed directly to:", privacyAccount.target);

    // Test basic functions
    const owner = await privacyAccount.owner();
    const currentRoot = await privacyAccount.getCurrentRoot();
    
    console.log("Owner:", owner);
    console.log("Initial Merkle Root:", currentRoot.toString());

    console.log("\n✅ Direct deployment successful!");
    console.log("=".repeat(50));
    console.log("Privacy Account:", privacyAccount.target);
    console.log("Test Token:", "0x5FbDB2315678afecb367f032d93F642f64180aa3");
    console.log("=".repeat(50));

    return privacyAccount.target;

  } catch (error) {
    console.error("Deployment failed:", error);
    throw error;
  }
}

main()
  .then((address) => {
    console.log("\nSave this address for testing:");
    console.log("Privacy Account:", address);
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });