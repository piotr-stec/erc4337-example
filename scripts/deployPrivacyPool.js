const hre = require("hardhat");

async function main() {
  console.log("Deploying PrivacyPool contract...");


  // Deploy PoseidonT3 library
  console.log("Deploying PoseidonT3 library...");
  const poseidonT3 = await hre.ethers.deployContract("PoseidonT3");
  await poseidonT3.waitForDeployment();
  console.log("PoseidonT3 deployed to:", poseidonT3.target);

  // Deploy MerkleTreeLib library 
  const MerkleTreeLibFactory = await hre.ethers.getContractFactory("MerkleTreeLib", {
    libraries: {
      PoseidonT3: poseidonT3.target,
    },
  });
  const merkleTreeLib = await MerkleTreeLibFactory.deploy();
  await merkleTreeLib.waitForDeployment();
  console.log(`MerkleTreeLib deployed to: ${merkleTreeLib.target}`);

  // Deploy HonkVerifier
  console.log("Deploying HonkVerifier...");
  const HonkVerifier = await hre.ethers.getContractFactory("HonkVerifier");
  const honkVerifier = await HonkVerifier.deploy();
  await honkVerifier.waitForDeployment();
  console.log(`HonkVerifier deployed to: ${honkVerifier.target}`);

  // Deploy HonkVerifierBinance
  console.log("Deploying HonkVerifierBinance...");
  const HonkVerifierBinance = await hre.ethers.getContractFactory("HonkVerifierBinance");
  const honkVerifierBinance = await HonkVerifierBinance.deploy();
  await honkVerifierBinance.waitForDeployment();
  console.log(`HonkVerifierBinance deployed to: ${honkVerifierBinance.target}`);
  
  // Deployment parameters
  const [deployer] = await hre.ethers.getSigners();
  const owner = deployer.address;
  const verifier = honkVerifier.target;
  const tlsnBinanceVerifier = honkVerifierBinance.target;

  // Deploy PrivacyPool with library linking
  console.log("Deploying PrivacyPool contract...");
  const PrivacyPool = await hre.ethers.getContractFactory("PrivacyPool", {
    libraries: {
      MerkleTreeLib: merkleTreeLib.target,
      PoseidonT3: poseidonT3.target,
    },
  });

  const privacyPool = await PrivacyPool.deploy(
    owner,
    verifier,
    hre.ethers.ZeroAddress, // tlsnTransactionVerifier
    tlsnBinanceVerifier
  );
  await privacyPool.waitForDeployment();

  console.log(`PrivacyPool deployed to: ${privacyPool.target}`);
  console.log(`Owner: ${owner}`);
  console.log(`Verifier: ${verifier}`);
  console.log(`Binance Verifier: ${tlsnBinanceVerifier}`);


  // Return deployed addresses for use in other scripts
  return {
    privacyPool: privacyPool.target,
    merkleTreeLib: merkleTreeLib.target,
    poseidonT3: poseidonT3.target,
    honkVerifier: honkVerifier.target,
    owner: owner
  };
}

// Allow script to be called from other scripts
if (require.main === module) {
  main()
    .then((addresses) => {
      console.log("\n=== Deployment Summary ===");
      console.log("PrivacyPool:", addresses.privacyPool);
      console.log("MerkleTreeLib:", addresses.merkleTreeLib);
      console.log("PoseidonT3:", addresses.poseidonT3);
      console.log("HonkVerifier:", addresses.honkVerifier);
      console.log("Owner:", addresses.owner);
      process.exit(0);
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}

module.exports = main;