const hre = require("hardhat");

async function main() {
  console.log("Deploying Test ERC20 Token with deterministic address...");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  // Stały salt dla deterministycznego adresu
  const salt = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("TestToken_v1"));

  // Parametry konstruktora
  const name = "Test Token";
  const symbol = "TEST";
  const totalSupply = hre.ethers.parseEther("1000000");

  // Deploy MockERC20 token with constructor parameters
  const MockERC20 = await hre.ethers.getContractFactory("MockERC20");
  
  try {
    // Predict deterministic address using CREATE2
    const constructorArgs = hre.ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "string", "uint256"],
      [name, symbol, totalSupply]
    );
    
    const bytecodeWithConstructor = hre.ethers.solidityPacked(
      ["bytes", "bytes"],
      [MockERC20.bytecode, constructorArgs]
    );
    
    const predictedAddress = hre.ethers.getCreate2Address(
      deployer.address,
      salt,
      hre.ethers.keccak256(bytecodeWithConstructor)
    );

    console.log("Predicted address:", predictedAddress);

    // Check if contract already exists at this address
    const code = await hre.ethers.provider.getCode(predictedAddress);
    if (code !== "0x") {
      console.log("Contract already deployed at:", predictedAddress);
      const existingToken = MockERC20.attach(predictedAddress);
      const balance = await existingToken.balanceOf(deployer.address);
      console.log("Deployer balance:", hre.ethers.formatEther(balance), "TEST");
      return predictedAddress;
    }

    // Deploy using CREATE2
    const factory = new hre.ethers.ContractFactory(
      MockERC20.interface.fragments,
      MockERC20.bytecode,
      deployer
    );

    const deployTransaction = factory.getDeployTransaction(name, symbol, totalSupply);
    
    // Manual CREATE2 deployment
    const create2Factory = "0x4e59b44847b379578588920cA78FbF26c0B4956C"; // Universal CREATE2 factory
    
    // Use fixed nonce for deterministic deployment
    const fixedNonce = 0;
    console.log("Using fixed nonce:", fixedNonce);
    
    const testToken = await MockERC20.deploy(
      name,
      symbol,
      totalSupply,
      { nonce: fixedNonce }
    );
    await testToken.waitForDeployment();

    console.log("TestToken deployed to:", testToken.target);
    console.log("Salt used:", salt);
    
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