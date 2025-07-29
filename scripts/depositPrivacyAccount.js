const hre = require("hardhat");

const PA_ADDRESS = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318";
const TOKEN_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Depositing with account:", deployer.address);

    const testToken = await hre.ethers.getContractAt("MockERC20", TOKEN_ADDRESS);


    const privacyAccount = await hre.ethers.getContractAt("Account", PA_ADDRESS);

    // Deposit 1 data - SN hash 0: low: 206695238856679289309719721270756912533, high: 24719846671636985223041990782682324696
    const deposit1 = {
        secretNullifierHash: (BigInt("24719846671636985223041990782682324696") << 128n) + BigInt("206695238856679289309719721270756912533"),
        amount: BigInt("703789571415866399765"),
        tokenAddress: "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
    };

    // Deposit 2 data - SN hash 1: low: 232139093813905680560086533889701793112, high: 63747943465059982269835692015246825560  
    const deposit2 = {
        secretNullifierHash: (BigInt("63747943465059982269835692015246825560") << 128n) + BigInt("232139093813905680560086533889701793112"),
        amount: BigInt("703789571415866399765"),
        tokenAddress: "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
    };


    // address token

    try {
        // Execute first deposit
        const txApprove1 = await testToken.approve(PA_ADDRESS, deposit1.amount);
        await txApprove1.wait();
        console.log("Approved token transfer for Privacy Account - Deposit 1");

        const tx1 = await privacyAccount.connect(deployer).deposit(deposit1.secretNullifierHash, deposit1.amount, TOKEN_ADDRESS);
        await tx1.wait();
        console.log("Deposit 1 successful!");

        // Execute second deposit
        const txApprove2 = await testToken.approve(PA_ADDRESS, deposit2.amount);
        await txApprove2.wait();
        console.log("Approved token transfer for Privacy Account - Deposit 2");

        const tx2 = await privacyAccount.connect(deployer).deposit(deposit2.secretNullifierHash, deposit2.amount, TOKEN_ADDRESS);
        await tx2.wait();
        console.log("Deposit 2 successful!");
    } catch (error) {
        console.error("Deposit failed:", error);
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
