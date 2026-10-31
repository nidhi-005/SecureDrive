
const hre = require("hardhat");

async function main() {
  const signers = await hre.ethers.getSigners();

  const deployer = signers[0];

  // For local development, use a separate account.
  // For Sepolia, provide INITIAL_SIGNER_ADDRESS.
  const initialSignerAddress =
    process.env.INITIAL_SIGNER_ADDRESS ||
    signers[1].address;

  console.log("Deploying SecureDriveIntegrity...");
  console.log("Contract owner:", deployer.address);
  console.log("Initial authorized signer:", initialSignerAddress);

  const Factory = await hre.ethers.getContractFactory(
    "SecureDriveIntegrity"
  );

  const contract = await Factory.deploy(initialSignerAddress);

  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();

  console.log("----------------------------------");
  console.log("Deployment successful!");
  console.log("Contract address:", contractAddress);
  console.log("----------------------------------");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
