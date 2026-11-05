const {
  JsonRpcProvider,
  Wallet,
  Contract
} = require('ethers');

const ABI = require('../blockchain/IntegrityABI');

let blockchainInstance = null;

const BYTES32_REGEX = /^0x[a-fA-F0-9]{64}$/;

function validateBytes32(value, fieldName) {
  if (typeof value !== 'string' || !BYTES32_REGEX.test(value)) {
    throw new Error(`${fieldName} must be a valid bytes32 hex string`);
  }
}

async function getBlockchain() {
  if (blockchainInstance) {
    return blockchainInstance;
  }

  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL;
  const contractAddress = process.env.BLOCKCHAIN_CONTRACT_ADDRESS;
  const expectedChainId = process.env.BLOCKCHAIN_CHAIN_ID;
  const privateKey = process.env.BLOCKCHAIN_SIGNER_PRIVATE_KEY;

  if (!rpcUrl || !contractAddress || !expectedChainId || !privateKey) {
    throw new Error('Blockchain environment variables are missing');
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) {
    throw new Error('Invalid blockchain contract address');
  }

  const provider = new JsonRpcProvider(rpcUrl);

  // Verify that we are connected to the expected network.
  const network = await provider.getNetwork();

  if (network.chainId !== BigInt(expectedChainId)) {
    throw new Error(
      `Wrong blockchain network. Expected chain ID ${expectedChainId}, ` +
      `received ${network.chainId}`
    );
  }

  // Confirm that a contract is deployed at the configured address.
  const deployedCode = await provider.getCode(contractAddress);

  if (!deployedCode || deployedCode === '0x') {
    throw new Error('No smart contract deployed at configured address');
  }

  const signer = new Wallet(privateKey, provider);

  const contract = new Contract(
    contractAddress,
    ABI,
    signer
  );

  // Check that the backend signer is authorized by the contract.
  const isAuthorized = await contract.authorizedSigners(signer.address);

  if (!isAuthorized) {
    throw new Error(
      `Backend signer ${signer.address} is not authorized by the contract`
    );
  }

  blockchainInstance = {
    provider,
    signer,
    contract,
    network
  };

  console.log('Blockchain connection established');
  console.log('Chain ID:', network.chainId.toString());
  console.log('Contract:', contractAddress);
  console.log('Backend signer:', signer.address);

  return blockchainInstance;
}


// --------------------------------------------------
// CONNECTION INFORMATION
// --------------------------------------------------

async function getConnectionInfo() {
  const { provider, signer, contract, network } =
    await getBlockchain();

  const owner = await contract.owner();

  return {
    connected: true,
    chainId: network.chainId.toString(),
    contractAddress: await contract.getAddress(),
    signerAddress: signer.address,
    contractOwner: owner
  };
}


// --------------------------------------------------
// GET LATEST INTEGRITY RECORD
// --------------------------------------------------

async function getLatestIntegrity(fileId) {
  validateBytes32(fileId, 'fileId');

  const { contract } = await getBlockchain();

  const record = await contract.getLatestIntegrity(fileId);

  return {
    commitment: record.commitment,
    version: BigInt(record.version.toString()),
    recordType: Number(record.recordType),
    anchoredAt: BigInt(record.anchoredAt.toString()),
    signer: record.signer
  };
}


// --------------------------------------------------
// GET HISTORICAL INTEGRITY RECORD
// --------------------------------------------------

async function getHistoricalIntegrity(fileId, version) {
  validateBytes32(fileId, 'fileId');

  if (!Number.isSafeInteger(Number(version)) || Number(version) < 1) {
    throw new Error('Invalid integrity version');
  }

  const { contract } = await getBlockchain();

  const record = await contract.getHistoricalIntegrity(
    fileId,
    BigInt(version)
  );

  return {
    commitment: record.commitment,
    version: BigInt(record.version.toString()),
    recordType: Number(record.recordType),
    anchoredAt: BigInt(record.anchoredAt.toString()),
    signer: record.signer
  };
}


// --------------------------------------------------
// GET LATEST VERSION
// --------------------------------------------------

async function getLatestVersion(fileId) {
  validateBytes32(fileId, 'fileId');

  const { contract } = await getBlockchain();

  const version = await contract.latestVersion(fileId);

  return BigInt(version.toString());
}


// --------------------------------------------------
// ANCHOR INTEGRITY COMMITMENT
// --------------------------------------------------

async function anchorIntegrity({
  fileId,
  version,
  commitment,
  recordType = 1
}) {
  validateBytes32(fileId, 'fileId');
  validateBytes32(commitment, 'commitment');

  if (!Number.isSafeInteger(Number(version)) || Number(version) < 1) {
    throw new Error('Invalid integrity version');
  }

  if (![1, 2].includes(recordType)) {
    throw new Error('Invalid integrity record type');
  }

  const { contract } = await getBlockchain();

  console.log('Submitting integrity transaction...');
  console.log('File ID:', fileId);
  console.log('Version:', version);
  console.log('Record type:', recordType);

  const tx = await contract.anchorIntegrity(
    fileId,
    BigInt(version),
    commitment,
    recordType
  );

  console.log('Transaction submitted:', tx.hash);

  // Wait for transaction confirmation.
  const receipt = await tx.wait();

  if (!receipt || receipt.status !== 1) {
    throw new Error('Blockchain transaction failed');
  }

  console.log('Integrity successfully anchored');
  console.log('Block number:', receipt.blockNumber);

  return {
    transactionHash: tx.hash,
    blockNumber: receipt.blockNumber,
    status: 'ANCHORED'
  };
}

async function anchorAuditEvent({ eventId, commitment }) {
  validateBytes32(eventId, 'eventId');
  validateBytes32(commitment, 'commitment');

  const { contract } = await getBlockchain();

  const tx = await contract.anchorAuditEvent(
    eventId,
    commitment
  );

  const receipt = await tx.wait();

  if (!receipt || receipt.status !== 1) {
    throw new Error('Audit anchoring transaction failed');
  }

  return {
    transactionHash: tx.hash,
    blockNumber: receipt.blockNumber,
    status: 'ANCHORED'
  };
}

async function getAuditEvent(eventId) {
  validateBytes32(eventId, 'eventId');

  const { contract } = await getBlockchain();

  const record = await contract.getAuditEvent(eventId);

  return {
    commitment: record.commitment,
    anchoredAt: BigInt(record.anchoredAt.toString()),
    signer: record.signer,
    exists: record.exists
  };
}

module.exports = {
  getBlockchain,
  getConnectionInfo,
  getLatestIntegrity,
  getHistoricalIntegrity,
  getLatestVersion,
  anchorIntegrity,
  anchorAuditEvent,
  getAuditEvent
};