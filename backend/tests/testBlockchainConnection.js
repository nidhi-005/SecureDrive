require('dotenv').config();

const {
  getConnectionInfo
} = require('../services/blockchainService');

async function main() {
  try {
    const info = await getConnectionInfo();

    console.log('\n========== BLOCKCHAIN STATUS ==========');
    console.log('Connected:', info.connected);
    console.log('Chain ID:', info.chainId);
    console.log('Contract:', info.contractAddress);
    console.log('Backend signer:', info.signerAddress);
    console.log('Contract owner:', info.contractOwner);
    console.log('=======================================\n');

  } catch (error) {
    console.error('Blockchain connection test failed:');
    console.error(error.message);
    process.exitCode = 1;
  }
}

main();