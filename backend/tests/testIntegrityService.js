require('dotenv').config();

const {
  generateBlockchainFileId,
  calculateCiphertextHash,
  createIntegrityCommitment
} = require('../services/integrityService');

function main() {
  const ciphertext = Buffer.from('Example encrypted file content');

  const blockchainFileId = generateBlockchainFileId();

  const ciphertextHash = calculateCiphertextHash(ciphertext);

  const metadata = {
    blockchainFileId,
    integrityVersion: 1,
    ciphertextHash,
    wrappedCEK: 'example-wrapped-cek',
    fileIV: 'example-file-iv',
    cekIV: 'example-cek-iv',
    wrappedCEKVersion: 1
  };

  const commitment1 = createIntegrityCommitment(metadata);

  // Same data must produce the same commitment.
  const commitment2 = createIntegrityCommitment(metadata);

  // Changing the ciphertext must produce a different commitment.
  const modifiedHash = calculateCiphertextHash(
    Buffer.from('Modified encrypted file content')
  );

  const modifiedCommitment = createIntegrityCommitment({
    ...metadata,
    ciphertextHash: modifiedHash
  });

  console.log('\n========== INTEGRITY TEST ==========');

  console.log('Blockchain file ID:', blockchainFileId);
  console.log('Ciphertext hash:', ciphertextHash);
  console.log('Commitment:', commitment1);

  console.log(
    'Deterministic:',
    commitment1 === commitment2
  );

  console.log(
    'Detects ciphertext modification:',
    commitment1 !== modifiedCommitment
  );

  console.log('====================================\n');

  if (commitment1 !== commitment2) {
    throw new Error('Deterministic commitment test failed');
  }

  if (commitment1 === modifiedCommitment) {
    throw new Error('Tampering detection test failed');
  }

  console.log('All integrity service tests passed.');
}

main();