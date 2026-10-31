const crypto = require('crypto');

const { AbiCoder } = require('ethers');

const abiCoder = AbiCoder.defaultAbiCoder();

// Increment this if the commitment structure changes in the future.
const COMMITMENT_FORMAT_VERSION = 1;

// Contract record types
const RECORD_TYPE = {
  FILE: 1,
  TOMBSTONE: 2
};

/**
 * Generate a random, opaque 32-byte blockchain file identifier.
 *
 * This is deliberately different from the MongoDB ObjectId.
 */
function generateBlockchainFileId() {
  return '0x' + crypto.randomBytes(32).toString('hex');
}

/**
 * Calculate SHA-256 of the actual encrypted file bytes.
 */
function calculateCiphertextHash(ciphertext) {
  if (!Buffer.isBuffer(ciphertext)) {
    throw new Error('Ciphertext must be a Buffer');
  }

  return '0x' + crypto
    .createHash('sha256')
    .update(ciphertext)
    .digest('hex');
}

/**
 * Generate a deterministic integrity commitment.
 *
 * The order and types below are part of the commitment format.
 * Do not change them without introducing a new format version.
 */
function createIntegrityCommitment({
  blockchainFileId,
  integrityVersion,
  ciphertextHash,
  wrappedCEK,
  fileIV,
  cekIV,
  wrappedCEKVersion
}) {
  if (!/^0x[a-fA-F0-9]{64}$/.test(blockchainFileId || '')) {
    throw new Error('Invalid blockchain file ID');
  }

  if (!/^0x[a-fA-F0-9]{64}$/.test(ciphertextHash || '')) {
    throw new Error('Invalid ciphertext hash');
  }

  if (!Number.isSafeInteger(integrityVersion) || integrityVersion < 1) {
    throw new Error('Invalid integrity version');
  }

  if (!Number.isSafeInteger(wrappedCEKVersion) || wrappedCEKVersion < 1) {
    throw new Error('Invalid wrapped CEK version');
  }

  if (
    typeof wrappedCEK !== 'string' ||
    typeof fileIV !== 'string' ||
    typeof cekIV !== 'string' ||
    !wrappedCEK ||
    !fileIV ||
    !cekIV
  ) {
    throw new Error('Missing key or IV metadata');
  }

  // Fixed ABI encoding: do not reorder these fields.
  const encoded = abiCoder.encode(
    [
      'uint8',
      'bytes32',
      'uint64',
      'bytes32',
      'string',
      'string',
      'string',
      'uint64'
    ],
    [
      COMMITMENT_FORMAT_VERSION,
      blockchainFileId,
      BigInt(integrityVersion),
      ciphertextHash,
      wrappedCEK,
      fileIV,
      cekIV,
      BigInt(wrappedCEKVersion)
    ]
  );

  // SHA-256 of the ABI-encoded bytes.
  const commitment = crypto
    .createHash('sha256')
    .update(Buffer.from(encoded.slice(2), 'hex'))
    .digest('hex');

  return '0x' + commitment;
}

module.exports = {
  COMMITMENT_FORMAT_VERSION,
  RECORD_TYPE,
  generateBlockchainFileId,
  calculateCiphertextHash,
  createIntegrityCommitment
};