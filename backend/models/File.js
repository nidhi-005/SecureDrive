const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  originalName: {
    type: String,
    required: true
  },

  storagePath: {
    type: String,
    required: true
  },

  wrappedCEK: {
    type: String,
    required: true
  },

  fileIV: {
    type: String,
    required: true
  },

  cekIV: {
    type: String,
    required: true
  },

  // Version of the currently active wrapped CEK.
  wrappedCEKVersion: {
    type: Number,
    default: 1
  },

  // -----------------------------------------
  // BLOCKCHAIN INTEGRITY FIELDS
  // -----------------------------------------

  // Random opaque bytes32 identifier used by the smart contract.
  blockchainFileId: {
    type: String,
    unique: true,
    sparse: true
  },

  // Version of the complete integrity state.
  integrityVersion: {
    type: Number,
    default: 1
  },

  // Commitment reconstructed from ciphertext and metadata.
  integrityCommitment: {
    type: String
  },

  // PENDING: not yet confirmed on-chain.
  // ANCHORED: transaction confirmed.
  integrityStatus: {
    type: String,
    enum: ['PENDING', 'ANCHORED'],
    default: 'PENDING'
  },

  blockchainTxHash: {
    type: String
  },

  blockchainAnchoredAt: {
    type: Date
  },

  size: {
    type: Number
  },

  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('File', fileSchema);