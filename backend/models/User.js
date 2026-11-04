const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  opaqueRegistrationRecord: { type: String, required: true },
  encryptionSalt: { type: String, required: true },
  wrappedMasterKey: { type: String, required: true },
  masterKeyIV: { type: String, required: true },

  // Version of the currently active wrapped Master Key.
  wrappedMasterKeyVersion: {
    type: Number,
    default: 1
  },

  deletionPending: {
    type: Boolean,
    default: false,
    index: true
  },

  // Random pseudonymous identifier.
  // This survives in audit records after the user document is deleted.
  accountRef: {
    type: String,
    unique: true,
    sparse: true,
    immutable: true
  },

  deletionRequestedAt: {
    type: Date,
    default: null
  },

  deletionScheduledFor: {
    type: Date,
    default: null
  },

  deletionRequestEventId: {
    type: String,
    default: null
  },

  deletionStatus: {
    type: String,
    enum: ['NONE', 'PENDING', 'PROCESSING'],
    default: 'NONE',
    index: true
  },

  deletionLeaseId: {
    type: String,
    default: null
  },

  deletionLeaseUntil: {
    type: Date,
    default: null
  },

  deletionAttempts: {
    type: Number,
    default: 0
  },

  createdAt: { type: Date, default: Date.now }
});

// Generate a pseudonymous reference for new and existing accounts.
userSchema.pre('save', function (next) {
  if (!this.accountRef) {
    this.accountRef = randomUUID();
  }
  next();
});

module.exports = mongoose.model('User', userSchema);
