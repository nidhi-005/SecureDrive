const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },

  role: {
    type: String,
    enum: ['USER', 'ADMIN'],
    default: 'USER',
    required: true
  },

  // DID authentication fields.
did: {
  type: String,
  unique: true,
  sparse: true
},

didMethod: {
  type: String,
  enum: ['did:key'],
  default: undefined
},

authMethod: {
  type: String,
  enum: ['did', 'opaque', 'webauthn'],
  default: 'opaque'
},


webauthnUserID: {
  type: String,
  default: null
},
  // Legacy OPAQUE authentication record remains optional for DID-only accounts.
  opaqueRegistrationRecord: { type: String, required: false },

  // Encryption fields remain optional until the separate encryption-setup stage.
  encryptionSalt: { type: String, required: false },
  wrappedMasterKey: { type: String, required: false },
  masterKeyIV: { type: String, required: false },

  encryptionReady: { type: Boolean, default: false },

  wrappedMasterKeyVersion: { type: Number, default: 1 },

  // Incrementing this invalidates all previously issued JWT sessions.
  sessionVersion: { type: Number, default: 0 },

  deletionPending: { type: Boolean, default: false, index: true },

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
