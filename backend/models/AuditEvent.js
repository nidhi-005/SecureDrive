const mongoose = require('mongoose');

const auditEventSchema = new mongoose.Schema({
  // Random 32-byte event identifier, suitable for blockchain bytes32.
  eventId: {
    type: String,
    required: true,
    unique: true,
    immutable: true
  },

  // Random pseudonymous account reference, not a MongoDB user ID.
  accountRef: {
    type: String,
    required: true,
    index: true,
    immutable: true
  },

  relatedEventId: {
    type: String,
    default: null,
    immutable: true
  },

  eventType: {
    type: String,
    required: true,
    enum: [
      // Account lifecycle
      'ACCOUNT_CREATED',
      'ACCOUNT_DELETION_REQUESTED',
      'ACCOUNT_DELETION_CANCELLED',
      'ACCOUNT_DELETED',

      // Authentication
      'LOGIN_SUCCESS',
      'LOGIN_FAILED',

      // File operations
      'FILE_UPLOADED',
      'FILE_DELETED',
      'FILE_CEK_RECOVERED',
      'FILE_CEK_REPAIRED',

      // Master key operations
      'MASTER_KEY_RECOVERED',
      'MASTER_KEY_REPAIRED',
      'MASTER_KEY_RECOVERY_FAILED',

      // Integrity monitoring
      'INTEGRITY_VERIFIED',
      'INTEGRITY_MISMATCH'
    ]
  },


  initiator: {
    type: String,
    enum: ['USER', 'ADMIN', 'SYSTEM'],
    default: 'USER'
  },

  severity: {
    type: String,
    enum: ['INFO', 'WARNING', 'CRITICAL'],
    default: 'INFO'
  },

  timestamp: {
    type: Date,
    required: true,
    immutable: true
  },

  // SHA-256 commitment of the canonical event fields.
  commitment: {
    type: String,
    required: true,
    immutable: true
  },

  blockchainStatus: {
    type: String,
    enum: ['PENDING', 'ANCHORED', 'FAILED'],
    default: 'PENDING'
  },

  transactionHash: {
    type: String,
    default: null
  },

  anchoredAt: {
    type: Date,
    default: null
  },

  anchorAttempts: {
    type: Number,
    default: 0
  },

  nextRetryAt: {
    type: Date,
    default: Date.now
  },

  lastAnchorError: {
    type: String,
    default: null
  },

  anchorLeaseId: {
    type: String,
    default: null
  },

  anchorLeaseUntil: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('AuditEvent', auditEventSchema);