const mongoose = require('mongoose');

const auditEventSchema = new mongoose.Schema({

  eventId: {
    type: String,
    required: true,
    unique: true,
    immutable: true
  },

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
    index: true
  },

  category: {
    type: String,
    required: true,
    enum: [
      'AUTHENTICATION',
      'FILE_OPERATIONS',
      'ACCOUNT_LIFECYCLE',
      'INTEGRITY',
      'KEY_MANAGEMENT',
      'SECURITY'
    ],
    index: true
  },

  initiator: {
    type: String,
    enum: ['USER', 'ADMIN', 'SYSTEM'],
    default: 'USER'
  },

  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW',
    index: true
  },

  outcome: {
    type: String,
    enum: ['SUCCESS', 'FAILURE', 'WARNING'],
    default: 'SUCCESS',
    index: true
  },

  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },

  timestamp: {
    type: Date,
    required: true,
    immutable: true,
    index: true
  },

  commitment: {
    type: String,
    required: true,
    immutable: true
  },

  blockchainStatus: {
    type: String,
    enum: ['PENDING', 'BATCHED', 'ANCHORED', 'FAILED'],
    default: 'PENDING',
    index: true
  },

  batchId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AuditBatch',
    default: null,
    index: true
  },

  leafIndex: {
    type: Number,
    default: null
  },

  merkleProof: {
    type: [String],
    default: []
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

  anchorLeaseId: {
    type: String,
    default: null
  },

  anchorLeaseUntil: {
    type: Date,
    default: null
  },

  nextRetryAt: {
    type: Date,
    default: Date.now
  },

  lastAnchorError: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

auditEventSchema.index({ accountRef: 1, timestamp: -1 });
auditEventSchema.index({ category: 1, timestamp: -1 });
auditEventSchema.index({ severity: 1, timestamp: -1 });
auditEventSchema.index({ blockchainStatus: 1, nextRetryAt: 1 });
auditEventSchema.index({
  blockchainStatus: 1,
  batchId: 1,
  nextRetryAt: 1,
  timestamp: 1
});

module.exports = mongoose.model('AuditEvent', auditEventSchema);
