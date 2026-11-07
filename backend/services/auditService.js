const crypto = require('crypto');
const AuditEvent = require('../models/AuditEvent');

const EVENT_CONFIG = {
  ACCOUNT_CREATED: ['ACCOUNT_LIFECYCLE', 'LOW', 'SUCCESS'],
  ACCOUNT_DELETION_REQUESTED: ['ACCOUNT_LIFECYCLE', 'MEDIUM', 'WARNING'],
  ACCOUNT_DELETION_CANCELLED: ['ACCOUNT_LIFECYCLE', 'LOW', 'SUCCESS'],
  ACCOUNT_DELETED: ['ACCOUNT_LIFECYCLE', 'MEDIUM', 'SUCCESS'],

  LOGIN_SUCCESS: ['AUTHENTICATION', 'LOW', 'SUCCESS'],
  LOGIN_FAILED: ['AUTHENTICATION', 'MEDIUM', 'FAILURE'],

  FILE_UPLOADED: ['FILE_OPERATIONS', 'LOW', 'SUCCESS'],
  FILE_DELETED: ['FILE_OPERATIONS', 'LOW', 'SUCCESS'],
  FILE_CEK_REPAIRED: ['KEY_MANAGEMENT', 'MEDIUM', 'SUCCESS'],

  MASTER_KEY_REPAIRED: ['KEY_MANAGEMENT', 'HIGH', 'SUCCESS'],
  MASTER_KEY_RECOVERY_FAILED: ['KEY_MANAGEMENT', 'CRITICAL', 'FAILURE'],

  INTEGRITY_VERIFIED: ['INTEGRITY', 'LOW', 'SUCCESS'],
  INTEGRITY_MISMATCH: ['INTEGRITY', 'CRITICAL', 'FAILURE']
};

function sha256(value) {
  return '0x' + crypto.createHash('sha256')
    .update(value)
    .digest('hex');
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = canonicalize(value[key]);
      return result;
    }, {});
  }

  return value;
}

async function createAuditEvent({
  accountRef,
  eventType,
  initiator = 'USER',
  severity,
  outcome,
  relatedEventId = null,
  details = {}
}) {
  if (!accountRef || !eventType) {
    throw new Error('accountRef and eventType are required');
  }

  const config = EVENT_CONFIG[eventType];

  if (!config) {
    throw new Error(`Unsupported audit event type: ${eventType}`);
  }

  const [category, defaultSeverity, defaultOutcome] = config;

  const eventId = '0x' + crypto.randomBytes(32).toString('hex');
  const timestamp = new Date();

  const safeDetails = canonicalize(details);

  const payload = {
    eventId,
    accountRef,
    eventType,
    category,
    initiator,
    severity: severity || defaultSeverity,
    outcome: outcome || defaultOutcome,
    relatedEventId,
    details: safeDetails,
    timestamp: timestamp.toISOString()
  };

  const commitment = sha256(JSON.stringify(payload));

  return AuditEvent.create({
    ...payload,
    timestamp,
    commitment,
    blockchainStatus: 'PENDING',
    nextRetryAt: new Date()
  });
}

module.exports = {
  createAuditEvent
};