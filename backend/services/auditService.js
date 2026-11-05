const crypto = require('crypto');
const AuditEvent = require('../models/AuditEvent');

async function createAuditEvent({
  accountRef,
  eventType,
  initiator = 'USER',
  severity = 'INFO',
  relatedEventId = null
}) {
  const eventId = '0x' + crypto.randomBytes(32).toString('hex');
  const timestamp = new Date();

  const payload = {
    eventId,
    accountRef,
    eventType,
    initiator,
    severity,
    timestamp: timestamp.toISOString()
  };

  // Include the reference in the commitment only when provided.
  if (relatedEventId) {
    payload.relatedEventId = relatedEventId;
  }

  const commitment = '0x' + crypto.createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');

  return AuditEvent.create({
    ...payload,
    timestamp,
    commitment,
    blockchainStatus: 'PENDING'
  });
}

module.exports = { createAuditEvent };