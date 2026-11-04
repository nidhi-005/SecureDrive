const crypto = require('crypto');
const AuditEvent = require('../models/AuditEvent');

async function createAuditEvent({
  accountRef,
  eventType,
  initiator = 'USER',
  severity = 'INFO'
}) {
  const eventId = '0x' + crypto.randomBytes(32).toString('hex');
  const timestamp = new Date();

  // Keep this exact field order stable for commitment verification.
  const payload = {
    eventId,
    accountRef,
    eventType,
    initiator,
    severity,
    timestamp: timestamp.toISOString()
  };

  const commitment = '0x' + crypto
    .createHash('sha256')
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