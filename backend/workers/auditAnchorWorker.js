
const crypto = require('crypto');
const AuditEvent = require('../models/AuditEvent');
const {
  anchorAuditEvent,
  getAuditEvent
} = require('../services/blockchainService');

const POLL_INTERVAL_MS = 10000;
const LEASE_DURATION_MS = 5 * 60 * 1000;
const MAX_RETRY_DELAY_MS = 60 * 60 * 1000;
const BATCH_SIZE = 5;

let timer = null;
let isRunning = false;

// function calculateRetryDelay(attempts) {
//   const delay = 30000 * Math.pow(2, Math.max(0, attempts - 1));
//   return Math.min(delay, MAX_RETRY_DELAY_MS);
// }

function calculateRetryDelay(attempts) {
  return 10000; // 10 seconds
}

function commitmentsMatch(first, second) {
  return (
    typeof first === 'string' &&
    typeof second === 'string' &&
    first.toLowerCase() === second.toLowerCase()
  );
}

async function markAnchored(event, leaseId, {
  transactionHash = null,
  anchoredAt = new Date()
} = {}) {
  const result = await AuditEvent.updateOne(
    {
      _id: event._id,
      anchorLeaseId: leaseId
    },
    {
      $set: {
        blockchainStatus: 'ANCHORED',
        transactionHash: transactionHash || event.transactionHash || null,
        anchoredAt,
        lastAnchorError: null,
        nextRetryAt: null,
        anchorLeaseId: null,
        anchorLeaseUntil: null
      }
    }
  );

  if (result.modifiedCount === 0) {
    console.warn(
      `Audit event ${event.eventId}: lease lost before MongoDB update`
    );
  }
}

async function markFailed(event, leaseId, error) {
  const delay = calculateRetryDelay(event.anchorAttempts);
  const nextRetryAt = new Date(Date.now() + delay);

  await AuditEvent.updateOne(
    {
      _id: event._id,
      anchorLeaseId: leaseId
    },
    {
      $set: {
        blockchainStatus: 'FAILED',
        lastAnchorError: String(error.message || error).slice(0, 1000),
        nextRetryAt,
        anchorLeaseId: null,
        anchorLeaseUntil: null
      }
    }
  );

  console.error(
    `Audit event ${event.eventId} failed. ` +
    `Retry scheduled for ${nextRetryAt.toISOString()}.`,
    error.message || error
  );
}

async function markCommitmentMismatch(event, leaseId, onChainCommitment) {
  const message =
    `CRITICAL: Commitment mismatch for audit event ${event.eventId}. ` +
    `MongoDB: ${event.commitment}; Blockchain: ${onChainCommitment}`;

  // Do not automatically retry a conflicting immutable record.
  await AuditEvent.updateOne(
    {
      _id: event._id,
      anchorLeaseId: leaseId
    },
    {
      $set: {
        blockchainStatus: 'FAILED',
        lastAnchorError: message,
        nextRetryAt: null,
        anchorLeaseId: null,
        anchorLeaseUntil: null
      }
    }
  );

  console.error(message);
}

async function processEvent(event, leaseId) {
  try {
    let existingRecord = null;

    // First check whether this event was already anchored.
    // The contract reverts when the event does not exist.
    try {
      existingRecord = await getAuditEvent(event.eventId);
    } catch (lookupError) {
      // Could mean the record is absent or the RPC is temporarily
      // unavailable. We attempt anchoring; failures remain retryable.
    }

    if (existingRecord && existingRecord.exists) {
      if (!commitmentsMatch(
        existingRecord.commitment,
        event.commitment
      )) {
        await markCommitmentMismatch(
          event,
          leaseId,
          existingRecord.commitment
        );
        return;
      }

      await markAnchored(event, leaseId, {
        anchoredAt: new Date(
          Number(existingRecord.anchoredAt) * 1000
        )
      });

      console.log(`Audit event already anchored: ${event.eventId}`);
      return;
    }

    // No existing record was found. Submit the transaction.
    let transactionHash = null;

    try {
      const result = await anchorAuditEvent({
        eventId: event.eventId,
        commitment: event.commitment
      });

      transactionHash = result.transactionHash;
    } catch (anchorError) {
      // A previous transaction may have succeeded even if its
      // response was lost. Check the chain again before retrying.
      let recoveredRecord;

      try {
        recoveredRecord = await getAuditEvent(event.eventId);
      } catch (lookupError) {
        throw anchorError;
      }

      if (!recoveredRecord || !recoveredRecord.exists) {
        throw anchorError;
      }

      if (!commitmentsMatch(
        recoveredRecord.commitment,
        event.commitment
      )) {
        await markCommitmentMismatch(
          event,
          leaseId,
          recoveredRecord.commitment
        );
        return;
      }

      await markAnchored(event, leaseId, {
        anchoredAt: new Date(
          Number(recoveredRecord.anchoredAt) * 1000
        )
      });

      console.log(`Recovered previously anchored event: ${event.eventId}`);
      return;
    }

    // Read the confirmed on-chain timestamp.
    let anchoredAt = new Date();

    try {
      const confirmedRecord = await getAuditEvent(event.eventId);

      if (
        confirmedRecord.exists &&
        commitmentsMatch(confirmedRecord.commitment, event.commitment)
      ) {
        anchoredAt = new Date(
          Number(confirmedRecord.anchoredAt) * 1000
        );
      } else if (confirmedRecord.exists) {
        await markCommitmentMismatch(
          event,
          leaseId,
          confirmedRecord.commitment
        );
        return;
      }
    } catch (error) {
      // The transaction itself was confirmed. Retain the local
      // confirmation time if the follow-up read is unavailable.
      console.warn('Could not read confirmed audit record:', error.message);
    }

    await markAnchored(event, leaseId, {
      transactionHash,
      anchoredAt
    });

    console.log(`Audit event anchored: ${event.eventId}`);
  } catch (error) {
    try {
      await markFailed(event, leaseId, error);
    } catch (dbError) {
      // If MongoDB is unavailable, the lease will eventually expire
      // and another worker poll can reclaim the event.
      console.error('Could not update failed audit event:', dbError);
    }
  }
}

async function claimNextEvent() {
  const now = new Date();
  const leaseId = crypto.randomUUID();


  return AuditEvent.findOneAndUpdate(
    {
      blockchainStatus: { $in: ['PENDING', 'FAILED'] },
      $and: [
        {
          $or: [
            { anchorLeaseUntil: null },
            { anchorLeaseUntil: { $lte: now } }
          ]
        },
        {
          nextRetryAt: { $lte: now }
        }
      ]
    },
    {
      $set: {
        anchorLeaseId: leaseId,
        anchorLeaseUntil: new Date(
          now.getTime() + LEASE_DURATION_MS
        )
      },
      $inc: {
        anchorAttempts: 1
      }
    },
    {
      new: true,
      sort: { createdAt: 1 }
    }
  ).then(event => ({ event, leaseId }));
}

async function pollAuditEvents() {
  if (isRunning) return;

  isRunning = true;

  try {
    for (let i = 0; i < BATCH_SIZE; i++) {
      const { event, leaseId } = await claimNextEvent();

      if (!event) break;

      await processEvent(event, leaseId);
    }
  } catch (error) {
    console.error('Audit anchoring worker error:', error);
  } finally {
    isRunning = false;
  }
}

function startAuditAnchorWorker() {
  if (timer) return;

  console.log('Audit anchoring worker started');

  // Process pending events immediately, then poll periodically.
  pollAuditEvents();
  timer = setInterval(pollAuditEvents, POLL_INTERVAL_MS);
}

module.exports = {
  startAuditAnchorWorker,
  pollAuditEvents
};
