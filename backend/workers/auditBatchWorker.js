const crypto = require('crypto');
const mongoose = require('mongoose');

const AuditEvent = require('../models/AuditEvent');
const AuditBatch = require('../models/AuditBatch');
const { buildMerkleTree } = require('../services/merkleService');
const { anchorAuditBatch } = require('../services/blockchainService');

const BATCH_SIZE = 25;
const POLL_INTERVAL_MS = 15000;
const MAX_RETRY_DELAY_MS = 60 * 60 * 1000;
const LEASE_DURATION_MS = 2 * 60 * 1000;

let timer = null;
let running = false;

function retryDelay(attempts) {
  return Math.min(
    30000 * Math.pow(2, Math.max(0, attempts - 1)),
    MAX_RETRY_DELAY_MS
  );
}

// Atomically reserve events and create their batch.
// Both operations commit together or neither commits.
async function createBatch() {
  const session = await mongoose.startSession();

  try {
    await session.withTransaction(async () => {
      const now = new Date();

      const events = await AuditEvent.find({
        blockchainStatus: 'PENDING',
        batchId: null,
        $or: [
          { nextRetryAt: null },
          { nextRetryAt: { $lte: now } }
        ]
      })
        .sort({ timestamp: 1 })
        .limit(BATCH_SIZE)
        .session(session)
        .lean();

      if (!events.length) return;

      const tree = buildMerkleTree(
        events.map(event => event.commitment)
      );

      const batchId =
        '0x' + crypto.randomBytes(32).toString('hex');

      const [batch] = await AuditBatch.create([{
        batchId,
        status: 'PENDING',
        eventIds: events.map(event => event.eventId),
        merkleRoot: tree.root,
        leafCount: events.length,
        attempts: 0,
        nextRetryAt: now
      }], { session });

      const result = await AuditEvent.updateMany(
        {
          _id: { $in: events.map(event => event._id) },
          blockchainStatus: 'PENDING',
          batchId: null
        },
        {
          $set: {
            blockchainStatus: 'BATCHED',
            batchId: batch._id,
            leafIndex: null,
            merkleProof: []
          }
        },
        { session }
      );

      if (result.modifiedCount !== events.length) {
        throw new Error('Event reservation conflict; transaction aborted');
      }

      // Store each event's proof and position.
      for (let i = 0; i < events.length; i++) {
        await AuditEvent.updateOne(
          {
            _id: events[i]._id,
            batchId: batch._id
          },
          {
            $set: {
              leafIndex: i,
              merkleProof: tree.proofs[i]
            }
          },
          { session }
        );
      }
    }, {
      readConcern: { level: 'snapshot' },
      writeConcern: { w: 'majority' }
    });
  } finally {
    await session.endSession();
  }
}

// Claim one batch using an atomic lease.
async function claimBatch() {
  const now = new Date();
  const leaseId = crypto.randomUUID();

  const batch = await AuditBatch.findOneAndUpdate(
    {
      status: { $in: ['PENDING', 'FAILED'] },
      $and: [
        {
          $or: [
            { nextRetryAt: null },
            { nextRetryAt: { $lte: now } }
          ]
        },
        {
          $or: [
            { leaseUntil: null },
            { leaseUntil: { $lte: now } }
          ]
        }
      ]
    },
    {
      $set: {
        leaseId,
        leaseUntil: new Date(now.getTime() + LEASE_DURATION_MS)
      }
    },
    {
      new: true,
      sort: { createdAt: 1 }
    }
  );

  return batch;
}

async function anchorPendingBatches() {
  // Limit work per poll to avoid monopolizing the worker.
  for (let i = 0; i < 3; i++) {
    const batch = await claimBatch();

    if (!batch) break;

    const leaseId = batch.leaseId;

    try {
      const result = await anchorAuditBatch({
        batchId: batch.batchId,
        merkleRoot: batch.merkleRoot,
        leafCount: batch.leafCount
      });

      const anchoredAt = new Date();

      const updated = await AuditBatch.updateOne(
        {
          _id: batch._id,
          leaseId,
          status: { $ne: 'ANCHORED' }
        },
        {
          $set: {
            status: 'ANCHORED',
            transactionHash: result.transactionHash,
            blockNumber: result.blockNumber,
            anchoredAt,
            lastError: null,
            nextRetryAt: null,
            leaseId: null,
            leaseUntil: null
          },
          $inc: { attempts: 1 }
        }
      );

      if (!updated.modifiedCount) {
        console.warn('Batch lease lost after anchoring:', batch.batchId);
        continue;
      }

      await AuditEvent.updateMany(
        { batchId: batch._id },
        {
          $set: {
            blockchainStatus: 'ANCHORED',
            transactionHash: result.transactionHash,
            anchoredAt,
            lastAnchorError: null,
            nextRetryAt: null
          }
        }
      );

    } catch (error) {
      const attempts = batch.attempts + 1;
      const nextRetryAt = new Date(
        Date.now() + retryDelay(attempts)
      );

      const message = String(error.message || error).slice(0, 1000);

      await AuditBatch.updateOne(
        { _id: batch._id, leaseId },
        {
          $set: {
            status: 'FAILED',
            lastError: message,
            nextRetryAt,
            leaseId: null,
            leaseUntil: null
          },
          $inc: { attempts: 1 }
        }
      );

      await AuditEvent.updateMany(
        { batchId: batch._id },
        {
          $set: {
            blockchainStatus: 'FAILED',
            lastAnchorError: message,
            nextRetryAt
          }
        }
      );

      console.error('Merkle batch anchoring failed:', batch.batchId, message);
    }
  }
}

async function poll() {
  if (running) return;

  running = true;

  try {
    await anchorPendingBatches();
    await createBatch();
  } catch (error) {
    console.error('Audit batch worker error:', error);
  } finally {
    running = false;
  }
}

function startAuditBatchWorker() {
  if (timer) return;

  console.log('Audit Merkle batch worker started');

  poll();
  timer = setInterval(poll, POLL_INTERVAL_MS);
}

module.exports = {
  startAuditBatchWorker,
  poll
};