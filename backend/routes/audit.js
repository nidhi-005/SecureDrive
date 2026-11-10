
const express = require('express');
const router = express.Router();

const AuditEvent = require('../models/AuditEvent');
const AuditBatch = require('../models/AuditBatch');
const { createAuditEvent } = require('../services/auditService');

const {
  getAuditEvent,
  getAuditBatchRoot,
  verifyAuditProof
} = require('../services/blockchainService');

// All routes in this file must be authenticated.
// The auth middleware is mounted in server.js.

function requireAccountRef(req, res) {
  if (!req.user || !req.user.accountRef) {
    res.status(409).json({
      error: 'Account reference is missing. Contact the administrator.',
      code: 'ACCOUNT_REFERENCE_MISSING'
    });
    return false;
  }

  return true;
}

// Pagination helper
function getPagination(query) {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(
    100,
    Math.max(1, parseInt(query.limit, 10) || 20)
  );

  return {
    page,
    limit,
    skip: (page - 1) * limit
  };
}

// Only allow known filters.
function buildFilters(query) {
  const filters = {};

  const allowedTypes = [
    'ACCOUNT_CREATED',
    'ACCOUNT_DELETION_REQUESTED',
    'ACCOUNT_DELETION_CANCELLED',
    'ACCOUNT_DELETED',
    'LOGIN_SUCCESS',
    'LOGIN_FAILED',
    'PASSKEY_LOGIN_FAILED',
    'ENCRYPTION_UNLOCK_FAILED',
    'FILE_UPLOADED',
    'FILE_DELETED',
    'FILE_CEK_REPAIRED',
    'MASTER_KEY_REPAIRED',
    'MASTER_KEY_RECOVERY_FAILED',
    'INTEGRITY_VERIFIED',
    'INTEGRITY_MISMATCH'
  ];

  const allowedSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const allowedStatuses = ['PENDING', 'BATCHED', 'ANCHORED', 'FAILED'];

  if (allowedTypes.includes(query.eventType)) {
    filters.eventType = query.eventType;
  }

  if (allowedSeverities.includes(query.severity)) {
    filters.severity = query.severity;
  }

  if (allowedStatuses.includes(query.blockchainStatus)) {
    filters.blockchainStatus = query.blockchainStatus;
  }

  return filters;
}

function getDateRange(query) {
  const allowed = [7, 30, 90, 365];
  const days = allowed.includes(Number(query.days))
    ? Number(query.days)
    : 30;

  const end = new Date();
  const start = new Date(end.getTime() - days * 86400000);

  return { start, end, days };
}

async function getDashboardStats(match, days) {
  const start = new Date(Date.now() - days * 86400000);

  const rangeMatch = {
    ...match,
    timestamp: { $gte: start, $lte: new Date() }
  };

  const [
    total,
    severity,
    categories,
    eventTypes,
    daily,
    outcomes,
    failedLogins,
    encryptionUnlockFailures,
    integrityMismatches,
    recoveryFailures,
    anchoring,
    accounts,
    loginCounts,
    suspiciousEvents,
    anchorMetrics,
    incidentAccounts
  ] = await Promise.all([
    AuditEvent.countDocuments(rangeMatch),

    AuditEvent.aggregate([
      { $match: rangeMatch },
      { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]),

    AuditEvent.aggregate([
      { $match: rangeMatch },
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]),

    AuditEvent.aggregate([
      { $match: rangeMatch },
      { $group: { _id: '$eventType', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]),

    AuditEvent.aggregate([
      { $match: rangeMatch },
      {
        $group: {
          _id: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$timestamp'
            }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]),

    AuditEvent.aggregate([
      { $match: rangeMatch },
      { $group: { _id: '$outcome', count: { $sum: 1 } } }
    ]),

    AuditEvent.countDocuments({
      ...rangeMatch,
      eventType: 'PASSKEY_LOGIN_FAILED'
    }),

    AuditEvent.countDocuments({
      ...rangeMatch,
      eventType: 'ENCRYPTION_UNLOCK_FAILED'
    }),

    AuditEvent.countDocuments({
      ...rangeMatch,
      eventType: 'INTEGRITY_MISMATCH'
    }),

    AuditEvent.countDocuments({
      ...rangeMatch,
      eventType: 'MASTER_KEY_RECOVERY_FAILED'
    }),

    AuditEvent.aggregate([
      { $match: rangeMatch },
      {
        $group: {
          _id: '$blockchainStatus',
          count: { $sum: 1 }
        }
      }
    ]),

    AuditEvent.aggregate([
      { $match: rangeMatch },
      {
        $group: {
          _id: '$accountRef',
          total: { $sum: 1 },
          incidents: {
            $sum: {
              $cond: [
                { $in: ['$severity', ['HIGH', 'CRITICAL']] },
                1,
                0
              ]
            }
          }
        }
      },
      { $sort: { total: -1 } },
      { $limit: 10 }
    ]),

    // Login success/failure counts
    AuditEvent.aggregate([
      {
        $match: {
          ...rangeMatch,
          eventType: { $in: ['LOGIN_SUCCESS', 'PASSKEY_LOGIN_FAILED'] }
        }
      },
      {
        $group: {
          _id: '$eventType',
          count: { $sum: 1 }
        }
      }
    ]),

    // High-severity security activity
    AuditEvent.aggregate([
      {
        $match: {
          ...rangeMatch,
          severity: { $in: ['HIGH', 'CRITICAL'] }
        }
      },
      {
        $group: {
          _id: '$eventType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]),

    // Blockchain timing and retry metrics
    AuditEvent.aggregate([
      { $match: rangeMatch },
      {
        $group: {
          _id: null,
          totalAttempts: {
            $sum: { $ifNull: ['$anchorAttempts', 0] }
          },
          averageAttempts: {
            $avg: '$anchorAttempts'
          },
          averageConfirmationMs: {
            $avg: {
              $cond: [
                {
                  $and: [
                    { $eq: ['$blockchainStatus', 'ANCHORED'] },
                    { $ne: ['$anchoredAt', null] }
                  ]
                },
                { $subtract: ['$anchoredAt', '$timestamp'] },
                null
              ]
            }
          },
          oldestPendingAt: {
            $min: {
              $cond: [
                { $in: ['$blockchainStatus', ['PENDING', 'BATCHED']] },
                '$timestamp',
                null
              ]
            }
          }
        }
      }
    ]),

    // Accounts with HIGH or CRITICAL events
    AuditEvent.aggregate([
      {
        $match: {
          ...rangeMatch,
          severity: { $in: ['HIGH', 'CRITICAL'] }
        }
      },
      {
        $group: {
          _id: '$accountRef',
          incidents: { $sum: 1 }
        }
      },
      { $sort: { incidents: -1 } },
      { $limit: 10 }
    ])
  ]);

  const statusMap = Object.fromEntries(
    anchoring.map(item => [item._id, item.count])
  );

  const anchored = statusMap.ANCHORED || 0;
  // BATCHED events have not been confirmed on-chain yet, so count them as pending.
  const pending = (statusMap.PENDING || 0) + (statusMap.BATCHED || 0);
  const failed = statusMap.FAILED || 0;
  const anchoringTotal = anchored + pending + failed;

  const loginMap = Object.fromEntries(
    loginCounts.map(item => [item._id, item.count])
  );

  const successfulLogins = loginMap.LOGIN_SUCCESS || 0;
  const failedLoginCount = loginMap.PASSKEY_LOGIN_FAILED || 0;
  const totalLogins = successfulLogins + failedLoginCount;

  const anchorData = anchorMetrics[0] || {};
  const oldestPendingAt = anchorData.oldestPendingAt;

  const pendingAgeMs = oldestPendingAt
    ? Date.now() - new Date(oldestPendingAt).getTime()
    : 0;

  return {
    periodDays: days,
    total,
    severity,
    categories,
    eventTypes,
    daily,
    outcomes,
    security: {
      failedLogins,
      encryptionUnlockFailures,
      integrityMismatches,
      recoveryFailures,
      successfulLogins,
      totalLogins,
      failedLoginRate: totalLogins
        ? Number((failedLoginCount / totalLogins * 100).toFixed(2))
        : 0,
      suspiciousEvents,
      incidentAccounts
    },
    anchoring: {
      anchored,
      pending,
      failed,
      total: anchoringTotal,
      successRate: anchoringTotal
        ? Number((anchored / anchoringTotal * 100).toFixed(2))
        : 0,
      totalAttempts: anchorData.totalAttempts || 0,
      averageAttempts: Number(
        (anchorData.averageAttempts || 0).toFixed(2)
      ),
      averageConfirmationMs: Math.round(
        anchorData.averageConfirmationMs || 0
      ),
      oldestPendingAgeMs: pendingAgeMs
    },
    accounts
  };
}

// GET /api/audit/me
// Return events belonging only to the authenticated user.
router.get('/me', async (req, res) => {
  if (!requireAccountRef(req, res)) return;
  try {
    const { page, limit, skip } = getPagination(req.query);
    const filters = buildFilters(req.query);

    filters.accountRef = req.user.accountRef;

    const [events, total] = await Promise.all([
      AuditEvent.find(filters)
        .select(
          'eventId eventType initiator severity timestamp commitment blockchainStatus transactionHash anchoredAt'
        )
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),

      AuditEvent.countDocuments(filters)
    ]);

    return res.json({
      events,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('User audit lookup failed:', err);

    return res.status(500).json({
      error: 'Could not retrieve audit events'
    });
  }
});

// GET /api/audit/me/stats
// User-specific dashboard statistics.
router.get('/me/stats', async (req, res) => {
  if (!requireAccountRef(req, res)) return;

  try {
    const { days } = getDateRange(req.query);
    const stats = await getDashboardStats(
      { accountRef: req.user.accountRef },
      days
    );

    return res.json(stats);
  } catch (err) {
    console.error('User audit statistics failed:', err);
    return res.status(500).json({
      error: 'Could not retrieve audit statistics'
    });
  }
});

// GET /api/audit/admin
// Admin-only: retrieve events across all accounts.
router.get('/admin', async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).json({
        error: 'Administrator access required'
      });
    }

    const { page, limit, skip } = getPagination(req.query);

    const filters = buildFilters(req.query);

    // Validate accountRef if provided.
    if (req.query.accountRef !== undefined) {
      if (
        typeof req.query.accountRef !== 'string' ||
        req.query.accountRef.length > 100
      ) {
        return res.status(400).json({
          error: 'Invalid account reference'
        });
      }
    }

    if (req.query.accountRef) {
      filters.accountRef = req.query.accountRef;
    }


    const [events, total] = await Promise.all([
      AuditEvent.find(filters)
        .select(
          'eventId accountRef eventType initiator severity timestamp commitment blockchainStatus transactionHash anchoredAt lastAnchorError'
        )
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),

      AuditEvent.countDocuments(filters)
    ]);

    return res.json({
      events,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Admin audit lookup failed:', err);

    return res.status(500).json({
      error: 'Could not retrieve audit events'
    });
  }
});

// GET /api/audit/admin/stats
// Admin-only: global dashboard statistics.
router.get('/admin/stats', async (req, res) => {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({
      error: 'Administrator access required'
    });
  }

  try {
    const { days } = getDateRange(req.query);
    const stats = await getDashboardStats({}, days);

    return res.json({
      ...stats,
      accountsWithEvents: await AuditEvent.distinct('accountRef', {
        timestamp: {
          $gte: new Date(Date.now() - days * 86400000)
        }
      }).then(refs => refs.length)
    });
  } catch (err) {
    console.error('Admin audit statistics failed:', err);
    return res.status(500).json({
      error: 'Could not retrieve admin statistics'
    });
  }
});

// Record a failed file-encryption password attempt without sending the
// password or derived key to the server.
router.post('/encryption-unlock-failed', async (req, res) => {
  if (!requireAccountRef(req, res)) return;

  try {
    await createAuditEvent({
      accountRef: req.user.accountRef,
      eventType: 'ENCRYPTION_UNLOCK_FAILED',
      initiator: 'USER',
      severity: 'MEDIUM',
      outcome: 'FAILURE',
      details: { method: 'FILE_ENCRYPTION_PASSWORD' }
    });

    return res.status(201).json({ recorded: true });
  } catch (error) {
    console.error('Encryption unlock failure audit failed:', error.message);
    return res.status(500).json({ error: 'Could not record unlock failure' });
  }
});

// GET /api/audit/:eventId/verify
// Verify an individual audit event or its Merkle batch against blockchain.
router.get('/:eventId/verify', async (req, res) => {
  try {
    const { eventId } = req.params;

    if (!/^0x[a-fA-F0-9]{64}$/.test(eventId)) {
      return res.status(400).json({
        error: 'Invalid event ID'
      });
    }

    if (req.user.role !== 'ADMIN' && !requireAccountRef(req, res)) {
      return;
    }

    const eventQuery = { eventId };

    if (req.user.role !== 'ADMIN') {
      eventQuery.accountRef = req.user.accountRef;
    }

    const event = await AuditEvent.findOne(eventQuery).lean();

    if (!event) {
      return res.status(404).json({
        error: 'Audit event not found'
      });
    }

    const database = {
      commitment: event.commitment,
      status: event.blockchainStatus,
      transactionHash: event.transactionHash
    };

    // --------------------------------------------------
    // PATH 1: INDIVIDUALLY ANCHORED EVENT
    // --------------------------------------------------

    if (!event.batchId) {
      let chainRecord;

      try {
        chainRecord = await getAuditEvent(eventId);
      } catch (error) {
        console.error('Individual blockchain verification failed:', error.message);

        return res.status(503).json({
          verified: false,
          status: 'BLOCKCHAIN_UNAVAILABLE',
          eventId,
          database,
          message: 'Blockchain verification is temporarily unavailable'
        });
      }

      if (!chainRecord.exists) {
        return res.json({
          verified: false,
          status: 'NOT_ANCHORED',
          eventId,
          database,
          network: {
            chainId: chainRecord.chainId,
            contractAddress: chainRecord.contractAddress
          },
          message: 'This event has not been found on the blockchain'
        });
      }

      const matches =
        chainRecord.commitment.toLowerCase() ===
        event.commitment.toLowerCase();

      return res.json({
        verified: matches,
        status: matches ? 'VERIFIED' : 'MISMATCH',
        verificationType: 'INDIVIDUAL',
        eventId,
        blockchain: {
          commitment: chainRecord.commitment,
          anchoredAt: chainRecord.anchoredAt.toString(),
          signer: chainRecord.signer,
          chainId: chainRecord.chainId,
          contractAddress: chainRecord.contractAddress
        },
        database,
        message: matches
          ? 'The blockchain commitment matches the database audit event'
          : 'WARNING: The database commitment does not match the blockchain record'
      });
    }

    // --------------------------------------------------
    // PATH 2: MERKLE-BATCH-ANCHORED EVENT
    // --------------------------------------------------

    const batch = await AuditBatch.findById(event.batchId).lean();

    if (!batch) {
      return res.status(409).json({
        verified: false,
        status: 'MISMATCH',
        eventId,
        database,
        message: 'The event references a batch that does not exist in the database'
      });
    }

    if (
      !batch.batchId ||
      !batch.merkleRoot ||
      !Number.isSafeInteger(event.leafIndex) ||
      event.leafIndex < 0 ||
      !Array.isArray(event.merkleProof)
    ) {
      return res.status(409).json({
        verified: false,
        status: 'MISMATCH',
        eventId,
        database,
        message: 'The event is missing its Merkle batch verification data'
      });
    }

    let chainBatch;

    try {
      chainBatch = await getAuditBatchRoot(batch.batchId);
    } catch (error) {
      console.error('Batch blockchain lookup failed:', error.message);

      return res.status(503).json({
        verified: false,
        status: 'BLOCKCHAIN_UNAVAILABLE',
        eventId,
        database,
        message: 'Could not retrieve the audit batch from the blockchain'
      });
    }

    if (!chainBatch.exists) {
      return res.json({
        verified: false,
        status: 'NOT_ANCHORED',
        verificationType: 'MERKLE_BATCH',
        eventId,
        database,
        network: {
          chainId: chainBatch.chainId,
          contractAddress: chainBatch.contractAddress
        },
        message: 'The audit batch has not been found on the blockchain'
      });
    }

    // Ensure MongoDB's batch metadata agrees with the chain.
    const batchMetadataMatches =
      chainBatch.merkleRoot.toLowerCase() === batch.merkleRoot.toLowerCase() &&
      chainBatch.leafCount === batch.leafCount &&
      event.leafIndex < chainBatch.leafCount;

    if (!batchMetadataMatches) {
      return res.json({
        verified: false,
        status: 'MISMATCH',
        verificationType: 'MERKLE_BATCH',
        eventId,
        database,
        blockchain: {
          merkleRoot: chainBatch.merkleRoot,
          leafCount: chainBatch.leafCount,
          chainId: chainBatch.chainId,
          contractAddress: chainBatch.contractAddress
        },
        message: 'The stored batch metadata does not match the blockchain'
      });
    }

    let proofValid;

    try {
      proofValid = await verifyAuditProof({
        batchId: batch.batchId,
        commitment: event.commitment,
        leafIndex: event.leafIndex,
        proof: event.merkleProof
      });
    } catch (error) {
      console.error('Merkle proof verification failed:', error.message);

      return res.status(503).json({
        verified: false,
        status: 'BLOCKCHAIN_UNAVAILABLE',
        eventId,
        database,
        message: 'Could not verify the Merkle proof on the blockchain'
      });
    }

    return res.json({
      verified: proofValid,
      status: proofValid ? 'VERIFIED' : 'MISMATCH',
      verificationType: 'MERKLE_BATCH',
      eventId,
      blockchain: {
        merkleRoot: chainBatch.merkleRoot,
        leafCount: chainBatch.leafCount,
        anchoredAt: chainBatch.anchoredAt.toString(),
        signer: chainBatch.signer,
        chainId: chainBatch.chainId,
        contractAddress: chainBatch.contractAddress
      },
      batch: {
        batchId: batch.batchId,
        leafIndex: event.leafIndex
      },
      database,
      message: proofValid
        ? 'The event commitment has been successfully verified against the on-chain Merkle root'
        : 'WARNING: The event Merkle proof does not match the on-chain root'
    });

  } catch (err) {
    console.error('Audit verification failed:', err);

    return res.status(500).json({
      error: 'Could not verify audit event'
    });
  }
});

module.exports = router;
