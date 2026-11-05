
const express = require('express');
const router = express.Router();

const AuditEvent = require('../models/AuditEvent');
const { getAuditEvent } = require('../services/blockchainService');

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
    'FILE_UPLOADED',
    'FILE_DELETED',
    'FILE_CEK_RECOVERED',
    'FILE_CEK_REPAIRED',
    'MASTER_KEY_RECOVERED',
    'MASTER_KEY_REPAIRED',
    'MASTER_KEY_RECOVERY_FAILED',
    'INTEGRITY_VERIFIED',
    'INTEGRITY_MISMATCH'
  ];

  const allowedSeverities = ['INFO', 'WARNING', 'CRITICAL'];
  const allowedStatuses = ['PENDING', 'ANCHORED', 'FAILED'];

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
    const accountRef = req.user.accountRef;

    const [total, anchored, pending, failed, critical] =
      await Promise.all([
        AuditEvent.countDocuments({ accountRef }),
        AuditEvent.countDocuments({
          accountRef,
          blockchainStatus: 'ANCHORED'
        }),
        AuditEvent.countDocuments({
          accountRef,
          blockchainStatus: 'PENDING'
        }),
        AuditEvent.countDocuments({
          accountRef,
          blockchainStatus: 'FAILED'
        }),
        AuditEvent.countDocuments({
          accountRef,
          severity: 'CRITICAL'
        })
      ]);

    return res.json({
      total,
      anchored,
      pending,
      failed,
      critical
    });
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
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).json({
        error: 'Administrator access required'
      });
    }

    const [
      total,
      anchored,
      pending,
      failed,
      critical,
      accountsWithEvents,
      eventTypes
    ] = await Promise.all([
      AuditEvent.countDocuments(),
      AuditEvent.countDocuments({ blockchainStatus: 'ANCHORED' }),
      AuditEvent.countDocuments({ blockchainStatus: 'PENDING' }),
      AuditEvent.countDocuments({ blockchainStatus: 'FAILED' }),
      AuditEvent.countDocuments({ severity: 'CRITICAL' }),

      AuditEvent.distinct('accountRef'),

      AuditEvent.aggregate([
        {
          $group: {
            _id: '$eventType',
            count: { $sum: 1 }
          }
        },
        { $sort: { count: -1 } }
      ])
    ]);

    return res.json({
      total,
      anchored,
      pending,
      failed,
      critical,
      accountsWithEvents: accountsWithEvents.length,
      eventTypes
    });
  } catch (err) {
    console.error('Admin audit statistics failed:', err);

    return res.status(500).json({
      error: 'Could not retrieve admin statistics'
    });
  }
});

// GET /api/audit/:eventId/verify
// Verify a MongoDB audit event against the blockchain.
router.get('/:eventId/verify', async (req, res) => {
  try {
    const { eventId } = req.params;

    if (!/^0x[a-fA-F0-9]{64}$/.test(eventId)) {
      return res.status(400).json({
        error: 'Invalid event ID'
      });
    }

    const event = await AuditEvent.findOne({ eventId }).lean();

    if (!event) {
      return res.status(404).json({
        error: 'Audit event not found'
      });
    }

    // Users must have a valid accountRef.
    // Admins can verify events belonging to any account.
    if (req.user.role !== 'ADMIN' && !requireAccountRef(req, res)) {
      return;
    }

    // Users can verify only their own events.
    // Admins can verify events belonging to any account.
    if (
      req.user.role !== 'ADMIN' &&
      event.accountRef !== req.user.accountRef
    ) {
      return res.status(403).json({
        error: 'You cannot verify another account’s events'
      });
    }

    let chainRecord;

    try {
      chainRecord = await getAuditEvent(eventId);
    } catch (blockchainError) {
      console.error(
        'Blockchain verification unavailable:',
        blockchainError.message
      );

      return res.status(503).json({
        verified: false,
        status: 'BLOCKCHAIN_UNAVAILABLE',
        message: 'Blockchain verification is temporarily unavailable'
      });
    }

    if (!chainRecord || !chainRecord.exists) {
      return res.json({
        verified: false,
        status: 'NOT_ANCHORED',
        eventId,
        mongoStatus: event.blockchainStatus,
        message: 'This event has not been found on the blockchain'
      });
    }

    const matches =
      chainRecord.commitment.toLowerCase() ===
      event.commitment.toLowerCase();

    return res.json({
      verified: matches,
      status: matches ? 'VERIFIED' : 'MISMATCH',
      eventId,
      eventType: event.eventType,
      timestamp: event.timestamp,
      blockchain: {
        commitment: chainRecord.commitment,
        anchoredAt: chainRecord.anchoredAt.toString(),
        signer: chainRecord.signer
      },
      database: {
        commitment: event.commitment,
        status: event.blockchainStatus,
        transactionHash: event.transactionHash
      },
      message: matches
        ? 'The blockchain commitment matches the database audit event'
        : 'WARNING: The database commitment does not match the blockchain record'
    });

  } catch (err) {
    console.error('Audit verification failed:', err);

    return res.status(500).json({
      error: 'Could not verify audit event'
    });
  }
});

module.exports = router;
