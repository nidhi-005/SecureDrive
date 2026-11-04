const { randomUUID } = require('crypto');

const User = require('../models/User');
const File = require('../models/File');
const AuditEvent = require('../models/AuditEvent');

const recoveryStore = require('../recovery/s3RecoveryStore');

const {
  deleteAllUserFilesFromS3
} = require('../config/s3');

const {
  createAuditEvent
} = require('../services/auditService');

const POLL_INTERVAL = 15000;
const LEASE_DURATION = 10 * 60 * 1000;

let running = false;
let interval = null;

async function claimDeletion() {
  const now = new Date();
  const leaseId = randomUUID();

  const user = await User.findOneAndUpdate(
    {
      deletionPending: true,
      $or: [
        {
          deletionStatus: 'PENDING',
          deletionScheduledFor: { $lte: now }
        },
        {
          deletionStatus: 'PROCESSING',
          deletionLeaseUntil: { $lte: now }
        }
      ]
    },
    {
      $set: {
        deletionStatus: 'PROCESSING',
        deletionLeaseId: leaseId,
        deletionLeaseUntil: new Date(
          now.getTime() + LEASE_DURATION
        )
      },
      $inc: {
        deletionAttempts: 1
      }
    },
    {
      new: true,
      sort: { deletionScheduledFor: 1 }
    }
  );

  return user;
}

async function processDeletion(user) {
  const userId = String(user._id);
  const leaseId = user.deletionLeaseId;
  const accountRef = user.accountRef;

  if (!accountRef) {
    throw new Error('Account has no pseudonymous accountRef');
  }

  console.log(`Processing account deletion: ${accountRef}`);

  // Confirm that this worker still owns the deletion claim.
  async function verifyLease() {
    const current = await User.findOne({
      _id: user._id,
      deletionStatus: 'PROCESSING',
      deletionLeaseId: leaseId
    }).select('_id');

    if (!current) {
      throw new Error('Deletion lease lost');
    }
  }

  // 1. Delete encrypted user files from the primary S3 bucket.
  await verifyLease();
  await deleteAllUserFilesFromS3(userId);

  // 2. Delete all recovery records from the recovery S3 bucket.
//   await verifyLease();
//   await recoveryStore.deleteUserRecords(userId);

  // 3. Delete file metadata and wrapped CEKs from MongoDB.
  await verifyLease();
  await File.deleteMany({ owner: user._id });

  // 4. Persist the final audit event.
  // Check first so retries do not create duplicate completion events.
  await verifyLease();

  const existingEvent = await AuditEvent.findOne({
    accountRef,
    eventType: 'ACCOUNT_DELETED'
  });

  if (!existingEvent) {
    await createAuditEvent({
      accountRef,
      eventType: 'ACCOUNT_DELETED',
      initiator: 'SYSTEM',
      severity: 'CRITICAL'
    });
  }

  // 5. Permanently remove the account.
  // The lease condition prevents a stale worker from deleting it.
  const deletedUser = await User.findOneAndDelete({
    _id: user._id,
    deletionStatus: 'PROCESSING',
    deletionLeaseId: leaseId
  });

  if (!deletedUser) {
    throw new Error('Could not finalize account deletion: lease lost');
  }

  // Remove any in-memory OPAQUE login state.
  if (global.opaqueLogins && deletedUser.email) {
    delete global.opaqueLogins[deletedUser.email];
  }

  console.log(`Account permanently deleted: ${accountRef}`);
}

async function runDeletionWorker() {
  if (running) return;

  running = true;

  try {
    const user = await claimDeletion();

    if (user) {
      try {
        await processDeletion(user);
      } catch (err) {
        console.error(
          'Account deletion processing failed:',
          err.message
        );

        // Make the account eligible for another attempt.
        // The account remains PROCESSING and is not lost.
        await User.updateOne(
          {
            _id: user._id,
            deletionStatus: 'PROCESSING',
            deletionLeaseId: user.deletionLeaseId
          },
          {
            $set: {
              deletionLeaseUntil: new Date(0)
            }
          }
        );
      }
    }
  } catch (err) {
    console.error('Deletion worker error:', err);
  } finally {
    running = false;
  }
}

function startDeletionWorker() {
  if (interval) return;

  console.log('Account deletion worker started');

  runDeletionWorker();

  interval = setInterval(
    runDeletionWorker,
    POLL_INTERVAL
  );
}

module.exports = { startDeletionWorker };