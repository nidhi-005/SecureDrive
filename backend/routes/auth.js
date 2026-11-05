const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const opaque = require('@serenity-kit/opaque');
const User = require('../models/User');
const recoveryStore = require('../recovery/s3RecoveryStore');
const auth = require('../middleware/auth');
const File = require('../models/File');
const { deleteAllUserFilesFromS3 } = require('../config/s3');
const { createAuditEvent } = require('../services/auditService');
const { randomUUID } = require('crypto');

if (!process.env.OPAQUE_SERVER_SETUP) {
  throw new Error('OPAQUE_SERVER_SETUP is required. Generate one with npx @serenity-kit/opaque create-server-setup and store it in your environment.');
}

const OPAQUE_SERVER_SETUP = process.env.OPAQUE_SERVER_SETUP;

async function recordAudit(data) {
  try {
    await createAuditEvent(data);
  } catch (error) {
    console.error('Audit event creation failed:', error.message);
  }
}

router.post('/signup-request', async (req, res) => {
  try {
    const { email, registrationRequest } = req.body;

    if (!email || !registrationRequest) {
      return res.status(400).json({ error: 'Email and registrationRequest are required' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup: OPAQUE_SERVER_SETUP,
      userIdentifier: email,
      registrationRequest
    });

    res.json({ email, registrationResponse });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup initialization failed' });
  }
});

router.post('/signup-finish', async (req, res) => {
  try {
    const { email, registrationRecord, wrappedMasterKey, masterKeyIV, encryptionSalt } = req.body;

    if (!email || !registrationRecord || !wrappedMasterKey || !masterKeyIV) {
      return res.status(400).json({ error: 'All signup fields are required' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const user = new User({
      email,
      opaqueRegistrationRecord: registrationRecord,
      encryptionSalt,
      wrappedMasterKey,
      masterKeyIV
    });
    await user.save();

    await recoveryStore.append({
      recordType: 'MASTER_KEY',
      userId: String(user._id),
      version: 1,
      wrappedKey: wrappedMasterKey,
      iv: masterKeyIV,
      createdAt: new Date().toISOString()
    });

    await recordAudit({
      accountRef: user.accountRef,
      eventType: 'ACCOUNT_CREATED',
      initiator: 'USER',
      severity: 'INFO'
    });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ token, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, startLoginRequest } = req.body;

    if (!email || !startLoginRequest) {
      return res.status(401).json({ error: 'Email and startLoginRequest required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'User does not exist' });
    }

    if (user.deletionPending) {
      return res.status(403).json({
        error: 'Account deletion is in progress'
      });
    }

    const { loginResponse, serverLoginState } = opaque.server.startLogin({
      serverSetup: OPAQUE_SERVER_SETUP,
      userIdentifier: email,
      registrationRecord: user.opaqueRegistrationRecord,
      startLoginRequest
    });

    if (!global.opaqueLogins) {
      global.opaqueLogins = {};
    }

    global.opaqueLogins[email] = {
      serverLoginState,
      timestamp: Date.now()
    };

    res.json({
      email: user.email,
      loginResponse,
      encryptionSalt: user.encryptionSalt,
      wrappedMasterKey: user.wrappedMasterKey,
      masterKeyIV: user.masterKeyIV
    });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Login failed' });
  }
});

router.post('/login-finish', async (req, res) => {
  try {
    const { email, finishLoginRequest } = req.body;

    if (!email || !finishLoginRequest) {
      return res.status(401).json({ error: 'Missing required fields' });
    }

    if (!global.opaqueLogins || !global.opaqueLogins[email]) {
      return res.status(401).json({ error: 'Login session not found' });
    }

    const loginSession = global.opaqueLogins[email];
    if (Date.now() - loginSession.timestamp > 5 * 60 * 1000) {
      delete global.opaqueLogins[email];
      return res.status(401).json({ error: 'Login session expired' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'User does not exist' });
    }

    if (user.deletionPending) {
      return res.status(403).json({
        error: 'Account deletion is in progress'
      });
    }

    const { sessionKey } = opaque.server.finishLogin({
      finishLoginRequest,
      serverLoginState: loginSession.serverLoginState
    });

    delete global.opaqueLogins[email];

    await recordAudit({
      accountRef: user.accountRef,
      eventType: 'LOGIN_SUCCESS',
      initiator: 'USER',
      severity: 'INFO'
    });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, email: user.email, sessionKey });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Login verification failed' });
  }
});

router.get('/recovery/master-key', auth, async (req, res) => {
  try {
    const records = await recoveryStore.getMasterKeyHistory(
      req.user.userId
    );

    res.json({
      records
    });
  } catch (err) {
    console.error('Master Key recovery lookup failed:', err);
    res.status(500).json({
      error: 'Could not fetch Master Key recovery data'
    });
  }
});

router.post('/recovery/master-key/repair', auth, async (req, res) => {
  try {
    const { wrappedMasterKey, masterKeyIV } = req.body;

    if (!wrappedMasterKey || !masterKeyIV) {
      return res.status(400).json({
        error: 'Missing Master Key recovery data'
      });
    }

    const User = require('../models/User');

    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    const newVersion =
      (user.wrappedMasterKeyVersion || 1) + 1;

    user.wrappedMasterKey = wrappedMasterKey;
    user.masterKeyIV = masterKeyIV;
    user.wrappedMasterKeyVersion = newVersion;

    await user.save();

    await recoveryStore.append({
      recordType: 'MASTER_KEY',
      userId: String(user._id),
      version: newVersion,
      wrappedKey: wrappedMasterKey,
      iv: masterKeyIV,
      createdAt: new Date().toISOString()
    });

    await recordAudit({
      accountRef: user.accountRef,
      eventType: 'MASTER_KEY_REPAIRED',
      initiator: 'USER',
      severity: 'WARNING'
    });

    res.json({
      message: 'Master Key repaired',
      version: newVersion
    });
  } catch (err) {
    console.error('Master Key repair failed:', err);

    res.status(500).json({
      error: 'Could not repair Master Key'
    });
  }
});

// Check whether account deletion is pending.
router.get('/account/deletion-status', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('deletionPending deletionRequestedAt deletionScheduledFor');

    if (!user) {
      return res.status(404).json({ error: 'Account not found' });
    }

    return res.json({
      deletionPending: user.deletionPending,
      requestedAt: user.deletionRequestedAt,
      scheduledFor: user.deletionScheduledFor
    });
  } catch (err) {
    console.error('Deletion status lookup failed:', err.message);
    return res.status(500).json({ error: 'Could not retrieve deletion status' });
  }
});

// Request account deletion. This only schedules deletion.
router.delete('/account', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ error: 'Account not found' });
    }

    if (user.deletionPending) {
      return res.status(409).json({
        error: 'Account deletion is already pending',
        scheduledFor: user.deletionScheduledFor
      });
    }

    // Backfill pseudonymous reference for existing accounts.
    if (!user.accountRef) {
      user.accountRef = randomUUID();
    }

    const graceDays = Number(
      process.env.ACCOUNT_DELETION_GRACE_DAYS || 7
    );

    if (!Number.isInteger(graceDays) || graceDays < 1 || graceDays > 30) {
      return res.status(500).json({
        error: 'Invalid deletion grace-period configuration'
      });
    }

    const requestedAt = new Date();
    // const scheduledFor = new Date(
    //   requestedAt.getTime() + graceDays * 24 * 60 * 60 * 1000
    // );

    const TESTING_GRACE_SECONDS = 30;
    const scheduledFor = new Date(
      requestedAt.getTime() + TESTING_GRACE_SECONDS * 1000
    );

    user.deletionPending = true;
    user.deletionRequestedAt = requestedAt;
    user.deletionScheduledFor = scheduledFor;
    user.deletionStatus = 'PENDING';
    user.deletionLeaseId = null;
    user.deletionLeaseUntil = null;
    user.deletionAttempts = 0;

    await user.save();

    try {
      const event = await createAuditEvent({
        accountRef: user.accountRef,
        eventType: 'ACCOUNT_DELETION_REQUESTED',
        initiator: 'USER',
        severity: 'WARNING'
      });

      user.deletionRequestEventId = event.eventId;
      await user.save();

    } catch (auditError) {
      // If audit persistence fails, revert the pending state.
      user.deletionPending = false;
      user.deletionRequestedAt = null;
      user.deletionScheduledFor = null;
      user.deletionRequestEventId = null;

      user.deletionStatus = 'NONE';
      user.deletionLeaseId = null;
      user.deletionLeaseUntil = null;
      user.deletionAttempts = 0;

      await user.save();
      throw auditError;
    }

    return res.status(202).json({
      message: 'Account deletion scheduled',
      deletionPending: true,
      requestedAt,
      scheduledFor,
      gracePeriodDays: graceDays
    });

  } catch (err) {
    console.error('Account deletion request failed:', err.message);

    return res.status(500).json({
      error: 'Could not schedule account deletion'
    });
  }
});


// Cancel a pending account deletion.

// Cancel a pending account deletion.
router.post('/account/deletion-cancel', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({
        error: 'Account not found'
      });
    }

    if (!user.deletionPending) {
      return res.status(409).json({
        error: 'No pending deletion request'
      });
    }

    if (
      !user.deletionScheduledFor ||
      user.deletionScheduledFor <= new Date()
    ) {
      return res.status(409).json({
        error: 'The deletion grace period has expired'
      });
    }

    // Persist cancellation evidence before changing account state.
    await createAuditEvent({
      accountRef: user.accountRef,
      eventType: 'ACCOUNT_DELETION_CANCELLED',
      initiator: 'USER',
      severity: 'INFO'
    });

    // Atomically cancel deletion only if it is still pending.
    const updatedUser = await User.findOneAndUpdate(
      {
        _id: req.user.userId,
        deletionPending: true,
        deletionStatus: 'PENDING',
        deletionScheduledFor: { $gt: new Date() }
      },
      {
        $set: {
          deletionPending: false,
          deletionStatus: 'NONE',
          deletionRequestedAt: null,
          deletionScheduledFor: null,
          deletionRequestEventId: null,
          deletionLeaseId: null,
          deletionLeaseUntil: null,
          deletionAttempts: 0
        }
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(409).json({
        error: 'Deletion can no longer be cancelled'
      });
    }

    return res.json({
      message: 'Account deletion cancelled',
      deletionPending: false
    });

  } catch (err) {
    console.error(
      'Account deletion cancellation failed:',
      err.message
    );

    return res.status(500).json({
      error: 'Could not cancel account deletion'
    });
  }
});

module.exports = router;