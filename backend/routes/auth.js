
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const opaque = require('@serenity-kit/opaque');
const { randomUUID } = require('crypto');

const User = require('../models/User');
const recoveryStore = require('../recovery/s3RecoveryStore');
const auth = require('../middleware/auth');
const { createAuditEvent } = require('../services/auditService');

if (!process.env.OPAQUE_SERVER_SETUP) {
  throw new Error(
    'OPAQUE_SERVER_SETUP is required. Generate one with npx @serenity-kit/opaque create-server-setup and store it in your environment.'
  );
}

const OPAQUE_SERVER_SETUP = process.env.OPAQUE_SERVER_SETUP;
const LOGIN_SESSION_TTL_MS = 5 * 60 * 1000;
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// In-memory, single-process OPAQUE session storage.
// Sessions are bound to an email and a unique login attempt.
if (!global.opaqueLogins) {
  global.opaqueLogins = new Map();
}

if (!(global.opaqueLogins instanceof Map)) {
  global.opaqueLogins = new Map();
}

function validLoginSessionId(value) {
  return typeof value === 'string' && UUID_REGEX.test(value);
}

function removeExpiredLoginSessions() {
  const now = Date.now();

  for (const [id, session] of global.opaqueLogins.entries()) {
    if (now - session.timestamp > LOGIN_SESSION_TTL_MS) {
      global.opaqueLogins.delete(id);
    }
  }
}

async function recordAudit(data) {
  try {
    await createAuditEvent(data);
  } catch (error) {
    console.error('Audit event creation failed:', error.message);
  }
}

// ============================================================
// SIGNUP — OPAQUE STEP 1
// ============================================================

router.post('/signup-request', async (req, res) => {
  try {
    const { email, registrationRequest } = req.body;

    if (!email || !registrationRequest) {
      return res.status(400).json({
        error: 'Email and registrationRequest are required'
      });
    }

    const existing = await User.findOne({ email });

    if (existing) {
      return res.status(400).json({
        error: 'Email already registered'
      });
    }

    const { registrationResponse } =
      opaque.server.createRegistrationResponse({
        serverSetup: OPAQUE_SERVER_SETUP,
        userIdentifier: email,
        registrationRequest
      });

    return res.json({
      email,
      registrationResponse
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      error: 'Signup initialization failed'
    });
  }
});

// ============================================================
// SIGNUP — OPAQUE STEP 2
// ============================================================

router.post('/signup-finish', async (req, res) => {
  let createdUser = null;

  try {
    const {
      email,
      registrationRecord,
      wrappedMasterKey,
      masterKeyIV,
      encryptionSalt
    } = req.body;

    if (
      !email ||
      !registrationRecord ||
      !wrappedMasterKey ||
      !masterKeyIV ||
      !encryptionSalt
    ) {
      return res.status(400).json({
        error: 'All signup fields are required'
      });
    }

    const existing = await User.findOne({ email });

    if (existing) {
      return res.status(400).json({
        error: 'Email already registered'
      });
    }

    const user = new User({
      email,
      opaqueRegistrationRecord: registrationRecord,
      encryptionSalt,
      wrappedMasterKey,
      masterKeyIV
    });

    await user.save();
    createdUser = user;

    // Initial recovery record must exist before signup succeeds.
    try {
      await recoveryStore.append({
        recordType: 'MASTER_KEY',
        userId: String(user._id),
        version: 1,
        wrappedKey: wrappedMasterKey,
        iv: masterKeyIV,
        createdAt: new Date().toISOString()
      });
    } catch (recoveryError) {
      // Prevent an account from being left half-initialized.
      await User.deleteOne({ _id: user._id });
      createdUser = null;
      throw recoveryError;
    }

    await recordAudit({
      accountRef: user.accountRef,
      eventType: 'ACCOUNT_CREATED',
      initiator: 'USER',
      severity: 'LOW'
    });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.status(201).json({
      token,
      email: user.email
    });
  } catch (err) {
    console.error(err);

    // Defensive cleanup if an error occurs after user creation.
    if (createdUser) {
      try {
        await User.deleteOne({ _id: createdUser._id });
      } catch (cleanupError) {
        console.error('Signup rollback failed:', cleanupError);
      }
    }

    if (err.code === 11000) {
      return res.status(409).json({
        error: 'Email already registered'
      });
    }

    return res.status(500).json({
      error: 'Signup failed'
    });
  }
});

// ============================================================
// LOGIN — OPAQUE STEP 1
// ============================================================

router.post('/login', async (req, res) => {
  try {
    const {
      email,
      startLoginRequest,
      loginSessionId
    } = req.body;

    if (
      !email ||
      !startLoginRequest ||
      !validLoginSessionId(loginSessionId)
    ) {
      return res.status(400).json({
        error: 'Invalid login request'
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const {
      loginResponse,
      serverLoginState
    } = opaque.server.startLogin({
      serverSetup: OPAQUE_SERVER_SETUP,
      userIdentifier: email,
      registrationRecord: user.opaqueRegistrationRecord,
      startLoginRequest
    });

    removeExpiredLoginSessions();

    global.opaqueLogins.set(loginSessionId, {
      email,
      serverLoginState,
      timestamp: Date.now()
    });

    return res.json({
      email: user.email,
      loginSessionId,
      loginResponse,
      encryptionSalt: user.encryptionSalt,
      wrappedMasterKey: user.wrappedMasterKey,
      masterKeyIV: user.masterKeyIV
    });
  } catch (err) {
    console.error(err);

    return res.status(401).json({
      error: 'Login failed'
    });
  }
});

// ============================================================
// LOGIN — OPAQUE STEP 2
// ============================================================

router.post('/login-finish', async (req, res) => {
  try {
    const {
      email,
      finishLoginRequest,
      loginSessionId
    } = req.body;

    if (
      !email ||
      !finishLoginRequest ||
      !validLoginSessionId(loginSessionId)
    ) {
      return res.status(400).json({
        error: 'Missing or invalid login fields'
      });
    }

    const loginSession =
      global.opaqueLogins.get(loginSessionId);

    if (!loginSession || loginSession.email !== email) {
      return res.status(401).json({
        error: 'Login session not found'
      });
    }

    // Sessions are single-use, even when authentication fails.
    global.opaqueLogins.delete(loginSessionId);

    if (
      Date.now() - loginSession.timestamp >
      LOGIN_SESSION_TTL_MS
    ) {
      return res.status(401).json({
        error: 'Login session expired'
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const { sessionKey } = opaque.server.finishLogin({
      finishLoginRequest,
      serverLoginState: loginSession.serverLoginState
    });

    // Cancel deletion if the account is still within its grace period.
    if (user.deletionPending) {
      const restoredUser = await User.findOneAndUpdate(
        {
          _id: user._id,
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

      if (!restoredUser) {
        return res.status(403).json({
          error: 'The deletion grace period has expired'
        });
      }

      // Record cancellation only after the database confirms it.
      await recordAudit({
        accountRef: user.accountRef,
        eventType: 'ACCOUNT_DELETION_CANCELLED',
        initiator: 'USER',
        severity: 'LOW'
      });
    }

    await recordAudit({
      accountRef: user.accountRef,
      eventType: 'LOGIN_SUCCESS',
      initiator: 'USER',
      severity: 'LOW'
    });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      email: user.email,
      sessionKey
    });
  } catch (err) {
    if (email) {
      const failedUser = await User.findOne({ email }).select('accountRef');

      if (failedUser) {
        await recordAudit({
          accountRef: failedUser.accountRef,
          eventType: 'LOGIN_FAILED',
          initiator: 'USER',
          severity: 'MEDIUM',
          outcome: 'FAILURE',
          details: {
            method: 'OPAQUE',
            reason: 'login_verification_failed'
          }
        });
      }
    }
    console.error(err);

    return res.status(401).json({
      error: 'Login verification failed'
    });
  }
});

// ============================================================
// RECOVERY — MASTER KEY HISTORY
// ============================================================

router.get('/recovery/master-key', auth, async (req, res) => {
  try {
    const records = await recoveryStore.getMasterKeyHistory(
      req.user.userId
    );

    return res.json({ records });
  } catch (err) {
    console.error('Master Key recovery lookup failed:', err);

    return res.status(500).json({
      error: 'Could not fetch Master Key recovery data'
    });
  }
});

// ============================================================
// RECOVERY — REPAIR MASTER KEY
// ============================================================

router.post('/recovery/master-key/repair', auth, async (req, res) => {
  try {
    const { wrappedMasterKey, masterKeyIV } = req.body;

    if (!wrappedMasterKey || !masterKeyIV) {
      return res.status(400).json({
        error: 'Missing Master Key recovery data'
      });
    }

    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    const newVersion =
      (user.wrappedMasterKeyVersion || 1) + 1;

    // Append recovery history before changing the active MongoDB value.
    await recoveryStore.append({
      recordType: 'MASTER_KEY',
      userId: String(user._id),
      version: newVersion,
      wrappedKey: wrappedMasterKey,
      iv: masterKeyIV,
      createdAt: new Date().toISOString()
    });

    user.wrappedMasterKey = wrappedMasterKey;
    user.masterKeyIV = masterKeyIV;
    user.wrappedMasterKeyVersion = newVersion;

    await user.save();

    await recordAudit({
      accountRef: user.accountRef,
      eventType: 'MASTER_KEY_REPAIRED',
      initiator: 'USER',
      severity: 'HIGH'
    });

    return res.json({
      message: 'Master Key repaired',
      version: newVersion
    });
  } catch (err) {
    console.error('Master Key repair failed:', err);

    return res.status(500).json({
      error: 'Could not repair Master Key'
    });
  }
});

// ============================================================
// ACCOUNT — DELETION STATUS
// ============================================================

router.get('/account/deletion-status', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select(
        'deletionPending deletionRequestedAt deletionScheduledFor role'
      );

    if (!user) {
      return res.status(404).json({
        error: 'Account not found'
      });
    }

    return res.json({
      deletionPending: user.deletionPending,
      requestedAt: user.deletionRequestedAt,
      scheduledFor: user.deletionScheduledFor,
      role: user.role
    });
  } catch (err) {
    console.error('Deletion status lookup failed:', err.message);

    return res.status(500).json({
      error: 'Could not retrieve deletion status'
    });
  }
});

// ============================================================
// ACCOUNT — REQUEST DELETION
// ============================================================

router.delete('/account', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({
        error: 'Account not found'
      });
    }

    if (user.deletionPending) {
      return res.status(409).json({
        error: 'Account deletion is already pending',
        scheduledFor: user.deletionScheduledFor
      });
    }

    if (!user.accountRef) {
      user.accountRef = randomUUID();
    }

    const requestedAt = new Date();
    const graceSecondsSetting =
      process.env.ACCOUNT_DELETION_GRACE_SECONDS;
    const graceDays =
      Number(process.env.ACCOUNT_DELETION_GRACE_DAYS || 7);

    let gracePeriod;

    if (graceSecondsSetting) {
      const graceSeconds = Number(graceSecondsSetting);

      if (
        !Number.isInteger(graceSeconds) ||
        graceSeconds < 1 ||
        graceSeconds > 30 * 24 * 60 * 60
      ) {
        return res.status(500).json({
          error: 'Invalid deletion grace-period configuration'
        });
      }

      gracePeriod = { gracePeriodSeconds: graceSeconds };
    } else {
      if (
        !Number.isInteger(graceDays) ||
        graceDays < 1 ||
        graceDays > 30
      ) {
        return res.status(500).json({
          error: 'Invalid deletion grace-period configuration'
        });
      }

      gracePeriod = { gracePeriodDays: graceDays };
    }

    const graceMilliseconds = gracePeriod.gracePeriodSeconds
      ? gracePeriod.gracePeriodSeconds * 1000
      : gracePeriod.gracePeriodDays * 24 * 60 * 60 * 1000;

    const scheduledFor = new Date(
      requestedAt.getTime() + graceMilliseconds
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
        severity: 'MEDIUM'
      });

      user.deletionRequestEventId = event.eventId;
      await user.save();
    } catch (auditError) {
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
      ...gracePeriod
    });
  } catch (err) {
    console.error('Account deletion request failed:', err.message);

    return res.status(500).json({
      error: 'Could not schedule account deletion'
    });
  }
});

// ============================================================
// ACCOUNT — CANCEL DELETION
// ============================================================

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

    // Audit only after cancellation has actually succeeded.
    await recordAudit({
      accountRef: updatedUser.accountRef,
      eventType: 'ACCOUNT_DELETION_CANCELLED',
      initiator: 'USER',
      severity: 'LOW'
    });

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
