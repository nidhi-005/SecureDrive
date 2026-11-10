const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const User = require('../models/User');
const Passkey = require('../models/Passkey');
const PasskeyChallenge = require('../models/PasskeyChallenge');
const auth = require('../middleware/auth');
const rateLimit = require('express-rate-limit');
const { createAuditEvent } = require('../services/auditService');

const passkeyCeremonyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many passkey attempts. Please wait and try again.' }
});

const router = express.Router();

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

async function recordLoginAudit(user, outcome, reason = 'authentication_failed') {
  if (!user?.accountRef) return;
  try {
    await createAuditEvent({
      accountRef: user.accountRef,
      eventType: outcome === 'SUCCESS' ? 'LOGIN_SUCCESS' : 'PASSKEY_LOGIN_FAILED',
      initiator: 'USER',
      severity: outcome === 'SUCCESS' ? 'LOW' : 'MEDIUM',
      outcome,
      details: {
        method: 'PASSKEY',
        ...(outcome === 'FAILURE' ? { reason } : {})
      }
    });
  } catch (error) {
    console.error('Passkey audit event creation failed:', error.message);
  }
}

// SimpleWebAuthn is loaded dynamically because the package is ESM.
let webauthnPromise;

function getWebAuthn() {
  if (!webauthnPromise) {
    webauthnPromise = import('@simplewebauthn/server');
  }

  return webauthnPromise;
}

function getWebAuthnConfig() {
  const rpName = process.env.WEBAUTHN_RP_NAME;
  const rpID = process.env.WEBAUTHN_RP_ID;
  const origin = process.env.WEBAUTHN_ORIGIN;

  if (!rpName || !rpID || !origin) {
    throw new Error('WebAuthn environment configuration is missing');
  }

  return { rpName, rpID, origin };
}

function normalizeEmail(value) {
  return typeof value === 'string'
    ? value.trim().toLowerCase()
    : '';
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isWithinDeletionGracePeriod(user, now = new Date()) {
  return Boolean(
    user?.deletionPending &&
    user.deletionStatus === 'PENDING' &&
    user.deletionScheduledFor &&
    user.deletionScheduledFor > now
  );
}

async function recordDeletionCancellation(user) {
  try {
    await createAuditEvent({
      accountRef: user.accountRef,
      eventType: 'ACCOUNT_DELETION_CANCELLED',
      initiator: 'USER',
      severity: 'LOW'
    });
  } catch (error) {
    console.error('Deletion cancellation audit event failed:', error.message);
  }
}

function issueToken(user) {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }

  return jwt.sign(
    {
      userId: String(user._id),
      email: user.email,
      sessionVersion: Number(user.sessionVersion || 0)
    },
    process.env.JWT_SECRET,
    { expiresIn: '12h', issuer: 'securedrive', audience: 'securedrive-web' }
  );
}

function challengeExpiry() {
  return new Date(Date.now() + CHALLENGE_TTL_MS);
}

// ------------------------------------------------------------
// REGISTRATION: generate passkey creation options
// POST /api/auth/passkey/register/options
// ------------------------------------------------------------

router.post('/register/options', passkeyCeremonyLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);

    if (!validEmail(email)) {
      return res.status(400).json({
        error: 'A valid email address is required'
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        error: 'An account with this email already exists. Sign in with your passkey.'
      });
    }

    const { generateRegistrationOptions } = await getWebAuthn();
    const { rpName, rpID } = getWebAuthnConfig();

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: email,

      // The library generates a random WebAuthn user ID.
      // Do not use email as the WebAuthn user ID.

      attestationType: 'none',

      // First credential is created on this device by default. Additional
      // credentials can later be registered locally or through a phone QR flow.
      preferredAuthenticatorType: 'localDevice',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required'
      },
      timeout: 60000
    });

    const challengeId = crypto.randomUUID();

    await PasskeyChallenge.create({
    challengeId,
    email,
    purpose: 'register',
    challenge: options.challenge,
    webauthnUserID: options.user.id,
    expiresAt: challengeExpiry()
    });

    return res.json({
    options,
    challengeId
    });

  } catch (error) {
    console.error('Passkey registration options error:', error);

    return res.status(500).json({
      error: 'Could not start passkey registration'
    });
  }
});

// ------------------------------------------------------------
// REGISTRATION: verify passkey and create account
// POST /api/auth/passkey/register/verify
// ------------------------------------------------------------

router.post('/register/verify', passkeyCeremonyLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const response = req.body.response;
    const { challengeId } = req.body;

    if (!validEmail(email) || !response?.id || !challengeId) {
      return res.status(400).json({
        error: 'Invalid registration request'
      });
    }

    // Consume the challenge atomically.
    const challengeRecord =
  await PasskeyChallenge.findOneAndDelete({
    challengeId,
    email,
    purpose: 'register',
    expiresAt: { $gt: new Date() }
  });

    if (!challengeRecord) {
      return res.status(401).json({
        error: 'Registration challenge expired or already used'
      });
    }

    const { verifyRegistrationResponse } = await getWebAuthn();
    const { rpID, origin } = getWebAuthnConfig();

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeRecord.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({
        error: 'Passkey registration verification failed'
      });
    }

    const {
      credential,
      credentialDeviceType,
      credentialBackedUp
    } = verification.registrationInfo;

    // Protect against duplicate credential registration.
    const existingCredential = await Passkey.findOne({
      credentialId: credential.id
    });

    if (existingCredential) {
      return res.status(409).json({
        error: 'This passkey is already registered'
      });
    }

    // Check again because another registration may have completed
    // while the authenticator ceremony was in progress.
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        error: 'An account with this email already exists. Sign in with your passkey.'
      });
    }

    const user = await User.create({
      email,
      authMethod: 'webauthn',
      webauthnUserID: challengeRecord.webauthnUserID,
      encryptionReady: false
    });

    try {
      await Passkey.create({
        user: user._id,
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64'),
        webauthnUserID: challengeRecord.webauthnUserID,
        counter: credential.counter,
        transports: credential.transports?.length ? credential.transports : [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp
      });
    } catch (error) {
      // Avoid leaving an account without its first credential.
      await User.deleteOne({ _id: user._id });
      throw error;
    }

    const token = issueToken(user);

    return res.status(201).json({
      token,
      email: user.email,
      encryptionReady: false,
      nextStep: 'encryption-setup'
    });

  } catch (error) {
    console.error('Passkey registration verification error:', error);

    if (error.code === 11000) {
      return res.status(409).json({
        error: 'An account with this email or passkey already exists.'
      });
    }

    return res.status(400).json({
      error: 'Passkey registration could not be verified'
    });
  }
});

// ------------------------------------------------------------
// ADD ANOTHER PASSKEY TO AN AUTHENTICATED ACCOUNT
// These endpoints let an already-authenticated user add a local passkey
// or register a passkey on a phone using the browser's hybrid/QR flow.
// ------------------------------------------------------------
router.post('/register/additional/options', auth, passkeyCeremonyLimiter, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user || user.deletionPending || user.authMethod !== 'webauthn') {
      return res.status(401).json({ error: 'Account cannot register another passkey' });
    }

    const passkeys = await Passkey.find({ user: user._id });
    if (!passkeys.length || !user.webauthnUserID) {
      return res.status(409).json({ error: 'The account has no valid primary passkey identity' });
    }

    const mode = req.body.mode === 'hybrid' ? 'hybrid' : 'local';
    const { generateRegistrationOptions } = await getWebAuthn();
    const { rpName, rpID } = getWebAuthnConfig();

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: user.email,
      userID: Buffer.from(user.webauthnUserID, 'base64url'),
      attestationType: 'none',
      excludeCredentials: passkeys.map(passkey => ({ id: passkey.credentialId })),
      preferredAuthenticatorType: mode === 'hybrid' ? 'remoteDevice' : 'localDevice',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required'
      },
      timeout: 60000
    });

    const challengeId = crypto.randomUUID();
    await PasskeyChallenge.create({
      challengeId,
      email: user.email,
      purpose: 'register-additional',
      challenge: options.challenge,
      webauthnUserID: user.webauthnUserID,
      expiresAt: challengeExpiry()
    });

    return res.json({ options, challengeId });
  } catch (error) {
    console.error('Additional passkey options error:', error);
    return res.status(500).json({ error: 'Could not start additional passkey registration' });
  }
});

router.post('/register/additional/verify', auth, passkeyCeremonyLimiter, async (req, res) => {
  try {
    const response = req.body.response;
    const { challengeId } = req.body;
    if (!response?.id || !challengeId) {
      return res.status(400).json({ error: 'Invalid additional passkey registration request' });
    }

    const user = await User.findById(req.user.userId);
    if (!user || user.deletionPending || user.authMethod !== 'webauthn') {
      return res.status(401).json({ error: 'Account cannot register another passkey' });
    }

    const challengeRecord = await PasskeyChallenge.findOneAndDelete({
      challengeId,
      email: user.email,
      purpose: 'register-additional',
      expiresAt: { $gt: new Date() }
    });
    if (!challengeRecord) {
      return res.status(401).json({ error: 'Passkey registration challenge expired or already used' });
    }

    const { verifyRegistrationResponse } = await getWebAuthn();
    const { rpID, origin } = getWebAuthnConfig();
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeRecord.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Additional passkey verification failed' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const existingCredential = await Passkey.findOne({ credentialId: credential.id });
    if (existingCredential) {
      return res.status(409).json({ error: 'This passkey is already registered' });
    }

    await Passkey.create({
      user: user._id,
      credentialId: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64'),
      webauthnUserID: challengeRecord.webauthnUserID,
      counter: credential.counter,
      transports: credential.transports?.length ? credential.transports : [],
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp
    });

    return res.status(201).json({
      success: true,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp
    });
  } catch (error) {
    console.error('Additional passkey verification error:', error);
    if (error.code === 11000) {
      return res.status(409).json({ error: 'This passkey is already registered' });
    }
    return res.status(400).json({ error: 'Additional passkey could not be verified' });
  }
});

// ------------------------------------------------------------
// LOGIN: generate authentication options
// POST /api/auth/passkey/login/options
// ------------------------------------------------------------

router.post('/login/options', passkeyCeremonyLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);

    if (!validEmail(email)) {
      return res.status(400).json({
        error: 'A valid email address is required'
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        error: 'No account exists for this email. Create an account first.'
      });
    }

    if (user.deletionPending && !isWithinDeletionGracePeriod(user)) {
      await recordLoginAudit(user, 'FAILURE', 'account_not_available');
      return res.status(401).json({
        error: 'Invalid account or passkey'
      });
    }

    const passkeys = await Passkey.find({
      user: user._id
    });

    if (!passkeys.length) {
      await recordLoginAudit(user, 'FAILURE', 'no_registered_passkey');
      return res.status(401).json({
        error: 'No passkey is registered for this account.'
      });
    }

    const { generateAuthenticationOptions } = await getWebAuthn();
    const { rpID } = getWebAuthnConfig();

    // Offer every credential registered to this account, including synced
    // passkeys. Local-device requests include stored transport hints below;
    // hybrid requests use discoverable credentials for the QR handoff.
    const mode = req.body.mode === 'hybrid' ? 'hybrid' : 'local';

    // All SecureDrive credentials are discoverable. Leaving allowCredentials
    // unset for hybrid login lets the phone select the matching passkey from
    // its own credential store instead of relying on this device's transport
    // metadata during the QR handoff.
    const options = await generateAuthenticationOptions({
      rpID,
      ...(mode === 'local'
        ? {
          allowCredentials: passkeys.map(passkey => ({
            id: passkey.credentialId,
            ...(passkey.transports?.length
              ? { transports: passkey.transports }
              : {})
          }))
        }
        : {}),
      userVerification: 'required',
      timeout: 60000
    });

    // WebAuthn Level 3 hints are preferences, not guarantees. Older browsers
    // ignore this field and show their normal authenticator chooser.
    options.hints = mode === 'hybrid' ? ['hybrid'] : ['client-device'];

    const challengeId = crypto.randomUUID();

    await PasskeyChallenge.create({
    challengeId,
    email,
    purpose: 'login',
    challenge: options.challenge,
    expiresAt: challengeExpiry()
    });

    return res.json({
    options,
    challengeId
    });

  } catch (error) {
    console.error('Passkey login options error:', error);

    return res.status(500).json({
      error: 'Could not start passkey login'
    });
  }
});

// ------------------------------------------------------------
// LOGIN: verify authenticator assertion
// POST /api/auth/passkey/login/verify
// ------------------------------------------------------------

router.post('/login/verify', passkeyCeremonyLimiter, async (req, res) => {
  let email = '';
  let attemptedUser;
  let failureRecorded = false;

  const recordFailure = async reason => {
    if (failureRecorded) return;
    failureRecorded = true;

    try {
      const user = attemptedUser || (
        validEmail(email)
          ? await User.findOne({ email }).select('accountRef')
          : null
      );
      await recordLoginAudit(user, 'FAILURE', reason);
    } catch (auditError) {
      console.error('Passkey login failure audit lookup failed:', auditError.message);
    }
  };

  try {
    email = normalizeEmail(req.body.email);
    const response = req.body.response;
    const { challengeId } = req.body;

    if (!validEmail(email) || !response?.id || !challengeId) {
      await recordFailure('invalid_authentication_request');
      return res.status(400).json({
        error: 'Invalid authentication request'
      });
    }

    const challengeRecord =
    await PasskeyChallenge.findOneAndDelete({
        challengeId,
        email,
        purpose: 'login',
        expiresAt: { $gt: new Date() }
    });

    if (!challengeRecord) {
      await recordFailure('challenge_expired_or_reused');
      return res.status(401).json({
        error: 'Authentication challenge expired or already used'
      });
    }

    const user = await User.findOne({ email });
    attemptedUser = user;

    if (!user || (user.deletionPending && !isWithinDeletionGracePeriod(user))) {
      await recordFailure('invalid_account_or_passkey');
      return res.status(401).json({
        error: 'Invalid account or passkey'
      });
    }

    const passkey = await Passkey.findOne({
      user: user._id,
      credentialId: response.id
    });

    if (!passkey) {
      await recordFailure('credential_not_registered');
      return res.status(401).json({
        error: 'Invalid account or passkey'
      });
    }

    const { verifyAuthenticationResponse } = await getWebAuthn();
    const { rpID, origin } = getWebAuthnConfig();

    const verification = await verifyAuthenticationResponse({
      response,

      expectedChallenge: challengeRecord.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,

      credential: {
        id: passkey.credentialId,
        publicKey: new Uint8Array(
          Buffer.from(passkey.publicKey, 'base64')
        ),
        counter: passkey.counter,
        transports: passkey.transports
      },

      requireUserVerification: true
    });

    if (!verification.verified) {
      await recordFailure('assertion_verification_failed');
      return res.status(401).json({
        error: 'Passkey authentication failed'
      });
    }

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

      await recordDeletionCancellation(user);
    }

    passkey.counter = verification.authenticationInfo.newCounter;
    passkey.lastUsedAt = new Date();

    await passkey.save();
    await recordLoginAudit(user, 'SUCCESS');

    const token = issueToken(user);

const encryptionReady = Boolean(
  user.wrappedMasterKey &&
  user.masterKeyIV &&
  user.encryptionSalt
);

return res.json({
  token,
  email: user.email,
  encryptionReady,

  encryptionSalt: encryptionReady
    ? user.encryptionSalt
    : null,

  wrappedMasterKey: encryptionReady
    ? user.wrappedMasterKey
    : null,

  masterKeyIV: encryptionReady
    ? user.masterKeyIV
    : null,

  nextStep: encryptionReady
    ? 'unlock-encryption'
    : 'encryption-setup'
});
  } catch (error) {
    await recordFailure('assertion_verification_failed');
    console.error('Passkey login verification error:', error);

    return res.status(401).json({
      error: 'Passkey authentication failed'
    });
  }
});


// ------------------------------------------------------------
// SESSION: restore authenticated account metadata after reload.
// The Master Key is never returned by this endpoint.
// GET /api/auth/passkey/session
// ------------------------------------------------------------
router.get('/session', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('email authMethod encryptionSalt wrappedMasterKey masterKeyIV encryptionReady deletionPending');

    if (!user || user.deletionPending || user.authMethod !== 'webauthn') {
      return res.status(401).json({ error: 'Session is not valid' });
    }

    const encryptionReady = Boolean(
      user.encryptionReady && user.encryptionSalt &&
      user.wrappedMasterKey && user.masterKeyIV
    );

    return res.json({
      email: user.email,
      encryptionReady,
      encryptionSalt: encryptionReady ? user.encryptionSalt : null,
      wrappedMasterKey: encryptionReady ? user.wrappedMasterKey : null,
      masterKeyIV: encryptionReady ? user.masterKeyIV : null
    });
  } catch (error) {
    console.error('Passkey session lookup failed:', error);
    return res.status(500).json({ error: 'Could not restore session' });
  }
});

// ------------------------------------------------------------
// LOGOUT: revoke this account's existing JWTs.
// POST /api/auth/passkey/logout
// ------------------------------------------------------------
router.post('/logout', auth, async (req, res) => {
  try {
    await User.updateOne(
      { _id: req.user.userId },
      { $inc: { sessionVersion: 1 } }
    );
    return res.json({ success: true });
  } catch (error) {
    console.error('Passkey logout failed:', error);
    return res.status(500).json({ error: 'Could not end session' });
  }
});

module.exports = router;
