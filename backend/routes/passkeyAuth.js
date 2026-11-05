const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const User = require('../models/User');
const Passkey = require('../models/Passkey');
const PasskeyChallenge = require('../models/PasskeyChallenge');

const router = express.Router();

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

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

function issueToken(user) {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }

  return jwt.sign(
    {
      userId: String(user._id),
      email: user.email
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function challengeExpiry() {
  return new Date(Date.now() + CHALLENGE_TTL_MS);
}

// ------------------------------------------------------------
// REGISTRATION: generate passkey creation options
// POST /api/auth/passkey/register/options
// ------------------------------------------------------------

router.post('/register/options', async (req, res) => {
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
        error: 'An account with this email already exists'
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

router.post('/register/verify', async (req, res) => {
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
        error: 'An account with this email already exists'
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
        transports: credential.transports || [],
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
        error: 'This account or passkey is already registered'
      });
    }

    return res.status(400).json({
      error: 'Passkey registration could not be verified'
    });
  }
});

// ------------------------------------------------------------
// LOGIN: generate authentication options
// POST /api/auth/passkey/login/options
// ------------------------------------------------------------

router.post('/login/options', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);

    if (!validEmail(email)) {
      return res.status(400).json({
        error: 'A valid email address is required'
      });
    }

    const user = await User.findOne({ email });

    if (!user || user.deletionPending) {
      return res.status(401).json({
        error: 'Invalid account or passkey'
      });
    }

    const passkeys = await Passkey.find({
      user: user._id
    });

    if (!passkeys.length) {
      return res.status(401).json({
        error: 'No passkey is registered for this account'
      });
    }

    const { generateAuthenticationOptions } = await getWebAuthn();
    const { rpID } = getWebAuthnConfig();

    const options = await generateAuthenticationOptions({
      rpID,

      allowCredentials: passkeys.map(passkey => ({
        id: passkey.credentialId,
        transports: passkey.transports
      })),

      userVerification: 'required',
      timeout: 60000
    });

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

router.post('/login/verify', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const response = req.body.response;
    const { challengeId } = req.body;

    if (!validEmail(email) || !response?.id || !challengeId) {
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
      return res.status(401).json({
        error: 'Authentication challenge expired or already used'
      });
    }

    const user = await User.findOne({ email });

    if (!user || user.deletionPending) {
      return res.status(401).json({
        error: 'Invalid account or passkey'
      });
    }

    const passkey = await Passkey.findOne({
      user: user._id,
      credentialId: response.id
    });

    if (!passkey) {
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
      return res.status(401).json({
        error: 'Passkey authentication failed'
      });
    }

    passkey.counter = verification.authenticationInfo.newCounter;
    passkey.lastUsedAt = new Date();

    await passkey.save();

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
    console.error('Passkey login verification error:', error);

    return res.status(401).json({
      error: 'Passkey authentication failed'
    });
  }
});

module.exports = router;