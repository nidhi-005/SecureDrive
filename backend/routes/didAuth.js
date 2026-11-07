const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const router = express.Router();

const User = require('../models/User');
const AuthChallenge = require('../models/AuthChallenge');
const { isValidDidKey, verifyDidSignature } = require('../services/didService');
const auth = require('../middleware/auth');
const recoveryStore = require('../recovery/s3RecoveryStore');

const CHALLENGE_TTL_MS = 5 *  60 * 1000;

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function issueToken(user) {
  return jwt.sign(
    { userId: String(user._id), email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Creates a short-lived, one-use challenge. The client signs the exact
// challenge object returned here using its local Ed25519 private key.
router.post('/challenge', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { did, purpose } = req.body;

    if (!email || !did || !['register', 'login'].includes(purpose)) {
      return res.status(400).json({ error: 'Email, DID and valid purpose are required' });
    }
    if (!isValidDidKey(did)) {
      return res.status(400).json({ error: 'Unsupported or invalid DID' });
    }

    const existingByEmail = await User.findOne({ email });
    const existingByDid = await User.findOne({ did });

    if (purpose === 'register') {
      if (existingByEmail || existingByDid) {
        return res.status(409).json({ error: 'Email or DID is already registered' });
      }
    } else {
      if (
        !existingByEmail ||
        existingByEmail.deletionPending ||
        existingByEmail.did !== did
      ) {
        // Avoid revealing whether an email or DID is registered.
        return res.status(401).json({ error: 'Invalid identity or credentials' });
      }
    }

    const now = new Date();
    const challengeId = crypto.randomBytes(32).toString('base64url');
    const challenge = {
      domain: req.get('host'),
      did,
      nonce: crypto.randomBytes(32).toString('base64url'),
      purpose,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS).toISOString(),
      challengeId
    };

    await AuthChallenge.create({
      challengeId,
      email,
      did,
      purpose,
      challenge,
      expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS)
    });

    return res.json({ challengeId, challenge });
  } catch (err) {
    console.error('DID challenge creation failed:', err.message);
    return res.status(500).json({ error: 'Could not create authentication challenge' });
  }
});

// Completes DID registration. This creates an identity-only account for now;
// encryption setup is a separate next stage and is explicitly flagged.
router.post('/register', async (req, res) => {
  let challengeRecord;
  try {
    const email = normalizeEmail(req.body.email);
    const { did, challengeId, signature } = req.body;

    if (!email || !did || !challengeId || !signature) {
      return res.status(400).json({ error: 'Email, DID, challengeId and signature are required' });
    }

    // Atomic consume prevents concurrent replay of the same challenge.
    challengeRecord = await AuthChallenge.findOneAndDelete({
      challengeId,
      email,
      did,
      purpose: 'register',
      expiresAt: { $gt: new Date() }
    });

    if (!challengeRecord) {
      return res.status(401).json({ error: 'Challenge is invalid, expired or already used' });
    }

    if (!verifyDidSignature({ did, challenge: challengeRecord.challenge, signature })) {
      return res.status(401).json({ error: 'DID signature verification failed' });
    }

    const existing = await User.findOne({ $or: [{ email }, { did }] });
    if (existing) {
      return res.status(409).json({ error: 'Email or DID is already registered' });
    }

    const user = await User.create({
      email,
      did,
      didMethod: 'did:key',
      authMethod: 'did',
      encryptionReady: false
    });

    const token = issueToken(user);
    return res.status(201).json({
      token,
      email: user.email,
      did: user.did,
      encryptionReady: false,
      nextStep: 'encryption-setup'
    });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ error: 'Email or DID is already registered' });
    }
    console.error('DID registration failed:', err.message);
    return res.status(500).json({ error: 'DID registration failed' });
  }
});

// Completes DID login and issues the same JWT shape used by existing middleware.
router.post('/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { did, challengeId, signature } = req.body;

    if (!email || !did || !challengeId || !signature) {
      return res.status(400).json({ error: 'Email, DID, challengeId and signature are required' });
    }

    const challengeRecord = await AuthChallenge.findOneAndDelete({
      challengeId,
      email,
      did,
      purpose: 'login',
      expiresAt: { $gt: new Date() }
    });

    if (!challengeRecord) {
      return res.status(401).json({ error: 'Challenge is invalid, expired or already used' });
    }

    if (!verifyDidSignature({ did, challenge: challengeRecord.challenge, signature })) {
      return res.status(401).json({ error: 'DID signature verification failed' });
    }

    const user = await User.findOne({ email, did });
    if (!user || user.deletionPending) {
      return res.status(401).json({ error: 'Invalid identity or credentials' });
    }

    const encryptionReady = Boolean(user.wrappedMasterKey && user.masterKeyIV && user.encryptionSalt);
    return res.json({
      token: issueToken(user),
      email: user.email,
      did: user.did,
      encryptionReady,
      encryptionSalt: encryptionReady ? user.encryptionSalt : undefined,
      wrappedMasterKey: encryptionReady ? user.wrappedMasterKey : undefined,
      masterKeyIV: encryptionReady ? user.masterKeyIV : undefined,
      nextStep: encryptionReady ? 'dashboard' : 'encryption-setup'
    });
  } catch (err) {
    console.error('DID login failed:', err.message);
    return res.status(500).json({ error: 'DID login failed' });
  }
});

router.get('/status', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('did authMethod wrappedMasterKey masterKeyIV encryptionSalt');
    if (!user || user.authMethod !== 'did' || !user.did) {
      return res.status(404).json({ error: 'DID account not found' });
    }
    const encryptionReady = Boolean(user.wrappedMasterKey && user.masterKeyIV && user.encryptionSalt);
    return res.json({ did: user.did, encryptionReady, nextStep: encryptionReady ? 'dashboard' : 'encryption-setup' });
  } catch (err) {
    console.error('DID status lookup failed:', err.message);
    return res.status(500).json({ error: 'Could not check account setup status' });
  }
});

// First-time setup of the independent file-encryption credential. The password
// itself never reaches the server; only a random salt and AES-GCM wrapped key do.
router.post('/encryption-setup', auth, async (req, res) => {
  try {
    const { encryptionSalt, wrappedMasterKey, masterKeyIV } = req.body;
    const isCanonicalBase64 = value => typeof value === 'string' &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
    if (![encryptionSalt, wrappedMasterKey, masterKeyIV].every(isCanonicalBase64)) {
      return res.status(400).json({ error: 'Encryption metadata must be valid Base64' });
    }
    if (
      Buffer.from(encryptionSalt, 'base64').length !== 16 ||
      Buffer.from(masterKeyIV, 'base64').length !== 12 ||
      Buffer.from(wrappedMasterKey, 'base64').length !== 48
    ) {
      return res.status(400).json({ error: 'Invalid encryption metadata lengths' });
    }

    // Atomic first-write prevents two setup requests from racing and replacing
    // the initial wrapped Master Key.
    const user = await User.findOneAndUpdate({
      _id: req.user.userId,
      authMethod: { $in: ['did', 'webauthn'] },
      deletionPending: { $ne: true },
      $and: [
        { $or: [{ wrappedMasterKey: { $exists: false } }, { wrappedMasterKey: null }] },
        { $or: [{ masterKeyIV: { $exists: false } }, { masterKeyIV: null }] },
        { $or: [{ encryptionSalt: { $exists: false } }, { encryptionSalt: null }] }
      ]
    }, {
      $set: { encryptionSalt, wrappedMasterKey, masterKeyIV, encryptionReady: true, wrappedMasterKeyVersion: 1 }
    }, { new: true, runValidators: true });

    if (!user) {
      const existing = await User.findById(req.user.userId).select('did authMethod wrappedMasterKey masterKeyIV encryptionSalt deletionPending');
      if (
        !existing ||
        !['did', 'webauthn'].includes(existing.authMethod)
      ) {
        return res.status(403).json({
          error: 'Authenticated account required'
        });
      }
      if (existing.deletionPending) return res.status(403).json({ error: 'Account deletion is in progress' });
      if (
        existing.encryptionSalt === encryptionSalt &&
        existing.wrappedMasterKey === wrappedMasterKey &&
        existing.masterKeyIV === masterKeyIV
      ) {
        return res.json({ success: true, encryptionReady: true, idempotent: true });
      }
      return res.status(409).json({ error: 'Encryption has already been configured for this account' });
    }

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
      // The primary wrapped key is already saved. Recovery-ledger failure must
      // not lock the user out of their newly configured account.
      console.error('Initial Master Key recovery record could not be written:', recoveryError.message);
    }

    return res.status(201).json({ success: true, encryptionReady: true });
  } catch (err) {
    console.error('DID encryption setup failed:', err.message);
    return res.status(500).json({ error: 'Could not configure file encryption' });
  }
});

module.exports = router;
