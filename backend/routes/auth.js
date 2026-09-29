const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const opaque = require('@serenity-kit/opaque');
const User = require('../models/User');
const recoveryStore = require('../recovery/localRecoveryStore');
const auth = require('../middleware/auth');

if (!process.env.OPAQUE_SERVER_SETUP) {
  throw new Error('OPAQUE_SERVER_SETUP is required. Generate one with npx @serenity-kit/opaque create-server-setup and store it in your environment.');
}

const OPAQUE_SERVER_SETUP = process.env.OPAQUE_SERVER_SETUP;

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

    const { sessionKey } = opaque.server.finishLogin({
      finishLoginRequest,
      serverLoginState: loginSession.serverLoginState
    });

    delete global.opaqueLogins[email];

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

module.exports = router;