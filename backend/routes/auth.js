const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const opaque = require('@serenity-kit/opaque');
const User = require('../models/User');
const recoveryStore = require('../recovery/s3RecoveryStore');
const auth = require('../middleware/auth');
const File = require('../models/File');
const { deleteAllUserFilesFromS3 } = require('../config/s3');

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

router.delete('/account', auth, async (req, res) => {
  const userId = String(req.user.userId);

  try {
    // 1. Mark the account as pending deletion.
    // This also makes retries safe if a previous attempt failed.
    const user = await User.findOneAndUpdate(
      { _id: userId },
      { $set: { deletionPending: true } },
      { new: true }
    ).select('_id email');

    if (!user) {
      return res.status(404).json({
        error: 'Account not found'
      });
    }

    // 2. Remove all encrypted file objects belonging to this user.
    // If this fails, stop and leave the account pending for retry.
    await deleteAllUserFilesFromS3(userId);

    // 3. Remove the user's file metadata from MongoDB.
    await File.deleteMany({ owner: userId });

    // 4. Remove the user record.
    const deletedUser = await User.findByIdAndDelete(userId);

    if (!deletedUser) {
      throw new Error('User record disappeared during deletion');
    }

    // 5. Clear any in-memory OPAQUE login challenge for this email.
    if (global.opaqueLogins) {
      delete global.opaqueLogins[deletedUser.email];
    }

    // IMPORTANT:
    // Do not delete, rewrite, or remove records from recoveryStore.
    // WORM-protected recovery history must remain untouched.

    return res.status(200).json({
      message: 'Account and associated active data deleted'
    });
  } catch (err) {
    // Avoid logging request data, tokens, or recovery records.
    console.error('Account deletion failed:', err.message);

    return res.status(500).json({
      error: 'Account deletion is incomplete. Retry the deletion or contact support.'
    });
  }
});

module.exports = router;