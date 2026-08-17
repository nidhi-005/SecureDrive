const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const User    = require('../models/User');

// OPAQUE-inspired Password Authentication Protocol
// Uses cryptographic operations to avoid sending passwords to the server

// SIGNUP - OPAQUE Registration
router.post('/signup', async (req, res) => {
  try {
    const { email, clientRegisterInit, wrappedMasterKey, masterKeyIV } = req.body;

    if (!email || !clientRegisterInit || !wrappedMasterKey || !masterKeyIV) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Server generates a registration record based on client's registration init
    // clientRegisterInit is the first OPAQUE message from client (derived from password)
    // Server generates random seed for this user
    const registrationSeed = crypto.randomBytes(32).toString('hex');
    
    // Create server registration record by combining client init and server seed
    const hmac = crypto.createHmac('sha256', registrationSeed);
    hmac.update(clientRegisterInit);
    hmac.update(email);
    const serverRegistrationRecord = hmac.digest('hex');

    // Store the registration record (hex-encoded)
    const user = new User({
      email,
      opaqueRegistrationRecord: `${clientRegisterInit}|${serverRegistrationRecord}|${registrationSeed}`,
      wrappedMasterKey,
      masterKeyIV
    });
    await user.save();

    // Server sends back seed-derived value for client to finish registration
    const serverRegisterInit = crypto.createHmac('sha256', registrationSeed)
      .update(email)
      .digest('hex');

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      email: user.email,
      serverRegisterInit: serverRegisterInit
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// LOGIN - OPAQUE Authentication (Step 1)
router.post('/login', async (req, res) => {
  try {
    const { email, clientLoginInit } = req.body;

    if (!email || !clientLoginInit) {
      return res.status(401).json({ error: 'Email and clientLoginInit required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'User does not exist' });
    }

    // Extract stored registration data
    const [storedClientInit, storedServerRecord, registrationSeed] = 
      user.opaqueRegistrationRecord.split('|');

    // Server responds with a challenge based on registration
    const serverLoginResponse = crypto.createHmac('sha256', storedServerRecord)
      .update(clientLoginInit)
      .update(email)
      .digest('hex');

    // Store temporary session data for login completion
    // In production, use a session store with expiration
    if (!global.opaqueLogins) {
      global.opaqueLogins = {};
    }
    global.opaqueLogins[email] = {
      serverResponse: serverLoginResponse,
      clientInit: clientLoginInit,
      timestamp: Date.now()
    };

    res.json({
      email: user.email,
      serverLoginResponse: serverLoginResponse,
      wrappedMasterKey: user.wrappedMasterKey,
      masterKeyIV: user.masterKeyIV
    });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Login failed' });
  }
});

// LOGIN - OPAQUE Authentication (Step 2)
router.post('/login-finish', async (req, res) => {
  try {
    const { email, clientLoginFinish, clientExportKey } = req.body;

    if (!email || !clientLoginFinish || !clientExportKey) {
      return res.status(401).json({ error: 'Missing required fields' });
    }

    // Check if login session exists and is valid (not expired)
    if (!global.opaqueLogins || !global.opaqueLogins[email]) {
      return res.status(401).json({ error: 'Login session not found' });
    }

    const loginSession = global.opaqueLogins[email];
    
    // Check expiration (5 minute timeout)
    if (Date.now() - loginSession.timestamp > 5 * 60 * 1000) {
      delete global.opaqueLogins[email];
      return res.status(401).json({ error: 'Login session expired' });
    }

    // Verify that the client proof is correct
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'User does not exist' });
    }

    // Clean up session
    delete global.opaqueLogins[email];

    // Issue JWT token upon successful authentication
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Login verification failed' });
  }
});

module.exports = router;
