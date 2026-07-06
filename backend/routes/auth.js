const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const User    = require('../models/User');

// SIGNUP
const bcrypt = require('bcryptjs');

// SIGNUP
router.post('/signup', async (req, res) => {
  try {
    const { email, password, wrappedMasterKey, masterKeyIV } = req.body;

    if (!email || !password || !wrappedMasterKey || !masterKeyIV) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash the password — bcrypt is one-way, server cannot reverse it
    const passwordHash = await bcrypt.hash(password, 12);

    const user = new User({ email, passwordHash, wrappedMasterKey, masterKeyIV });
    await user.save();

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

// LOGIN — now verifies password
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare submitted password against stored hash
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      email:            user.email,
      wrappedMasterKey: user.wrappedMasterKey,
      masterKeyIV:      user.masterKeyIV
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

module.exports = router;