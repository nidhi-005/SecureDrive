const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const User    = require('../models/User');

// SIGNUP
router.post('/signup', async (req, res) => {
  try {
    console.log("BODY:", req.body);
    const { email, wrappedMasterKey, masterKeyIV } = req.body;
    console.log("EMAIL:", email);
    const existing = await User.findOne({ email });
    console.log("EXISTING:", existing);
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const user = new User({ email, wrappedMasterKey, masterKeyIV });
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ token, email: user.email });
  } catch (err) {
    console.error('Signup error:', err);
    if (err.name === 'ValidationError') {
      return res.status(400).json({
        error: 'Validation failed',
        details: Object.keys(err.errors).reduce((acc, key) => {
          acc[key] = err.errors[key].message;
          return acc;
        }, {})
      });
    }
    res.status(500).json({ error: 'Signup failed' });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  try {
    const { email } = req.body;
    console.log("BODY:", req.body);
    console.log("EMAIL:", email);
    const user = await User.findOne({ email });
    console.log("User:", user);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      email: user.email,
      wrappedMasterKey: user.wrappedMasterKey,
      masterKeyIV:      user.masterKeyIV
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

module.exports = router;