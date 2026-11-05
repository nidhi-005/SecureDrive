const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded.userId || !mongoose.isValidObjectId(decoded.userId)) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const user = await User.findById(decoded.userId)
      .select('_id email deletionPending accountRef role');

    if (!user) {
      return res.status(401).json({
        error: 'Account no longer exists'
      });
    }

    // Allow only deletion management while deletion is pending.
    const allowedDuringDeletion =
      (req.method === 'DELETE' && req.path === '/account') ||
      (req.method === 'POST' &&
        req.path === '/account/deletion-cancel') ||
      (req.method === 'GET' &&
        req.path === '/account/deletion-status');

    if (user.deletionPending && !allowedDuringDeletion) {
      return res.status(403).json({
        error: 'Account deletion is in progress',
        deletionPending: true
      });
    }

    req.user = {
      userId: String(user._id),
      email: user.email,
      accountRef: user.accountRef,
      deletionPending: user.deletionPending,
      role: user.role
    };

    next();

  } catch (err) {
    if (err.name === 'JsonWebTokenError' ||
      err.name === 'TokenExpiredError' ||
      err.name === 'CastError') {
      return res.status(401).json({
        error: 'Invalid or expired token'
      });
    }

    console.error('Authentication error:', err);

    return res.status(500).json({
      error: 'Authentication could not be completed'
    });
  }
};