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

    const user = await User.findById(decoded.userId).select('_id email');

    if (!user) {
      return res.status(401).json({
        error: 'Account no longer exists'
      });
    }

    req.user = {
      userId: String(user._id),
      email: user.email
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