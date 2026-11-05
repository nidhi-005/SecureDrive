const mongoose = require('mongoose');

const passkeyChallengeSchema = new mongoose.Schema({
  challengeId: {
    type: String,
    required: true,
    unique: true
  },

  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },

  purpose: {
    type: String,
    enum: ['register', 'login'],
    required: true
  },

  challenge: {
    type: String,
    required: true
  },

  webauthnUserID: {
    type: String,
    default: null
  },

  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
  }
}, {
  timestamps: true
});

module.exports = mongoose.model(
  'PasskeyChallenge',
  passkeyChallengeSchema
);