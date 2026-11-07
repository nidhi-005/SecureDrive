const mongoose = require('mongoose');

const authChallengeSchema = new mongoose.Schema({
  challengeId: { type: String, required: true, unique: true, index: true },
  email: { type: String, required: true, lowercase: true, trim: true },
  did: { type: String, required: true },
  purpose: { type: String, enum: ['register', 'login'], required: true },
  challenge: { type: mongoose.Schema.Types.Mixed, required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });

module.exports = mongoose.model('AuthChallenge', authChallengeSchema);
