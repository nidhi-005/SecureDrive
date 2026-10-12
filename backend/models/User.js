const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  opaqueRegistrationRecord: { type: String, required: true },
  encryptionSalt: { type: String, required: true },
  wrappedMasterKey: { type: String, required: true },
  masterKeyIV: { type: String, required: true },

  // Version of the currently active wrapped Master Key.
  wrappedMasterKeyVersion: {
    type: Number,
    default: 1
  },

  deletionPending: {
    type: Boolean,
    default: false,
    index: true
  },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
