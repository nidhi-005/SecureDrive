const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  // OPAQUE registration data stored instead of bcrypt hash
  opaqueRegistrationRecord: {
    type: String,
    required: true  // Base64-encoded registration record
  },
  wrappedMasterKey: { type: String, required: true },
  masterKeyIV:      { type: String, required: true },
  createdAt:        { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
