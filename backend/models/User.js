const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  wrappedMasterKey: { type: String, required: true },
  masterKeyIV:      { type: String, required: true },
  createdAt:        { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
