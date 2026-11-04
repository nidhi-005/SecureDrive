// const mongoose = require('mongoose');

// const userSchema = new mongoose.Schema({
//   email: { type: String, required: true, unique: true, lowercase: true },
//   opaqueRegistrationRecord: { type: String, required: true },
//   encryptionSalt: { type: String, required: true },
//   wrappedMasterKey: { type: String, required: true },
//   masterKeyIV: { type: String, required: true },

//   // Version of the currently active wrapped Master Key.
//   wrappedMasterKeyVersion: {
//     type: Number,
//     default: 1
//   },

//   deletionPending: {
//     type: Boolean,
//     default: false,
//     index: true
//   },

//   createdAt: { type: Date, default: Date.now }
// });

// module.exports = mongoose.model('User', userSchema);
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },

  // DID authentication fields. A user may temporarily retain OPAQUE during migration.
  did: { type: String, unique: true, sparse: true },
  didMethod: { type: String, enum: ['did:key'], default: undefined },
  authMethod: { type: String, enum: ['opaque', 'did', 'hybrid'], default: 'opaque' },

  // Legacy OPAQUE authentication record remains optional for DID-only accounts.
  opaqueRegistrationRecord: { type: String, required: false },

  // Encryption fields remain optional until the separate encryption-setup stage.
  encryptionSalt: { type: String, required: false },
  wrappedMasterKey: { type: String, required: false },
  masterKeyIV: { type: String, required: false },

  encryptionReady: { type: Boolean, default: false },

  wrappedMasterKeyVersion: { type: Number, default: 1 },

  deletionPending: { type: Boolean, default: false, index: true },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
