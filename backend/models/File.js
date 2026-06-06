const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  originalName: { type: String, required: true },
  storagePath:  { type: String, required: true },
  wrappedCEK:   { type: String, required: true },
  fileIV:       { type: String, required: true },
  cekIV:        { type: String, required: true },
  size:         { type: Number },
  uploadedAt:   { type: Date, default: Date.now }
});

module.exports = mongoose.model('File', fileSchema);
