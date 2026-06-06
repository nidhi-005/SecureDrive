const express = require('express');
const router  = express.Router();
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const File    = require('../models/File');

// Configure multer — where to store uploaded (encrypted) files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '../uploads'));
  },
  filename: (req, file, cb) => {
    // Random filename — original name stored in DB, not exposed here
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max — DoS protection
});

// ─── UPLOAD ──────────────────────────────────────────
router.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const { originalName, wrappedCEK, fileIV, cekIV } = req.body;
    console.log(req.file);
    console.log(req.body);
    if (!req.file) {
      return res.status(400).json({ error: 'No file received' });
    }

    const newFile = new File({
      owner:        req.user.userId,  // from JWT middleware — links file to user
      originalName,
      storagePath:  req.file.filename,
      wrappedCEK,
      fileIV,
      cekIV,
      size:         req.file.size
    });

    await newFile.save();
    res.status(201).json({ message: 'File uploaded', fileId: newFile._id });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ─── LIST FILES ───────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    // Only returns files owned by the logged-in user
    const files = await File.find({ owner: req.user.userId })
      .select('-storagePath') // don't expose internal storage paths
      .sort({ uploadedAt: -1 });

    res.json(files);
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch files' });
  }
});

// ─── GET FILE METADATA (for decryption) ──────────────
router.get('/:fileId/meta', async (req, res) => {
  try {
    const file = await File.findOne({
      _id:   req.params.fileId,
      owner: req.user.userId  // ownership check — can't fetch someone else's metadata
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.json({
      originalName: file.originalName,
      wrappedCEK:   file.wrappedCEK,
      fileIV:       file.fileIV,
      cekIV:        file.cekIV
    });
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch metadata' });
  }
});

// ─── DOWNLOAD (encrypted file bytes) ─────────────────
router.get('/:fileId/download', async (req, res) => {
  try {
    const file = await File.findOne({
      _id:   req.params.fileId,
      owner: req.user.userId  // ownership check
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    const filePath = path.join(__dirname, '../uploads', file.storagePath);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File data missing' });
    }

    res.download(filePath, file.originalName);
  } catch (err) {
    res.status(500).json({ error: 'Download failed' });
  }
});

// ─── DELETE ───────────────────────────────────────────
router.delete('/:fileId', async (req, res) => {
  try {
    const file = await File.findOne({
      _id:   req.params.fileId,
      owner: req.user.userId  // ownership check
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Delete from disk
    const filePath = path.join(__dirname, '../uploads', file.storagePath);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from DB
    await File.findByIdAndDelete(req.params.fileId);
    res.json({ message: 'File deleted' });

  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

module.exports = router;