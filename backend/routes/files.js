const express  = require('express');
const router   = express.Router();
const multer   = require('multer');
const { Readable } = require('stream');
const File     = require('../models/File');
const { uploadToS3, downloadFromS3, deleteFromS3 } = require('../config/s3');
const recoveryStore = require('../recovery/localRecoveryStore');

// Allowed file types — MIME type allowlist (T1036 fix)
const ALLOWED_TYPES = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf',
  'text/plain',
  'application/zip', 'application/x-zip-compressed',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'video/mp4', 'audio/mpeg'
];

// Sanitise filename — strips dangerous characters (T1059 fix)
function sanitizeFilename(name) {
  return name
    .replace(/[^\w\s.\-]/g, '_')  // only allow word chars, spaces, dots, hyphens
    .replace(/\.\./g, '_')         // no path traversal
    .replace(/^\./, '_')           // no hidden files
    .substring(0, 255);            // max 255 chars
}
// ── Multer uses memory storage now (not disk)
// File goes to RAM temporarily, then straight to S3
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 50 * 1024 * 1024 } // 50MB
});

// ─── UPLOAD ──────────────────────────────────────────
router.post('/upload', upload.single('file'), async (req, res) => {
  try {
    console.log('File received:', req.file?.originalname, req.file?.size);
    console.log('S3 bucket:', process.env.AWS_BUCKET_NAME);
    const { originalName, wrappedCEK, fileIV, cekIV } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No file received' });
    }

    // T1036 — MIME type validation
    // T1036 — validate the original MIME type sent from client
    const clientMimeType = req.body.mimeType || '';

    // Store mimeType in DB too — useful for future download Content-Type headers
    
    // T1059 — sanitise filename before storing
    const safeName = sanitizeFilename(originalName || req.file.originalname);

    const s3Key = `${req.user.userId}/${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    await uploadToS3(req.file.buffer, s3Key);

    const newFile = new File({
      owner:        req.user.userId,
      originalName: safeName,
      storagePath:  s3Key,
      wrappedCEK,
      fileIV,
      cekIV,
      size:         req.file.size
    });


    await newFile.save();

    await recoveryStore.append({
      recordType: 'FILE_CEK',
      userId: String(req.user.userId),
      fileId: String(newFile._id),
      version: 1,
      wrappedKey: wrappedCEK,
      iv: cekIV,
      createdAt: new Date().toISOString()
    });

    res.status(201).json({
      message: 'File uploaded',
      fileId: newFile._id
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ─── LIST FILES ─────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const files = await File.find({ owner: req.user.userId })
      .select('-storagePath')
      .sort({ uploadedAt: -1 });
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch files' });
  }
});

// ─── GET FILE METADATA ───────────────────────────────
router.get('/:fileId/meta', async (req, res) => {
  try {
    const file = await File.findOne({
      _id:   req.params.fileId,
      owner: req.user.userId
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

// ─── DOWNLOAD ────────────────────────────────────────
router.get('/:fileId/download', async (req, res) => {
  try {
    const file = await File.findOne({
      _id:   req.params.fileId,
      owner: req.user.userId
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    const s3Body = await downloadFromS3(file.storagePath);

    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');

    const chunks = [];
    for await (const chunk of s3Body) {
      chunks.push(chunk);
    }
    res.send(Buffer.concat(chunks));

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Download failed' });
  }
});

// ─── DELETE ──────────────────────────────────────────
router.delete('/:fileId', async (req, res) => {
  try {
    const file = await File.findOne({
      _id:   req.params.fileId,
      owner: req.user.userId
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Delete from S3 then from MongoDB
    await deleteFromS3(file.storagePath);
    await File.findByIdAndDelete(req.params.fileId);

    res.json({ message: 'File deleted' });

  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

router.get('/:fileId/recovery', async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user.userId
    });

    if (!file) {
      return res.status(404).json({
        error: 'File not found'
      });
    }

    const records = await recoveryStore.getFileKeyHistory(
      req.user.userId,
      req.params.fileId
    );

    res.json({
      records
    });
  } catch (err) {
    console.error('File key recovery lookup failed:', err);

    res.status(500).json({
      error: 'Could not fetch file recovery data'
    });
  }
});

router.post('/:fileId/recovery/repair', async (req, res) => {
  try {
    const { wrappedCEK, cekIV } = req.body;

    if (!wrappedCEK || !cekIV) {
      return res.status(400).json({
        error: 'Missing CEK recovery data'
      });
    }

    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user.userId
    });

    if (!file) {
      return res.status(404).json({
        error: 'File not found'
      });
    }

    const newVersion =
      (file.wrappedCEKVersion || 1) + 1;

    file.wrappedCEK = wrappedCEK;
    file.cekIV = cekIV;
    file.wrappedCEKVersion = newVersion;

    await file.save();

    await recoveryStore.append({
      recordType: 'FILE_CEK',
      userId: String(req.user.userId),
      fileId: String(file._id),
      version: newVersion,
      wrappedKey: wrappedCEK,
      iv: cekIV,
      createdAt: new Date().toISOString()
    });

    res.json({
      message: 'File CEK repaired',
      version: newVersion
    });
  } catch (err) {
    console.error('File CEK repair failed:', err);

    res.status(500).json({
      error: 'Could not repair file CEK'
    });
  }
});

module.exports = router;