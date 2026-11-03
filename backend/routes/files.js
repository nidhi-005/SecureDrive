const express = require('express');
const router = express.Router();
const multer = require('multer');
const { Readable } = require('stream');
const File = require('../models/File');
const { uploadToS3, downloadFromS3, deleteFromS3 } = require('../config/s3');
const recoveryStore = require('../recovery/s3RecoveryStore');

const {
  generateBlockchainFileId,
  calculateCiphertextHash,
  createIntegrityCommitment,
  RECORD_TYPE
} = require('../services/integrityService');

const {
  anchorIntegrity
} = require('../services/blockchainService');

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
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// ─── UPLOAD ──────────────────────────────────────────
router.post('/upload', upload.single('file'), async (req, res) => {
  let uploadedS3Key = null;
  let savedFile = null;

  try {
    console.log('File received:', req.file?.originalname, req.file?.size);

    const { originalName, wrappedCEK, fileIV, cekIV } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No file received' });
    }

    if (!wrappedCEK || !fileIV || !cekIV) {
      return res.status(400).json({
        error: 'Missing encryption metadata'
      });
    }

    // Sanitize filename.
    const safeName = sanitizeFilename(originalName || req.file.originalname);

    // Generate a random opaque identifier for the blockchain.
    const blockchainFileId = generateBlockchainFileId();

    // Initial integrity version.
    const integrityVersion = 1;

    // Upload actual encrypted bytes to S3.
    const s3Key = `${req.user.userId}/${Date.now()}-${Math.round(Math.random() * 1e9)}`;

    await uploadToS3(req.file.buffer, s3Key);
    uploadedS3Key = s3Key;

    // Create MongoDB record in PENDING state.
    const newFile = new File({
      owner: req.user.userId,
      originalName: safeName,
      storagePath: s3Key,

      wrappedCEK,
      fileIV,
      cekIV,

      wrappedCEKVersion: 1,

      blockchainFileId,
      integrityVersion,
      integrityStatus: 'PENDING',

      size: req.file.size
    });

    await newFile.save();
    savedFile = newFile;

    await recoveryStore.append({
      recordType: 'FILE_CEK',
      userId: String(req.user.userId),
      fileId: String(newFile._id),
      version: 1,
      wrappedKey: wrappedCEK,
      iv: cekIV,
      createdAt: new Date().toISOString()
    });

    // Hash the actual encrypted bytes.
    const ciphertextHash = calculateCiphertextHash(
      req.file.buffer
    );

    // Generate canonical integrity commitment.
    const commitment = createIntegrityCommitment({
      blockchainFileId,
      integrityVersion,
      ciphertextHash,
      wrappedCEK,
      fileIV,
      cekIV,
      wrappedCEKVersion: 1
    });

    // Persist commitment BEFORE submitting blockchain transaction.
    newFile.integrityCommitment = commitment;
    await newFile.save();


    // Submit blockchain transaction (best-effort).
    let anchorResult = null;

    try {
      anchorResult = await anchorIntegrity({
        fileId: blockchainFileId,
        version: integrityVersion,
        commitment,
        recordType: RECORD_TYPE.FILE
      });

      // Mark ANCHORED only after successful confirmation.
      newFile.integrityStatus = 'ANCHORED';
      newFile.blockchainTxHash = anchorResult.transactionHash;
      newFile.blockchainAnchoredAt = new Date();

      await newFile.save();

      console.log('File successfully uploaded and anchored.');

    } catch (blockchainError) {
      // File is already safely stored in S3 and MongoDB.
      // Keep integrity status as PENDING.
      console.error(
        'Blockchain anchoring unavailable. File remains pending:',
        blockchainError.message
      );

      newFile.integrityStatus = 'PENDING';
      await newFile.save();
    }

    // Return successful upload response because file storage succeeded.
    return res.status(201).json({
      message: anchorResult
        ? 'File uploaded and integrity anchored'
        : 'File uploaded. Blockchain integrity anchoring is pending',

      fileId: newFile._id,

      integrity: {
        status: newFile.integrityStatus,
        version: newFile.integrityVersion,
        transactionHash: newFile.blockchainTxHash || null
      }
    });

  } catch (err) {
    console.error('Blockchain-integrated upload failed:', err);

    // Do not delete a saved file automatically.
    // It may already have an on-chain transaction pending or confirmed.
    if (savedFile) {
      return res.status(503).json({
        error: 'File saved but blockchain anchoring is not confirmed',
        fileId: savedFile._id,
        integrityStatus: savedFile.integrityStatus || 'PENDING',
        message: 'Do not assume this file is integrity-verified. Reconciliation is required.'
      });
    }

    // If MongoDB creation never succeeded, remove the uploaded S3 object
    // to avoid leaving an orphaned object.
    if (uploadedS3Key) {
      try {
        await deleteFromS3(uploadedS3Key);
      } catch (cleanupError) {
        console.error(
          'Failed to clean up orphaned S3 upload:',
          cleanupError
        );
      }
    }

    return res.status(500).json({
      error: 'Upload failed'
    });
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
      _id: req.params.fileId,
      owner: req.user.userId
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.json({
      originalName: file.originalName,
      wrappedCEK: file.wrappedCEK,
      fileIV: file.fileIV,
      cekIV: file.cekIV
    });
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch metadata' });
  }
});

// ─── DOWNLOAD ────────────────────────────────────────
router.get('/:fileId/download', async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.fileId,
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
      _id: req.params.fileId,
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