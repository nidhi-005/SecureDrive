import {
  apiDelete,
  apiDownload,
  apiGetFileKeyRecovery,
  apiGetMeta,
  apiListFiles,
  apiRepairFileKey,
  apiUpload,
  base64ToUint8Array
} from '../api.js';

import {
  encryptFile,
  unwrapCEK,
  wrapCEK
} from '../crypto.js';

import { getMasterKey } from './keyStore.js';

// ── Toast ────────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');

  if (!t) return;

  t.textContent = msg;
  t.className = type;
  t.style.display = 'block';

  setTimeout(() => {
    t.style.display = 'none';
  }, 3000);
}

// ── Drag and Drop ────────────────────────────────────────
function handleDragOver(e) {
  e.preventDefault();

  document.getElementById('upload-zone')
    ?.classList.add('dragover');
}

function handleDragLeave() {
  document.getElementById('upload-zone')
    ?.classList.remove('dragover');
}

function handleDrop(e) {
  e.preventDefault();

  document.getElementById('upload-zone')
    ?.classList.remove('dragover');

  const file = e.dataTransfer.files[0];

  if (file) uploadFile(file);
}

function handleFileSelect(e) {
  const file = e.target.files[0];

  if (file) uploadFile(file);
}

// ── Upload ──────────────────────────────────────────────
async function uploadFile(file) {
  const masterKey = getMasterKey();

  if (!masterKey) return;

  const status = document.getElementById('upload-status');

  if (!status) return;

  status.style.display = 'block';

  try {
    status.textContent = `🔐 Encrypting ${file.name}...`;

    const buffer = await file.arrayBuffer();

    const {
      encryptedFile,
      wrappedCEK,
      fileIV,
      cekIV
    } = await encryptFile(buffer, masterKey);

    status.textContent = '☁️ Uploading encrypted file...';

    await apiUpload(
      encryptedFile,
      file.name,
      wrappedCEK,
      fileIV,
      cekIV
    );

    status.textContent = '✅ Upload complete!';

    setTimeout(() => {
      status.style.display = 'none';
    }, 2000);

    showToast('File encrypted and uploaded!');

    await loadFiles();

    document.getElementById('file-input').value = '';

  } catch (err) {
    status.textContent = '❌ ' + err.message;

    showToast('Upload failed', 'error');
  }
}

// ── Load Files ───────────────────────────────────────────
async function loadFiles() {
  const list = document.getElementById('files-list');

  if (!list) return;

  try {
    const files = await apiListFiles();

    if (files.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🔒</div>
          No encrypted files yet.<br>
          Upload your first file above.
        </div>`;

      return;
    }

    list.innerHTML = files.map(f => `
      <div class="file-card" id="card-${f._id}">
        <div class="file-left">
          <div class="file-icon">
            ${getFileIcon(f.originalName)}
          </div>

          <div>
            <div class="file-name">
              ${escapeHtml(f.originalName)}
            </div>

            <div class="file-meta">
              ${formatSize(f.size)} &nbsp;·&nbsp;
              ${formatDate(f.uploadedAt)}
            </div>
          </div>
        </div>

        <div class="file-actions">
          <button
            class="btn-download"
            data-file-id="${escapeHtml(String(f._id))}"
            data-file-name="${escapeHtml(f.originalName)}">
            ↓ Download
          </button>

          <button
            class="btn-delete"
            data-file-id="${escapeHtml(String(f._id))}">
            Delete
          </button>
        </div>
      </div>
    `).join('');

    attachFileListeners();

  } catch (err) {
    list.innerHTML = `
      <div style="color:#f87171;font-size:13px;padding:20px 0">
        Failed to load files: ${escapeHtml(err.message)}
      </div>`;
  }
}

// ── Download ────────────────────────────────────────────
async function downloadFile(fileId, fileName) {
  const masterKey = getMasterKey();

  if (!masterKey) return;

  showToast('Decrypting...');

  try {
    const meta = await apiGetMeta(fileId);

    const downloadResult = await apiDownload(fileId);

    const encryptedBuffer = downloadResult.buffer;
    const integrityStatus = downloadResult.integrityStatus;

    let cek;
    let recovered = false;

    // First try the current CEK from MongoDB.
    try {
      cek = await unwrapCEK(
        meta.wrappedCEK,
        meta.cekIV,
        masterKey
      );

    } catch (primaryError) {
      console.warn(
        'Primary CEK unwrap failed. Attempting recovery...',
        primaryError
      );

      const recoveryData =
        await apiGetFileKeyRecovery(fileId);

      if (
        !recoveryData.records ||
        recoveryData.records.length === 0
      ) {
        throw new Error(
          'File key recovery data unavailable'
        );
      }

      // Try newest to oldest.
      for (const record of recoveryData.records) {
        try {
          cek = await unwrapCEK(
            record.wrappedKey,
            record.iv,
            masterKey
          );

          recovered = true;
          break;

        } catch (recoveryError) {
          console.warn(
            `File CEK recovery version ${record.version} failed`
          );
        }
      }

      if (!cek) {
        throw new Error(
          'Could not recover file encryption key'
        );
      }
    }

    // Decrypt file.
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToUint8Array(meta.fileIV)
      },
      cek,
      encryptedBuffer
    );

    // Repair MongoDB if recovery was required.
    if (recovered) {
      try {
        const repaired = await wrapCEK(
          cek,
          masterKey
        );

        await apiRepairFileKey(
          fileId,
          repaired.wrappedCEK,
          repaired.cekIV
        );

        console.log(
          'File CEK successfully recovered and repaired.'
        );

      } catch (repairError) {
        console.error(
          'File CEK recovered, but primary repair failed:',
          repairError
        );
      }
    }

    // Download decrypted file.
    const blob = new Blob([decryptedBuffer]);

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;
    a.download = fileName;

    a.click();

    URL.revokeObjectURL(url);

    showToast(
      recovered
        ? 'File recovered and downloaded!'
        : 'File decrypted and downloaded!'
    );

  } catch (err) {
    console.error(err);

    showToast(
      'Download failed: ' + err.message,
      'error'
    );
  }
}

// ── Delete File ─────────────────────────────────────────
async function deleteFile(fileId) {
  if (!confirm('Delete this file? This cannot be undone.')) {
    return;
  }

  try {
    await apiDelete(fileId);

    showToast('File deleted');

    await loadFiles();

  } catch (err) {
    showToast('Delete failed', 'error');
  }
}

// ── Helpers ──────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();

  const map = {
    pdf: '📄',
    jpg: '🖼️',
    jpeg: '🖼️',
    png: '🖼️',
    gif: '🖼️',
    mp4: '🎬',
    mp3: '🎵',
    zip: '📦',
    rar: '📦',
    doc: '📝',
    docx: '📝',
    txt: '📃',
    xls: '📊',
    xlsx: '📊'
  };

  return map[ext] || '📁';
}

function formatSize(bytes) {
  if (!bytes) return '—';

  if (bytes < 1024) {
    return bytes + ' B';
  }

  if (bytes < 1024 * 1024) {
    return (bytes / 1024).toFixed(1) + ' KB';
  }

  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-IN', {
    day: 'numeric',
    month: 'short',
    year: 'numeric'
  });
}

// ── File Event Listeners ─────────────────────────────────
function attachFileListeners() {
  document.querySelectorAll('.btn-download').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const fileId = e.currentTarget.dataset.fileId;
      const fileName = e.currentTarget.dataset.fileName;

      downloadFile(fileId, fileName);
    });
  });

  document.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const fileId = e.currentTarget.dataset.fileId;

      deleteFile(fileId);
    });
  });
}

// ── Initialize File Dashboard ───────────────────────────
export function initFileDashboard() {
  const uploadZone = document.getElementById('upload-zone');

  const fileInput = document.getElementById('file-input');

  if (uploadZone) {
    uploadZone.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      fileInput?.click();
    });

    uploadZone.addEventListener('dragover', handleDragOver);
    uploadZone.addEventListener('dragleave', handleDragLeave);
    uploadZone.addEventListener('drop', handleDrop);
  }

  if (fileInput) {
    fileInput.addEventListener('change', handleFileSelect);
  }

  return loadFiles();
}

export { loadFiles };

