import {
  apiDelete,
  apiDeleteAccount,
  apiDownload,
  apiGetFileKeyRecovery,
  apiGetMeta,
  apiListFiles,
  apiLogout,
  apiRepairFileKey,
  apiUpload,
  base64ToUint8Array
} from '../api.js';
import {
  encryptFile,
  unwrapCEK,
  wrapCEK
} from '../crypto.js';
import { clearSession, getMasterKey, getUserEmail, hydrateSession, isSessionActive } from './keyStore.js';

// ── Init ───────────────────────────────────────────────────
async function init() {
  const restored = await hydrateSession();

  if (!restored || !isSessionActive()) {
    window.location.replace('index.html');
    return;
  }

  // A page reload intentionally discards the in-memory Master Key.
  // Re-authenticate the session and ask for the separate encryption password.
  if (!getMasterKey()) {
    window.location.replace('index.html?restore=1');
    return;
  }

  document.getElementById('user-email').textContent = getUserEmail() || '';
  await loadFiles();
}

// ── Toast ──────────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = type;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

// ── Logout ─────────────────────────────────────────────────
async function handleLogout() {
  try { await apiLogout(); }
  catch (error) { console.warn('Server logout could not be confirmed:', error); }
  clearSession();
  window.location.replace('index.html');
}

// ── Delete Account ─────────────────────────────────────────────────
async function handleDeleteAccount() {
  const email = getUserEmail() || 'your account';

  const confirmed = confirm(
    `Permanently delete ${email}?\n\n` +
    'This will delete your account, encrypted files stored in S3, ' +
    'and file metadata. Immutable recovery records will be retained ' +
    'according to the recovery storage retention policy. ' +
    'This action cannot be undone.'
  );

  if (!confirmed) return;

  const deleteBtn = document.getElementById('delete-account-btn');

  if (deleteBtn) {
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting...';
  }

  try {
    await apiDeleteAccount();

    // Clear the master key, saved session key, email, and JWT.
    clearSession();

    alert(
      'Your account and active data have been deleted. ' +
      'Immutable recovery records are retained according to the retention policy.'
    );
    window.location.replace('index.html');
  } catch (err) {
    console.error('Account deletion failed:', err);

    alert(
      `Account deletion failed: ${err.message}\n\n` +
      'Check the server logs before attempting again.'
    );

    if (deleteBtn) {
      deleteBtn.disabled = false;
      deleteBtn.textContent = 'Delete Account';
    }
  }
}

// ── Drag and drop ──────────────────────────────────────────
function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.add('dragover');
}

function handleDragLeave() {
  document.getElementById('upload-zone').classList.remove('dragover');
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
}

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) uploadFile(file);
}

// ── UPLOAD ─────────────────────────────────────────────────

async function uploadFile(file) {
  const masterKey = getMasterKey();
  if (!masterKey) return;

  const status = document.getElementById('upload-status');
  status.style.display = 'block';

  let uploadSucceeded = false;

  try {
    status.textContent = `🔐 Encrypting ${file.name}...`;

    const buffer = await file.arrayBuffer();

    const { encryptedFile, wrappedCEK, fileIV, cekIV } =
      await encryptFile(buffer, masterKey);

    status.textContent = '☁️ Uploading encrypted file...';

    await apiUpload(
      encryptedFile,
      file.name,
      wrappedCEK,
      fileIV,
      cekIV
    );

    uploadSucceeded = true;

    status.textContent = '✅ Upload complete!';
    showToast('File encrypted and uploaded!');

  } catch (err) {
    console.error('Upload response:', err);

    status.textContent = '⚠️ ' + err.message;

    showToast(
      'Upload response: ' + err.message,
      'error'
    );

  } finally {
    // Always refresh the dashboard, even when the server
    // returns an error after successfully saving the file.
    try {
      await loadFiles();
    } catch (refreshError) {
      console.error('Dashboard refresh failed:', refreshError);
    }

    document.getElementById('file-input').value = '';

    setTimeout(() => {
      status.style.display = 'none';
    }, 3000);
  }
}

// ── LOAD FILES ─────────────────────────────────────────────
async function loadFiles() {
  const list = document.getElementById('files-list');
  try {
    const files = await apiListFiles();
    if (files.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🔒</div>
          No encrypted files yet.<br>Upload your first file above.
        </div>`;
      return;
    }
    list.innerHTML = files.map(f => `
      <div class="file-card" id="card-${f._id}">
        <div class="file-left">
          <div class="file-icon">${getFileIcon(f.originalName)}</div>
          <div>
            <div class="file-name">${escapeHtml(f.originalName)}</div>
            <div class="file-meta">
              ${formatSize(f.size)} &nbsp;·&nbsp; ${formatDate(f.uploadedAt)}
            </div>
          </div>
        </div>
        <div class="file-actions">
          <button class="btn-download" data-file-id="${f._id}" data-file-name="${escapeHtml(f.originalName)}">
            ↓ Download
          </button>
          <button class="btn-delete" data-file-id="${f._id}">
            Delete
          </button>
        </div>
      </div>
    `).join('');

    // Attach event listeners to dynamically created buttons
    attachFileListeners();
  } catch (err) {
    list.textContent = `Failed to load files: ${err.message}`;
  }
}

// ── DOWNLOAD ───────────────────────────────────────────────
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

    // ─────────────────────────────────────────────
    // First try the current CEK from MongoDB.
    // ─────────────────────────────────────────────
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
        throw new Error('File key recovery data unavailable');
      }

      // Try newest → oldest.
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
        throw new Error('Could not recover file encryption key');
      }
    }

    // ─────────────────────────────────────────────
    // Decrypt the file using the recovered/current CEK.
    // ─────────────────────────────────────────────
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToUint8Array(meta.fileIV)
      },
      cek,
      encryptedBuffer
    );

    // ─────────────────────────────────────────────
    // Repair MongoDB if recovery was required.
    // ─────────────────────────────────────────────
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
        // File was already successfully decrypted.
        console.error(
          'File CEK recovered, but primary repair failed:',
          repairError
        );
      }
    }

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

// ── DELETE ─────────────────────────────────────────────────
async function deleteFile(fileId) {
  if (!confirm('Delete this file? This cannot be undone.')) return;
  try {
    await apiDelete(fileId);
    showToast('File deleted');
    await loadFiles();
  } catch (err) {
    showToast('Delete failed', 'error');
  }
}

// ── Helpers ────────────────────────────────────────────────
// T1059 fix — escape HTML before rendering filenames
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = {
    pdf: '📄', jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️',
    mp4: '🎬', mp3: '🎵', zip: '📦', rar: '📦',
    doc: '📝', docx: '📝', txt: '📃', xls: '📊', xlsx: '📊'
  };
  return map[ext] || '📁';
}

function formatSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-IN', {
    day: 'numeric', month: 'short', year: 'numeric'
  });
}

// ── Attach Event Listeners to Dynamic File Buttons ────────
function attachFileListeners() {
  // Download buttons
  document.querySelectorAll('.btn-download').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const fileId = e.target.dataset.fileId;
      const fileName = e.target.dataset.fileName;
      downloadFile(fileId, fileName);
    });
  });

  // Delete buttons
  document.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const fileId = e.target.dataset.fileId;
      deleteFile(fileId);
    });
  });
}

// ── Dashboard Initialization ───────────────────────────────
function initDashboard() {
  // Logout button
  const logoutBtn = document.getElementById('logout-btn');
  const deleteAccountBtn = document.getElementById('delete-account-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleLogout);
  }
  if (deleteAccountBtn) {
    deleteAccountBtn.addEventListener('click', handleDeleteAccount);
  }

  // Upload zone
  const uploadZone = document.getElementById('upload-zone');
  const fileInput = document.getElementById('file-input');

  if (uploadZone) {
    // Click to select file
    uploadZone.addEventListener('click', () => {
      fileInput?.click();
    });

    // Drag and drop
    uploadZone.addEventListener('dragover', handleDragOver);
    uploadZone.addEventListener('dragleave', handleDragLeave);
    uploadZone.addEventListener('drop', handleDrop);
  }

  if (fileInput) {
    fileInput.addEventListener('change', handleFileSelect);
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
    init();
  });
} else {
  initDashboard();
  init();
}