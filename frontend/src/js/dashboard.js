import { encryptFile, decryptFile } from '../crypto.js';
import {
  apiLogout, apiUpload, apiListFiles,
  apiGetMeta, apiDownload, apiDelete
} from '../api.js';
import { getMasterKey, getUserEmail, clearSession, isSessionActive } from './keyStore.js';

// ── Restore Master Key from session ───────────────────────
let masterKey = null;

// async function restoreMasterKey() {
//   const stored = sessionStorage.getItem('masterKeyTemp');
//   if (!stored) {
//     // Not logged in — send back to login
//     window.location.href = 'index.html';
//     return;
//   }

//   const keyBytes = new Uint8Array(JSON.parse(stored));
//   masterKey = await crypto.subtle.importKey(
//     'raw', keyBytes,
//     { name: 'AES-GCM' },
//     true,
//     ['wrapKey', 'unwrapKey']
//   );
// }

// ── Init ───────────────────────────────────────────────────
async function init() {
  if (!isSessionActive()) {
    // Key not in memory — session expired or direct navigation
    // Send back to login
    window.location.href = 'index.html';
    return;
  }

  document.getElementById('user-email').textContent = getUserEmail() || '';
  await loadFiles();
}

// ── Toast ──────────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent  = msg;
  t.className    = type;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

// ── Logout ─────────────────────────────────────────────────
window.handleLogout = () => {
  clearSession();
  apiLogout();
};

// ── Drag and drop ──────────────────────────────────────────
window.handleDragOver = (e) => {
  e.preventDefault();
  document.getElementById('upload-zone').classList.add('dragover');
};

window.handleDragLeave = () => {
  document.getElementById('upload-zone').classList.remove('dragover');
};

window.handleDrop = (e) => {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
};

window.handleFileSelect = (e) => {
  const file = e.target.files[0];
  if (file) uploadFile(file);
};

// ── UPLOAD ─────────────────────────────────────────────────
async function uploadFile(file) {
  const masterKey = getMasterKey();
  if (!masterKey) return; // redirected to login by getMasterKey

  const status = document.getElementById('upload-status');
  status.style.display = 'block';

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
      cekIV,
      file.type || 'application/octet-stream'  // ← pass real MIME type
    );

    status.textContent = '✅ Upload complete!';
    setTimeout(() => status.style.display = 'none', 2000);

    showToast('File encrypted and uploaded!');
    await loadFiles();
    document.getElementById('file-input').value = '';
  } catch (err) {
    status.textContent = '❌ ' + err.message;
    showToast(err.message, 'error');
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
          <button class="btn-download"
            onclick="downloadFile('${f._id}', '${escapeHtml(f.originalName)}')">
            ↓ Download
          </button>
          <button class="btn-delete" onclick="deleteFile('${f._id}')">
            Delete
          </button>
        </div>
      </div>
    `).join('');

  } catch (err) {
    list.innerHTML = `<div style="color:#f87171;font-size:13px;padding:20px 0">
      Failed to load files: ${err.message}
    </div>`;
  }
}

// ── DOWNLOAD + DECRYPT ─────────────────────────────────────
window.downloadFile = async (fileId, fileName) => {
  const masterKey = getMasterKey();
  if (!masterKey) return;

  showToast('Decrypting...');
  try {
    const meta            = await apiGetMeta(fileId);
    const encryptedBuffer = await apiDownload(fileId);
    const decryptedBuffer = await decryptFile(
      encryptedBuffer,
      meta.wrappedCEK,
      meta.fileIV,
      meta.cekIV,
      masterKey
    );

    const blob = new Blob([decryptedBuffer]);
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);

    showToast('File decrypted and downloaded!');
  } catch (err) {
    showToast('Download failed: ' + err.message, 'error');
  }
};

// ── DELETE ─────────────────────────────────────────────────
window.deleteFile = async (fileId) => {
  if (!confirm('Delete this file? This cannot be undone.')) return;
  try {
    await apiDelete(fileId);
    showToast('File deleted');
    await loadFiles();
  } catch (err) {
    showToast('Delete failed', 'error');
  }
};

// ── Helpers ────────────────────────────────────────────────
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
    pdf:'📄', jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🖼️',
    mp4:'🎬', mp3:'🎵', zip:'📦', rar:'📦',
    doc:'📝', docx:'📝', txt:'📃', xls:'📊', xlsx:'📊'
  };
  return map[ext] || '📁';
}

function formatSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024)       return bytes + ' B';
  if (bytes < 1024*1024)  return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/(1024*1024)).toFixed(1) + ' MB';
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-IN', {
    day: 'numeric', month: 'short', year: 'numeric'
  });
}

// Start
init();