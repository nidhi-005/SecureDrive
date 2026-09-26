import {
  apiDelete,
  apiDownload,
  apiGetMeta,
  apiListFiles,
  apiLogout, apiUpload
} from '../api.js';
import { decryptFile, encryptFile } from '../crypto.js';
import { clearSession, getMasterKey, getUserEmail, hydrateSession, isSessionActive } from './keyStore.js';

// ── Init ───────────────────────────────────────────────────
async function init() {
  const restored = await hydrateSession();

  if (!restored || !isSessionActive()) {
    window.location.href = 'index.html';
    return;
  }

  document.getElementById('user-email').textContent = getUserEmail() || '';
  await loadFiles();
}

// ── Toast ──────────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent   = msg;
  t.className     = type;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

// ── Logout ─────────────────────────────────────────────────
function handleLogout() {
  clearSession(); // clears key from module memory
  apiLogout();    // clears JWT from sessionStorage, redirects to login
  window.location.href = 'index.html';
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
  if (!masterKey) return; // redirected to login by getMasterKey

  const status = document.getElementById('upload-status');
  status.style.display = 'block';

  try {
    status.textContent = `🔐 Encrypting ${file.name}...`;
    const buffer = await file.arrayBuffer();

    const { encryptedFile, wrappedCEK, fileIV, cekIV } =
      await encryptFile(buffer, masterKey);

    status.textContent = '☁️ Uploading encrypted file...';
    await apiUpload(encryptedFile, file.name, wrappedCEK, fileIV, cekIV);

    status.textContent = '✅ Upload complete!';
    setTimeout(() => status.style.display = 'none', 2000);

    showToast('File encrypted and uploaded!');
    await loadFiles();
    document.getElementById('file-input').value = '';
  } catch (err) {
    status.textContent = '❌ ' + err.message;
    showToast('Upload failed', 'error');
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
    list.innerHTML = `<div style="color:#f87171;font-size:13px;padding:20px 0">
      Failed to load files: ${err.message}
    </div>`;
  }
}

// ── DOWNLOAD ───────────────────────────────────────────────
async function downloadFile(fileId, fileName) {
  const masterKey = getMasterKey();
  if (!masterKey) return;

  showToast('Decrypting...');
  try {
    const meta            = await apiGetMeta(fileId);
    const encryptedBuffer = await apiDownload(fileId);
    const decryptedBuffer = await decryptFile(
      encryptedBuffer, meta.wrappedCEK, meta.fileIV, meta.cekIV, masterKey
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
    pdf:'📄', jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🖼️',
    mp4:'🎬', mp3:'🎵', zip:'📦', rar:'📦',
    doc:'📝', docx:'📝', txt:'📃', xls:'📊', xlsx:'📊'
  };
  return map[ext] || '📁';
}

function formatSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024)      return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/(1024*1024)).toFixed(1) + ' MB';
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
  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleLogout);
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