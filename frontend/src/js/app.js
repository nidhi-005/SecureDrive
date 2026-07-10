import {
  deriveKeyFromPassword,
  generateMasterKey,
  wrapMasterKey,
  unwrapMasterKey,
  encryptFile,
  decryptFile
} from '../crypto.js';

import {
  apiSignup, apiLogin, apiLogout,
  apiUpload, apiListFiles,
  apiGetMeta, apiDownload, apiDelete
} from '../api.js';

// ── Master Key lives here — in module memory
// Never exported, never in sessionStorage
// Cleared when tab closes
let masterKey = null;

// ══════════════════════════════════════════
// SCREEN SWITCHING
// ══════════════════════════════════════════

function showAuth() {
  document.getElementById('auth-screen').style.display = 'flex';
  document.getElementById('app-screen').style.display  = 'none';
  document.getElementById('nav').style.display         = 'none';
}

function showDashboard(email) {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('app-screen').style.display  = '';
  document.getElementById('nav').style.display         = 'flex';
  document.getElementById('user-email').textContent    = email;
  loadFiles();
}

// ══════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════

window.switchTab = (tab) => {
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-signup').classList.toggle('active', tab === 'signup');
  document.getElementById('login-form').style.display  = tab === 'login'  ? '' : 'none';
  document.getElementById('signup-form').style.display = tab === 'signup' ? '' : 'none';
};

function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent   = msg;
  el.style.display = 'block';
}

function clearError(id) {
  document.getElementById(id).style.display = 'none';
}

function attachEnterHandler(inputId, handler) {
  const input = document.getElementById(inputId);
  if (!input) return;

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      handler();
    }
  });
}

window.handleSignup = async () => {
  clearError('signup-error');
  const email    = document.getElementById('signup-email').value.trim();
  const password = document.getElementById('signup-password').value;

  if (!email || !password)  return showError('signup-error', 'Please fill in all fields');
  if (password.length < 8)  return showError('signup-error', 'Password must be at least 8 characters');

  const btn = document.getElementById('signup-btn');
  btn.disabled    = true;
  btn.textContent = 'Creating account...';

  try {
    const derivedKey = await deriveKeyFromPassword(password);
    const mk         = await generateMasterKey();
    const { wrappedMasterKey, masterKeyIV } = await wrapMasterKey(mk, derivedKey);

    await apiSignup(email, password, wrappedMasterKey, masterKeyIV);

    // Store in module variable — NOT sessionStorage
    masterKey = mk;
    showDashboard(email);
    showToast('Account created!');
  } catch (err) {
    showError('signup-error', err.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Create Account';
  }
};

window.handleLogin = async () => {
  clearError('login-error');
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  if (!email || !password) return showError('login-error', 'Please fill in all fields');

  const btn = document.getElementById('login-btn');
  btn.disabled    = true;
  btn.textContent = 'Logging in...';

  try {
    const data       = await apiLogin(email, password);
    const derivedKey = await deriveKeyFromPassword(password);
    masterKey        = await unwrapMasterKey(
      data.wrappedMasterKey,
      data.masterKeyIV,
      derivedKey
    );

    // Store in module variable — NOT sessionStorage
    showDashboard(email);
    showToast('Welcome back!');
  } catch (err) {
    showError('login-error', 'Invalid email or password');
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Login';
  }
};

attachEnterHandler('login-email', window.handleLogin);
attachEnterHandler('login-password', window.handleLogin);
attachEnterHandler('signup-email', window.handleSignup);
attachEnterHandler('signup-password', window.handleSignup);

window.handleLogout = () => {
  masterKey = null; // clear from module memory
  apiLogout();      // clear JWT from sessionStorage
  showAuth();
};

// ══════════════════════════════════════════
// FILE OPERATIONS
// ══════════════════════════════════════════

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

async function uploadFile(file) {
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
      Failed to load files: ${err.message}</div>`;
  }
}

window.downloadFile = async (fileId, fileName) => {
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
    a.href = url; a.download = fileName; a.click();
    URL.revokeObjectURL(url);
    showToast('File decrypted and downloaded!');
  } catch (err) {
    showToast('Download failed: ' + err.message, 'error');
  }
};

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

// ══════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent   = msg;
  t.className     = type;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

function escapeHtml(str) {
  return str
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#039;');
}

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = {
    pdf:'📄',jpg:'🖼️',jpeg:'🖼️',png:'🖼️',gif:'🖼️',
    mp4:'🎬',mp3:'🎵',zip:'📦',rar:'📦',
    doc:'📝',docx:'📝',txt:'📃',xls:'📊',xlsx:'📊'
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
    day:'numeric', month:'short', year:'numeric'
  });
}

// Start on auth screen
showAuth();