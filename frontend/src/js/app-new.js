import {
    decryptFile,
    deriveKeyFromPassword,
    encryptFile,
    generateMasterKey,
    unwrapMasterKey,
    wrapMasterKey
} from '../crypto.js';

import {
    apiDelete,
    apiDownload,
    apiGetMeta,
    apiListFiles,
    apiLoginFinish,
    apiLoginStart,
    apiLogout,
    apiSignup,
    apiUpload,
    base64ToUint8Array,
    uint8ArrayToBase64
} from '../api.js';

// ── Master Key lives here — in module memory
// Never exported, never in sessionStorage
// Cleared when tab closes
let masterKey = null;

// Simple OPAQUE-like implementation using Web Crypto API
class OPAQUEClient {
  constructor(password, username) {
    this.password = password;
    this.username = username;
  }

  async registerInit() {
    const passwordBytes = new TextEncoder().encode(this.password);
    const usernameBytes = new TextEncoder().encode(this.username);
    const combined = new Uint8Array(passwordBytes.length + usernameBytes.length);
    combined.set(passwordBytes);
    combined.set(usernameBytes, passwordBytes.length);
    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
  }

  async registerFinish(serverRegisterInitBytes) {
    const passwordBytes = new TextEncoder().encode(this.password);
    const combined = new Uint8Array(passwordBytes.length + serverRegisterInitBytes.length);
    combined.set(passwordBytes);
    combined.set(serverRegisterInitBytes, passwordBytes.length);
    return await crypto.subtle.digest('SHA-256', combined);
  }

  async loginInit() {
    const passwordBytes = new TextEncoder().encode(this.password);
    const usernameBytes = new TextEncoder().encode(this.username);
    const combined = new Uint8Array(passwordBytes.length + usernameBytes.length);
    combined.set(passwordBytes);
    combined.set(usernameBytes, passwordBytes.length);
    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
  }

  async loginFinish(serverLoginResponseBytes) {
    const passwordBytes = new TextEncoder().encode(this.password);
    const combined = new Uint8Array(passwordBytes.length + serverLoginResponseBytes.length);
    combined.set(passwordBytes);
    combined.set(serverLoginResponseBytes, passwordBytes.length);
    const clientFinish = await crypto.subtle.digest('SHA-256', combined);
    const exportKey = await crypto.subtle.digest('SHA-256', clientFinish);
    return {
      clientLoginFinish: new Uint8Array(clientFinish),
      clientExportKey: uint8ArrayToBase64(new Uint8Array(exportKey))
    };
  }
}

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

function switchTab(tab) {
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-signup').classList.toggle('active', tab === 'signup');
  document.getElementById('login-form').style.display  = tab === 'login'  ? '' : 'none';
  document.getElementById('signup-form').style.display = tab === 'signup' ? '' : 'none';
}

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

async function handleSignup() {
  clearError('signup-error');
  const email    = document.getElementById('signup-email').value.trim();
  const password = document.getElementById('signup-password').value;

  if (!email || !password)  return showError('signup-error', 'Please fill in all fields');
  if (password.length < 8)  return showError('signup-error', 'Password must be at least 8 characters');

  const btn = document.getElementById('signup-btn');
  btn.disabled    = true;
  btn.textContent = 'Creating account...';

  try {
    const opaqueClient = new OPAQUEClient(password, email);
    const clientRegisterInitBytes = await opaqueClient.registerInit();
    const clientRegisterInit = uint8ArrayToBase64(clientRegisterInitBytes);

    const derivedKey = await deriveKeyFromPassword(password);
    const mk         = await generateMasterKey();
    const { wrappedMasterKey, masterKeyIV } = await wrapMasterKey(mk, derivedKey);

    const serverResponse = await apiSignup(email, clientRegisterInit, wrappedMasterKey, masterKeyIV);

    const serverRegisterInitBytes = base64ToUint8Array(serverResponse.serverRegisterInit);
    await opaqueClient.registerFinish(serverRegisterInitBytes);

    masterKey = mk;
    showToast('Account created!');
    showDashboard(email);
  } catch (err) {
    showError('signup-error', err.message);
    btn.disabled    = false;
    btn.textContent = 'Create Account';
  }
}

async function handleLogin() {
  clearError('login-error');
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  if (!email || !password) return showError('login-error', 'Please fill in all fields');

  const btn = document.getElementById('login-btn');
  btn.disabled    = true;
  btn.textContent = 'Logging in...';

  try {
    const opaqueClient = new OPAQUEClient(password, email);

    const clientLoginInitBytes = await opaqueClient.loginInit();
    const clientLoginInit = uint8ArrayToBase64(clientLoginInitBytes);

    const serverResponse = await apiLoginStart(email, clientLoginInit);

    const serverLoginResponseBytes = base64ToUint8Array(serverResponse.serverLoginResponse);
    const { clientLoginFinish, clientExportKey } = await opaqueClient.loginFinish(
      serverLoginResponseBytes
    );

    const clientLoginFinishB64 = uint8ArrayToBase64(clientLoginFinish);
    await apiLoginFinish(email, clientLoginFinishB64, clientExportKey);

    const derivedKey = await deriveKeyFromPassword(password);
    masterKey = await unwrapMasterKey(
      serverResponse.wrappedMasterKey,
      serverResponse.masterKeyIV,
      derivedKey
    );

    showToast('Welcome back!');
    showDashboard(email);
  } catch (err) {
    showError('login-error', 'Invalid email or password');
    btn.disabled    = false;
    btn.textContent = 'Login';
  }
}

function handleLogout() {
  masterKey = null;
  apiLogout();
  showAuth();
}

// ══════════════════════════════════════════
// FILE OPERATIONS
// ══════════════════════════════════════════

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
          <button class="btn-download" data-file-id="${f._id}" data-file-name="${escapeHtml(f.originalName)}">
            ↓ Download
          </button>
          <button class="btn-delete" data-file-id="${f._id}">
            Delete
          </button>
        </div>
      </div>
    `).join('');
    attachFileListeners();
  } catch (err) {
    list.innerHTML = `<div style="color:#f87171;font-size:13px;padding:20px 0">
      Failed to load files: ${err.message}</div>`;
  }
}

function attachFileListeners() {
  document.querySelectorAll('.btn-download').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const fileId = e.target.dataset.fileId;
      const fileName = e.target.dataset.fileName;
      downloadFile(fileId, fileName);
    });
  });

  document.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const fileId = e.target.dataset.fileId;
      deleteFile(fileId);
    });
  });
}

async function downloadFile(fileId, fileName) {
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
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
    showToast('File decrypted and downloaded!');
  } catch (err) {
    showToast('Download failed: ' + err.message, 'error');
  }
}

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
    day: 'numeric', month: 'short', year: 'numeric'
  });
}

// ══════════════════════════════════════════
// EVENT LISTENER INITIALIZATION
// ══════════════════════════════════════════

function initializeEventListeners() {
  // Tab switching
  const tabLogin = document.getElementById('tab-login');
  const tabSignup = document.getElementById('tab-signup');
  
  if (tabLogin) tabLogin.addEventListener('click', () => switchTab('login'));
  if (tabSignup) tabSignup.addEventListener('click', () => switchTab('signup'));

  // Login form
  const loginBtn = document.getElementById('login-btn');
  if (loginBtn) loginBtn.addEventListener('click', handleLogin);
  attachEnterHandler('login-email', handleLogin);
  attachEnterHandler('login-password', handleLogin);

  // Signup form
  const signupBtn = document.getElementById('signup-btn');
  if (signupBtn) signupBtn.addEventListener('click', handleSignup);
  attachEnterHandler('signup-email', handleSignup);
  attachEnterHandler('signup-password', handleSignup);

  // Logout button
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

  // Upload zone
  const uploadZone = document.getElementById('upload-zone');
  const fileInput = document.getElementById('file-input');

  if (uploadZone) {
    uploadZone.addEventListener('click', () => fileInput?.click());
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
  document.addEventListener('DOMContentLoaded', initializeEventListeners);
} else {
  initializeEventListeners();
}

showAuth();
