// ============================================================
// SECUREDRIVE — API MODULE
// All communication with the Express backend lives here.
// Crypto module handles encryption.
// This module handles sending/receiving from the server.
// ============================================================

const BASE_URL = "https://securedrive-mmls.onrender.com/api";

// ─────────────────────────────────────────────────────────────
// Helper: get stored JWT token from sessionStorage
// sessionStorage clears when tab closes — safer than localStorage
// ─────────────────────────────────────────────────────────────

function getToken() {
  return sessionStorage.getItem('token');
}

function saveToken(token) {
  sessionStorage.setItem('token', token);
}

function clearToken() {
  sessionStorage.removeItem('token');
}

// Helper: build auth header for protected routes
function authHeader() {
  return { 'Authorization': `Bearer ${getToken()}` };
}

// ─────────────────────────────────────────────────────────────
// AUTH — Signup
// Sends email + wrapped master key to backend
// ─────────────────────────────────────────────────────────────

// Signup — now sends password too
async function apiSignup(email, password, wrappedMasterKey, masterKeyIV) {
  const res = await fetch(`${BASE_URL}/auth/signup`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email, password, wrappedMasterKey, masterKeyIV })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Signup failed');
  saveToken(data.token);
  return data;
}

// Login — now sends password too
async function apiLogin(email, password) {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Login failed');
  saveToken(data.token);
  return data;
}

// ─────────────────────────────────────────────────────────────
// AUTH — Logout
// ─────────────────────────────────────────────────────────────

function apiLogout() {
  clearToken();
  window.location.reload();
}

// ─────────────────────────────────────────────────────────────
// FILES — Upload
// Sends encrypted file + crypto metadata to backend
// ─────────────────────────────────────────────────────────────

async function apiUpload(encryptedBuffer, originalName, wrappedCEK, fileIV, cekIV, mimeType) {
  const formData = new FormData();
  const blob = new Blob([encryptedBuffer], { type: 'application/octet-stream' });
  formData.append('file',         blob, originalName);
  formData.append('originalName', originalName);
  formData.append('mimeType',     mimeType);          // ← add this
  formData.append('wrappedCEK',   wrappedCEK);
  formData.append('fileIV',       fileIV);
  formData.append('cekIV',        cekIV);

  const res = await fetch(`${BASE_URL}/files/upload`, {
    method:  'POST',
    headers: authHeader(),
    body:    formData
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Upload failed');
  return data;
}

// ─────────────────────────────────────────────────────────────
// FILES — List all files for logged-in user
// ─────────────────────────────────────────────────────────────

async function apiListFiles() {
  const res = await fetch(`${BASE_URL}/files`, {
    headers: authHeader()
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Could not fetch files');
  return data;
}

// ─────────────────────────────────────────────────────────────
// FILES — Get metadata (wrappedCEK, IVs) for decryption
// ─────────────────────────────────────────────────────────────

async function apiGetMeta(fileId) {
  const res = await fetch(`${BASE_URL}/files/${fileId}/meta`, {
    headers: authHeader()
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Could not fetch metadata');
  return data;
}

// ─────────────────────────────────────────────────────────────
// FILES — Download encrypted file bytes
// ─────────────────────────────────────────────────────────────

async function apiDownload(fileId) {
  const res = await fetch(`${BASE_URL}/files/${fileId}/download`, {
    headers: authHeader()
  });

  if (!res.ok) throw new Error('Download failed');

  // Return raw ArrayBuffer — crypto.js will decrypt it
  return await res.arrayBuffer();
}

// ─────────────────────────────────────────────────────────────
// FILES — Delete
// ─────────────────────────────────────────────────────────────

async function apiDelete(fileId) {
  const res = await fetch(`${BASE_URL}/files/${fileId}`, {
    method:  'DELETE',
    headers: authHeader()
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Delete failed');
  return data;
}

// ─────────────────────────────────────────────────────────────
// Helper: check if user is logged in
// ─────────────────────────────────────────────────────────────

function isLoggedIn() {
  return !!getToken();
}

export {
  apiSignup,
  apiLogin,
  apiLogout,
  apiUpload,
  apiListFiles,
  apiGetMeta,
  apiDownload,
  apiDelete,
  isLoggedIn
};