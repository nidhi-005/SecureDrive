// ============================================================
// SECUREDRIVE — API MODULE
// All communication with the Express backend lives here.
// Crypto module handles encryption.
// This module handles sending/receiving from the server.
// ============================================================

const BASE_URL = 'http://localhost:3000/api';

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

async function apiSignup(email, wrappedMasterKey, masterKeyIV) {
  const res = await fetch(`${BASE_URL}/auth/signup`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email, wrappedMasterKey, masterKeyIV })
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Signup failed');

  saveToken(data.token);
  return data;
}

// ─────────────────────────────────────────────────────────────
// AUTH — Login
// Gets wrapped master key back from server
// ─────────────────────────────────────────────────────────────

async function apiLogin(email) {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email })
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Login failed');

  saveToken(data.token);
  return data; // contains wrappedMasterKey and masterKeyIV
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

async function apiUpload(encryptedBuffer, originalName, wrappedCEK, fileIV, cekIV) {
  // Must use FormData — sending binary file + text fields together
  const formData = new FormData();

  // Convert ArrayBuffer to Blob to send as file
  const blob = new Blob([encryptedBuffer], { type: 'application/octet-stream' });
  formData.append('file',         blob, originalName);
  formData.append('originalName', originalName);
  formData.append('wrappedCEK',   wrappedCEK);
  formData.append('fileIV',       fileIV);
  formData.append('cekIV',        cekIV);

  const res = await fetch(`${BASE_URL}/files/upload`, {
    method:  'POST',
    headers: authHeader(), // JWT token — no Content-Type, FormData sets it
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