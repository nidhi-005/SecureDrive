// ============================================================
// SECUREDRIVE — API MODULE
// All communication with the Express backend lives here.
// Crypto module handles encryption.
// This module handles sending/receiving from the server.
// ============================================================

// const BASE_URL = 'https://securedrive-mmls.onrender.com/api';
const BASE_URL = 'http://127.0.0.1:3000/api'

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
// OPAQUE Helper: Convert Uint8Array to Base64
// ─────────────────────────────────────────────────────────────
function uint8ArrayToBase64(array) {
  let binary = '';
  const bytes = new Uint8Array(array);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// OPAQUE Helper: Convert Base64 to Uint8Array
function base64ToUint8Array(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ─────────────────────────────────────────────────────────────
// AUTH — OPAQUE Signup (request + finish)
// Uses the official Serenity OPAQUE protocol.
// ─────────────────────────────────────────────────────────────

async function apiSignupRequest(email, registrationRequest) {
  const res = await fetch(`${BASE_URL}/auth/signup-request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, registrationRequest })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Signup failed');
  return data;
}

async function apiSignupFinish(email, registrationRecord, wrappedMasterKey, masterKeyIV, encryptionSalt) {
  const res = await fetch(`${BASE_URL}/auth/signup-finish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, registrationRecord, wrappedMasterKey, masterKeyIV, encryptionSalt })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Signup failed');
  saveToken(data.token);
  return data;
}

// ─────────────────────────────────────────────────────────────
// AUTH — OPAQUE Login (Step 1)
// Sends startLoginRequest to server, gets loginResponse.
// ─────────────────────────────────────────────────────────────

async function apiLoginStart(email, startLoginRequest) {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, startLoginRequest })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Login failed');
  return data;
}

// ─────────────────────────────────────────────────────────────
// AUTH — OPAQUE Login (Step 2)
// Sends finishLoginRequest to complete authentication.
// ─────────────────────────────────────────────────────────────

async function apiLoginFinish(email, finishLoginRequest) {
  const res = await fetch(`${BASE_URL}/auth/login-finish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, finishLoginRequest })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Login verification failed');
  saveToken(data.token);
  return data;
}

// ─────────────────────────────────────────────────────────────
// AUTH — Logout
// ─────────────────────────────────────────────────────────────

function apiLogout() {
  clearToken();
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
  apiDelete,
  apiDownload,
  apiGetMeta,
  apiListFiles,
  apiLoginFinish,
  apiLoginStart,
  apiLogout,
  apiSignupFinish,
  apiSignupRequest,
  apiUpload,
  base64ToUint8Array,
  isLoggedIn,
  uint8ArrayToBase64
};

