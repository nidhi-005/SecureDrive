// ============================================================
// SECUREDRIVE — API MODULE
// All communication with the Express backend lives here.
// Crypto module handles encryption.
// This module handles sending/receiving from the server.
// ============================================================

// const BASE_URL = 'https://securedrive-mmls.onrender.com/api';
const BASE_URL = (import.meta.env.VITE_API_BASE || 'http://localhost:3000/api').replace(/\/$/, '')

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
  sessionStorage.removeItem('secureDriveUserEmail');
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
// AUTH — DID challenge / registration / login
// ─────────────────────────────────────────────────────────────

async function apiDidChallenge(email, did, purpose) {
  const res = await fetch(`${BASE_URL}/auth/did/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, did, purpose })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Could not create DID challenge');
  return data;
}

async function apiDidRegister(email, did, challengeId, signature) {
  const res = await fetch(`${BASE_URL}/auth/did/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, did, challengeId, signature })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'DID registration failed');
  saveToken(data.token);
  sessionStorage.setItem('secureDriveUserEmail', data.email || email);
  return data;
}

async function apiDidLogin(email, did, challengeId, signature) {
  const res = await fetch(`${BASE_URL}/auth/did/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, did, challengeId, signature })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'DID login failed');
  saveToken(data.token);
  sessionStorage.setItem('secureDriveUserEmail', data.email || email);
  return data;
}

async function apiDidStatus() {
  const res = await fetch(`${BASE_URL}/auth/did/status`, { headers: authHeader() });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Could not check DID account status');
  return data;
}

async function apiDidEncryptionSetup(encryptionSalt, wrappedMasterKey, masterKeyIV) {
  const res = await fetch(`${BASE_URL}/auth/did/encryption-setup`, {
    method: 'POST',
    headers: { ...authHeader(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ encryptionSalt, wrappedMasterKey, masterKeyIV })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Could not configure file encryption');
  return data;
}

// ─────────────────────────────────────────────────────────────
// AUTH — Logout
// ─────────────────────────────────────────────────────────────

async function apiLogout() {
  try {
    await fetch(`${BASE_URL}/auth/passkey/logout`, {
      method: 'POST',
      headers: authHeader()
    });
  } finally {
    clearToken();
  }
}

async function apiGetPasskeySession() {
  const res = await fetch(`${BASE_URL}/auth/passkey/session`, {
    headers: authHeader()
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Session expired');
  return data;
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

  // Return ciphertext plus the advisory integrity result. A blockchain
  // outage or mismatch must not prevent the caller from decrypting/downloading.
  return {
    buffer: await res.arrayBuffer(),
    integrityStatus: res.headers.get('X-Integrity-Status') || 'UNVERIFIED'
  };
}

// ─────────────────────────────────────────────────────────────
// RECOVERY — Master Key history
// ─────────────────────────────────────────────────────────────

async function apiGetMasterKeyRecovery() {
  const res = await fetch(`${BASE_URL}/auth/recovery/master-key`, {
    headers: authHeader()
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || 'Could not fetch Master Key recovery data');
  }

  return data;
}

// ─────────────────────────────────────────────────────────────
// RECOVERY — Repair current Master Key
// ─────────────────────────────────────────────────────────────

async function apiRepairMasterKey(wrappedMasterKey, masterKeyIV) {
  const res = await fetch(`${BASE_URL}/auth/recovery/master-key/repair`, {
    method: 'POST',
    headers: {
      ...authHeader(),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      wrappedMasterKey,
      masterKeyIV
    })
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || 'Could not repair Master Key');
  }

  return data;
}

// ─────────────────────────────────────────────────────────────
// RECOVERY — File CEK history
// ─────────────────────────────────────────────────────────────

async function apiGetFileKeyRecovery(fileId) {
  const res = await fetch(
    `${BASE_URL}/files/${fileId}/recovery`,
    {
      headers: authHeader()
    }
  );

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || 'Could not fetch file recovery data');
  }

  return data;
}

// ─────────────────────────────────────────────────────────────
// RECOVERY — Repair current file CEK
// ─────────────────────────────────────────────────────────────

async function apiRepairFileKey(
  fileId,
  wrappedCEK,
  cekIV
) {
  const res = await fetch(
    `${BASE_URL}/files/${fileId}/recovery/repair`,
    {
      method: 'POST',
      headers: {
        ...authHeader(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        wrappedCEK,
        cekIV
      })
    }
  );

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || 'Could not repair file key');
  }

  return data;
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

async function apiDeleteAccount() {
  const res = await fetch(`${BASE_URL}/auth/account`, {
    method: 'DELETE',
    headers: authHeader()
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || 'Account deletion failed');
  }

  return data;
}

// ─────────────────────────────────────────────────────────────
// Helper: check if user is logged in
// ─────────────────────────────────────────────────────────────

function isLoggedIn() {
  return !!getToken();
}

export {
  apiDelete, apiDeleteAccount, apiDidChallenge, apiDidEncryptionSetup, apiDidStatus,
  apiDidLogin, apiDidRegister, apiDownload,
  apiGetFileKeyRecovery,
  apiGetMasterKeyRecovery,
  apiGetPasskeySession,
  apiGetMeta,
  apiListFiles,
  apiLoginFinish,
  apiLoginStart,
  apiLogout,
  apiRepairFileKey,
  apiRepairMasterKey,
  apiSignupFinish,
  apiSignupRequest,
  apiUpload, base64ToUint8Array,
  isLoggedIn,
  uint8ArrayToBase64
};

