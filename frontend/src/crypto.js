// ============================================================
// SECUREDRIVE — CRYPTO MODULE
// All encryption/decryption happens here, in the browser.
// The server never sees any keys or plaintext.
// Uses the Web Crypto API — built into every modern browser.
// ============================================================

const PBKDF2_ITERATIONS = 600000; // NIST 2023 recommended minimum
const SALT = "SecureDrive_v1";    // Fixed salt — in production this should be per-user random

// ─────────────────────────────────────────────────────────────
// HELPER: Convert between string ↔ ArrayBuffer ↔ Base64
// Web Crypto works with raw bytes (ArrayBuffer), not strings.
// We store keys as Base64 strings in MongoDB.
// ─────────────────────────────────────────────────────────────

function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ─────────────────────────────────────────────────────────────
// STEP 1: Derive a key from the user's password using PBKDF2
//
// Why PBKDF2? A simple hash of a password is fast to compute,
// so attackers can try millions of guesses per second.
// PBKDF2 runs 600,000 iterations — makes brute force 
// computationally expensive. This is the NIST standard.
//
// Input:  user's password (string)
// Output: a CryptoKey — cannot be extracted from browser memory
// ─────────────────────────────────────────────────────────────

async function deriveKeyFromPassword(password) {
  // First import the raw password as a "base key"
  const baseKey = await crypto.subtle.importKey(
    "raw",
    strToBytes(password),
    "PBKDF2",
    false,        // not extractable
    ["deriveKey"]
  );

  // Then derive the actual AES key using PBKDF2
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name:       "PBKDF2",
      salt:       strToBytes(SALT),
      iterations: PBKDF2_ITERATIONS,
      hash:       "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 }, // output: 256-bit AES key
    false,        // NOT extractable — key stays inside browser crypto subsystem
    ["wrapKey", "unwrapKey"]
  );

  return derivedKey;
}

// ─────────────────────────────────────────────────────────────
// STEP 2: Generate a Master Key
//
// This is a random 256-bit AES key generated fresh at signup.
// It never changes (only its encrypted form does when password changes).
// It lives in browser memory during the session only.
// ─────────────────────────────────────────────────────────────

async function generateMasterKey() {
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,         // extractable — we need to wrap (encrypt) it for storage
    ["wrapKey", "unwrapKey"]
  );
}

// ─────────────────────────────────────────────────────────────
// STEP 3: Wrap (encrypt) the Master Key using the derived key
//
// "Wrapping" = encrypting a key with another key.
// We encrypt the Master Key with the password-derived key.
// Result is stored in MongoDB. Server cannot unwrap it.
//
// Output: { wrappedMasterKey: base64, masterKeyIV: base64 }
// ─────────────────────────────────────────────────────────────

async function wrapMasterKey(masterKey, derivedKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 12 bytes for AES-GCM

  const wrappedBuffer = await crypto.subtle.wrapKey(
    "raw",
    masterKey,
    derivedKey,
    { name: "AES-GCM", iv }
  );

  return {
    wrappedMasterKey: bytesToBase64(wrappedBuffer),
    masterKeyIV:      bytesToBase64(iv)
  };
}

// ─────────────────────────────────────────────────────────────
// STEP 4: Unwrap (decrypt) the Master Key on login
//
// Reverse of step 3.
// Takes the stored wrappedMasterKey + user's password → Master Key
// ─────────────────────────────────────────────────────────────

async function unwrapMasterKey(wrappedMasterKeyB64, masterKeyIVB64, derivedKey) {
  const wrappedBytes = base64ToBytes(wrappedMasterKeyB64);
  const iv           = base64ToBytes(masterKeyIVB64);

  const masterKey = await crypto.subtle.unwrapKey(
    "raw",
    wrappedBytes,
    derivedKey,
    { name: "AES-GCM", iv },           // how it was wrapped
    { name: "AES-GCM", length: 256 },  // what we get back
    true,
    ["wrapKey", "unwrapKey"]
  );

  return masterKey;
}

// ─────────────────────────────────────────────────────────────
// STEP 5: Encrypt a file for upload
//
// For each file:
//   1. Generate a random Content Encryption Key (CEK)
//   2. Encrypt the file with the CEK using AES-GCM
//   3. Wrap the CEK with the Master Key
//
// Why a CEK per file instead of encrypting with Master Key directly?
//   - Password change: only re-wrap Master Key, not all files
//   - File sharing: share one CEK without exposing others
//   - Blast radius: one CEK compromised = one file affected
//
// Output: { encryptedFile, wrappedCEK, fileIV, cekIV }
// ─────────────────────────────────────────────────────────────

async function encryptFile(fileArrayBuffer, masterKey) {
  // Generate a unique random key for this specific file
  const cek = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  // Generate unique IVs — CRITICAL: never reuse an IV with the same key
  const fileIV = crypto.getRandomValues(new Uint8Array(12));
  const cekIV  = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the actual file using the CEK
  const encryptedFile = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: fileIV },
    cek,
    fileArrayBuffer
  );

  // Wrap (encrypt) the CEK using the Master Key
  const wrappedCEKBuffer = await crypto.subtle.wrapKey(
    "raw",
    cek,
    masterKey,
    { name: "AES-GCM", iv: cekIV }
  );

  return {
    encryptedFile,                       // ArrayBuffer — send this as the file
    wrappedCEK: bytesToBase64(wrappedCEKBuffer),
    fileIV:     bytesToBase64(fileIV),
    cekIV:      bytesToBase64(cekIV)
  };
}

// ─────────────────────────────────────────────────────────────
// STEP 6: Decrypt a downloaded file
//
// Reverse of step 5.
// Takes encrypted file + metadata from server → original file
// ─────────────────────────────────────────────────────────────

async function decryptFile(encryptedBuffer, wrappedCEKB64, fileIVB64, cekIVB64, masterKey) {
  const cekIV  = base64ToBytes(cekIVB64);
  const fileIV = base64ToBytes(fileIVB64);

  // Unwrap (decrypt) the CEK using the Master Key
  const cek = await crypto.subtle.unwrapKey(
    "raw",
    base64ToBytes(wrappedCEKB64),
    masterKey,
    { name: "AES-GCM", iv: cekIV },
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // Decrypt the actual file using the CEK
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fileIV },
    cek,
    encryptedBuffer
  );

  return decryptedBuffer;
}

// ─────────────────────────────────────────────────────────────
// EXPORT everything — api.js and app.js will use these
// ─────────────────────────────────────────────────────────────

export {
  deriveKeyFromPassword,
  generateMasterKey,
  wrapMasterKey,
  unwrapMasterKey,
  encryptFile,
  decryptFile,
  bytesToBase64,
  base64ToBytes
};