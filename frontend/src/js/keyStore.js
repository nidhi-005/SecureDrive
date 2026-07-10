// ============================================================
// KEY STORE — holds Master Key in module memory
// Never exported to bytes, never put in sessionStorage
// A non-extractable CryptoKey cannot be read by JavaScript
// even if XSS code tries to access this module
// ============================================================

let _masterKey = null;
let _userEmail = null;

export function setMasterKey(key, email) {
  _masterKey = key;
  _userEmail = email;
}

export function getMasterKey() {
  if (!_masterKey) {
    // Key not in memory — user needs to log in again
    window.location.href = 'index.html';
    return null;
  }
  return _masterKey;
}

export function getUserEmail() {
  return _userEmail;
}

export function clearSession() {
  _masterKey = null;
  _userEmail = null;
}

export function isSessionActive() {
  return _masterKey !== null;
}