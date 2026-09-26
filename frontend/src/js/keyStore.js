// ============================================================
// KEY STORE — holds the Master Key in memory and restores it
// from sessionStorage when the page is reloaded.
// ============================================================

let _masterKey = null;
let _userEmail = null;
const SESSION_EMAIL_KEY = 'secureDriveUserEmail';
const SESSION_MASTER_KEY = 'secureDriveMasterKey';

function bytesToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export async function setMasterKey(key, email) {
  _masterKey = key;
  _userEmail = email;

  try {
    const exportedKey = await crypto.subtle.exportKey('raw', key);
    sessionStorage.setItem(SESSION_MASTER_KEY, bytesToBase64(exportedKey));
    sessionStorage.setItem(SESSION_EMAIL_KEY, email || '');
  } catch (error) {
    // Ignore storage issues in restricted environments.
  }
}

export async function hydrateSession() {
  if (_masterKey) return true;

  try {
    const storedKey = sessionStorage.getItem(SESSION_MASTER_KEY);
    const storedEmail = sessionStorage.getItem(SESSION_EMAIL_KEY);

    if (!storedKey) {
      _userEmail = storedEmail || _userEmail;
      return !!sessionStorage.getItem('token');
    }

    const keyBytes = base64ToBytes(storedKey);
    _masterKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    _userEmail = storedEmail || _userEmail;
    return true;
  } catch (error) {
    clearSession();
    return false;
  }
}

export function getMasterKey() {
  if (!_masterKey) {
    if (!sessionStorage.getItem('token')) {
      window.location.href = 'index.html';
    }
    return null;
  }
  return _masterKey;
}

export function getUserEmail() {
  if (!_userEmail) {
    try {
      _userEmail = sessionStorage.getItem(SESSION_EMAIL_KEY) || null;
    } catch (error) {
      _userEmail = null;
    }
  }
  return _userEmail;
}

export function clearSession() {
  _masterKey = null;
  _userEmail = null;

  try {
    sessionStorage.removeItem(SESSION_EMAIL_KEY);
    sessionStorage.removeItem(SESSION_MASTER_KEY);
    sessionStorage.removeItem('token');
  } catch (error) {
    // Ignore storage issues.
  }
}

export function isSessionActive() {
  if (_masterKey !== null) return true;
  return !!sessionStorage.getItem('token') || !!sessionStorage.getItem(SESSION_MASTER_KEY);
}