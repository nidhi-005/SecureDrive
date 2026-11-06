// Master Key is intentionally memory-only. It is never serialized to
// localStorage, sessionStorage, cookies, or IndexedDB.
let _masterKey = null;
let _userEmail = null;
const SESSION_EMAIL_KEY = 'secureDriveUserEmail';
try { sessionStorage.removeItem('secureDriveMasterKey'); } catch (_) {}
try { localStorage.removeItem('secureDriveMasterKey'); } catch (_) {}

export async function setMasterKey(key, email) {
  if (!key || key.algorithm?.name !== 'AES-GCM') {
    throw new TypeError('A valid AES-GCM CryptoKey is required');
  }

  // Convert the setup/unwrapped key into a non-extractable working key.
  // It remains usable for CEK wrap/unwrap but cannot be exported by app code.
  if (key.extractable) {
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    try {
      _masterKey = await crypto.subtle.importKey(
        'raw',
        raw,
        { name: 'AES-GCM', length: 256 },
        false,
        ['wrapKey', 'unwrapKey']
      );
    } finally {
      raw.fill(0);
    }
  } else {
    _masterKey = key;
  }

  _userEmail = email || null;
  try {
    if (_userEmail) sessionStorage.setItem(SESSION_EMAIL_KEY, _userEmail);
  } catch (_) {
    // Storage is optional; the key remains in memory.
  }
}

export async function hydrateSession() {
  // Authentication state may survive a reload, but the MK never does.
  if (_masterKey) return true;
  try { localStorage.removeItem('secureDriveMasterKey'); } catch (_) {}
  try {
    // Remove any raw Master Key left behind by the previous application version.
    sessionStorage.removeItem('secureDriveMasterKey');
    _userEmail = sessionStorage.getItem(SESSION_EMAIL_KEY) || null;
    return Boolean(sessionStorage.getItem('token'));
  } catch (_) {
    return false;
  }
}

export function getMasterKey() {
  return _masterKey;
}

export function getUserEmail() {
  if (!_userEmail) {
    try { _userEmail = sessionStorage.getItem(SESSION_EMAIL_KEY) || null; }
    catch (_) { _userEmail = null; }
  }
  return _userEmail;
}

export function clearMasterKey() {
  _masterKey = null;
}

export function clearSession() {
  _masterKey = null;
  _userEmail = null;
  try {
    sessionStorage.removeItem(SESSION_EMAIL_KEY);
    sessionStorage.removeItem('secureDriveMasterKey');
    sessionStorage.removeItem('token');
  } catch (_) {}
  try {
    localStorage.removeItem(SESSION_EMAIL_KEY);
    localStorage.removeItem('secureDriveMasterKey');
    localStorage.removeItem('token');
  } catch (_) {}
}

export function isSessionActive() {
  try { return Boolean(sessionStorage.getItem('token')); }
  catch (_) { return false; }
}
