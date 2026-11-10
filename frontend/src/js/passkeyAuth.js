
import {
  startRegistration,
  startAuthentication
} from '@simplewebauthn/browser';

import {
  deriveKeyFromPassword,
  generateMasterKey,
  generateSalt,
  wrapMasterKey,
  bytesToBase64,
  base64ToBytes
} from '../crypto.js';

import { setMasterKey } from './keyStore.js';
import {
  MasterKeyRecoveryError,
  unwrapMasterKeyWithRecovery
} from './masterKeyRecovery.js';

const API_BASE = (import.meta.env.VITE_API_BASE || 'http://localhost:3000/api').replace(/\/$/, '');

let authenticatedEmail = null;
let encryptionMetadata = null;
let pendingEncryptionSetup = null;

const $ = id => document.getElementById(id);

function showMessage(id, message, isError = true) {
  const element = $(id);
  if (!element) return;

  element.textContent = message;
  element.style.display = 'block';
  element.style.color = isError ? '#f87171' : '#6ee7b7';
}

function clearMessage(id) {
  const element = $(id);
  if (!element) return;

  element.textContent = '';
  element.style.display = 'none';
}

function resetToPasskeyScreen() {
  authenticatedEmail = null;
  encryptionMetadata = null;
  pendingEncryptionSetup = null;

  ['passkey-email', 'encryption-password', 'encryption-password-confirm', 'unlock-password']
    .forEach(id => {
      if ($(id)) $(id).value = '';
    });

  ['passkey-message', 'setup-message', 'unlock-message', 'device-passkey-message'].forEach(clearMessage);
  showSection('passkey-section');
  $('screen-title').textContent = 'Welcome to SecureDrive';
  $('screen-subtitle').textContent = 'Secure, passwordless account access.';
}

function showSection(sectionId) {
  [
    'passkey-section',
    'encryption-setup',
    'encryption-unlock'
  ].forEach(id => {
    $(id).style.display = id === sectionId ? 'block' : 'none';
  });

  const deviceTools = $('device-passkey-tools');
  if (deviceTools) {
    deviceTools.style.display =
      sectionId === 'encryption-setup' || sectionId === 'encryption-unlock'
        ? 'block'
        : 'none';
  }
}

function setBusy(button, busy, busyText, normalText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : normalText;
}

function getEmail() {
  const email = $('passkey-email').value.trim().toLowerCase();

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error('Enter a valid email address.');
  }

  return email;
}

async function post(path, body, authenticated = false) {
  const headers = {
    'Content-Type': 'application/json'
  };

  if (authenticated) {
    const token = sessionStorage.getItem('token');

    if (!token) {
      throw new Error('Your session has expired. Please sign in again.');
    }

    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || 'Request failed.');
  }

  return data;
}

function saveAuthentication(data) {
  authenticatedEmail = data.email;
  sessionStorage.setItem('token', data.token);
  sessionStorage.setItem('secureDriveUserEmail', data.email);
}

async function restoreAuthenticatedSession() {
  const token = sessionStorage.getItem('token');
  if (!token) return false;

  try {
    const response = await fetch(`${API_BASE}/auth/passkey/session`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Session expired');

    authenticatedEmail = data.email;
    sessionStorage.setItem('secureDriveUserEmail', data.email);

    if (data.encryptionReady) {
      encryptionMetadata = {
        encryptionSalt: data.encryptionSalt,
        wrappedMasterKey: data.wrappedMasterKey,
        masterKeyIV: data.masterKeyIV
      };
      showSection('encryption-unlock');
      $('screen-title').textContent = 'Welcome back';
      $('screen-subtitle').textContent =
        'Your session is active. Enter your separate file-encryption password to unlock your files.';
    } else {
      showSection('encryption-setup');
      $('screen-title').textContent = 'Protect your files';
    }
    return true;
  } catch (error) {
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('secureDriveUserEmail');
    return false;
  }
}

// Keep the unlocked Master Key in this document's memory. A full-page
// navigation would destroy it, so load the dashboard into the current document.
// Refreshing dashboard.html intentionally starts a fresh document and requires
// the separate encryption password again.
async function openDashboard() {
  const response = await fetch('./dashboard.html', { cache: 'no-store' });
  if (!response.ok) throw new Error('Could not open the SecureDrive dashboard.');

  const html = await response.text();
  const parsed = new DOMParser().parseFromString(html, 'text/html');
  parsed.body.querySelectorAll('script').forEach(script => script.remove());

  document.title = parsed.title || 'SecureDrive — Dashboard';
  document.head.innerHTML = parsed.head.innerHTML;
  document.body.innerHTML = parsed.body.innerHTML;
  history.pushState({}, '', 'dashboard.html');

  await import('./dashboard.js');
}

// --------------------------------------------------
// REGISTRATION
// --------------------------------------------------

async function registerWithPasskey() {
  const button = $('passkey-register-btn');

  try {
    clearMessage('passkey-message');

    const email = getEmail();

    setBusy(
      button,
      true,
      'Registering...',
      'Create account with Passkey'
    );

    const optionsData = await post(
      '/auth/passkey/register/options',
      { email }
    );

    const registrationResponse = await startRegistration({
      optionsJSON: optionsData.options
    });

    const result = await post(
      '/auth/passkey/register/verify',
      {
        email,
        response: registrationResponse,
        challengeId: optionsData.challengeId
      }
    );

    saveAuthentication(result);

    showSection('encryption-setup');

    $('screen-title').textContent = 'Protect your files';
    $('screen-subtitle').textContent =
      'Your passkey was registered successfully.';

    showMessage(
      'setup-message',
      'Create your separate encryption password.',
      false
    );

  } catch (error) {
    console.error(error);
    const message = error.name === 'NotAllowedError'
      ? 'Local passkey registration was cancelled or is not available on this device. Check that your device supports Windows Hello, Touch ID, or another platform authenticator.'
      : (error.message || 'Passkey registration failed.');
    showMessage('passkey-message', message);
  } finally {
    setBusy(
      button,
      false,
      '',
      'Create account with Passkey'
    );
  }
}

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

async function loginWithPasskey(mode = 'local') {
  const button = mode === 'hybrid'
    ? $('passkey-hybrid-login-btn')
    : $('passkey-login-btn');

  try {
    clearMessage('passkey-message');

    const email = getEmail();

    const idleLabel = mode === 'hybrid'
      ? 'Sign in using another device (phone / QR)'
      : "Sign in with this device's passkey";

    setBusy(
      button,
      true,
      mode === 'hybrid' ? 'Waiting for phone...' : 'Verifying passkey...',
      idleLabel
    );

    const optionsData = await post(
      '/auth/passkey/login/options',
      { email, mode }
    );

    const authenticationResponse = await startAuthentication({
      optionsJSON: optionsData.options
    });

    const result = await post(
      '/auth/passkey/login/verify',
      {
        email,
        response: authenticationResponse,
        challengeId: optionsData.challengeId
      }
    );

    saveAuthentication(result);

    if (
      !result.encryptionReady ||
      !result.encryptionSalt ||
      !result.wrappedMasterKey ||
      !result.masterKeyIV
    ) {
      showSection('encryption-setup');

      $('screen-title').textContent = 'Protect your files';

      showMessage(
        'setup-message',
        'Your account needs file encryption setup.',
        false
      );

      return;
    }

    encryptionMetadata = {
      encryptionSalt: result.encryptionSalt,
      wrappedMasterKey: result.wrappedMasterKey,
      masterKeyIV: result.masterKeyIV
    };

    showSection('encryption-unlock');

    $('screen-title').textContent = 'Welcome back';
    $('screen-subtitle').textContent =
      'Passkey verified. Unlock your files.';

  } catch (error) {
    console.error(error);
    const message = error.name === 'NotAllowedError'
      ? (mode === 'hybrid'
          ? 'Cross-device authentication was cancelled or is unavailable. Try a compatible browser and a phone that has a SecureDrive passkey registered.'
          : 'No passkey was selected, or authentication was cancelled. Try your device passkey or choose the phone/another-device option.')
      : (error.message || 'Passkey login failed.');
    showMessage('passkey-message', message);
  } finally {
    setBusy(
      button,
      false,
      '',
      mode === 'hybrid'
        ? 'Sign in using another device (phone / QR)'
        : "Sign in with this device's passkey"
    );
  }
}

// --------------------------------------------------
// REGISTER AN ADDITIONAL PASSKEY
// Use mode='local' for this device, or mode='hybrid' to ask the browser
// to prefer a remote authenticator (typically a phone QR flow).
// --------------------------------------------------
async function registerAdditionalPasskey(mode = 'local') {
  const button = mode === 'hybrid'
    ? $('add-hybrid-passkey-btn')
    : $('add-local-passkey-btn');

  try {
    clearMessage('device-passkey-message');

    if (!sessionStorage.getItem('token')) {
      throw new Error('Sign in again before adding another passkey.');
    }

    setBusy(button, true, 'Preparing...', mode === 'hybrid'
      ? 'Add passkey using phone / QR'
      : 'Add passkey on this device');

    const optionsData = await post(
      '/auth/passkey/register/additional/options',
      { mode },
      true
    );

    const registrationResponse = await startRegistration({
      optionsJSON: optionsData.options
    });

    const result = await post(
      '/auth/passkey/register/additional/verify',
      {
        response: registrationResponse,
        challengeId: optionsData.challengeId
      },
      true
    );

    const message = result.backedUp
      ? 'Additional passkey registered. Your credential provider reports that it is backed up/synced.'
      : 'Additional passkey registered successfully.';
    showMessage('device-passkey-message', message, false);
  } catch (error) {
    console.error(error);
    const message = error.name === 'NotAllowedError'
      ? (mode === 'hybrid'
          ? 'Phone/QR passkey registration was cancelled or is not supported by this browser. Try a compatible browser and phone.'
          : 'Passkey registration was cancelled or is unavailable on this device.')
      : (error.message || 'Could not register another passkey.');
    showMessage('device-passkey-message', message);
  } finally {
    setBusy(button, false, '', mode === 'hybrid'
      ? 'Add passkey using phone / QR'
      : 'Add passkey on this device');
  }
}

// --------------------------------------------------
// FIRST-TIME MASTER KEY SETUP
// --------------------------------------------------

async function setupEncryption() {
  const button = $('encryption-setup-btn');

  try {
    clearMessage('setup-message');

    const password = $('encryption-password').value;
    const confirmation = $('encryption-password-confirm').value;

    if (password.length < 8) {
      throw new Error(
        'Encryption password must contain at least 8 characters.'
      );
    }

    if (password !== confirmation) {
      throw new Error('The passwords do not match.');
    }

    if (!authenticatedEmail) {
      throw new Error('Your authenticated account is missing.');
    }

    setBusy(
      button,
      true,
      'Setting up encryption...',
      'Set up file encryption'
    );

    if (!pendingEncryptionSetup) {
      const salt = generateSalt();
      const derivedKey = await deriveKeyFromPassword(password, salt);
      const masterKey = await generateMasterKey();
      const wrapped = await wrapMasterKey(masterKey, derivedKey);

      const passwordDigest = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(password)
      );
      pendingEncryptionSetup = {
        masterKey,
        passwordDigest: bytesToBase64(passwordDigest),
        payload: {
          encryptionSalt: bytesToBase64(salt),
          wrappedMasterKey: wrapped.wrappedMasterKey,
          masterKeyIV: wrapped.masterKeyIV
        }
      };
    } else {
      const retryDigest = bytesToBase64(await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(password)
      ));
      if (pendingEncryptionSetup.passwordDigest !== retryDigest) {
        throw new Error('A previous setup attempt is pending. Re-enter the same encryption password to safely retry.');
      }
    }

    await post(
      '/auth/did/encryption-setup',
      pendingEncryptionSetup.payload,
      true
    );

    await setMasterKey(pendingEncryptionSetup.masterKey, authenticatedEmail);
    pendingEncryptionSetup = null;

    $('encryption-password').value = '';
    $('encryption-password-confirm').value = '';

    await openDashboard();

  } catch (error) {
    console.error(error);
    showMessage(
      'setup-message',
      error.message || 'Encryption setup failed.'
    );
  } finally {
    setBusy(
      button,
      false,
      '',
      'Set up file encryption'
    );
  }
}

// --------------------------------------------------
// UNLOCK EXISTING MASTER KEY
// --------------------------------------------------

async function unlockEncryption() {
  const button = $('encryption-unlock-btn');

  try {
    clearMessage('unlock-message');

    const password = $('unlock-password').value;

    if (!password) {
      throw new Error('Enter your file encryption password.');
    }

    if (!encryptionMetadata) {
      throw new Error('Encryption metadata is missing. Sign in again.');
    }

    setBusy(
      button,
      true,
      'Unlocking...',
      'Unlock SecureDrive'
    );

    const salt = base64ToBytes(
      encryptionMetadata.encryptionSalt
    );

    const derivedKey = await deriveKeyFromPassword(
      password,
      salt
    );

    const { masterKey, repairError } = await unwrapMasterKeyWithRecovery(
      encryptionMetadata,
      derivedKey
    );

    await setMasterKey(masterKey, authenticatedEmail);

    $('unlock-password').value = '';

    await openDashboard();

    if (repairError) {
      window.alert(
        'Your Master Key was recovered and your files are unlocked, but the active key could not be repaired. Contact support before signing out.'
      );
    }

  } catch (error) {
    console.error(error);

    showMessage(
      'unlock-message',
      error instanceof MasterKeyRecoveryError
        ? error.message
        : 'Could not unlock your files. Check your encryption password.'
    );
  } finally {
    setBusy(
      button,
      false,
      '',
      'Unlock SecureDrive'
    );
  }
}

// --------------------------------------------------
// INITIALIZE
// --------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  $('passkey-register-btn').addEventListener(
    'click',
    registerWithPasskey
  );

  $('passkey-login-btn').addEventListener(
    'click',
    () => loginWithPasskey('local')
  );

  $('passkey-hybrid-login-btn').addEventListener(
    'click',
    () => loginWithPasskey('hybrid')
  );

  $('add-local-passkey-btn').addEventListener(
    'click',
    () => registerAdditionalPasskey('local')
  );

  $('add-hybrid-passkey-btn').addEventListener(
    'click',
    () => registerAdditionalPasskey('hybrid')
  );

  $('encryption-setup-btn').addEventListener(
    'click',
    setupEncryption
  );

  $('encryption-unlock-btn').addEventListener(
    'click',
    unlockEncryption
  );

  showSection('passkey-section');

  window.addEventListener('pageshow', event => {
    if (!event.persisted) return;

    if (!sessionStorage.getItem('token')) {
      resetToPasskeyScreen();
      return;
    }

    restoreAuthenticatedSession();
  });

  $('passkey-email').addEventListener('keydown', event => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    $('passkey-register-btn').click();
  });

  ['encryption-password', 'encryption-password-confirm'].forEach(id => {
    $(id).addEventListener('keydown', event => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      $('encryption-setup-btn').click();
    });
  });

  $('unlock-password').addEventListener('keydown', event => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    $('encryption-unlock-btn').click();
  });

  // If the tab was reloaded while the authenticated session is still active,
  // restore only account metadata. The Master Key must be unlocked again.
  restoreAuthenticatedSession();
});
