
import {
  startRegistration,
  startAuthentication
} from '@simplewebauthn/browser';

import {
  deriveKeyFromPassword,
  generateMasterKey,
  generateSalt,
  unwrapMasterKey,
  wrapMasterKey,
  bytesToBase64,
  base64ToBytes
} from '../crypto.js';

import { setMasterKey } from './keyStore.js';

const API_BASE = 'http://localhost:3000/api';

let authenticatedEmail = null;
let encryptionMetadata = null;

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

function showSection(sectionId) {
  [
    'passkey-section',
    'encryption-setup',
    'encryption-unlock'
  ].forEach(id => {
    $(id).style.display = id === sectionId ? 'block' : 'none';
  });
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
    showMessage(
      'passkey-message',
      error.message || 'Passkey registration failed.'
    );
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

async function loginWithPasskey() {
  const button = $('passkey-login-btn');

  try {
    clearMessage('passkey-message');

    const email = getEmail();

    setBusy(
      button,
      true,
      'Verifying passkey...',
      'Sign in with Passkey'
    );

    const optionsData = await post(
      '/auth/passkey/login/options',
      { email }
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
    showMessage(
      'passkey-message',
      error.message || 'Passkey login failed.'
    );
  } finally {
    setBusy(
      button,
      false,
      '',
      'Sign in with Passkey'
    );
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

    const salt = generateSalt();

    const derivedKey = await deriveKeyFromPassword(
      password,
      salt
    );

    const masterKey = await generateMasterKey();

    const wrapped = await wrapMasterKey(
      masterKey,
      derivedKey
    );

    await post(
      '/auth/did/encryption-setup',
      {
        encryptionSalt: bytesToBase64(salt),
        wrappedMasterKey: wrapped.wrappedMasterKey,
        masterKeyIV: wrapped.masterKeyIV
      },
      true
    );

    await setMasterKey(masterKey, authenticatedEmail);

    $('encryption-password').value = '';
    $('encryption-password-confirm').value = '';

    window.location.href = 'dashboard.html';

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

    const masterKey = await unwrapMasterKey(
      encryptionMetadata.wrappedMasterKey,
      encryptionMetadata.masterKeyIV,
      derivedKey
    );

    await setMasterKey(masterKey, authenticatedEmail);

    $('unlock-password').value = '';

    window.location.href = 'dashboard.html';

  } catch (error) {
    console.error(error);

    showMessage(
      'unlock-message',
      'Could not unlock your files. Check your encryption password.'
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
    loginWithPasskey
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
});
