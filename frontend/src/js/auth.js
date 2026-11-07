import {
  apiDidChallenge,
  apiDidEncryptionSetup,
  apiDidLogin,
  apiDidRegister,
  apiDidStatus,
  base64ToUint8Array
} from '../api.js';
import {
  bytesToBase64,
  deriveKeyFromPassword,
  generateMasterKey,
  generateSalt,
  unwrapMasterKey,
  wrapMasterKey
} from '../crypto.js';
import {
  createDidIdentity,
  downloadIdentityBackup,
  getStoredIdentity,
  parseIdentityBackupFile,
  restoreEncryptedIdentityBackup,
  signDidChallenge
} from '../did/didIdentity.js';
import { setMasterKey } from './keyStore.js';

const $ = id => document.getElementById(id);
let pendingEncryptionSetup = null;

function showError(id, message) {
  const element = $(id);
  element.textContent = message;
  element.style.display = 'block';
}

function clearError(id) {
  const element = $(id);
  if (!element) return;
  element.textContent = '';
  element.style.display = 'none';
}

function setBusy(button, busy, busyText, idleText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : idleText;
}

function showLogin() {
  $('auth-tabs').style.display = '';
  $('login-form').style.display = '';
  $('signup-form').style.display = 'none';
  $('encryption-setup').style.display = 'none';
  $('tab-login').classList.add('active');
  $('tab-signup').classList.remove('active');
  $('screen-title').textContent = 'Welcome back';
  $('screen-subtitle').textContent = 'Sign in with your decentralized identity.';
}

function showSignup() {
  $('auth-tabs').style.display = '';
  $('login-form').style.display = 'none';
  $('signup-form').style.display = '';
  $('encryption-setup').style.display = 'none';
  $('tab-signup').classList.add('active');
  $('tab-login').classList.remove('active');
  $('screen-title').textContent = 'Create your identity';
  $('screen-subtitle').textContent = 'Your DID is generated and controlled on this device.';
}

function showEncryptionSetup(email) {
  $('auth-tabs').style.display = 'none';
  $('login-form').style.display = 'none';
  $('signup-form').style.display = 'none';
  $('encryption-setup').style.display = '';
  $('screen-title').textContent = 'Protect your files';
  $('screen-subtitle').textContent = `Set up file encryption for ${email}.`;
  $('encryption-password').focus();
}

async function completeEncryptionSetup(email) {
  clearError('setup-error');
  const password = $('encryption-password').value;
  const confirmation = $('encryption-password-confirm').value;
  if (password.length < 8) throw new Error('Your file encryption password must be at least 8 characters.');
  if (password !== confirmation) throw new Error('The file encryption passwords do not match.');

  if (!pendingEncryptionSetup) {
    const salt = generateSalt();
    const derivedKey = await deriveKeyFromPassword(password, salt);
    const masterKey = await generateMasterKey();
    const wrapped = await wrapMasterKey(masterKey, derivedKey);
    pendingEncryptionSetup = {
      password,
      masterKey,
      encryptionSalt: bytesToBase64(salt),
      wrappedMasterKey: wrapped.wrappedMasterKey,
      masterKeyIV: wrapped.masterKeyIV
    };
  } else if (pendingEncryptionSetup.password !== password) {
    throw new Error('A setup attempt is pending. Retry with the same password, or reload and sign in again.');
  }

  await apiDidEncryptionSetup(
    pendingEncryptionSetup.encryptionSalt,
    pendingEncryptionSetup.wrappedMasterKey,
    pendingEncryptionSetup.masterKeyIV
  );
  await setMasterKey(pendingEncryptionSetup.masterKey, email);
  pendingEncryptionSetup = null;
  window.location.href = 'dashboard.html';
}

async function handleSignup() {
  clearError('signup-error');
  const email = $('signup-email').value.trim().toLowerCase();
  const backupPassword = $('signup-backup-password').value;
  const button = $('signup-btn');
  if (!email || !email.includes('@')) return showError('signup-error', 'Enter a valid email address.');
  if (backupPassword.length < 12) return showError('signup-error', 'Your identity backup password must be at least 12 characters.');

  setBusy(button, true, 'Creating DID identity...', 'Create DID identity');
  try {
    // Reuse an existing local identity when a previous registration attempt
    // was interrupted; never silently overwrite the device's current DID key.
    let identity = await getStoredIdentity();
    if (!identity?.did || !identity?.privateKey) {
      identity = await createDidIdentity(backupPassword);
    }
    await downloadIdentityBackup();

    const { challengeId, challenge } = await apiDidChallenge(email, identity.did, 'register');
    const proof = await signDidChallenge(challenge);
    const result = await apiDidRegister(email, identity.did, challengeId, proof.signature);

    $('encryption-password').value = '';
    $('encryption-password-confirm').value = '';
    showEncryptionSetup(result.email || email);
  } catch (error) {
    showError('signup-error', error.message || 'Could not create your account.');
  } finally {
    setBusy(button, false, '', 'Create DID identity');
  }
}

async function handleLogin() {
  clearError('login-error');
  const email = $('login-email').value.trim().toLowerCase();
  const encryptionPassword = $('login-encryption-password').value;
  const button = $('login-btn');
  if (!email || !email.includes('@')) return showError('login-error', 'Enter a valid email address.');
  if (!encryptionPassword) return showError('login-error', 'Enter your file encryption password.');

  setBusy(button, true, 'Verifying DID...', 'Sign in with DID');
  try {
    const identity = await getStoredIdentity();
    if (!identity?.did || !identity?.privateKey) {
      throw new Error('No DID identity is available on this device. Restore your encrypted identity backup below first.');
    }

    const { challengeId, challenge } = await apiDidChallenge(email, identity.did, 'login');
    const proof = await signDidChallenge(challenge);
    const result = await apiDidLogin(email, identity.did, challengeId, proof.signature);

    if (!result.encryptionReady || result.nextStep === 'encryption-setup') {
      showEncryptionSetup(email);
      return;
    }

    try {
      const salt = base64ToUint8Array(result.encryptionSalt);
      const derivedKey = await deriveKeyFromPassword(encryptionPassword, salt);
      const masterKey = await unwrapMasterKey(result.wrappedMasterKey, result.masterKeyIV, derivedKey);
      await setMasterKey(masterKey, email);
      window.location.href = 'dashboard.html';
    } catch {
      sessionStorage.removeItem('token');
      throw new Error('DID authentication succeeded, but the file encryption password is incorrect.');
    }
  } catch (error) {
    showError('login-error', error.message || 'Login failed.');
  } finally {
    setBusy(button, false, '', 'Sign in with DID');
  }
}

async function handleRestoreIdentity() {
  clearError('restore-error');
  const file = $('identity-backup-file').files[0];
  const password = $('identity-backup-password').value;
  if (!file || !password) return showError('restore-error', 'Select your identity backup file and enter its backup password.');
  const button = $('restore-btn');
  setBusy(button, true, 'Restoring...', 'Restore identity');
  try {
    const backup = await parseIdentityBackupFile(file);
    const restored = await restoreEncryptedIdentityBackup(backup, password);
    showError('restore-error', `Identity restored: ${restored.did}`);
    $('restore-error').style.color = '#6ee7b7';
  } catch (error) {
    showError('restore-error', error.message || 'Could not restore identity.');
    $('restore-error').style.color = '#f87171';
  } finally {
    setBusy(button, false, '', 'Restore identity');
  }
}

async function initAuthScreen() {
  $('tab-login').addEventListener('click', showLogin);
  $('tab-signup').addEventListener('click', showSignup);
  $('login-btn').addEventListener('click', handleLogin);
  $('signup-btn').addEventListener('click', handleSignup);
  $('restore-btn').addEventListener('click', handleRestoreIdentity);
  $('setup-btn').addEventListener('click', async () => {
    const button = $('setup-btn');
    setBusy(button, true, 'Setting up encryption...', 'Set up file encryption');
    try {
      const email = $('signup-email').value.trim().toLowerCase() || $('login-email').value.trim().toLowerCase() || sessionStorage.getItem('secureDriveUserEmail');
      if (!email) throw new Error('Your account email is missing. Please sign in again.');
      await completeEncryptionSetup(email);
    } catch (error) {
      showError('setup-error', error.message || 'Encryption setup failed.');
    } finally {
      setBusy(button, false, '', 'Set up file encryption');
    }
  });

  // Allow an interrupted first-time setup to resume after a page refresh.
  if (sessionStorage.getItem('token')) {
    try {
      const status = await apiDidStatus();
      $('login-email').value = sessionStorage.getItem('secureDriveUserEmail') || '';
      if (status.encryptionReady) {
        if (sessionStorage.getItem('secureDriveMasterKey')) {
          window.location.href = 'dashboard.html';
          return;
        }
        // A token alone is not enough to unlock files; ask the user to prove
        // DID control again and enter the independent encryption password.
        showLogin();
        return;
      }
      showEncryptionSetup($('login-email').value || 'your account');
      return;
    } catch {
      sessionStorage.removeItem('token');
    }
  }
  showLogin();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAuthScreen);
} else {
  initAuthScreen();
}
