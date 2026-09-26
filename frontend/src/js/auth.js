import * as opaque from '@serenity-kit/opaque';

import {
  bytesToBase64,
  deriveKeyFromPassword,
  generateMasterKey,
  generateSalt,
  unwrapMasterKey,
  wrapMasterKey
} from '../crypto.js';

import {
  apiLoginFinish,
  apiLoginStart,
  apiSignupFinish,
  apiSignupRequest,
  base64ToUint8Array
} from '../api.js';
import { setMasterKey } from './keyStore.js';

// ── Tab switch ──────────────────────────────────────────────
function switchTab(tab) {
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-signup').classList.toggle('active', tab === 'signup');
  document.getElementById('login-form').style.display  = tab === 'login'  ? '' : 'none';
  document.getElementById('signup-form').style.display = tab === 'signup' ? '' : 'none';
}

function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent   = msg;
  el.style.display = 'block';
}

function clearError(id) {
  document.getElementById(id).style.display = 'none';
}

function attachEnterHandler(inputId, handler) {
  const input = document.getElementById(inputId);
  if (!input) return;

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      handler();
    }
  });
}

// ── SIGNUP ──────────────────────────────────────────────────
async function handleSignup() {
  clearError('signup-error');
  const email    = document.getElementById('signup-email').value.trim();
  const password = document.getElementById('signup-password').value;

  if (!email || !password)  return showError('signup-error', 'Please fill in all fields');
  if (password.length < 8)  return showError('signup-error', 'Password must be at least 8 characters');

  const btn = document.getElementById('signup-btn');
  btn.disabled    = true;
  btn.textContent = 'Creating account...';

  try {
    await opaque.ready;
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password });
    const serverResponse = await apiSignupRequest(email, registrationRequest);

    const registrationResult = opaque.client.finishRegistration({
      password,
      clientRegistrationState,
      registrationResponse: serverResponse.registrationResponse
    });

    const encryptionSalt = generateSalt();

    const derivedKey = await deriveKeyFromPassword(registrationResult.exportKey, encryptionSalt);
    const mk = await generateMasterKey();
    const { wrappedMasterKey, masterKeyIV } = await wrapMasterKey(mk, derivedKey);

    await apiSignupFinish(email, registrationResult.registrationRecord, wrappedMasterKey, masterKeyIV, bytesToBase64(encryptionSalt));

    await setMasterKey(mk, email);
    window.location.href = 'dashboard.html';
  } catch (err) {
    showError('signup-error', err.message);
    btn.disabled    = false;
    btn.textContent = 'Create Account';
  }
}

// ── LOGIN ───────────────────────────────────────────────────
async function handleLogin() {
  clearError('login-error');
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  if (!email || !password) return showError('login-error', 'Please fill in all fields');

  const btn = document.getElementById('login-btn');
  btn.disabled    = true;
  btn.textContent = 'Logging in...';

  try {
    await opaque.ready;
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
    const serverResponse = await apiLoginStart(email, startLoginRequest);

    const loginResult = opaque.client.finishLogin({
      password,
      clientLoginState,
      loginResponse: serverResponse.loginResponse
    });

    if (!loginResult) {
      throw new Error('Invalid email or password');
    }

    await apiLoginFinish(email, loginResult.finishLoginRequest);

    const encryptionSalt = base64ToUint8Array(serverResponse.encryptionSalt);

    const derivedKey = await deriveKeyFromPassword(loginResult.exportKey, encryptionSalt);
    const mk = await unwrapMasterKey(
      serverResponse.wrappedMasterKey,
      serverResponse.masterKeyIV,
      derivedKey
    );

    await setMasterKey(mk, email);
    window.location.href = 'dashboard.html';
  } catch (err) {
    showError('login-error', 'Invalid email or password');
    btn.disabled    = false;
    btn.textContent = 'Login';
  }
}

// ── Event Listener Registration ───────────────────────────
// Register all event handlers when DOM is ready
function initAuthScreen() {
  if (sessionStorage.getItem('token')) {
    window.location.href = 'dashboard.html';
    return;
  }

  // Tab switching
  const tabLogin = document.getElementById('tab-login');
  const tabSignup = document.getElementById('tab-signup');
  
  if (tabLogin) {
    tabLogin.addEventListener('click', () => switchTab('login'));
  }
  if (tabSignup) {
    tabSignup.addEventListener('click', () => switchTab('signup'));
  }

  // Login form
  const loginBtn = document.getElementById('login-btn');
  const loginEmail = document.getElementById('login-email');
  const loginPassword = document.getElementById('login-password');
  
  if (loginBtn) {
    loginBtn.addEventListener('click', handleLogin);
  }
  if (loginEmail) {
    attachEnterHandler('login-email', handleLogin);
  }
  if (loginPassword) {
    attachEnterHandler('login-password', handleLogin);
  }

  // Signup form
  const signupBtn = document.getElementById('signup-btn');
  const signupEmail = document.getElementById('signup-email');
  const signupPassword = document.getElementById('signup-password');
  
  if (signupBtn) {
    signupBtn.addEventListener('click', handleSignup);
  }
  if (signupEmail) {
    attachEnterHandler('signup-email', handleSignup);
  }
  if (signupPassword) {
    attachEnterHandler('signup-password', handleSignup);
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAuthScreen);
} else {
  initAuthScreen();
}