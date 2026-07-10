import {
  deriveKeyFromPassword,
  generateMasterKey,
  wrapMasterKey,
  unwrapMasterKey
} from '../crypto.js';

import { apiSignup, apiLogin } from '../api.js';
import { setMasterKey } from './keyStore.js';

// ── Tab switch ──────────────────────────────────────────────
window.switchTab = (tab) => {
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-signup').classList.toggle('active', tab === 'signup');
  document.getElementById('login-form').style.display  = tab === 'login'  ? '' : 'none';
  document.getElementById('signup-form').style.display = tab === 'signup' ? '' : 'none';
};

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
window.handleSignup = async () => {
  clearError('signup-error');
  const email    = document.getElementById('signup-email').value.trim();
  const password = document.getElementById('signup-password').value;

  if (!email || !password)  return showError('signup-error', 'Please fill in all fields');
  if (password.length < 8)  return showError('signup-error', 'Password must be at least 8 characters');

  const btn = document.getElementById('signup-btn');
  btn.disabled    = true;
  btn.textContent = 'Creating account...';

  try {
    const derivedKey = await deriveKeyFromPassword(password);
    const mk         = await generateMasterKey();
    const { wrappedMasterKey, masterKeyIV } = await wrapMasterKey(mk, derivedKey);

    await apiSignup(email, password, wrappedMasterKey, masterKeyIV);

    // Store in keyStore — NOT sessionStorage
    // mk is a non-extractable CryptoKey — JS cannot read raw bytes
    setMasterKey(mk, email);

    window.location.href = 'dashboard.html';
  } catch (err) {
    showError('signup-error', err.message);
    btn.disabled    = false;
    btn.textContent = 'Create Account';
  }
};

// ── LOGIN ───────────────────────────────────────────────────
window.handleLogin = async () => {
  clearError('login-error');
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  if (!email || !password) return showError('login-error', 'Please fill in all fields');

  const btn = document.getElementById('login-btn');
  btn.disabled    = true;
  btn.textContent = 'Logging in...';

  try {
    const data       = await apiLogin(email, password);
    const derivedKey = await deriveKeyFromPassword(password);
    const mk         = await unwrapMasterKey(
      data.wrappedMasterKey,
      data.masterKeyIV,
      derivedKey
    );

    // Store in keyStore — NOT sessionStorage
    setMasterKey(mk, email);

    window.location.href = 'dashboard.html';
  } catch (err) {
    showError('login-error', 'Invalid email or password');
    btn.disabled    = false;
    btn.textContent = 'Login';
  }
};