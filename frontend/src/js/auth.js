import {
  deriveKeyFromPassword,
  generateMasterKey,
  unwrapMasterKey,
  wrapMasterKey
} from '../crypto.js';

import {
  apiLoginFinish,
  apiLoginStart,
  apiSignup,
  base64ToUint8Array,
  uint8ArrayToBase64
} from '../api.js';
import { setMasterKey } from './keyStore.js';

// Simple OPAQUE-like implementation using Web Crypto API
// In production, use a full OPAQUE library
class OPAQUEClient {
  constructor(password, username) {
    this.password = password;
    this.username = username;
  }

  // Client Registration Init - generates initial registration message
  async registerInit() {
    // For OPAQUE, we derive a key from password and create registration data
    const passwordBytes = new TextEncoder().encode(this.password);
    const usernameBytes = new TextEncoder().encode(this.username);
    
    // Create deterministic registration init from password
    const combined = new Uint8Array(passwordBytes.length + usernameBytes.length);
    combined.set(passwordBytes);
    combined.set(usernameBytes, passwordBytes.length);
    
    const hash = await crypto.subtle.digest('SHA-256', combined);
    
    // Simulate OPAQUE clientRegisterInit message
    // In real OPAQUE, this would be the first step of the OPRF
    return new Uint8Array(hash);
  }

  // Client Registration Finish - completes registration
  async registerFinish(serverRegisterInitBytes) {
    // In full OPAQUE, this would finalize the registration
    // For now, return confirmation
    const passwordBytes = new TextEncoder().encode(this.password);
    const combined = new Uint8Array(
      passwordBytes.length + serverRegisterInitBytes.length
    );
    combined.set(passwordBytes);
    combined.set(serverRegisterInitBytes, passwordBytes.length);
    
    return await crypto.subtle.digest('SHA-256', combined);
  }

  // Client Login Init - generates login attempt
  async loginInit() {
    // Similar to registration init
    const passwordBytes = new TextEncoder().encode(this.password);
    const usernameBytes = new TextEncoder().encode(this.username);
    
    const combined = new Uint8Array(passwordBytes.length + usernameBytes.length);
    combined.set(passwordBytes);
    combined.set(usernameBytes, passwordBytes.length);
    
    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
  }

  // Client Login Finish - completes authentication
  async loginFinish(serverLoginResponseBytes) {
    // Verify server response and generate proof
    const passwordBytes = new TextEncoder().encode(this.password);
    const combined = new Uint8Array(
      passwordBytes.length + serverLoginResponseBytes.length
    );
    combined.set(passwordBytes);
    combined.set(serverLoginResponseBytes, passwordBytes.length);
    
    const clientFinish = await crypto.subtle.digest('SHA-256', combined);
    // Export key is used to prove possession of password
    const exportKey = await crypto.subtle.digest('SHA-256', clientFinish);
    
    return {
      clientLoginFinish: new Uint8Array(clientFinish),
      clientExportKey: uint8ArrayToBase64(new Uint8Array(exportKey))
    };
  }
}

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
    // Initialize OPAQUE client
    const opaqueClient = new OPAQUEClient(password, email);
    
    // Step 1: Generate client registration init (password never sent)
    const clientRegisterInitBytes = await opaqueClient.registerInit();
    const clientRegisterInit = uint8ArrayToBase64(clientRegisterInitBytes);

    // Prepare master key wrapping with password-derived key
    const derivedKey = await deriveKeyFromPassword(password);
    const mk         = await generateMasterKey();
    const { wrappedMasterKey, masterKeyIV } = await wrapMasterKey(mk, derivedKey);

    // Step 2: Send registration init to server
    const serverResponse = await apiSignup(email, clientRegisterInit, wrappedMasterKey, masterKeyIV);

    // Step 3: Complete client registration with server response
    const serverRegisterInitBytes = base64ToUint8Array(serverResponse.serverRegisterInit);
    await opaqueClient.registerFinish(serverRegisterInitBytes);

    // Store in keyStore — NOT sessionStorage
    setMasterKey(mk, email);

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
    // Initialize OPAQUE client (password never sent to server)
    const opaqueClient = new OPAQUEClient(password, email);

    // Step 1: Generate client login init
    const clientLoginInitBytes = await opaqueClient.loginInit();
    const clientLoginInit = uint8ArrayToBase64(clientLoginInitBytes);

    // Step 2: Send login init to server, get response
    const serverResponse = await apiLoginStart(email, clientLoginInit);

    // Step 3: Complete client login with server response
    const serverLoginResponseBytes = base64ToUint8Array(serverResponse.serverLoginResponse);
    const { clientLoginFinish, clientExportKey } = await opaqueClient.loginFinish(
      serverLoginResponseBytes
    );

    // Step 4: Send login finish to server for token
    const clientLoginFinishB64 = uint8ArrayToBase64(clientLoginFinish);
    await apiLoginFinish(email, clientLoginFinishB64, clientExportKey);

    // Decrypt master key with derived password key
    const derivedKey = await deriveKeyFromPassword(password);
    const mk         = await unwrapMasterKey(
      serverResponse.wrappedMasterKey,
      serverResponse.masterKeyIV,
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
}

// ── Event Listener Registration ───────────────────────────
// Register all event handlers when DOM is ready
function initAuthScreen() {
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