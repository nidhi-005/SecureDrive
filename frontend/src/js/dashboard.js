
import {
  apiDeleteAccount,
  apiLogout
} from '../api.js';

import {
  clearSession,
  getUserEmail,
  hydrateSession,
  isSessionActive
} from './keyStore.js';

import {
  initFileDashboard
} from './fileDashboard.js';

import {
  initAuditDashboard
} from './auditDashboard.js';

// ── Logout ───────────────────────────────────────────────
function handleLogout() {
  clearSession();

  apiLogout();

  window.location.href = 'index.html';
}

// ── Delete Account ───────────────────────────────────────
async function handleDeleteAccount() {
  const email = getUserEmail() || 'your account';

  const confirmed = confirm(
    `Permanently delete ${email}?\n\n` +
    'This will delete your account, encrypted files stored in S3, ' +
    'and file metadata. Immutable recovery records will be retained ' +
    'according to the recovery storage retention policy. ' +
    'This action cannot be undone.'
  );

  if (!confirmed) return;

  const deleteBtn = document.getElementById('delete-account-btn');

  if (deleteBtn) {
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting...';
  }

  try {
    await apiDeleteAccount();

    clearSession();

    apiLogout();

    alert(
      'Your account and active data have been deleted. ' +
      'Immutable recovery records are retained according to the retention policy.'
    );

    window.location.replace('index.html');

  } catch (err) {
    console.error('Account deletion failed:', err);

    alert(
      `Account deletion failed: ${err.message}\n\n` +
      'Check the server logs before attempting again.'
    );

    if (deleteBtn) {
      deleteBtn.disabled = false;
      deleteBtn.textContent = 'Delete Account';
    }
  }
}

// ── Initialize Dashboard ─────────────────────────────────
function initDashboard() {
  document.getElementById('logout-btn')
    ?.addEventListener('click', handleLogout);

  document.getElementById('delete-account-btn')
    ?.addEventListener('click', handleDeleteAccount);
}

// ── Application Initialization ───────────────────────────
async function init() {
  const restored = await hydrateSession();

  if (!restored || !isSessionActive()) {
    window.location.href = 'index.html';
    return;
  }

  const emailElement = document.getElementById('user-email');

  if (emailElement) {
    emailElement.textContent = getUserEmail() || '';
  }

  initDashboard();

  await Promise.all([
    initFileDashboard(),
    initAuditDashboard()
  ]);
}

// ── Start Application ────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
