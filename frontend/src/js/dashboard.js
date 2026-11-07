import {
  apiDeleteAccount,
  apiGetDeletionStatus,
  apiLogout
} from '../api.js';

import {
  clearSession,
  getMasterKey,
  getUserEmail,
  hydrateSession,
  isSessionActive
} from './keyStore.js';

import { initAuditDashboard } from './auditDashboard.js';
import { initFileDashboard } from './fileDashboard.js';

async function handleLogout() {
  try {
    await apiLogout();
  } catch (error) {
    console.warn('Server logout could not be confirmed:', error);
  } finally {
    clearSession();
    window.location.href = 'index.html';
  }
}

function updateAdminVisibility(isAdmin) {
  const adminElements = document.querySelectorAll('.admin-only');

  adminElements.forEach(element => {
    element.classList.toggle('hidden', !isAdmin);
  });
}

async function handleDeleteAccount() {
  const email = getUserEmail() || 'your account';
  const confirmed = confirm(
    `Schedule deletion for ${email}?\n\n` +
    'Your account and encrypted files will be deleted after the configured grace period. ' +
    'Log in again before the scheduled time to cancel the deletion.'
  );

  if (!confirmed) return;

  const deleteButton = document.getElementById('delete-account-btn');
  if (deleteButton) {
    deleteButton.disabled = true;
    deleteButton.textContent = 'Scheduling...';
  }

  try {
    const result = await apiDeleteAccount();
    const scheduledDate = new Date(result.scheduledFor);
    const scheduledTime = Number.isNaN(scheduledDate.getTime())
      ? 'the scheduled time returned by the server'
      : scheduledDate.toLocaleString();

    clearSession();
    apiLogout();

    alert(
      `Account deletion is scheduled for ${scheduledTime}.\n\n` +
      'Your account and active data will be deleted at that time. ' +
      'To cancel, log in again before the scheduled time. ' +
      'Immutable recovery records are retained according to the recovery storage retention policy.'
    );

    window.location.replace('index.html');
  } catch (error) {
    console.error('Account deletion scheduling failed:', error);
    alert(`Could not schedule account deletion: ${error.message}`);

    if (deleteButton) {
      deleteButton.disabled = false;
      deleteButton.textContent = 'Delete Account';
    }
  }
}

function showDashboardPage(page) {
  document.querySelectorAll('.dashboard-page').forEach(section => {
    const isActive = section.id === `${page}-page`;
    section.classList.toggle('hidden', !isActive);
    section.setAttribute('aria-hidden', String(!isActive));
  });

  document.querySelectorAll('.dashboard-tab').forEach(button => {
    const isActive = button.dataset.page === page;
    button.classList.toggle('active', isActive);
    button.setAttribute('aria-selected', String(isActive));
    button.tabIndex = isActive ? 0 : -1;
  });
}

function initializeDashboardPages(isAdmin) {
  const tabs = document.getElementById('dashboard-tabs');
  const fileTab = document.getElementById('files-tab');

  if (!isAdmin) {
    tabs?.classList.remove('hidden');
    fileTab?.addEventListener('click', () => showDashboardPage('files'));
    document.getElementById('audit-tab')
      ?.addEventListener('click', () => showDashboardPage('audit'));
    showDashboardPage('files');
    return;
  }

  fileTab?.classList.add('hidden');
  document.getElementById('audit-tab')?.classList.add('hidden');
  showDashboardPage('audit');
}

function initDashboard() {
  document.getElementById('logout-btn')
    ?.addEventListener('click', handleLogout);
  document.getElementById('delete-account-btn')
    ?.addEventListener('click', handleDeleteAccount);
}

async function init() {
  const restored = await hydrateSession();

  if (!restored || !isSessionActive()) {
    window.location.replace('index.html');
    return;
  }

  // A page reload intentionally discards the in-memory Master Key.
  // Re-authenticate the session and ask for the separate encryption password.
  if (!getMasterKey()) {
    window.location.replace('index.html?restore=1');
    return;
  }

  const emailElement = document.getElementById('user-email');
  if (emailElement) emailElement.textContent = getUserEmail() || '';

  initDashboard();

  try {
    const account = await apiGetDeletionStatus();
    const isAdmin = account.role === 'ADMIN';
    updateAdminVisibility(isAdmin);

    await initAuditDashboard(isAdmin);
    if (!isAdmin) await initFileDashboard();
    initializeDashboardPages(isAdmin);

    document.getElementById('dashboard-pages')?.setAttribute('aria-busy', 'false');
  } catch (error) {
    console.error('Dashboard initialization failed:', error);
    alert(`Could not load the dashboard: ${error.message}`);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
