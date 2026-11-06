import {
  apiGetAdminAudit,
  apiGetAdminAuditStats,
  apiGetMyAudit,
  apiGetMyAuditStats,
  apiVerifyAuditEvent
} from '../api.js';

const PAGE_SIZE = 20;
const EXPLORER_BASES = {
  '1': 'https://etherscan.io',
  '11155111': 'https://sepolia.etherscan.io'
};

let isAdmin = false;
let currentPage = 1;
let totalPages = 1;

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showAuditToast(message, type = 'success') {
  const toast = document.getElementById('toast');

  if (!toast) return;

  toast.textContent = message;
  toast.className = type;
  toast.style.display = 'block';

  setTimeout(() => {
    toast.style.display = 'none';
  }, 3000);
}

function getFilters() {
  const params = {
    eventType: document.getElementById('auditEventFilter')?.value || '',
    severity: document.getElementById('auditSeverityFilter')?.value || '',
    blockchainStatus: document.getElementById('auditStatusFilter')?.value || '',
    page: String(currentPage),
    limit: String(PAGE_SIZE)
  };

  if (isAdmin) {
    params.accountRef = document.getElementById('adminAccountFilter')?.value.trim() || '';
  }

  return params;
}

async function loadAuditStats() {
  const statsContainer = document.getElementById(
    isAdmin ? 'adminAuditSection' : 'userAuditStats'
  );

  if (!statsContainer) return;

  try {
    const stats = isAdmin
      ? await apiGetAdminAuditStats()
      : await apiGetMyAuditStats();
    const values = isAdmin
      ? {
          adminAuditTotal: stats.total,
          adminAuditAnchored: stats.anchored,
          adminAuditPending: stats.pending,
          adminAuditFailed: stats.failed,
          adminAuditAccounts: stats.accountsWithEvents
        }
      : {
          auditTotal: stats.total,
          auditAnchored: stats.anchored,
          auditPending: stats.pending,
          auditFailed: stats.failed,
          auditCritical: stats.critical
        };

    Object.entries(values).forEach(([id, value]) => {
      const element = document.getElementById(id);
      if (element) element.textContent = Number(value) || 0;
    });
  } catch (error) {
    console.error('Failed to load audit statistics:', error);
    showAuditToast('Failed to load audit statistics', 'error');
  }
}

function renderAuditEvent(event) {
  const eventId = escapeHtml(event.eventId);
  const status = escapeHtml(event.blockchainStatus);
  const severity = escapeHtml(event.severity);
  const transactionHash = event.transactionHash
    ? escapeHtml(event.transactionHash)
    : 'Not available';

  return `
    <article class="audit-event-card">
      <div class="audit-event-top">
        <h3>${escapeHtml(event.eventType)}</h3>
        <span class="audit-status status-${status}">${status}</span>
      </div>
      <div class="audit-event-meta">
        ${isAdmin ? `<div><strong>Account reference:</strong> ${escapeHtml(event.accountRef)}</div>` : ''}
        <div><strong>Initiator:</strong> ${escapeHtml(event.initiator)}</div>
        <div><strong>Severity:</strong> <span class="severity-${severity}">${severity}</span></div>
        <div><strong>Timestamp:</strong> ${escapeHtml(event.timestamp)}</div>
        <div><strong>Event ID:</strong> ${eventId}</div>
        <div><strong>Commitment:</strong> ${escapeHtml(event.commitment)}</div>
        <div><strong>Transaction hash:</strong> ${transactionHash}</div>
      </div>
      <div class="audit-event-actions">
        <button class="btn-verify" type="button" data-event-id="${eventId}">Verify on blockchain</button>
      </div>
      <div class="verification-result" id="verification-${eventId}" aria-live="polite"></div>
    </article>
  `;
}

async function loadAuditEvents() {
  const container = document.getElementById('auditEventsContainer');

  if (!container) return;

  container.innerHTML = '<p class="audit-empty">Loading audit activity...</p>';

  try {
    const data = isAdmin
      ? await apiGetAdminAudit(getFilters())
      : await apiGetMyAudit(getFilters());
    const events = data.events || [];
    const pagination = data.pagination || {};

    currentPage = Number(pagination.page) || currentPage;
    totalPages = Math.max(1, Number(pagination.totalPages) || 1);
    container.innerHTML = events.length
      ? events.map(renderAuditEvent).join('')
      : '<div class="audit-empty">No audit events match these filters.</div>';

    const pageInfo = document.getElementById('auditPageInfo');
    const previousButton = document.getElementById('auditPrevBtn');
    const nextButton = document.getElementById('auditNextBtn');

    if (pageInfo) pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    if (previousButton) previousButton.disabled = currentPage <= 1;
    if (nextButton) nextButton.disabled = currentPage >= totalPages;
  } catch (error) {
    console.error('Failed to load audit events:', error);
    container.innerHTML = '<div class="audit-empty">Failed to load audit activity.</div>';
    showAuditToast('Failed to load audit activity', 'error');
  }
}

function getExplorerUrl(chainId, transactionHash) {
  const baseUrl = EXPLORER_BASES[String(chainId)];
  return baseUrl && transactionHash
    ? `${baseUrl}/tx/${encodeURIComponent(transactionHash)}`
    : null;
}

function renderVerificationDetails(result) {
  const network = result.network || result.blockchain || {};
  const database = result.database || {};
  const blockchain = result.blockchain || {};
  const transactionHash = database.transactionHash;
  const explorerUrl = getExplorerUrl(network.chainId, transactionHash);

  return `
    <div class="verification-details">
      <p><strong>Chain ID:</strong> ${escapeHtml(network.chainId || 'Unavailable')}</p>
      <p><strong>Contract:</strong> ${escapeHtml(network.contractAddress || 'Unavailable')}</p>
      <p><strong>Read from contract:</strong> <code>getAuditEvent(bytes32 eventId)</code></p>
      <p><strong>Event ID:</strong> ${escapeHtml(result.eventId)}</p>
      <p><strong>Audit record commitment:</strong> ${escapeHtml(database.commitment || 'Unavailable')}</p>
      <p><strong>On-chain commitment:</strong> ${escapeHtml(blockchain.commitment || 'Not found')}</p>
      <p><strong>Transaction hash:</strong> ${
        transactionHash
          ? `${escapeHtml(transactionHash)}${explorerUrl
            ? ` · <a href="${explorerUrl}" target="_blank" rel="noopener noreferrer">Open in block explorer</a>`
            : ' · No public explorer link is configured for this chain ID.'}`
          : 'Not available'
      }</p>
      ${blockchain.anchoredAt ? `<p><strong>Anchored at:</strong> ${escapeHtml(blockchain.anchoredAt)}</p>` : ''}
      ${blockchain.signer ? `<p><strong>Signer:</strong> ${escapeHtml(blockchain.signer)}</p>` : ''}
      <p class="verification-guidance">For an independent check, open the contract on a block explorer for this chain,
        call <code>getAuditEvent</code> with the event ID, then compare its commitment with the audit record commitment above.</p>
    </div>
  `;
}

async function verifyAuditEvent(eventId, button) {
  const resultContainer = document.getElementById(`verification-${eventId}`);
  if (!resultContainer) return;

  if (button) {
    button.disabled = true;
    button.textContent = 'Verifying...';
  }

  resultContainer.textContent = 'Checking the on-chain commitment...';
  resultContainer.className = 'verification-result';

  try {
    const result = await apiVerifyAuditEvent(eventId);
    const verified = result.verified === true;

    resultContainer.className = `verification-result ${verified ? 'success' : 'error'}`;
    resultContainer.innerHTML =
      `<p><strong>${escapeHtml(result.status || 'Verification result')}:</strong> ${escapeHtml(result.message || '')}</p>` +
      renderVerificationDetails(result);
  } catch (error) {
    console.error('Audit verification failed:', error);
    resultContainer.textContent = `Verification failed: ${error.message}`;
    resultContainer.className = 'verification-result error';
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Verify on blockchain';
    }
  }
}

function attachAuditListeners() {
  const container = document.getElementById('auditEventsContainer');

  if (container && container.dataset.listenersAttached !== 'true') {
    container.dataset.listenersAttached = 'true';
    container.addEventListener('click', event => {
      const button = event.target.closest('.btn-verify');
      if (button?.dataset.eventId) {
        verifyAuditEvent(button.dataset.eventId, button);
      }
    });
  }

  document.getElementById('refreshAuditBtn')
    ?.addEventListener('click', refreshAuditDashboard);
  document.getElementById('applyAuditFiltersBtn')
    ?.addEventListener('click', () => {
      currentPage = 1;
      loadAuditEvents();
    });
  document.getElementById('auditPrevBtn')
    ?.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage -= 1;
        loadAuditEvents();
      }
    });
  document.getElementById('auditNextBtn')
    ?.addEventListener('click', () => {
      if (currentPage < totalPages) {
        currentPage += 1;
        loadAuditEvents();
      }
    });
}

async function refreshAuditDashboard() {
  const button = document.getElementById('refreshAuditBtn');

  if (button) {
    button.disabled = true;
    button.textContent = 'Refreshing...';
  }

  try {
    await Promise.all([loadAuditStats(), loadAuditEvents()]);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Refresh';
    }
  }
}

export async function initAuditDashboard(admin = false) {
  isAdmin = admin;
  document.getElementById('userAuditStats')?.classList.toggle('hidden', isAdmin);
  document.getElementById('adminAuditSection')?.classList.toggle('hidden', !isAdmin);
  document.getElementById('adminAccountFilter')?.classList.toggle('hidden', !isAdmin);
  attachAuditListeners();
  await refreshAuditDashboard();
  return isAdmin;
}

export {
  loadAuditEvents,
  loadAuditStats,
  refreshAuditDashboard,
  verifyAuditEvent
};
