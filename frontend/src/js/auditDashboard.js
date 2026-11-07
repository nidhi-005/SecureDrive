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
let selectedDays = 30;
const auditCharts = {};

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

function renderAuditCharts(stats) {
  if (typeof Chart === 'undefined') {
    console.error('Chart.js is not loaded');
    return;
  }

  const chartConfigs = {
    auditTrendChart: {
      type: 'line',
      data: {
        labels: stats.daily.map(x => x._id),
        datasets: [{
          label: 'Audit events',
          data: stats.daily.map(x => x.count),
          tension: 0.35,
          fill: true
        }]
      }
    },

    auditSeverityChart: {
      type: 'doughnut',
      data: {
        labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        datasets: [{
          data: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(
            level => stats.severity.find(x => x._id === level)?.count || 0
          )
        }]
      }
    },

    auditCategoryChart: {
      type: 'bar',
      data: {
        labels: stats.categories.map(x => x._id.replace(/_/g, ' ')),
        datasets: [{
          label: 'Events',
          data: stats.categories.map(x => x.count),
          backgroundColor: '#1eb5fb'
        }]
      }
    },

    auditBlockchainChart: {
      type: 'doughnut',
      data: {
        labels: ['Anchored', 'Pending', 'Batched', 'Failed'],
        datasets: [{
          data: [
            stats.anchoring.anchored,
            stats.anchoring.pending,
            stats.anchoring.batched,
            stats.anchoring.failed
          ]
        }]
      }
    },

    auditEventTypeChart: {
      type: 'bar',
      data: {
        labels: stats.eventTypes.map(x =>
          x._id.replace(/_/g, ' ')
        ),
        datasets: [{
          label: 'Events',
          data: stats.eventTypes.map(x => x.count),
          backgroundColor: '#1eb5fb'
        }]
      }
    },

    auditAccountChart: {
      type: 'bar',
      data: {
        labels: stats.accounts.map(x => x._id),
        datasets: [{
          label: 'Audit events',
          data: stats.accounts.map(x => x.total),
          backgroundColor: '#1eb5fb'
        }]
      }
    },

    auditIncidentAccountChart: {
      type: 'bar',
      data: {
        labels: stats.security.incidentAccounts.map(x => x._id),
        datasets: [{
          label: 'Security incidents',
          data: stats.security.incidentAccounts.map(x => x.incidents),
          backgroundColor: '#1eb5fb'
        }]
      }
    }
  };

  Object.entries(chartConfigs).forEach(([id, config]) => {
    if (
      !isAdmin &&
      ['auditAccountChart', 'auditIncidentAccountChart'].includes(id)
    ) {
      return;
    }

    const canvas = document.getElementById(id);
    if (!canvas) return;

    if (auditCharts[id]) {
      auditCharts[id].destroy();
    }

    auditCharts[id] = new Chart(canvas, {
      ...config,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: config.type === 'doughnut',
            position: 'bottom'
          }
        },
        scales: config.type === 'line' || config.type === 'bar'
          ? { y: { beginAtZero: true, ticks: { precision: 0 } } }
          : {}
      }
    });
  });

  const formatDuration = ms => {
    if (!ms) return '0 min';

    const minutes = Math.floor(ms / 60000);

    if (minutes < 60) return `${minutes} min`;

    const hours = Math.floor(minutes / 60);

    if (hours < 24) return `${hours} hr`;

    return `${Math.floor(hours / 24)} days`;
  };

  const insights = {
    auditFailedLogins: stats.security.failedLogins,
    auditIntegrityMismatches: stats.security.integrityMismatches,
    auditRecoveryFailures: stats.security.recoveryFailures,

    auditAnchorSuccessRate: `${stats.anchoring.successRate}%`,

    auditFailedLoginRate: `${stats.security.failedLoginRate}%`,

    auditSuspiciousEvents: stats.security.suspiciousEvents
      .reduce((sum, item) => sum + item.count, 0),

    auditAverageAnchorTime: formatDuration(
      stats.anchoring.averageConfirmationMs
    ),

    auditOldestPendingAge: formatDuration(
      stats.anchoring.oldestPendingAgeMs
    )
  };

  Object.entries(insights).forEach(([id, value]) => {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  });
}

async function loadAuditStats() {
  const statsContainer = document.getElementById(
    isAdmin ? 'adminAuditSection' : 'userAuditStats'
  );

  if (!statsContainer) return;

  try {
    const stats = isAdmin
      ? await apiGetAdminAuditStats(selectedDays)
      : await apiGetMyAuditStats(selectedDays);
    const values = isAdmin
      ? {
        adminAuditTotal: stats.total,
        adminAuditAnchored: stats.anchoring.anchored,
        adminAuditPending: stats.anchoring.pending,
        adminAuditFailed: stats.anchoring.failed,
        adminAuditAccounts: stats.accountsWithEvents
      }
      : {
        auditTotal: stats.total,
        auditAnchored: stats.anchoring.anchored,
        auditPending: stats.anchoring.pending,
        auditFailed: stats.anchoring.failed,
        auditCritical: stats.severity.find(
          item => item._id === 'CRITICAL'
        )?.count || 0
      };

    Object.entries(values).forEach(([id, value]) => {
      const element = document.getElementById(id);
      if (element) element.textContent = Number(value) || 0;
    });
    renderAuditCharts(stats);
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
      <p><strong>Transaction hash:</strong> ${transactionHash
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

  document.getElementById('auditPeriod')
    ?.addEventListener('change', async event => {
      selectedDays = Number(event.target.value) || 30;
      currentPage = 1;
      await refreshAuditDashboard();
    });

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

