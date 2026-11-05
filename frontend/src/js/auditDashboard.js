import {
  apiGetMyAudit,
  apiGetMyAuditStats,
  apiVerifyAuditEvent
} from '../api.js';

// =====================================================
// HELPERS
// =====================================================

function escapeHtml(str) {
  return String(str ?? '')
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

// =====================================================
// LOAD AUDIT STATISTICS
// =====================================================

async function loadAuditStats() {
  const container = document.getElementById('userAuditStats');

  if (!container) return;

  try {
    const stats = await apiGetMyAuditStats();

    const values = {
      auditTotal: stats.total,
      auditAnchored: stats.anchored,
      auditPending: stats.pending,
      auditFailed: stats.failed,
      auditCritical: stats.critical
    };

    Object.entries(values).forEach(([id, value]) => {
      const element = document.getElementById(id);

      if (element) {
        element.textContent = Number(value) || 0;
      }
    });

  } catch (err) {
    console.error('Failed to load audit statistics:', err);
    showAuditToast('Failed to load audit statistics', 'error');
  }
}

// =====================================================
// LOAD AUDIT EVENTS
// =====================================================

async function loadAuditEvents() {
  const container = document.getElementById('auditEventsContainer');

  if (!container) return;

  container.innerHTML = `
    <p class="audit-empty">Loading audit activity...</p>
  `;

  try {
    const data = await apiGetMyAudit();
    const events = data.events || [];

    if (!events.length) {
      container.innerHTML = `
        <div class="audit-empty">
          No audit events found.
        </div>
      `;
      return;
    }

    container.innerHTML = events.map(event => {
      const eventId = escapeHtml(event.eventId);
      const status = escapeHtml(event.blockchainStatus);
      const severity = escapeHtml(event.severity);

      return `
        <div class="audit-event-card">

          <div class="audit-event-top">

            <h3>
              ${escapeHtml(event.eventType)}
            </h3>

            <span class="audit-status status-${status}">
              ${status}
            </span>

          </div>

          <div class="audit-event-meta">

            <div>
              <strong>Initiator:</strong>
              ${escapeHtml(event.initiator)}
            </div>

            <div>
              <strong>Severity:</strong>
              <span class="severity-${severity}">
                ${severity}
              </span>
            </div>

            <div>
              <strong>Timestamp:</strong>
              ${escapeHtml(event.timestamp)}
            </div>

            <div>
              <strong>Event ID:</strong>
              ${eventId}
            </div>

          </div>

          <div class="audit-event-actions">

            <button
              class="btn-verify"
              type="button"
              data-event-id="${eventId}">
              Verify Event
            </button>

          </div>

          <div
            class="verification-result"
            id="verification-${eventId}"
            aria-live="polite">
          </div>

        </div>
      `;
    }).join('');

  } catch (err) {
    console.error('Failed to load audit events:', err);

    container.innerHTML = `
      <div class="audit-empty">
        Failed to load audit activity.
      </div>
    `;
  }
}

// =====================================================
// VERIFY AUDIT EVENT
// =====================================================

async function verifyAuditEvent(eventId) {
  const resultContainer = document.getElementById(
    `verification-${eventId}`
  );

  if (!resultContainer) return;

  resultContainer.textContent =
    'Verifying against blockchain...';

  resultContainer.className = 'verification-result';

  try {
    const result = await apiVerifyAuditEvent(eventId);

    resultContainer.textContent =
      result.message || 'Verification completed.';

    resultContainer.className =
      'verification-result ' +
      (result.verified ? 'success' : 'error');

  } catch (err) {
    console.error('Audit verification failed:', err);

    resultContainer.textContent =
      'Verification failed: ' + err.message;

    resultContainer.className =
      'verification-result error';
  }
}

// =====================================================
// EVENT LISTENERS
// =====================================================

function attachAuditListeners() {
  const container = document.getElementById('auditEventsContainer');

  if (!container) return;

  // Event delegation avoids duplicate listeners after refresh.
  if (container.dataset.listenersAttached === 'true') return;

  container.dataset.listenersAttached = 'true';

  container.addEventListener('click', event => {
    const button = event.target.closest('.btn-verify');

    if (!button) return;

    const eventId = button.dataset.eventId;

    if (eventId) {
      verifyAuditEvent(eventId);
    }
  });

  const refreshButton = document.getElementById('refreshAuditBtn');

  refreshButton?.addEventListener('click', refreshAuditDashboard);
}

// =====================================================
// REFRESH DASHBOARD
// =====================================================

async function refreshAuditDashboard() {
  const button = document.getElementById('refreshAuditBtn');

  if (button) {
    button.disabled = true;
    button.textContent = 'Refreshing...';
  }

  try {
    await Promise.all([
      loadAuditStats(),
      loadAuditEvents()
    ]);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Refresh';
    }
  }
}

// =====================================================
// INITIALIZE
// =====================================================

export async function initAuditDashboard() {
  attachAuditListeners();

  await refreshAuditDashboard();
}

export {
  loadAuditEvents,
  loadAuditStats, refreshAuditDashboard, verifyAuditEvent
};

