'use strict';

// ── State ──────────────────────────────────────────────────────────────
let currentPage = 1;
let currentFilter = '';
let totalPages = 1;

// ── Helpers ────────────────────────────────────────────────────────────

function statusIcon(status) {
  const icons = { safe: '✅', suspicious: '⚠️', malicious: '🚨', unknown: '❓', error: '⚡' };
  return icons[status] ?? '❓';
}

function timeAgo(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function vtLabel(score) {
  if (score === null || score === undefined) return 'N/A';
  if (score === 0) return '0 engines flagged';
  return `${score} engine${score === 1 ? '' : 's'} flagged`;
}

function sbLabel(hit, threatTypes) {
  if (hit === null || hit === undefined) return 'N/A';
  if (!hit) return '✅ Clean';
  const types = (threatTypes && threatTypes.length > 0)
    ? threatTypes.join(', ')
    : 'flagged';
  return `⚠️ ${types}`;
}

function domainAgeLabel(days, flag) {
  if (days === null || days === undefined) return 'N/A';
  const label = `${days} day${days === 1 ? '' : 's'}`;
  return flag ? `${label} ⚠️ New domain` : label;
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Result panel ───────────────────────────────────────────────────────

function renderResult(scan) {
  const section = document.getElementById('result-section');
  const panel = document.getElementById('result-panel');

  // Reset classes
  panel.className = `result-panel status-${scan.status}`;

  panel.innerHTML = `
    <div class="result-header">
      <span class="status-badge status-${escapeHTML(scan.status)}">
        ${statusIcon(scan.status)} ${escapeHTML(scan.status)}
      </span>
      <span class="result-url" title="${escapeHTML(scan.url)}">${escapeHTML(scan.url)}</span>
    </div>

    <div class="result-grid">
      <div class="check-card">
        <div class="check-label">VirusTotal</div>
        <div class="check-value">${escapeHTML(vtLabel(scan.virustotal_score))}</div>
        ${scan.virustotal_link
          ? `<div class="check-sub"><a href="${escapeHTML(scan.virustotal_link)}" target="_blank" rel="noopener">View report ↗</a></div>`
          : ''}
      </div>

      <div class="check-card">
        <div class="check-label">Safe Browsing</div>
        <div class="check-value">${escapeHTML(sbLabel(scan.safe_browsing_hit, scan.threat_types))}</div>
      </div>

      <div class="check-card">
        <div class="check-label">Domain Age</div>
        <div class="check-value">${escapeHTML(domainAgeLabel(scan.domain_age_days, scan.domain_age_flag))}</div>
        ${scan.domain_created_at
          ? `<div class="check-sub">Registered ${new Date(scan.domain_created_at).toLocaleDateString()}</div>`
          : ''}
      </div>
    </div>

    <div class="result-actions">
      <a class="btn-secondary" href="/api/scans/${escapeHTML(scan.id)}" target="_blank" rel="noopener">
        View full JSON
      </a>
    </div>
  `;

  section.hidden = false;
}

// ── History table ──────────────────────────────────────────────────────

async function loadHistory() {
  const tbody = document.getElementById('history-tbody');
  const emptyRow = document.getElementById('history-empty');
  const pagination = document.getElementById('pagination');

  const params = new URLSearchParams({
    page: currentPage,
    limit: 20,
  });
  if (currentFilter) params.set('status', currentFilter);

  let data;
  try {
    const res = await fetch(`/api/scans?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch (err) {
    console.error('Failed to load history:', err);
    return;
  }

  const scans = data.data ?? [];
  totalPages = Math.max(1, Math.ceil(data.total / data.limit));

  // Clear existing rows (keep the empty-state row, we'll toggle it)
  Array.from(tbody.querySelectorAll('tr:not(#history-empty)')).forEach(r => r.remove());

  if (scans.length === 0) {
    emptyRow.hidden = false;
    pagination.hidden = true;
    return;
  }

  emptyRow.hidden = true;

  scans.forEach(scan => {
    const tr = document.createElement('tr');
    tr.className = `status-${scan.status}`;
    tr.innerHTML = `
      <td class="url-cell" title="${escapeHTML(scan.url)}">${escapeHTML(scan.url)}</td>
      <td><span class="table-badge">${statusIcon(scan.status)} ${escapeHTML(scan.status)}</span></td>
      <td>${escapeHTML(vtLabel(scan.virustotal_score))}</td>
      <td>${escapeHTML(sbLabel(scan.safe_browsing_hit, scan.threat_types))}</td>
      <td>${escapeHTML(domainAgeLabel(scan.domain_age_days, scan.domain_age_flag))}</td>
      <td>${timeAgo(scan.scanned_at)}</td>
      <td><a class="detail-link" href="/api/scans/${escapeHTML(scan.id)}" target="_blank" rel="noopener">JSON ↗</a></td>
    `;
    tbody.appendChild(tr);
  });

  // Pagination
  if (data.total > data.limit) {
    document.getElementById('page-info').textContent = `Page ${currentPage} of ${totalPages}`;
    document.getElementById('prev-btn').disabled = currentPage <= 1;
    document.getElementById('next-btn').disabled = currentPage >= totalPages;
    pagination.hidden = false;
  } else {
    pagination.hidden = true;
  }
}

// ── Form submission ────────────────────────────────────────────────────

document.getElementById('scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const urlInput = document.getElementById('url-input');
  const submitBtn = document.getElementById('submit-btn');
  const formError = document.getElementById('form-error');

  const url = urlInput.value.trim();
  if (!url) return;

  // Loading state
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Scanning…';
  formError.hidden = true;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();

    if (!res.ok) {
      formError.textContent = data.error ?? 'Scan failed. Please try again.';
      formError.hidden = false;
      return;
    }

    renderResult(data);

    // Reset to first page and reload history
    currentPage = 1;
    await loadHistory();
  } catch (err) {
    formError.textContent = 'Network error. Is the server running?';
    formError.hidden = false;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Check URL';
  }
});

// ── Filter ─────────────────────────────────────────────────────────────

document.getElementById('status-filter').addEventListener('change', async (e) => {
  currentFilter = e.target.value;
  currentPage = 1;
  await loadHistory();
});

// ── Pagination ─────────────────────────────────────────────────────────

document.getElementById('prev-btn').addEventListener('click', async () => {
  if (currentPage > 1) {
    currentPage--;
    await loadHistory();
  }
});

document.getElementById('next-btn').addEventListener('click', async () => {
  if (currentPage < totalPages) {
    currentPage++;
    await loadHistory();
  }
});

// ── Init ───────────────────────────────────────────────────────────────

loadHistory();
