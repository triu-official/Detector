// In-memory cache — avoids localStorage which is blocked in sandboxed iframes
const _memCache = { results: [] };
let deferredInstallPrompt = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('\"', '&quot;')
    .replaceAll("'", '&#39;');
}

function safeLabel(value) {
  return ['safe', 'suspicious', 'phishing'].includes(value) ? value : 'safe';
}

function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

// Safe storage helpers — try sessionStorage, fall back to in-memory
function readRecentResults() {
  try {
    return JSON.parse(sessionStorage.getItem('detector-recent') || '[]');
  } catch {
    return _memCache.results;
  }
}

function writeRecentResults(items) {
  const trimmed = items.slice(0, 10);
  try {
    sessionStorage.setItem('detector-recent', JSON.stringify(trimmed));
  } catch {
    _memCache.results = trimmed;
  }
  updateCachedCount();
}

function updateCachedCount() {
  const countNode = document.getElementById('cached-count');
  if (countNode) countNode.textContent = String(readRecentResults().length);
}

function renderResult(target, result) {
  const label = safeLabel(result.label);
  const score = result.risk_score ?? result.score ?? 0;
  const reasons = (result.reasons || result.explanations || [])
    .map((r) => `<li>${escapeHtml(typeof r === 'string' ? r : r.detail || r.reason || JSON.stringify(r))}</li>`)
    .join('');
  const domain = escapeHtml(result.domain || result.url || '');
  const reachability = (result.reachability || 'unknown').replaceAll('_', ' ');
  target.innerHTML = `
    <div class="pill pill-${label}">${escapeHtml(String(score))}/100 · ${escapeHtml(label)}</div>
    <p><strong>${domain}</strong></p>
    <p class="muted">${escapeHtml(result.url || '')}</p>
    <p>Reachability: ${reachability}</p>
    ${reasons ? `<ul class="bullet-list">${reasons}</ul>` : ''}
    <a class="ghost-button" href="/result/${escapeHtml(String(result.analysis_id || result.id || ''))}">Open full details &rarr;</a>
  `;
}

function prependRecentResult(result) {
  const items = [result, ...readRecentResults().filter((item) => item.url !== result.url)];
  writeRecentResults(items);
  const container = document.getElementById('recent-results');
  if (!container) return;
  const label = safeLabel(result.label);
  const link = document.createElement('a');
  link.className = 'recent-item';
  link.href = `/result/${result.analysis_id || result.id}`;
  link.innerHTML = `<span class="pill pill-${label}">${escapeHtml(label)}</span><strong>${escapeHtml(result.domain || result.url)}</strong><small>just now</small>`;
  // Remove placeholder if present
  const placeholder = container.querySelector('.muted');
  if (placeholder) placeholder.remove();
  container.prepend(link);
}

async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const registration = await navigator.serviceWorker.register('/sw.js');
    const notifyButton = document.getElementById('notify-button');
    if (notifyButton) {
      notifyButton.addEventListener('click', async () => {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
          await registration.showNotification('Detector notifications enabled', {
            body: 'You will be alerted when risky scans complete.',
          });
        }
      });
    }
  } catch (error) {
    console.warn('Service worker registration skipped:', error.message);
  }
}

function setupInstallPrompt() {
  const installButton = document.getElementById('install-button');
  if (!installButton) return;
  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    deferredInstallPrompt = event;
    installButton.classList.remove('hidden');
  });
  installButton.addEventListener('click', async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    installButton.classList.add('hidden');
  });
  window.addEventListener('appinstalled', () => installButton.classList.add('hidden'));
}

function setupThemeToggle() {
  const toggle = document.getElementById('theme-toggle');
  let saved = 'dark';
  try { saved = sessionStorage.getItem('detector-theme') || 'dark'; } catch { /* ignore */ }
  document.documentElement.dataset.theme = saved;
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { sessionStorage.setItem('detector-theme', next); } catch { /* ignore */ }
  });
}

// Resolve the final result object whether we got async job or sync response
async function resolveAnalysisResult(responsePayload, responseOk) {
  if (!responseOk) {
    throw new Error(responsePayload.error?.message || 'Unable to analyze URL. Please try again.');
  }

  // Sync fallback path — result is embedded directly
  if (responsePayload.status === 'completed' && responsePayload.result) {
    return responsePayload.result;
  }

  // Async path — poll job status
  const statusUrl = responsePayload.status_url;
  if (!statusUrl) {
    throw new Error('Unexpected response from server.');
  }

  for (let attempt = 0; attempt < 30; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 1200));
    const statusResp = await fetch(statusUrl, {
      headers: { 'X-CSRFToken': getCsrfToken() },
    });
    const statusPayload = await statusResp.json();
    if (statusPayload.status === 'completed') return statusPayload.result;
    if (statusPayload.status === 'failed') {
      throw new Error(statusPayload.error?.message || 'Analysis job failed.');
    }
  }
  throw new Error('Analysis is taking longer than expected. Please try again in a moment.');
}

function setLoadingState(resultContent, loading) {
  if (loading) {
    resultContent.innerHTML = `
      <div class="skeleton skeleton-text" style="width:60%"></div>
      <div class="skeleton skeleton-text"></div>
      <div class="skeleton skeleton-text" style="width:80%"></div>
      <p class="muted" style="margin-top:1rem">Analyzing URL…</p>
    `;
  }
}

function setupAnalyzeForm() {
  const form = document.getElementById('analyze-form');
  const resultContent = document.getElementById('result-content');
  const errorBox = document.getElementById('analysis-error');
  if (!form || !resultContent || !errorBox) return;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorBox.classList.add('hidden');
    errorBox.textContent = '';
    const formData = new FormData(form);
    const url = String(formData.get('url') || '').trim();
    if (!url) {
      errorBox.textContent = 'Please enter a URL or domain.';
      errorBox.classList.remove('hidden');
      return;
    }

    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Analyzing…'; }
    setLoadingState(resultContent, true);

    try {
      // Try async endpoint first; if it returns completed immediately (sync fallback) we use that
      const response = await fetch('/api/analyze/async', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify({ url }),
      });
      const payload = await response.json();
      const result = await resolveAnalysisResult(payload, response.ok);
      renderResult(resultContent, result);
      prependRecentResult(result);

      // Push notification for risky labels
      if (
        'serviceWorker' in navigator &&
        Notification.permission === 'granted' &&
        ['suspicious', 'phishing'].includes(result.label)
      ) {
        const reg = await navigator.serviceWorker.ready;
        await reg.showNotification('Detector found a risky URL', {
          body: `${result.domain} scored ${result.risk_score}/100 (${result.label})`,
        });
      }
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.classList.remove('hidden');
      resultContent.innerHTML = '';
    } finally {
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Analyze now'; }
    }
  });
}

function setupFeedback() {
  const form = document.getElementById('feedback-form');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const response = await fetch(form.action, {
      method: 'POST',
      headers: { 'X-CSRFToken': getCsrfToken() },
    });
    if (response.ok) form.innerHTML = '<p class="helper">Feedback recorded — thank you!</p>';
  });
}

function setupOfflineView() {
  const offlineResults = document.getElementById('offline-results');
  if (offlineResults) {
    const cached = readRecentResults();
    offlineResults.innerHTML = cached.length
      ? cached.map((item) => {
          const label = safeLabel(item.label);
          return `<a class="recent-item" href="/result/${escapeHtml(String(item.analysis_id || item.id || ''))}"><span class="pill pill-${label}">${escapeHtml(label)}</span><strong>${escapeHtml(item.domain || item.url)}</strong><small>${escapeHtml(item.url || '')}</small></a>`;
        }).join('')
      : '<p class="muted">No cached results yet.</p>';
  }
  const retryButton = document.getElementById('retry-online');
  if (retryButton) retryButton.addEventListener('click', () => window.location.assign('/'));
}

window.addEventListener('online', () => {
  const node = document.getElementById('network-status');
  if (node) node.textContent = 'Online';
});
window.addEventListener('offline', () => {
  const node = document.getElementById('network-status');
  if (node) node.textContent = 'Offline';
});

document.addEventListener('DOMContentLoaded', () => {
  updateCachedCount();
  setupThemeToggle();
  setupAnalyzeForm();
  setupFeedback();
  setupInstallPrompt();
  setupOfflineView();
  registerServiceWorker();
});
