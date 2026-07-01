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
  const score = result.risk_score ?? 0;
  const reasons = (result.reasons || [])
    .map((r) => `<li>${escapeHtml(typeof r === 'string' ? r : r.detail || r.reason || JSON.stringify(r))}</li>`)
    .join('');
  const domain = escapeHtml(result.domain || result.url || '');
  const reachability = (result.reachability || 'unknown').replaceAll('_', ' ');
  const errorHtml = result.error
    ? `<p class="flash flash-error">${escapeHtml(result.error.message || '')}</p>`
    : '';
  target.innerHTML = `
    <div class="pill pill-${label}">${escapeHtml(String(score))}/100 · ${escapeHtml(label)}</div>
    <p><strong>${domain}</strong></p>
    <p class="muted">${escapeHtml(result.url || '')}</p>
    <p>Reachability: ${reachability}</p>
    ${reasons ? `<ul class="bullet-list">${reasons}</ul>` : ''}
    ${errorHtml}
  `;
}

function prependRecentResult(result) {
  const items = [result, ...readRecentResults().filter((item) => item.url !== result.url)];
  writeRecentResults(items);
  const container = document.getElementById('recent-results');
  if (!container) return;
  const label = safeLabel(result.label);
  const item = document.createElement('div');
  item.className = 'recent-item';
  item.innerHTML = `<span class="pill pill-${label}">${escapeHtml(label)}</span><strong>${escapeHtml(result.domain || result.url)}</strong><small>just now</small>`;
  const placeholder = container.querySelector('.muted');
  if (placeholder) placeholder.remove();
  container.prepend(item);
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

function setLoadingState(resultContent, loading) {
  if (loading) {
    resultContent.innerHTML = `
      <div class="skeleton skeleton-text" style="width:60%"></div>
      <div class="skeleton skeleton-text"></div>
      <div class="skeleton skeleton-text" style="width:80%"></div>
      <p class="muted" style="margin-top:1rem">Analyzing URL\u2026</p>
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
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Analyzing\u2026'; }
    setLoadingState(resultContent, true);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify({ url }),
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error?.message || 'Unable to analyze URL. Please try again.');
      }
      renderResult(resultContent, result);
      prependRecentResult(result);

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
    if (response.ok) form.innerHTML = '<p class="helper">Feedback recorded \u2014 thank you!</p>';
  });
}

function setupOfflineView() {
  const offlineResults = document.getElementById('offline-results');
  if (offlineResults) {
    const cached = readRecentResults();
    offlineResults.innerHTML = cached.length
      ? cached.map((item) => {
          const label = safeLabel(item.label);
          return `<div class="recent-item"><span class="pill pill-${label}">${escapeHtml(label)}</span><strong>${escapeHtml(item.domain || item.url)}</strong><small>${escapeHtml(item.url || '')}</small></div>`;
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