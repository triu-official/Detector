const storageKey = 'detector-recent-results';
let deferredInstallPrompt = null;

function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

function readRecentResults() {
  try {
    return JSON.parse(localStorage.getItem(storageKey) || '[]');
  } catch {
    return [];
  }
}

function writeRecentResults(items) {
  localStorage.setItem(storageKey, JSON.stringify(items.slice(0, 10)));
  updateCachedCount();
}

function updateCachedCount() {
  const countNode = document.getElementById('cached-count');
  if (countNode) countNode.textContent = String(readRecentResults().length);
}

function renderResult(target, result) {
  target.innerHTML = `
    <div class="pill pill-${result.label}">${result.risk_score}/100 · ${result.label}</div>
    <p><strong>${result.domain}</strong></p>
    <p class="muted">${result.url}</p>
    <p>Reachability: ${result.reachability.replaceAll('_', ' ')}</p>
    <ul class="bullet-list">${result.reasons.map((reason) => `<li>${reason}</li>`).join('')}</ul>
    <a class="ghost-button" href="/result/${result.analysis_id}">Open details</a>
  `;
}

function prependRecentResult(result) {
  const items = [result, ...readRecentResults().filter((item) => item.url !== result.url)];
  writeRecentResults(items);
  const container = document.getElementById('recent-results');
  if (!container) return;
  const link = document.createElement('a');
  link.className = 'recent-item';
  link.href = `/result/${result.analysis_id}`;
  link.innerHTML = `<span class="pill pill-${result.label}">${result.label}</span><strong>${result.domain}</strong><small>just now</small>`;
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
          await registration.showNotification('Detector notifications enabled', { body: 'You will be alerted when risky scans complete.' });
        }
      });
    }
  } catch (error) {
    console.error('Failed to register service worker', error);
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
  const saved = localStorage.getItem('detector-theme') || 'dark';
  document.documentElement.dataset.theme = saved;
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('detector-theme', next);
  });
}

function setupAnalyzeForm() {
  const form = document.getElementById('analyze-form');
  const resultContent = document.getElementById('result-content');
  const errorBox = document.getElementById('analysis-error');
  if (!form || !resultContent || !errorBox) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorBox.classList.add('hidden');
    const formData = new FormData(form);
    const url = String(formData.get('url') || '').trim();
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify({ url }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error?.message || 'Unable to analyze URL');
      renderResult(resultContent, payload);
      prependRecentResult(payload);
      if (Notification.permission === 'granted' && ['suspicious', 'phishing'].includes(payload.label) && navigator.serviceWorker.ready) {
        const registration = await navigator.serviceWorker.ready;
        await registration.showNotification('Detector found a risky URL', { body: `${payload.domain} scored ${payload.risk_score}/100 (${payload.label})` });
      }
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.classList.remove('hidden');
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
    if (response.ok) form.innerHTML = '<p class="helper">Feedback recorded for future tuning.</p>';
  });
}

function setupOfflineView() {
  const offlineResults = document.getElementById('offline-results');
  if (offlineResults) {
    offlineResults.innerHTML = readRecentResults()
      .map((item) => `<a class="recent-item" href="/result/${item.analysis_id}"><span class="pill pill-${item.label}">${item.label}</span><strong>${item.domain}</strong><small>${item.url}</small></a>`)
      .join('') || '<p class="muted">No cached results yet.</p>';
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
