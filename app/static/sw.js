const CACHE_NAME = 'detector-shell-v1';
const RESULT_CACHE = 'detector-results-v1';
const SHELL_URLS = ['/', '/offline', '/manifest.json', '/static/css/app.css', '/static/js/app.js', '/static/icons/icon-192.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_URLS)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET') return;
  if (url.pathname.startsWith('/result/')) {
    event.respondWith(
      caches.open(RESULT_CACHE).then(async (cache) => {
        const cached = await cache.match(request);
        const network = fetch(request)
          .then((response) => {
            cache.put(request, response.clone());
            cache.keys().then((keys) => {
              if (keys.length > 10) cache.delete(keys[0]);
            });
            return response;
          })
          .catch(() => cached || caches.match('/offline'));
        return cached || network;
      })
    );
    return;
  }
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => caches.match('/offline')));
    return;
  }
  event.respondWith(caches.match(request).then((cached) => cached || fetch(request)));
});
