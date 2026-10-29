// Offline cache for the MITRE ATT&CK v20.0 Studio.
// Bump CACHE_VERSION whenever index.html or the playbook JSON changes so old copies are dropped.
const CACHE_VERSION = 'v20-2';
const CACHE_NAME = `mitre-studio-${CACHE_VERSION}`;

const PRECACHE = [
  './',
  './index.html',
  './manifest.json',
  './icon.svg',
  './playbooks/mitre_playbooks_v20.json'
];

// Third-party hosts the page loads styling from. Only these are cached so the page keeps its look offline;
// everything else cross-origin (api.github.com, raw.githubusercontent.com) always goes to the network.
const CDN_HOSTS = ['cdn.tailwindcss.com', 'fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((key) => key.startsWith('mitre-studio-') && key !== CACHE_NAME).map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  const sameOrigin = url.origin === self.location.origin;
  if (!sameOrigin && !CDN_HOSTS.includes(url.hostname)) return;

  // Network first so a new deploy shows up immediately; the cache is only the offline fallback.
  event.respondWith(
    fetch(request)
      .then((response) => {
        const cacheable = sameOrigin ? response.ok : (response.ok || response.type === 'opaque');
        if (cacheable) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request).then((cached) => {
        if (cached) return cached;
        if (request.mode === 'navigate') return caches.match('./index.html');
        return Response.error();
      }))
  );
});
