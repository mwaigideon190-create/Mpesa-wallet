// Tradecoin service worker: lets Chrome install the app and shows the last page when offline.
// It never touches the API (wallet, login, trades, admin): only page loads and static files.
const CACHE = 'tradecoin-v2';
const SHELL = ['/', '/index.html', '/admin.html', '/layouts.css', '/site.js', '/admin-logo.png', '/manifest.webmanifest', '/admin.webmanifest', '/icon-192.png', '/icon-512.png', '/admin-icon-192.png', '/admin-icon-512.png'];
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => Promise.all(SHELL.map((u) => c.add(u).catch(() => {})))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin) return;
  if (/^\/(site|auth|wallet|admin\/|mk|game|health|mpesa|agent|treasury)/.test(u.pathname)) return; // API: always straight to the network
  e.respondWith(fetch(r).then((res) => {
    if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(r, copy)); }
    return res;
  }).catch(() => caches.match(r).then((m) => m || (r.mode === 'navigate' ? caches.match(u.pathname === '/admin.html' ? '/admin.html' : '/index.html') : undefined))));
});
