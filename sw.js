const CACHE = 'nulkey-v3';
const CACHE_FILES = ['index.html', 'app.js', 'icon.png'];

self.addEventListener('install', e => {
    e.waitUntil(
        caches.open(CACHE).then(cache => cache.addAll(CACHE_FILES))
    );
});

self.addEventListener('fetch', e => {
    // Only cache same-origin GET requests for static assets
    if (e.request.method !== 'GET' || !e.request.url.startsWith(self.location.origin)) {
        return;
    }
    
    e.respondWith(
        caches.match(e.request).then(response => {
            return response || fetch(e.request);
        })
    );
});

// Clean up old caches
self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys().then(names => {
            return Promise.all(
                names.filter(name => name !== CACHE)
                     .map(name => caches.delete(name))
            );
        })
    );
});