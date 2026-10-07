// Suki Chat Service Worker
const CACHE_NAME = 'suki-chat-v1';
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './css/app.css',
  './css/chat.css',
  './css/auth.css',
  './css/responsive.css',
  './js/supabase.js',
  './js/utils.js',
  './js/auth.js',
  './js/chat.js',
  './js/messages.js',
  './js/stories.js',
  './js/calls.js',
  './js/profile.js',
  './js/settings.js',
  './js/groups.js',
  './js/stickers.js',
  './js/notifications.js',
  './js/app.js'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS_TO_CACHE))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) return caches.delete(key);
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  // Only cache static local assets, don't cache Supabase API calls
  if (e.request.url.includes('supabase.co')) {
    return;
  }
  e.respondWith(
    caches.match(e.request).then((res) => res || fetch(e.request))
  );
});

// Push notification handler
self.addEventListener('push', (e) => {
  let data = { title: 'Suki Chat', body: 'New message received' };
  if (e.data) {
    try {
      data = e.data.json();
    } catch (_) {
      data.body = e.data.text();
    }
  }
  const options = {
    body: data.body,
    icon: '/assets/icons/icon-192.png',
    badge: '/assets/icons/badge-72.png',
    vibrate: [100, 50, 100],
    data: data.data || {}
  };
  e.waitUntil(self.registration.showNotification(data.title, options));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window' }).then((clientList) => {
      for (const client of clientList) {
        if (client.url === '/' && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});
