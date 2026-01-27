// sw.js
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// Odbieranie powiadomienia PUSH z serwera
self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};

  const title = data.title || 'Nowa wiadomość od eatmi.pl';
  const options = {
    body: data.body || 'Sprawdź co nowego!',
    icon: '/appicon.png', // ✅ Ikona z pliku appicon.png
    badge: '/appicon.png', // Mała ikona na pasku (Android)
    vibrate: [100, 50, 100],
    data: {
      url: data.url || '/'
    }
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// Kliknięcie w powiadomienie
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Jeśli aplikacja jest otwarta, sfocusuj ją
      if (clientList.length > 0) {
        return clientList[0].focus();
      }
      // Jeśli nie, otwórz nową
      return clients.openWindow(event.notification.data.url);
    })
  );
});
