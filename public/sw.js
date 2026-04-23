// Web Push Service Worker for Background Notifications
// This script runs independently of the web page and listens for push events from the Stalwart server

self.addEventListener('push', function(event) {
  if (event.data) {
    try {
      const data = event.data.json();
      const title = data.title || 'New Email Received';
      const options = {
        body: data.body || 'You have new messages in Webmail',
        icon: '/mail-icon.png', // Fallback icon path
        badge: '/badge-icon.png',
        data: data.url // Useful for knowing what to open when clicked
      };
      
      event.waitUntil(self.registration.showNotification(title, options));
    } catch (e) {
      // Fallback for non-JSON payloads (JMAP StateChange ping)
      event.waitUntil(
        self.registration.showNotification('New Email', {
          body: 'Your inbox has been updated.',
          icon: '/mail-icon.png',
        })
      );
    }
  }
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  
  // Open the webmail app when the notification is clicked
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      if (clientList.length > 0) {
        let client = clientList[0];
        for (let i = 0; i < clientList.length; i++) {
          if (clientList[i].focused) {
            client = clientList[i];
          }
        }
        return client.focus();
      }
      return clients.openWindow('/');
    })
  );
});
