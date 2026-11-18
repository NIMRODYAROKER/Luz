// Luz — מקבל התראות ומציג אותן גם כשהאתר סגור
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('push', (e) => {
  let d = { title: 'Luz', body: 'יש לך משימות פתוחות' };
  try { d = e.data.json(); } catch {}
  e.waitUntil(self.registration.showNotification(d.title, {
    body: d.body, icon: '/icon-192.png', badge: '/icon-192.png', tag: 'luz', renotify: true, lang: 'he', dir: 'rtl'
  }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) if ('focus' in c) return c.focus();
    return self.clients.openWindow('/');
  }));
});
