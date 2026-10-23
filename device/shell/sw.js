// clarelay 外壳的 Service Worker：只负责推送和通知点击（不缓存页面）
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {}; try { d = e.data.json(); } catch {}
  const jobs = [self.registration.showNotification(d.title || 'clarelay', { body: d.body || '', tag: d.tag || undefined, renotify: !!d.tag, data: d, icon: '/icon.svg' })];
  if (typeof d.badge === 'number' && self.navigator.setAppBadge) jobs.push(d.badge ? self.navigator.setAppBadge(d.badge) : self.navigator.clearAppBadge());
  e.waitUntil(Promise.all(jobs).catch(() => {}));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const d = e.notification.data || {};
  const open = d.device ? [d.device, d.app || '', d.target || ''].map(encodeURIComponent).join('|') : '';
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) { c.postMessage({ clarelay: 1, type: 'notification-open', open }); return c.focus(); }
    return self.clients.openWindow('/' + (open ? '?open=' + encodeURIComponent(open) : ''));
  })());
});
