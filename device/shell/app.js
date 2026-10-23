// clarelay 外壳：登录、设备列表、嵌入各台电脑的应用、红点 / 角标 / 推送、管理。
// 嵌入应用的约定（postMessage，都带 clarelay: 1）：
//   应用 → 外壳：ready {app, version} · title {text} · viewing {target} · unread {total}
//   外壳 → 应用：embedded {shell, version} · open {target}
'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const api = async (p, body) => {
  const r = await fetch(p, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {});
  let j = null; try { j = await r.json(); } catch {}
  if (r.status === 401 && p !== '/api/login') { showLogin(); throw new Error('没登录'); }
  if (!r.ok) throw new Error(j?.error || 'HTTP ' + r.status);
  return j;
};
const ago = t => { if (!t) return ''; const s = (Date.now() - t) / 1000; return s < 60 ? '刚刚' : s < 3600 ? Math.floor(s / 60) + ' 分钟前' : s < 86400 ? Math.floor(s / 3600) + ' 小时前' : Math.floor(s / 86400) + ' 天前'; };

let me = null, devices = [], unread = [], current = null, view = 'none', es = null;
const frames = new Map();          // 设备 id → { iframe, origin, ready, pendingOpen }
const params = new URLSearchParams(location.search);

// ---------- 登录 ----------
function showLogin(err) { $('app').classList.add('hidden'); $('login').classList.remove('hidden'); $('lerr').textContent = err || ''; es?.close(); }
async function login() {
  $('lerr').textContent = '';
  try {
    await api('/api/login', { user: $('user').value.trim(), pass: $('pass').value });
    $('pass').value = '';
    const next = params.get('next');
    if (next && next.startsWith('/_auth?')) { location.href = next; return; }
    start();
  } catch (e) { $('lerr').textContent = e.message; }
}
$('lbtn').onclick = login;
$('pass').onkeydown = e => { if (e.key === 'Enter') login(); };

// ---------- 启动 ----------
async function start() {
  try { me = await api('/api/me'); } catch { return showLogin(); }
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  updatePushButton();
  connectEvents();
}
function connectEvents() {
  es?.close();
  es = new EventSource('/api/events');
  es.addEventListener('devices', e => { devices = JSON.parse(e.data); render(); });
  es.addEventListener('unread', e => { unread = JSON.parse(e.data); render(); });
  es.addEventListener('sessions', () => { if (view === 'admin') loadAdmin(); });
  es.onerror = () => { fetch('/api/me').then(r => { if (r.status === 401) showLogin(); }); };
}

// ---------- 设备列表 ----------
const unreadOf = id => unread.filter(u => u.device === id).reduce((n, u) => n + (u.unread || 0), 0);
function render() {
  const list = devices.filter(d => d.status === 'active');
  $('devs').innerHTML = list.length ? list.map(d => {
    const n = unreadOf(d.id);
    return `<div class="dev ${current === d.id && view === 'device' ? 'sel' : ''}" data-id="${esc(d.id)}">
      <span class="dot ${d.online ? 'on' : ''}"></span>
      <span class="nm">${esc(d.name)}<small>${d.online ? (d.services.length ? esc(d.services.join(' · ')) : '在线') : '离线 · ' + ago(d.lastSeen)}</small></span>
      ${n ? `<span class="badge">${n > 99 ? '99+' : n}</span>` : ''}</div>`;
  }).join('') : '<div id="empty">还没有电脑加入。点「管理」生成邀请码。</div>';
  for (const el of $('devs').querySelectorAll('.dev')) el.onclick = () => openDevice(el.dataset.id);
  const total = unread.reduce((n, u) => n + (u.unread || 0), 0);
  $('total').textContent = total > 99 ? '99+' : total; $('total').classList.toggle('hidden', !total);
  if (navigator.setAppBadge) (total ? navigator.setAppBadge(total) : navigator.clearAppBadge()).catch(() => {});
  if (view === 'device' && current) {
    const d = devices.find(x => x.id === current);
    if (!d || d.status !== 'active') closeDevice();
  }
  const pending = devices.filter(d => d.status === 'pending').length;
  $('btn-admin').textContent = pending ? `管理（${pending} 台待批准）` : '管理';
}

// ---------- 打开一台电脑（iframe） ----------
async function openDevice(id, back = '/', openTarget = null) {
  const d = devices.find(x => x.id === id);
  if (!d) return;
  current = id; view = 'device';
  document.body.classList.add('open');
  $('admin').classList.add('hidden'); $('frames').classList.remove('hidden'); $('reload').classList.remove('hidden');
  $('title').textContent = d.name + (frames.get(id)?.title ? ' · ' + frames.get(id).title : '');
  for (const [k, f] of frames) f.iframe.classList.toggle('hidden', k !== id);
  $('empty')?.classList.add('hidden');
  let f = frames.get(id);
  if (!f || !f.iframe.isConnected) {
    if (!d.online) { showEmpty(d.name + ' 不在线'); render(); return; }
    let url;
    try { url = (await api('/api/ticket', { device: id, back })).url; } catch (e) { showEmpty(e.message); render(); return; }
    const iframe = document.createElement('iframe');
    iframe.allow = 'clipboard-read; clipboard-write; microphone; autoplay; fullscreen';
    iframe.src = url;
    f = { iframe, origin: new URL(url).origin, ready: false, pendingOpen: openTarget };
    frames.set(id, f);
    $('frames').appendChild(iframe);
  } else if (openTarget) {
    if (f.ready) post(f, { type: 'open', target: openTarget }); else f.pendingOpen = openTarget;
  }
  render();
}
function showEmpty(text) {
  let e = $('empty'); if (!e) { e = document.createElement('div'); e.id = 'empty'; $('frames').appendChild(e); }
  e.textContent = text; e.classList.remove('hidden');
  for (const f of frames.values()) f.iframe.classList.add('hidden');
}
function closeDevice() {
  document.body.classList.remove('open'); view = 'none';
  api('/api/viewing', {}).catch(() => {});
  render();
}
$('back').onclick = closeDevice;
$('reload').onclick = () => { const f = frames.get(current); if (f) { f.iframe.remove(); frames.delete(current); } openDevice(current); };
const post = (f, m) => f.iframe.contentWindow?.postMessage({ clarelay: 1, ...m }, f.origin);

// ---------- 和嵌入应用通信 ----------
window.addEventListener('message', e => {
  const m = e.data;
  if (!m || m.clarelay !== 1) return;
  if (e.source === navigator.serviceWorker?.controller || (e.origin === location.origin && m.type === 'notification-open')) return handleOpen(m.open);
  let id = null, f = null;
  for (const [k, v] of frames) if (v.origin === e.origin && v.iframe.contentWindow === e.source) { id = k; f = v; }
  if (!f) return;                                   // 只认自己嵌入的电脑
  if (m.type === 'ready') {
    f.ready = true; f.app = String(m.app || '');
    post(f, { type: 'embedded', shell: location.origin, version: me?.version });
    if (f.pendingOpen) { post(f, { type: 'open', target: f.pendingOpen }); f.pendingOpen = null; }
  } else if (m.type === 'title') {
    f.title = String(m.text || '').slice(0, 80);
    const d = devices.find(x => x.id === id);
    if (id === current && view === 'device') $('title').textContent = (d ? d.name + ' · ' : '') + f.title;
  } else if (m.type === 'viewing') {
    f.viewing = m.target ? String(m.target) : '';
    if (id === current && document.visibilityState === 'visible') api('/api/viewing', { device: id, app: f.app, target: f.viewing }).catch(() => {});
  }
});
document.addEventListener('visibilitychange', () => {
  const f = frames.get(current);
  if (document.visibilityState === 'visible' && view === 'device' && f?.viewing) api('/api/viewing', { device: current, app: f.app, target: f.viewing }).catch(() => {});
  else api('/api/viewing', {}).catch(() => {});
});
navigator.serviceWorker?.addEventListener('message', e => { if (e.data?.clarelay === 1 && e.data.type === 'notification-open') handleOpen(e.data.open); });
function handleOpen(open) {
  if (!open) return;
  const [device, app, target] = String(open).split('|').map(decodeURIComponent);
  const go = () => openDevice(device, '/', target || null);
  if (devices.length) go(); else setTimeout(go, 800);
  void app;
}

// ---------- 推送 ----------
const b64uToBytes = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); const b = atob(s + '='.repeat((4 - s.length % 4) % 4)); return Uint8Array.from(b, c => c.charCodeAt(0)); };
async function updatePushButton() {
  const btn = $('btn-push');
  if (!('PushManager' in window) || !('serviceWorker' in navigator)) { btn.textContent = '本浏览器不支持通知'; btn.disabled = true; return; }
  const reg = await navigator.serviceWorker.ready.catch(() => null);
  const sub = await reg?.pushManager.getSubscription();
  btn.textContent = sub ? '关闭通知' : '开启通知';
  btn.onclick = async () => {
    try {
      if (sub) { await sub.unsubscribe(); await api('/api/push/unsubscribe', {}); }
      else {
        if (await Notification.requestPermission() !== 'granted') return alert('没有通知权限。iPhone 需要先「添加到主屏幕」，再从主屏幕打开');
        const s = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64uToBytes(me.vapid) });
        await api('/api/push/subscribe', { subscription: s.toJSON() });
      }
    } catch (e) { alert('通知设置失败：' + e.message); }
    updatePushButton();
  };
}
$('btn-logout').onclick = async () => { if (!confirm('退出登录？')) return; await api('/api/logout', {}).catch(() => {}); location.href = '/'; };

// ---------- 管理 ----------
$('btn-admin').onclick = () => {
  view = 'admin'; current = null; document.body.classList.add('open');
  $('frames').classList.add('hidden'); $('reload').classList.add('hidden'); $('admin').classList.remove('hidden');
  $('title').textContent = '管理'; render(); loadAdmin();
};
async function loadAdmin() {
  const s = await api('/api/admin/state');
  $('inv-list').innerHTML = s.invites.map(i => `<div class="row"><span class="grow">${esc(i.note || '（无备注）')}<small>${new Date(i.expires).toLocaleString()} 前有效</small></span><button class="bad" data-inv="${esc(i.id)}">作废</button></div>`).join('');
  $('adm-devs').innerHTML = s.devices.length ? s.devices.map(d => `<div class="row">
      <span class="grow">${esc(d.name)} <span class="pill ${esc(d.status)}">${{ active: '已生效', pending: '待批准', revoked: '已撤销' }[d.status] || esc(d.status)}</span>
        <small>${d.online ? '在线' : '离线 · ' + ago(d.lastSeen)} · ${esc(d.url)}${d.version ? ' · ' + esc(d.version) : ''}${d.invite ? ' · 邀请：' + esc(d.invite) : ''}</small></span>
      ${d.status === 'pending' ? `<button class="pri" data-dev="${esc(d.id)}" data-act="approve">批准</button>` : ''}
      ${d.status !== 'revoked' ? `<button data-dev="${esc(d.id)}" data-act="rename">改名</button><button class="bad" data-dev="${esc(d.id)}" data-act="revoke">撤销</button>` : `<button class="bad" data-dev="${esc(d.id)}" data-act="delete">删除</button>`}
    </div>`).join('') : '<small>还没有设备</small>';
  $('adm-sess').innerHTML = s.sessions.map(x => `<div class="row"><span class="grow">${esc(x.ua)}${x.current ? ' <span class="pill">本机</span>' : ''}<small>${esc(x.ip || '')} · 最后活动 ${ago(x.lastSeen)}${x.push ? ' · 已开通知' : ''}</small></span>${x.current ? '' : `<button class="bad" data-sid="${esc(x.sid)}">撤销</button>`}</div>`).join('');
  $('set-approve').checked = s.settings.requireApproval; $('set-notify').checked = s.settings.notify; $('set-chars').value = s.settings.snippetChars;
  for (const b of document.querySelectorAll('[data-inv]')) b.onclick = async () => { await api('/api/admin/invite/delete', { id: b.dataset.inv }); loadAdmin(); };
  for (const b of document.querySelectorAll('[data-dev]')) b.onclick = async () => {
    const act = b.dataset.act, d = s.devices.find(x => x.id === b.dataset.dev);
    let name;
    if (act === 'rename') { name = prompt('新名字', d.name); if (!name) return; }
    if (act === 'revoke' && !confirm(`撤销「${d.name}」？它会立刻断开，要重新邀请才能加入。`)) return;
    await api('/api/admin/device', { id: d.id, action: act, name }).catch(e => alert(e.message)); loadAdmin();
  };
  for (const b of document.querySelectorAll('[data-sid]')) b.onclick = async () => { if (!confirm('撤销这个浏览器的登录？')) return; await api('/api/admin/session', { sid: b.dataset.sid, action: 'revoke' }); loadAdmin(); };
}
$('inv-new').onclick = async () => {
  const r = await api('/api/admin/invite', { note: $('inv-note').value.trim(), hours: Number($('inv-hours').value) });
  const out = $('invite-out');
  out.innerHTML = `<div>${esc(r.invite)}</div><div style="margin-top:8px"><button id="inv-copy">复制</button> <small>一次性；在要加入的电脑上粘贴（claclaw 设置 →「我的设备」，或 <code>node device/agent.mjs &lt;邀请码&gt;</code>）</small></div>`;
  out.classList.remove('hidden');
  $('inv-copy').onclick = () => navigator.clipboard.writeText(r.invite).then(() => { $('inv-copy').textContent = '已复制'; });
  $('inv-note').value = ''; loadAdmin();
};
const saveSettings = () => api('/api/admin/settings', { requireApproval: $('set-approve').checked, notify: $('set-notify').checked, snippetChars: Number($('set-chars').value) }).catch(e => alert(e.message));
$('set-approve').onchange = saveSettings; $('set-notify').onchange = saveSettings; $('set-chars').onchange = saveSettings;
$('push-test').onclick = async () => { const r = await api('/api/push/test', {}); alert(r.sent ? '已发出，看看手机' : '这个浏览器还没开启通知'); };

// ---------- 进入 ----------
start().then(() => { if (params.get('open')) handleOpen(params.get('open')); history.replaceState(null, '', '/'); });
