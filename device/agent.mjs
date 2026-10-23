// clarelay 设备组网 · 电脑端：加入设备圈、保持和中继的连接、在本机解开 HTTPS、门卫检查，再转给本机应用（如 claclaw）。
//
//   import { startDevice } from 'clarelay/device';
//   const dev = await startDevice({ invite, state, name, services: { claclaw: 'http://127.0.0.1:8787' } });
//
// 命令行：node device/agent.mjs <设备邀请码> --name 办公室Mac --to http://127.0.0.1:8787 [--state 文件]
//   测试用：--acme devca --ca 测试CA.pem --connect 127.0.0.1:端口
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { DEVICE_VERSION, prefixed, serveTls, realIp, parseDeviceInvite, verifyTicket, lineChannel, rand, b64u } from './common.mjs';
import { newKey, keyPem, loadKey, certificate, csr, expiresIn } from './x509.mjs';
import { acmeIssue, LETSENCRYPT, LETSENCRYPT_STAGING } from './acme.mjs';

const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'proxy-authorization', 'proxy-authenticate']);
const GATE = '__Host-clarelay-gate';

/**
 * @param {object} o
 * @param {string} [o.invite]   设备邀请码（第一次加入时需要；之后从 state 读）
 * @param {string} [o.state]    状态文件（默认 ~/.clarelay-device.json）：设备身份、证书都在里面，权限 600
 * @param {string} [o.name]     在设备列表里显示的名字
 * @param {Record<string,string>} o.services  开放的应用 { claclaw: 'http://127.0.0.1:8787' }（v1 只用第一个）
 * @param {'letsencrypt'|'staging'|'devca'} [o.acme]  证书来源（默认 letsencrypt；devca 只用于测试）
 * @param {string} [o.ca]       额外信任的 CA（PEM，测试用）
 * @param {{host:string,port:number}} [o.connect]  连中继时实际连的地址（测试用；默认就是圈子域名）
 * @param {(s:object)=>void} [o.onStatus]
 * @param {(...a)=>void} [o.log]
 */
export async function startDevice(o = {}) {
  const log = o.log || (() => {});
  const STATE = o.state || path.join(os.homedir(), '.clarelay-device.json');
  let st = {}; try { st = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch {}
  const saveState = () => { fs.mkdirSync(path.dirname(STATE), { recursive: true }); fs.writeFileSync(STATE + '.tmp', JSON.stringify(st, null, 1), { mode: 0o600 }); fs.renameSync(STATE + '.tmp', STATE); };
  const services = o.services || {};
  const target = Object.values(services)[0];
  if (!target || !/^https?:\/\//.test(target)) throw new Error('services 里要有一个本机应用地址，例如 { claclaw: "http://127.0.0.1:8787" }');
  const caOpt = o.ca ? { ca: [...tls.rootCertificates, o.ca] } : {};

  // ---------- 加入 ----------
  if (o.invite) {
    const inv = parseDeviceInvite(o.invite);
    if (!st.id || st.domain !== inv.domain || st.revoked) {
      const r = await req(inv.domain, inv.port, 'POST', '/_device/join', { code: inv.code, name: o.name || os.hostname() }, {});
      if (r.status !== 200) throw new Error('加入设备圈失败：' + (r.j?.error || 'HTTP ' + r.status));
      st = { domain: r.j.domain, port: r.j.port, id: r.j.id, token: r.j.token, label: r.j.label, gatePub: r.j.gatePub, shell: r.j.shell, status: r.j.status, name: o.name || os.hostname(),
        gateSecret: rand(32), acmeAccount: keyPem(newKey()) };
      saveState();
      log('已加入设备圈：' + st.domain + '（' + (st.status === 'pending' ? '等管理员批准' : '已生效') + '）');
    }
  }
  if (!st.id) throw new Error('还没加入设备圈：需要设备邀请码');
  if (!st.gateSecret) { st.gateSecret = rand(32); saveState(); }
  const portSuffix = st.port && st.port !== 443 ? ':' + st.port : '';
  const URL_SELF = 'https://' + st.label + '.' + st.domain + portSuffix, SHELL = 'https://' + st.domain + portSuffix, HOST_SELF = st.label + '.' + st.domain;

  function req(domain, port, method, p, body, extra) {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    return new Promise((ok, bad) => {
      const r = https.request({ host: o.connect?.host || domain, port: o.connect?.port || port, servername: domain, method, path: p, timeout: 20e3, ...caOpt,
        headers: { host: domain + (port === 443 ? '' : ':' + port), ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}), ...extra } }, res => {
        const c = []; res.on('data', d => c.push(d)); res.on('end', () => { let j = null; try { j = JSON.parse(Buffer.concat(c).toString('utf8')); } catch {} ok({ status: res.statusCode, j }); });
      });
      r.on('timeout', () => r.destroy(new Error('timeout'))); r.on('error', bad); r.end(data || undefined);
    });
  }
  const authHeaders = () => ({ authorization: 'Bearer ' + st.token, 'x-device-id': st.id });

  // ---------- 本机 HTTPS（证书在本机，中继看不到内容） ----------
  const cert = () => (st.cert && st.certKey && expiresIn(st.cert) > 0) ? { cert: st.cert, key: st.certKey } : (() => { const k = newKey(); return { cert: certificate({ key: k, hosts: [HOST_SELF], days: 7 }), key: keyPem(k) }; })();
  let localCtx = tls.createSecureContext({ ...cert(), minVersion: 'TLSv1.2' });
  const local = http.createServer((q, s) => onRequest(q, s));   // TLS 在 serveTls() 里做（证书在本机）
  local.on('upgrade', (q, sock, head) => onUpgrade(q, sock, head));
  local.headersTimeout = 60e3; local.requestTimeout = 0; local.keepAliveTimeout = 65e3;

  // ---------- 门卫 ----------
  // 放行条件（任一）：本网址的门卫 cookie（由一次性通行票换来，绑定圈子登录 sid）。
  // 没有门卫 cookie：若带着中继签发的「已授权设备」凭证（Domain=圈子域名 的 cookie）→ 送去外壳换通行票；否则一律 404。
  // 独立主屏幕 App（iOS 的 cookie 和 Safari 分开）：页面里的 manifest 链接改写成带一次性凭证的地址，start_url 指向 /_clarelay/start 换门卫 cookie。
  let sids = new Set(), enrolls = new Set(), snippetChars = 20;
  const usedTickets = new Map();
  st.usedStarts ||= {};
  const hmac = s => crypto.createHmac('sha256', st.gateSecret).update(s).digest('base64url');
  const seal = obj => { const p = b64u(JSON.stringify(obj)); return p + '.' + hmac(p); };
  const unseal = v => { const [p, sig] = String(v || '').split('.'); if (!p || !sig || hmac(p) !== sig) return null; try { return JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch { return null; } };
  const GATE_AGE = 400 * 86400;
  const gateCookie = sid => seal({ sid, exp: Date.now() + GATE_AGE * 1000 });
  const setGate = sid => `${GATE}=${gateCookie(sid)}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${GATE_AGE}`;
  const cookieOf = (req, name) => { const m = String(req.headers.cookie || '').match(new RegExp('(?:^|;\\s*)' + name.replace(/[-]/g, '\\-') + '=([A-Za-z0-9_.-]+)')); return m ? m[1] : null; };
  function gateSid(req) { const j = unseal(cookieOf(req, GATE)); return j && j.exp > Date.now() && sids.has(j.sid) ? j.sid : null; }
  const gateOk = req => !!gateSid(req);
  function enrolledProof(req) {   // 中继签的「已授权设备」凭证
    const t = verifyTicket(st.gatePub, cookieOf(req, '__Secure-clarelay-proof'));
    return !!(t && t.k === 'proof' && t.exp > Date.now() && enrolls.has(t.e));
  }
  const clientIp = req => realIp(req.socket);
  const frameHeaders = { 'content-security-policy': `frame-ancestors 'self' ${SHELL}` };
  const notFound = res => { res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...frameHeaders }); res.end('Not Found'); };
  const safeBack = b => /^\/(?!\/)/.test(String(b || '')) ? String(b) : '/';
  function onRequest(req, res) {
    const u = new URL(req.url, URL_SELF);
    if (u.pathname === '/_clarelay/auth') {
      const t = verifyTicket(st.gatePub, u.searchParams.get('ticket'));
      if (!t || t.aud !== st.label || t.exp < Date.now() || usedTickets.has(t.n) || !sids.has(t.sid)) return notFound(res);
      usedTickets.set(t.n, t.exp); for (const [n, e] of usedTickets) if (e < Date.now()) usedTickets.delete(n);
      res.writeHead(302, { location: safeBack(u.searchParams.get('back')), 'set-cookie': setGate(t.sid), 'cache-control': 'no-store', ...frameHeaders });
      return res.end();
    }
    if (u.pathname === '/_clarelay/start') {          // 独立主屏幕 App 第一次打开
      const j = unseal(u.searchParams.get('t'));
      if (!j || j.k !== 'start' || j.exp < Date.now() || st.usedStarts[j.n] || !sids.has(j.sid)) {
        if (gateOk(req)) { res.writeHead(302, { location: safeBack(u.searchParams.get('back')) }); return res.end(); }
        return notFound(res);
      }
      st.usedStarts[j.n] = j.exp; for (const [n, e] of Object.entries(st.usedStarts)) if (e < Date.now()) delete st.usedStarts[n]; saveState();
      res.writeHead(302, { location: safeBack(u.searchParams.get('back')), 'set-cookie': setGate(j.sid), 'cache-control': 'no-store' });
      return res.end();
    }
    if (u.pathname === '/_clarelay/manifest') {       // 浏览器取 manifest 可能不带 cookie：凭链接里的凭证
      const j = unseal(u.searchParams.get('m'));
      if (!j || j.k !== 'manifest' || j.exp < Date.now() || !sids.has(j.sid)) return notFound(res);
      return serveManifest(req, res, j.sid, safeBack(u.searchParams.get('src')));
    }
    if (!gateOk(req)) {
      if (req.method === 'GET' && /text\/html/.test(req.headers.accept || '') && enrolledProof(req)) {   // 已授权的设备直接打开本网址：去外壳换通行票
        res.writeHead(302, { location: SHELL + '/_auth?host=' + st.label + '&back=' + encodeURIComponent(req.url), 'cache-control': 'no-store' }); return res.end();
      }
      return notFound(res);   // 其他人：什么都不给
    }
    proxy(req, res);
  }
  function serveManifest(req, res, sid, src) {
    const t = new URL(target), mod = t.protocol === 'https:' ? https : http;
    const h = fwdHeaders(req); h['accept-encoding'] = 'identity'; delete h.cookie;
    const up = mod.request({ host: t.hostname, port: t.port, method: 'GET', path: src, headers: h, setHost: false }, r => {
      const c = []; r.on('data', d => c.push(d));
      r.on('end', () => {
        let m; try { m = JSON.parse(Buffer.concat(c).toString('utf8')); } catch { return notFound(res); }
        const tok = seal({ k: 'start', sid, exp: Date.now() + 30 * 864e5, n: rand(12) });
        m.start_url = '/_clarelay/start?t=' + tok + '&back=' + encodeURIComponent(safeBack(m.start_url || '/'));
        m.scope ||= '/';
        if (!m.id) m.id = '/';
        res.writeHead(200, { 'content-type': 'application/manifest+json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify(m));
      });
    });
    up.on('error', () => notFound(res)); up.end();
  }
  function fwdHeaders(req) {
    const h = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && !/^x-forwarded-/.test(k) && k !== 'forwarded' && k !== 'x-real-ip') h[k] = v;
    if (h.cookie) { h.cookie = h.cookie.split(/;\s*/).filter(c => !c.startsWith(GATE + '=')).join('; '); if (!h.cookie) delete h.cookie; }
    h['x-forwarded-for'] = clientIp(req); h['x-forwarded-proto'] = 'https'; h['x-forwarded-host'] = req.headers.host || HOST_SELF;
    return h;   // Host 原样保留
  }
  function proxy(req, res) {
    const t = new URL(target), mod = t.protocol === 'https:' ? https : http;
    const page = req.method === 'GET' && /text\/html/.test(req.headers.accept || '');   // 页面：要改写 manifest 链接，向应用要不压缩的
    const h0 = fwdHeaders(req); if (page) h0['accept-encoding'] = 'identity';
    const up = mod.request({ host: t.hostname, port: t.port, method: req.method, path: req.url, headers: h0, setHost: false }, r => {
      const h = { ...r.headers }; delete h['x-frame-options'];
      for (const k of Object.keys(h)) if (HOP.has(k)) delete h[k];
      if (!h['content-security-policy']?.includes('frame-ancestors')) Object.assign(h, frameHeaders);
      if (page && /text\/html/.test(h['content-type'] || '') && !h['content-encoding']) {
        const c = []; let n = 0;
        r.on('data', d => { n += d.length; c.push(d); });
        r.on('end', () => {
          let html = Buffer.concat(c).toString('utf8');
          const sid = gateSid(req);
          if (sid && n < 4 * 1024 * 1024) html = html.replace(/(<link\b[^>]*\brel=["']?manifest["']?[^>]*\bhref=["'])([^"']+)(["'])/i, (all, a, href, b) => {
            const src = href.startsWith('/') ? href : '/' + href.replace(/^\.\//, '');
            return a + '/_clarelay/manifest?m=' + seal({ k: 'manifest', sid, exp: Date.now() + 7 * 864e5 }) + '&amp;src=' + encodeURIComponent(src) + b;
          });
          delete h['content-length']; delete h['etag'];
          res.writeHead(r.statusCode, h); res.end(html);
        });
        return;
      }
      res.writeHead(r.statusCode, h); r.pipe(res);
    });
    up.on('error', e => { if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', ...frameHeaders }); res.end('本机应用连不上：' + e.message); } else res.destroy(); });
    req.pipe(up);
  }
  function onUpgrade(req, sock, head) {
    sock.on('error', () => {});
    if (!gateOk(req)) { sock.end('HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n'); return; }
    const t = new URL(target), mod = t.protocol === 'https:' ? https : http;
    const h = fwdHeaders(req); h.connection = 'Upgrade'; h.upgrade = req.headers.upgrade;
    const up = mod.request({ host: t.hostname, port: t.port, method: req.method, path: req.url, headers: h, setHost: false });
    up.on('upgrade', (r, us, uhead) => {
      let out = `HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\n`;
      for (let i = 0; i < r.rawHeaders.length; i += 2) out += r.rawHeaders[i] + ': ' + r.rawHeaders[i + 1] + '\r\n';
      sock.write(out + '\r\n'); if (uhead?.length) sock.write(uhead); if (head?.length) us.write(head);
      us.pipe(sock); sock.pipe(us);
      const kill = () => { us.destroy(); sock.destroy(); }; us.on('error', kill); us.on('close', kill); sock.on('close', kill);
    });
    up.on('response', r => { sock.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nconnection: close\r\n\r\n`); });
    up.on('error', () => sock.destroy());
    up.end();
  }

  // ---------- 控制连接 ----------
  const ev = new EventEmitter();
  let stopped = false, ctrl = null, sendCtrl = null, online = false, status = st.status || 'pending', backoff = 5000, certState = { ok: !!(st.cert && expiresIn(st.cert) > 0), expires: st.cert ? Date.now() + expiresIn(st.cert) : 0 };
  const acmeTokens = new Map();
  const pendingEvents = new Map();   // 掉线期间的提醒：每个对象只留最后一条
  const emitStatus = (extra = {}) => { const s = { online, status, url: URL_SELF, cert: certState, ...extra }; o.onStatus?.(s); ev.emit('status', s); };
  const upgradeReq = (p) => new Promise((ok, bad) => {
    const r = https.request({ host: o.connect?.host || st.domain, port: o.connect?.port || st.port, servername: st.domain, path: p, ...caOpt,
      headers: { host: st.domain + portSuffix, connection: 'Upgrade', upgrade: 'clarelay', ...authHeaders() }, timeout: 20e3 });
    r.on('upgrade', (res, sock, head) => { r.setTimeout(0); if (head?.length) sock.unshift(head); ok(sock); });
    r.on('response', res => { res.resume(); bad(Object.assign(new Error(res.statusCode === 401 ? '设备已被撤销或凭证无效' : 'HTTP ' + res.statusCode), { status: res.statusCode })); });
    r.on('timeout', () => r.destroy(new Error('timeout'))); r.on('error', bad); r.end();
  });
  // 数据连接收到第一行 PROXY 头后，就在本机解开 HTTPS
  function serveData(sock, onUsed) {
    sock.setNoDelay(true);
    let buf = Buffer.alloc(0);
    const onData = d => {
      buf = Buffer.concat([buf, d]);
      const i = buf.indexOf('\r\n'); if (i < 0) { if (buf.length > 200) sock.destroy(); return; }
      sock.removeListener('data', onData); sock.pause();
      onUsed?.();
      const line = buf.subarray(0, i).toString('latin1').split(' ');   // PROXY TCP4 ip 0.0.0.0 port 443
      serveTls(local, prefixed(sock, buf.subarray(i + 2)), () => localCtx, line[0] === 'PROXY' ? line[2] : '');
    };
    sock.on('data', onData); sock.on('error', () => {});
  }
  function openData(id) {
    upgradeReq('/_device/accept?id=' + encodeURIComponent(id)).then(sock => serveData(sock)).catch(e => log('数据连接失败：' + e.message));
  }
  // 预先连好几条空闲数据连接放在中继上：手机来访问时直接用，首次打开快很多（中继远的时候每条新连接要多花约 1 秒）
  const POOL = o.pool ?? 4;
  let pooled = 0;
  function fillPool() {
    if (stopped || status !== 'active' || !online) return;
    while (pooled < POOL) {
      pooled++;
      upgradeReq('/_device/accept?pool=1').then(sock => {
        let used = false;
        sock.on('close', () => { if (!used) { pooled--; setTimeout(fillPool, 3000); } });
        serveData(sock, () => { used = true; pooled--; fillPool(); });
      }).catch(() => { pooled--; setTimeout(fillPool, 5000); });
    }
  }
  async function connect() {
    while (!stopped) {
      try {
        const sock = await upgradeReq('/_device/control');
        ctrl = sock; sock.setKeepAlive(true, 30e3);
        sendCtrl = lineChannel(sock, onCtrl);
        sendCtrl({ t: 'services', services: Object.keys(services), version: DEVICE_VERSION });
        for (const m of pendingEvents.values()) sendCtrl(m); pendingEvents.clear();
        backoff = 5000;
        const ping = setInterval(() => sendCtrl?.({ t: 'ping' }), 30e3);
        await new Promise(r => { sock.on('close', r); sock.on('error', () => {}); });
        clearInterval(ping); ctrl = null; sendCtrl = null;
        if (online) { online = false; emitStatus(); log('和中继断开，重连中'); }
      } catch (e) {
        if (e.status === 401) { status = 'revoked'; st.revoked = true; saveState(); emitStatus({ error: e.message }); log(e.message); return; }
        if (online) { online = false; emitStatus({ error: e.message }); }
        log('连不上中继：' + e.message + '，' + backoff / 1000 + ' 秒后重试');
      }
      if (stopped) return;
      await new Promise(r => setTimeout(r, backoff)); backoff = Math.min(backoff * 2, 60e3);
    }
  }
  function onCtrl(m) {
    if (m.t === 'hello') {
      status = m.status; sids = new Set(m.sids || []); enrolls = new Set(m.enrolls || []); snippetChars = m.snippetChars ?? 20;
      if (m.name && m.name !== st.name) st.name = m.name;
      if (m.gatePub && m.gatePub !== st.gatePub) st.gatePub = m.gatePub;
      st.status = status; saveState();
      online = true; emitStatus(); log('已连上中继（' + (status === 'active' ? '已生效' : '等管理员批准') + '）：' + URL_SELF);
      if (status === 'active') { ensureCert(); fillPool(); }
    } else if (m.t === 'open') openData(m.id);
    else if (m.t === 'pool-used') fillPool();
    else if (m.t === 'sessions') { sids = new Set(m.sids || []); if (m.enrolls) enrolls = new Set(m.enrolls); }
    else if (m.t === 'settings') snippetChars = m.snippetChars ?? snippetChars;
    else if (m.t === 'status') { status = m.status; st.status = status; if (m.name) st.name = m.name; saveState(); emitStatus(); if (status === 'active') { ensureCert(); fillPool(); } }
    else if (m.t === 'acme') sendCtrl?.({ t: 'acme', id: m.id, keyAuth: acmeTokens.get(m.token) || '' });
    else if (m.t === 'revoked') { status = 'revoked'; st.revoked = true; saveState(); emitStatus(); stopped = true; }
  }

  // ---------- 证书 ----------
  let certBusy = false;
  async function ensureCert() {
    if (certBusy || status !== 'active') return;
    const mode0 = o.acme || 'letsencrypt';
    let issuer = ''; try { issuer = new crypto.X509Certificate(st.cert).issuer; } catch {}
    const wrong = mode0 === 'letsencrypt' && /STAGING|Fake/i.test(issuer);
    if (st.cert && !wrong && expiresIn(st.cert) > Math.max(10 * 864e5, (st.certLife || 90 * 864e5) / 3)) return;
    certBusy = true;
    try {
      const mode = o.acme || 'letsencrypt';
      let out;
      if (mode === 'devca') {
        const k = newKey(), r = await req(st.domain, st.port, 'POST', '/_device/devcert', { csr: b64u(csr(k, [HOST_SELF])) }, authHeaders());
        if (r.status !== 200) throw new Error(r.j?.error || 'HTTP ' + r.status);
        out = { cert: r.j.cert, key: keyPem(k) };
      } else {
        out = await acmeIssue({ directory: mode === 'staging' ? LETSENCRYPT_STAGING : LETSENCRYPT, accountKey: loadKey(st.acmeAccount), hosts: [HOST_SELF], email: o.email,
          respond: async (t, ka) => { acmeTokens.set(t, ka); }, cleanup: t => acmeTokens.delete(t), log });
      }
      st.cert = out.cert; st.certKey = out.key; st.certLife = expiresIn(out.cert); saveState();
      localCtx = tls.createSecureContext({ cert: st.cert, key: st.certKey, minVersion: 'TLSv1.2' });
      certState = { ok: true, expires: Date.now() + expiresIn(st.cert) }; emitStatus(); log('证书已就绪：' + HOST_SELF);
    } catch (e) { certState = { ...certState, ok: certState.ok, error: e.message }; emitStatus({ error: '证书申请失败：' + e.message }); log('证书申请失败：' + e.message); }
    finally { certBusy = false; }
  }
  const certTimer = setInterval(ensureCert, 6 * 3600e3); certTimer.unref?.();

  const loop = connect();

  // ---------- 提醒 ----------
  function sendEvent(m) {
    const key = m.app + '\t' + m.target;
    if (sendCtrl && online) sendCtrl(m); else { pendingEvents.delete(key); pendingEvents.set(key, m); }
  }
  Object.defineProperties(ev, {
    url: { get: () => URL_SELF }, shellUrl: { get: () => SHELL }, online: { get: () => online }, status: { get: () => status }, cert: { get: () => certState },
    id: { get: () => st.id }, name: { get: () => st.name },
  });
  return Object.assign(ev, {
    notify(e) {
      const snippet = [...String(e.snippet || '')].slice(0, snippetChars).join('');   // 只把前 N 个字交给中继
      sendEvent({ t: 'notify', app: String(e.app), target: String(e.target), kind: e.kind || '', title: String(e.title || ''), snippet, unread: Number(e.unread) || 0 });
    },
    read(e) { sendEvent({ t: 'read', app: String(e.app), target: String(e.target) }); },
    async stop() { stopped = true; clearInterval(certTimer); ctrl?.destroy(); await Promise.race([loop, new Promise(r => setTimeout(r, 1000))]); },
  });
}

// ---------- 命令行 ----------
const isMain = (() => { try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (isMain) {
  const argv = process.argv.slice(2), arg = k => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : undefined; };
  const invite = argv.find(a => a.includes('clarelay-device1.'));
  const to = arg('to') || 'http://127.0.0.1:8787';
  const ts = () => new Date().toISOString().slice(11, 19);
  try {
    const dev = await startDevice({ invite, name: arg('name'), state: arg('state'), services: { [arg('app') || 'claclaw']: to }, acme: arg('acme'),
      ca: arg('ca') ? fs.readFileSync(arg('ca'), 'utf8') : undefined, connect: arg('connect') ? { host: arg('connect').split(':')[0], port: Number(arg('connect').split(':')[1]) } : undefined,
      log: (...a) => console.log(ts(), ...a), onStatus: s => console.log(ts(), '状态：', s.online ? '在线' : '离线', s.status, s.cert?.ok ? '证书正常' : '证书未就绪', s.error || '') });
    console.log('本机网址：' + dev.url + '\n手机打开：' + dev.shellUrl);
    process.on('SIGINT', () => dev.stop().then(() => process.exit(0)));
  } catch (e) { console.log(e.message); process.exit(1); }
}
