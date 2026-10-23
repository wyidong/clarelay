#!/usr/bin/env node
// clarelay 设备组网 · 中继（跑在你自己的外网服务器上，占 80 和 443）
//
//   node device/server.mjs --domain myrelay.duckdns.org [--data 目录] [--acme letsencrypt|staging|devca|selfsigned]
//   node device/server.mjs admin --data 目录          # 设置管理员账号和密码（只能在服务器上做）
//   node device/server.mjs invite --data 目录 --domain … [--note 备注]   # 命令行生成一个设备邀请码
//
//   --http-port / --https-port  默认 80 / 443（测试时可以换）
//   --acme  letsencrypt（默认）| staging（Let's Encrypt 测试环境）| devca（本地测试 CA，只用于测试）| selfsigned
//   --email Let's Encrypt 账号邮箱（可选）
//
// 443 上按 TLS 里的域名分流：<圈子域名> 由中继自己解开（外壳 / 管理后台 / 接口）；<设备>.<圈子域名> 原样转给那台电脑。
import http from 'node:http';
import tls from 'node:tls';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { DEVICE_VERSION, prefixed, serveTls, realIp, makeDeviceInvite, signTicket, lineChannel, parseSni, limiter, rand, randLabel, safeEq, sha256, b64u } from './common.mjs';
import { newKey, keyPem, loadKey, certificate, expiresIn, signCsrWithCa } from './x509.mjs';
import { acmeIssue, LETSENCRYPT, LETSENCRYPT_STAGING } from './acme.mjs';
import { newVapid, sendPush } from './webpush.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const arg = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 ? (argv[i + 1] ?? true) : d; };
const CMD = argv[0] && !argv[0].startsWith('--') ? argv[0] : 'serve';
const DIR = path.resolve(arg('data', path.join(HERE, '..', 'device-data')));
fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
const STATE_F = path.join(DIR, 'state.json');
const log = (...a) => console.log(new Date().toISOString().slice(0, 19).replace('T', ' '), ...a);

// ---------- 状态 ----------
let S = {}; try { S = JSON.parse(fs.readFileSync(STATE_F, 'utf8')); } catch {}
S.devices ||= {}; S.invites ||= {}; S.sessions ||= {}; S.push ||= {}; S.unread ||= {}; S.enrolls ||= {}; S.enrollCodes ||= {}; S.transfers ||= {};
S.settings = { requireApproval: true, snippetChars: 20, notify: true, ...(S.settings || {}) };
if (!S.signKey) { const kp = crypto.generateKeyPairSync('ed25519'); S.signKey = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }); S.signPub = kp.publicKey.export({ type: 'spki', format: 'pem' }); }
if (!S.vapid) S.vapid = newVapid();
if (!S.acmeAccount) S.acmeAccount = keyPem(newKey());
let saveTimer = null, lastWrite = 0;
const saveNow = () => { clearTimeout(saveTimer); saveTimer = null; fs.writeFileSync(STATE_F + '.tmp', JSON.stringify(S, null, 1), { mode: 0o600 }); fs.renameSync(STATE_F + '.tmp', STATE_F); lastWrite = fs.statSync(STATE_F).mtimeMs; };
const save = () => { if (!saveTimer) saveTimer = setTimeout(saveNow, 300); };
saveNow();
const SIGN_KEY = crypto.createPrivateKey(S.signKey);
// 服务运行中，用命令行改管理员 / 生成邀请码：合并磁盘上的改动
function watchState() {
  fs.watchFile(STATE_F, { interval: 1000 }, st => {
    if (!st.mtimeMs || Math.abs(st.mtimeMs - lastWrite) < 1) return;
    let disk; try { disk = JSON.parse(fs.readFileSync(STATE_F, 'utf8')); } catch { return; }
    lastWrite = st.mtimeMs;
    if (disk.admin && JSON.stringify(disk.admin) !== JSON.stringify(S.admin)) { S.admin = disk.admin; log('管理员已更新'); }
    for (const [c, v] of Object.entries(disk.invites || {})) if (!S.invites[c]) S.invites[c] = v;
    for (const [c, v] of Object.entries(disk.enrollCodes || {})) if (!S.enrollCodes[c]) S.enrollCodes[c] = v;
    let revoked = false;
    for (const [k, v] of Object.entries(disk.sessions || {})) if (v.revoked && S.sessions[k] && !S.sessions[k].revoked) { S.sessions[k].revoked = true; revoked = true; }
    if (revoked) pushAccess();
    save();
  });
}

// ---------- 命令行：设置管理员 / 生成邀请码 ----------
const scryptHash = (pass, salt) => crypto.scryptSync(pass, salt, 32).toString('base64url');
async function ask(q, hidden) {
  if (!process.stdin.isTTY) { // 管道输入：一行一个
    ask.lines ||= fs.readFileSync(0, 'utf8').split('\n'); return (ask.lines.shift() || '').trim();
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (hidden) rl._writeToOutput = s => { if (s.includes(q)) process.stdout.write(s); };
  return new Promise(ok => rl.question(q, a => { rl.close(); if (hidden) process.stdout.write('\n'); ok(a.trim()); }));
}
if (CMD === 'admin') {
  const user = await ask('管理员用户名：') || 'admin';
  const pass = await ask('管理员密码（至少 10 位）：', true);
  if (pass.length < 10) { console.log('密码太短'); process.exit(1); }
  const salt = rand(16); S.admin = { user, salt, hash: scryptHash(pass, salt) };
  for (const k of Object.keys(S.sessions)) S.sessions[k].revoked = true;   // 改密码：所有已登录的浏览器都要重新登录
  saveNow(); console.log('已设置管理员：' + user + '（已有的浏览器登录全部失效）'); process.exit(0);
}
const DOMAIN = String(arg('domain', S.domain || '')).toLowerCase().replace(/\.$/, '');
if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(DOMAIN)) { console.log('要用 --domain 指定圈子域名，例如 --domain myrelay.duckdns.org'); process.exit(1); }
if (S.domain !== DOMAIN) { S.domain = DOMAIN; saveNow(); }
const HTTPS_PORT = Number(arg('https-port', 443)), HTTP_PORT = Number(arg('http-port', 80));
function newInvite(note = '', hours = 24) {
  const code = rand(18);
  S.invites[code] = { created: Date.now(), expires: Date.now() + hours * 3600e3, note: String(note).slice(0, 80) };
  save(); return makeDeviceInvite({ domain: DOMAIN, code, port: HTTPS_PORT });
}
function newEnrollCode(note = '') {
  const code = rand(24);
  S.enrollCodes[code] = { created: Date.now(), expires: Date.now() + 10 * 60e3, note: String(note).slice(0, 80) };
  save(); return SHELL_ORIGIN_EARLY() + '/enroll?c=' + code;
}
function SHELL_ORIGIN_EARLY() { return 'https://' + DOMAIN + (HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT); }
if (CMD === 'enroll') { const url = newEnrollCode(arg('note', '命令行生成')); saveNow(); console.log(url + '\n（10 分钟内在要授权的设备上打开，只能用一次）'); process.exit(0); }
if (CMD === 'invite') { const inv = newInvite(arg('note', '命令行生成'), Number(arg('hours', 24))); saveNow(); console.log(inv); process.exit(0); }

// ---------- 证书 ----------
const ACME_MODE = String(arg('acme', 'letsencrypt'));
const CERT_F = path.join(DIR, 'cert.pem'), KEY_F = path.join(DIR, 'key.pem');
let devCa = null;
if (ACME_MODE === 'devca') {
  const caKeyF = path.join(DIR, 'devca-key.pem'), caF = path.join(DIR, 'devca.pem');
  if (!fs.existsSync(caF)) { const k = newKey(); fs.writeFileSync(caKeyF, keyPem(k), { mode: 0o600 }); fs.writeFileSync(caF, certificate({ key: k, cn: 'clarelay dev CA ' + DOMAIN, ca: true, days: 3650 })); }
  devCa = { key: loadKey(fs.readFileSync(caKeyF)), cert: fs.readFileSync(caF, 'utf8'), cn: 'clarelay dev CA ' + DOMAIN };
}
const coversDomain = cert => { try { return new crypto.X509Certificate(cert).subjectAltName.split(', ').includes('DNS:' + DOMAIN); } catch { return false; } };
const certIssuer = cert => { try { return new crypto.X509Certificate(cert).issuer; } catch { return ''; } };
function currentCert() {
  try { const cert = fs.readFileSync(CERT_F, 'utf8'), key = fs.readFileSync(KEY_F, 'utf8'); if (expiresIn(cert) > 0 && coversDomain(cert)) return { cert, key }; } catch {}
  const k = newKey(); return { cert: certificate({ key: k, hosts: [DOMAIN], days: 7 }), key: keyPem(k), temporary: true };
}
const acmeTokens = new Map();   // 中继自己证书的 HTTP-01：token → keyAuth
async function ensureOwnCert() {
  let cur = null; try { cur = fs.readFileSync(CERT_F, 'utf8'); } catch {}
  // 换了域名、或者从测试环境（STAGING）换到正式环境：重新申请
  const stagingCert = /STAGING|Fake/i.test(certIssuer(cur || ''));
  if (cur && expiresIn(cur) > 30 * 864e5 && coversDomain(cur) && !(ACME_MODE === 'letsencrypt' && stagingCert)) return;
  if (ACME_MODE === 'selfsigned') return;
  try {
    let out;
    if (devCa) { const k = newKey(); out = { cert: certificate({ key: k, hosts: [DOMAIN], issuerKey: devCa.key, issuerCn: devCa.cn, days: 90 }), key: keyPem(k) }; }
    else out = await acmeIssue({ directory: ACME_MODE === 'staging' ? LETSENCRYPT_STAGING : LETSENCRYPT, accountKey: loadKey(S.acmeAccount), email: arg('email'), hosts: [DOMAIN],
      respond: async (t, ka) => { acmeTokens.set(t, ka); }, cleanup: t => acmeTokens.delete(t), log });
    fs.writeFileSync(KEY_F, out.key, { mode: 0o600 }); fs.writeFileSync(CERT_F, out.cert);
    ownCtx = tls.createSecureContext({ ...currentCert(), minVersion: 'TLSv1.2' }); log('中继证书已更新：' + DOMAIN);
  } catch (e) { log('中继证书申请失败：' + e.message + '（1 小时后重试）'); }
}

// ---------- 在线设备 ----------
const online = new Map();      // 设备 id → { send, sock, services, lastSeen }
const pendingOpen = new Map(); // 数据连接编号 → { sock, buf, ip, port, deviceId, timer }
const acmeAsk = new Map();     // 问设备要验证内容：编号 → resolve
const streams = new Map();     // 设备 id → 正在转发的连接（撤销时全部掐断）
const deviceByLabel = label => Object.values(S.devices).find(d => d.label === label);
const pubDevice = d => ({ id: d.id, name: d.name, label: d.label, url: 'https://' + d.label + '.' + DOMAIN + (HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT), status: d.status,
  online: online.has(d.id), services: online.get(d.id)?.services || d.services || [], lastSeen: d.lastSeen, created: d.created, version: d.version || '' });
const activeSids = () => Object.values(S.sessions).filter(s => !s.revoked).map(s => s.sid);
const activeEnrolls = () => Object.values(S.enrolls).filter(e => !e.revoked).map(e => e.id);
const pushAccess = () => pushToDevices({ t: 'sessions', sids: activeSids(), enrolls: activeEnrolls() });
function pushToDevices(msg) { for (const o of online.values()) o.send(msg); }
const deviceList = () => Object.values(S.devices).filter(d => d.status !== 'revoked').map(pubDevice);

// ---------- 浏览器实时事件（SSE） ----------
const sse = new Set();         // { res, sid }
function broadcast(event, data) { const s = 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n'; for (const c of sse) c.res.write(s); }
const unreadList = () => { const out = []; for (const [dev, m] of Object.entries(S.unread)) for (const [k, v] of Object.entries(m)) { const [app, target] = k.split('\t'); out.push({ device: dev, app, target, ...v }); } return out; };
const devicesChanged = () => { broadcast('devices', deviceList()); };

// ---------- 提醒 ----------
const viewing = new Map();     // sid → { device, app, target, ts }
const lastPush = new Map();    // 设备\t应用\t对象 → 时间
async function notifyPush(deviceId, e) {
  if (!S.settings.notify || !(e.unread > 0)) return;
  const key = deviceId + '\t' + e.app + '\t' + e.target;
  for (const v of viewing.values()) if (v.device === deviceId && v.app === e.app && v.target === e.target && Date.now() - v.ts < 90e3) return;   // 有人正在看
  if (Date.now() - (lastPush.get(key) || 0) < 10e3) return;   // 10 秒内合并
  lastPush.set(key, Date.now());
  const d = S.devices[deviceId], total = unreadList().reduce((n, x) => n + (x.unread || 0), 0);
  const payload = { title: e.title || d?.name || 'clarelay', body: e.snippet || '', device: deviceId, app: e.app, target: e.target, kind: e.kind, badge: total, tag: key };
  for (const [sid, subs] of Object.entries(S.push)) {
    if (!activeSids().includes(sid)) { delete S.push[sid]; save(); continue; }
    for (const sub of [...subs]) {
      try {
        const st = await sendPush(sub, payload, { vapid: S.vapid, subject: 'https://' + DOMAIN });
        if (st === 404 || st === 410) { S.push[sid] = S.push[sid].filter(x => x.endpoint !== sub.endpoint); save(); }
      } catch (err) { log('推送失败', err.message); }
    }
  }
}
function onNotify(deviceId, m) {
  const app = String(m.app || '').slice(0, 40), target = String(m.target || '').slice(0, 200);
  if (!app || !target) return;
  const map = (S.unread[deviceId] ||= {}), key = app + '\t' + target;
  const unread = Math.max(0, Math.min(99999, Number(m.unread) || 0));
  if (!unread) delete map[key];
  else map[key] = { kind: String(m.kind || '').slice(0, 20), title: String(m.title || '').slice(0, 80), snippet: [...String(m.snippet || '')].slice(0, S.settings.snippetChars).join(''), unread, ts: Date.now() };
  save(); broadcast('unread', unreadList());
  if (unread) notifyPush(deviceId, { app, target, ...map[key] });
}
function onRead(deviceId, m) {
  const map = S.unread[deviceId]; if (!map) return;
  if (delete map[String(m.app) + '\t' + String(m.target)]) { save(); broadcast('unread', unreadList()); }
}

// ---------- 浏览器登录 ----------
const loginLimitIp = limiter(10, 15 * 60e3), loginLimitAll = limiter(60, 15 * 60e3);
const COOKIE = '__Host-clarelay';
function sessionOf(req) {
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)__Host-clarelay=([A-Za-z0-9_-]+)/);
  if (!m) return null;
  const s = S.sessions[b64u(sha256(m[1]))];
  if (!s || s.revoked) return null;
  if (s.enroll && !Object.values(S.enrolls).some(e => e.id === s.enroll && !e.revoked)) return null;
  if (Date.now() - (s.lastSeen || 0) > 60e3) { s.lastSeen = Date.now(); save(); }
  return s;
}
// ---------- 授权设备（浏览器）：没授权的浏览器看到的一律是 404，连登录框都没有 ----------
const ENROLL = '__Host-clarelay-dev';
const enrollCookie = secret => `${ENROLL}=${secret}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${400 * 86400}`;
function enrollOf(req) {
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)__Host-clarelay-dev=([A-Za-z0-9_-]+)/);
  const e = m && S.enrolls[b64u(sha256(m[1]))];
  if (!e || e.revoked) return null;
  if (Date.now() - (e.lastSeen || 0) > 60e3) { e.lastSeen = Date.now(); save(); }
  return e;
}
function newEnroll(req, via, note = '') {
  const secret = rand(32), e = { id: rand(9), created: Date.now(), lastSeen: Date.now(), ua: uaName(req.headers['user-agent']), ip: realIp(req.socket), via, note };
  S.enrolls[b64u(sha256(secret))] = e; saveNow(); setTimeout(pushAccess, 0);
  log('授权设备：' + e.ua + '（' + via + '）', e.ip);
  return { e, cookie: enrollCookie(secret) };
}
// 「已授权设备」凭证：Domain=圈子域名，各台电脑的门卫凭它把直接打开电脑网址的人送去换通行票（没有它就 404）
const proofCookie = e => `__Secure-clarelay-proof=${signTicket(SIGN_KEY, { k: 'proof', e: e.id, exp: Date.now() + 30 * 864e5 })}; Domain=${DOMAIN}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${30 * 86400}`;
const addCookie = (res, c) => { const h = res.getHeader('set-cookie'); res.setHeader('set-cookie', [...(h ? [].concat(h) : []), c]); };
function notFound(res) { if (res.writableEnded) return; res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }); res.end('Not Found'); }
const enrollLimit = limiter(20, 15 * 60e3);
const uaName = ua => { ua = String(ua || ''); const dev = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Macintosh/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : '浏览器'; const br = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : ''; return dev + (br ? ' · ' + br : ''); };

// ---------- HTTP 小工具 ----------
const ipOf = sock => String(sock.remoteAddress || '').replace(/^::ffff:/, '');
function send(res, code, obj, headers = {}) { if (res.writableEnded) return; res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers }); res.end(obj === undefined ? '' : JSON.stringify(obj)); }
function body(req, max = 64 * 1024) {
  return new Promise((ok, bad) => { const c = []; let n = 0; req.on('data', d => { n += d.length; if (n > max) { bad(new Error('too large')); req.destroy(); } else c.push(d); }); req.on('end', () => { try { ok(c.length ? JSON.parse(Buffer.concat(c).toString('utf8')) : {}); } catch { bad(new Error('bad json')); } }); req.on('error', bad); });
}
const SHELL_ORIGIN = 'https://' + DOMAIN + (HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT);
const sameOrigin = req => req.headers.origin === SHELL_ORIGIN;
const deviceAuth = req => { const t = String(req.headers.authorization || '').replace(/^Bearer /, ''); const id = String(req.headers['x-device-id'] || ''); const d = S.devices[id]; return d && d.status !== 'revoked' && safeEq(b64u(sha256(t)), d.tokenHash) ? d : null; };
const SHELL_DIR = path.join(HERE, 'shell');
// 外壳版本：所有外壳文件内容的哈希。页面引用 /app.js?v=<版本>（可长期缓存）；版本变了，已打开的外壳会提示刷新
const shellVersion = () => { const h = crypto.createHash('sha256'); for (const f of fs.readdirSync(SHELL_DIR).sort()) h.update(f).update(fs.readFileSync(path.join(SHELL_DIR, f))); return h.digest('base64url').slice(0, 10); };
let SHELL_V = shellVersion();
fs.watch(SHELL_DIR, () => { clearTimeout(fs._clv); fs._clv = setTimeout(() => { const v = shellVersion(); if (v !== SHELL_V) { SHELL_V = v; log('外壳已更新：' + v); broadcast('shell', { v }); } }, 500); });
const STATIC = { '/': ['index.html', 'text/html'], '/index.html': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/sw.js': ['sw.js', 'text/javascript'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'], '/icon.svg': ['icon.svg', 'image/svg+xml'] };
const SECURITY_HEADERS = {
  'content-security-policy': `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src https://*.${DOMAIN}${HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'strict-transport-security': 'max-age=31536000',
};

// ---------- 443 上中继自己解开的部分 ----------
async function handle(req, res) {
  const u = new URL(req.url, 'https://' + DOMAIN), p = u.pathname, ip = realIp(req.socket);
  try {
    // ---- 设备 ----
    if (p === '/_device/join' && req.method === 'POST') {
      if (loginLimitIp('join:' + ip)) return send(res, 429, { error: '请求太频繁' });
      const b = await body(req), inv = S.invites[String(b.code || '')];
      if (!inv || inv.usedBy || inv.expires < Date.now()) return send(res, 404, { error: '邀请码无效、已用过或已过期' });
      const id = rand(9), token = rand(32);
      let label; do label = randLabel(); while (deviceByLabel(label));
      S.devices[id] = { id, label, name: String(b.name || '电脑').slice(0, 40), tokenHash: b64u(sha256(token)), status: S.settings.requireApproval ? 'pending' : 'active', created: Date.now(), invite: inv.note, ip };
      inv.usedBy = id; inv.used = Date.now(); saveNow();
      log('设备加入：' + S.devices[id].name + '（' + S.devices[id].status + '）', ip);
      devicesChanged();
      return send(res, 200, { id, token, label, domain: DOMAIN, port: HTTPS_PORT, gatePub: S.signPub, status: S.devices[id].status, shell: SHELL_ORIGIN });
    }
    if (p === '/_device/devcert' && req.method === 'POST') {   // 只有测试 CA 模式
      const d = deviceAuth(req); if (!d || !devCa) return send(res, 403, { error: 'no' });
      const b = await body(req);
      let cert; try { cert = signCsrWithCa(Buffer.from(String(b.csr), 'base64url'), devCa.key, devCa.cn, 30); } catch (e) { return send(res, 400, { error: e.message }); }
      const host = new crypto.X509Certificate(cert).subjectAltName;
      if (host !== 'DNS:' + d.label + '.' + DOMAIN) return send(res, 403, { error: '只能给自己的网址申请证书' });
      return send(res, 200, { cert: cert + devCa.cert });
    }
    if (p === '/_device/ca') return devCa ? send(res, 200, { ca: devCa.cert }) : send(res, 404, { error: 'no' });
    if ((p === '/_relay/version' || p === '/_device/version') && deviceAuth(req)) return send(res, 200, { ok: true, name: 'clarelay-device', version: DEVICE_VERSION });

    // ---- 授权门：一次性授权链接、主屏幕 App 的授权转移、老登录自动转授权；其余没授权一律 404 ----
    if (p === '/enroll' && req.method === 'GET') {
      if (enrollLimit(ip)) return notFound(res);
      const code = String(u.searchParams.get('c') || ''), c = S.enrollCodes[code];
      if (!c || c.used || c.expires < Date.now()) { log('无效授权链接', ip); return notFound(res); }
      c.used = Date.now();
      const { cookie } = newEnroll(req, '授权链接', c.note);
      res.writeHead(302, { location: '/', 'set-cookie': cookie, 'cache-control': 'no-store' }); return res.end();
    }
    let en = enrollOf(req);
    if (p === '/' && u.searchParams.get('t')) {    // iPhone 主屏幕 App：cookie 和 Safari 不共用，靠 start_url 里的一次性凭证转过来
      const k = b64u(sha256(String(u.searchParams.get('t')))), t = S.transfers[k];
      if (!en && t && !t.used && t.expires > Date.now() && Object.values(S.enrolls).some(e => e.id === t.from && !e.revoked)) {
        t.used = Date.now();
        const { cookie } = newEnroll(req, '主屏幕 App');
        res.writeHead(302, { location: '/', 'set-cookie': cookie, 'cache-control': 'no-store' }); return res.end();
      }
      if (en) { res.writeHead(302, { location: '/' }); return res.end(); }
    }
    if (!en) {
      const s0 = sessionOf(req);
      if (s0 && !s0.enroll) { const r = newEnroll(req, '已有登录'); en = r.e; s0.enroll = en.id; save(); res.setHeader('set-cookie', [r.cookie]); }
    }
    let mfTok = null;
    if (p === '/manifest.webmanifest' && u.searchParams.get('m')) {   // 取 manifest 可能不带 cookie：凭页面里链接上的凭证
      const t = verifyTicket(S.signPub, u.searchParams.get('m'));
      if (t && t.k === 'mf' && t.exp > Date.now()) mfTok = Object.values(S.enrolls).find(e => e.id === t.e && !e.revoked) || null;
    }
    if (!en && mfTok) en = mfTok;
    if (!en) return notFound(res);
    if (p === '/' || p === '/index.html' || p === '/_auth') addCookie(res, proofCookie(en));
    if ((p === '/' || p === '/index.html') && req.method === 'GET') {
      const html = fs.readFileSync(path.join(SHELL_DIR, 'index.html'), 'utf8').replace('src="/app.js"', 'src="/app.js?v=' + SHELL_V + '"').replace('href="/manifest.webmanifest"', 'href="/manifest.webmanifest?m=' + signTicket(SIGN_KEY, { k: 'mf', e: en.id, exp: Date.now() + 7 * 864e5 }) + '"');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...SECURITY_HEADERS }); return res.end(html);
    }
    if (p === '/manifest.webmanifest') {
      for (const [k, t] of Object.entries(S.transfers)) if (t.from === en.id || t.expires < Date.now() || t.used) delete S.transfers[k];
      const tok = rand(24); S.transfers[b64u(sha256(tok))] = { from: en.id, expires: Date.now() + 7 * 864e5 }; save();
      const m = JSON.parse(fs.readFileSync(path.join(SHELL_DIR, 'manifest.webmanifest'), 'utf8')); m.start_url = '/?t=' + tok;
      res.writeHead(200, { 'content-type': 'application/manifest+json; charset=utf-8', 'cache-control': 'no-store' }); return res.end(JSON.stringify(m));
    }

    // ---- 静态：外壳 ----
    if (STATIC[p] && req.method === 'GET') {
      const [f, type] = STATIC[p];
      res.writeHead(200, { 'content-type': type + '; charset=utf-8', 'cache-control': f === 'sw.js' || f === 'index.html' ? 'no-cache' : f === 'app.js' && u.searchParams.get('v') === SHELL_V ? 'max-age=31536000, immutable' : 'no-cache', ...SECURITY_HEADERS });
      return res.end(fs.readFileSync(path.join(SHELL_DIR, f)));
    }
    // 直接打开某台电脑网址、没登录：门卫把人送到这里
    if (p === '/_auth') {
      const s = sessionOf(req), label = String(u.searchParams.get('host') || ''), back = String(u.searchParams.get('back') || '/');
      const d = deviceByLabel(label);
      if (s && d && d.status === 'active') { res.writeHead(302, { location: ticketUrl(d, s, back) }); return res.end(); }
      res.writeHead(302, { location: '/?next=' + encodeURIComponent(req.url) }); return res.end();
    }

    // ---- 接口 ----
    if (!p.startsWith('/api/')) return notFound(res);
    if (req.method === 'POST' && !sameOrigin(req)) return send(res, 403, { error: '来源不对' });
    if (p === '/api/login' && req.method === 'POST') {
      if (loginLimitIp(ip) || loginLimitAll('all')) return send(res, 429, { error: '尝试太多次，稍后再试' });
      const b = await body(req);
      if (!S.admin) return send(res, 503, { error: '还没设置管理员：在服务器上运行 node device/server.mjs admin' });
      const ok = safeEq(String(b.user || ''), S.admin.user) & safeEq(scryptHash(String(b.pass || ''), S.admin.salt), S.admin.hash);
      if (!ok) { log('登录失败', ip); return send(res, 401, { error: '用户名或密码不对' }); }
      const secret = rand(32), sid = rand(9);
      S.sessions[b64u(sha256(secret))] = { sid, created: Date.now(), lastSeen: Date.now(), ua: uaName(req.headers['user-agent']), ip, enroll: en.id };
      saveNow(); log('登录', ip, uaName(req.headers['user-agent']));
      pushAccess(); broadcast('sessions', 1);
      return send(res, 200, { ok: true }, { 'set-cookie': `${COOKIE}=${secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${30 * 86400}` });
    }
    const s = sessionOf(req);
    if (!s) return send(res, 401, { error: '没登录' });
    if (p === '/api/logout' && req.method === 'POST') { s.revoked = true; saveNow(); pushAccess(); return send(res, 200, { ok: true }, { 'set-cookie': `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0` }); }
    if (p === '/api/version') return send(res, 200, { v: SHELL_V, version: DEVICE_VERSION });
    if (p === '/api/me') return send(res, 200, { user: S.admin.user, admin: true, sid: s.sid, domain: DOMAIN, version: DEVICE_VERSION, shell: SHELL_V, settings: S.settings, vapid: S.vapid.pub });
    if (p === '/api/devices') return send(res, 200, { devices: deviceList(), unread: unreadList() });
    if (p === '/api/ticket' && req.method === 'POST') {
      const b = await body(req), d = S.devices[String(b.device || '')];
      if (!d || d.status !== 'active') return send(res, 404, { error: '没有这台设备或还没批准' });
      if (!online.has(d.id)) return send(res, 409, { error: '这台电脑不在线' });
      return send(res, 200, { url: ticketUrl(d, s, String(b.back || '/'), b.long ? 10 * 60e3 : 60e3) });
    }
    if (p === '/api/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no' });
      res.write('event: shell\ndata: ' + JSON.stringify({ v: SHELL_V }) + '\n\nevent: devices\ndata: ' + JSON.stringify(deviceList()) + '\n\nevent: unread\ndata: ' + JSON.stringify(unreadList()) + '\n\n');
      const c = { res, sid: s.sid }; sse.add(c);
      const ping = setInterval(() => res.write(': ping\n\n'), 25e3);
      req.on('close', () => { sse.delete(c); clearInterval(ping); viewing.delete(s.sid); });
      return;
    }
    if (p === '/api/viewing' && req.method === 'POST') {
      const b = await body(req);
      if (b.device && b.target) viewing.set(s.sid, { device: String(b.device), app: String(b.app || ''), target: String(b.target), ts: Date.now() }); else viewing.delete(s.sid);
      return send(res, 200, { ok: true });
    }
    if (p === '/api/push/subscribe' && req.method === 'POST') {
      const b = await body(req), sub = b.subscription;
      if (!sub?.endpoint || !/^https:\/\//.test(sub.endpoint) || !sub.keys?.p256dh || !sub.keys?.auth) return send(res, 400, { error: '订阅格式不对' });
      const list = (S.push[s.sid] ||= []).filter(x => x.endpoint !== sub.endpoint); list.push({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } });
      S.push[s.sid] = list.slice(-3); saveNow(); return send(res, 200, { ok: true });
    }
    if (p === '/api/push/unsubscribe' && req.method === 'POST') { delete S.push[s.sid]; saveNow(); return send(res, 200, { ok: true }); }
    if (p === '/api/push/test' && req.method === 'POST') {
      let n = 0; for (const sub of S.push[s.sid] || []) { try { await sendPush(sub, { title: 'clarelay', body: '推送测试', tag: 'test' }, { vapid: S.vapid, subject: 'https://' + DOMAIN }); n++; } catch {} }
      return send(res, 200, { ok: true, sent: n });
    }

    // ---- 管理 ----
    if (p === '/api/admin/state') {
      const now = Date.now();
      return send(res, 200, {
        devices: Object.values(S.devices).map(d => ({ ...pubDevice(d), invite: d.invite, ip: d.ip })),
        invites: Object.entries(S.invites).filter(([, v]) => !v.usedBy && v.expires > now).map(([code, v]) => ({ id: b64u(sha256(code)).slice(0, 10), note: v.note, expires: v.expires, created: v.created })),
        sessions: Object.entries(S.sessions).filter(([, v]) => !v.revoked).map(([, v]) => ({ sid: v.sid, ua: v.ua, ip: v.ip, created: v.created, lastSeen: v.lastSeen, current: v.sid === s.sid, push: (S.push[v.sid] || []).length })),
        settings: S.settings,
        enrolls: Object.values(S.enrolls).filter(e => !e.revoked).map(e => ({ id: e.id, ua: e.ua, note: e.note, via: e.via, ip: e.ip, created: e.created, lastSeen: e.lastSeen, current: e.id === en.id,
          loggedIn: Object.values(S.sessions).some(v => v.enroll === e.id && !v.revoked), push: Object.values(S.sessions).some(v => v.enroll === e.id && !v.revoked && (S.push[v.sid] || []).length) })),
      });
    }
    if (p === '/api/admin/enroll' && req.method === 'POST') { const b = await body(req); return send(res, 200, { url: newEnrollCode(b.note || ''), minutes: 10 }); }
    if (p === '/api/admin/enrollment' && req.method === 'POST') {
      const b = await body(req);
      const e = Object.values(S.enrolls).find(x => x.id === b.id);
      if (!e) return send(res, 404, { error: '没有这台设备' });
      if (b.action === 'revoke') {
        e.revoked = Date.now();
        for (const v of Object.values(S.sessions)) if (v.enroll === e.id) { v.revoked = true; delete S.push[v.sid]; for (const c of sse) if (c.sid === v.sid) c.res.end(); }
        saveNow(); pushAccess(); log('取消授权：' + e.ua);
      } else if (b.action === 'rename') { e.note = String(b.name || '').slice(0, 40); saveNow(); }
      return send(res, 200, { ok: true });
    }
    if (p === '/api/admin/invite' && req.method === 'POST') { const b = await body(req); return send(res, 200, { invite: newInvite(b.note || '', Math.min(168, Math.max(1, Number(b.hours) || 24))) }); }
    if (p === '/api/admin/invite/delete' && req.method === 'POST') {
      const b = await body(req); for (const code of Object.keys(S.invites)) if (b64u(sha256(code)).slice(0, 10) === b.id) delete S.invites[code];
      saveNow(); return send(res, 200, { ok: true });
    }
    if (p === '/api/admin/device' && req.method === 'POST') {
      const b = await body(req), d = S.devices[String(b.id || '')];
      if (!d) return send(res, 404, { error: '没有这台设备' });
      if (b.action === 'approve') d.status = 'active';
      else if (b.action === 'revoke') { d.status = 'revoked'; delete S.unread[d.id]; }
      else if (b.action === 'rename') d.name = String(b.name || d.name).slice(0, 40);
      else if (b.action === 'delete' && d.status === 'revoked') delete S.devices[d.id];
      else return send(res, 400, { error: '不支持的操作' });
      saveNow();
      const o = online.get(d.id);
      if (d.status === 'revoked') { for (const x of streams.get(d.id) || []) x.destroy(); streams.delete(d.id); }
      if (o) { if (d.status === 'revoked' || !S.devices[d.id]) { o.send({ t: 'revoked' }); o.sock.destroy(); online.delete(d.id); } else o.send({ t: 'status', status: d.status, name: d.name }); }
      log('设备' + b.action + '：' + d.name);
      devicesChanged(); broadcast('unread', unreadList());
      return send(res, 200, { ok: true });
    }
    if (p === '/api/admin/session' && req.method === 'POST') {
      const b = await body(req);
      for (const v of Object.values(S.sessions)) if (v.sid === b.sid && b.action === 'revoke') { v.revoked = true; delete S.push[v.sid]; }
      saveNow(); pushAccess();
      for (const c of sse) if (c.sid === b.sid) c.res.end();
      return send(res, 200, { ok: true });
    }
    if (p === '/api/admin/settings' && req.method === 'POST') {
      const b = await body(req);
      if ('requireApproval' in b) S.settings.requireApproval = !!b.requireApproval;
      if ('notify' in b) S.settings.notify = !!b.notify;
      if ('snippetChars' in b) S.settings.snippetChars = Math.max(0, Math.min(200, Number(b.snippetChars) || 0));
      saveNow(); pushToDevices({ t: 'settings', snippetChars: S.settings.snippetChars });
      return send(res, 200, { ok: true, settings: S.settings });
    }
    return send(res, 404, { error: 'not found' });
  } catch (e) { send(res, 500, { error: e.message }); }
}
function ticketUrl(d, s, back, ttl = 60e3) {
  if (!/^\/(?!\/)/.test(back)) back = '/';
  const t = signTicket(SIGN_KEY, { aud: d.label, sid: s.sid, exp: Date.now() + ttl, n: rand(12) });
  return pubDevice(d).url + '/_clarelay/auth?ticket=' + t + '&back=' + encodeURIComponent(back);
}

// ---- 设备的控制连接和数据连接（HTTP Upgrade） ----
function upgrade(req, sock, head) {
  const u = new URL(req.url, 'https://x');
  const d = deviceAuth(req);
  if (!d) { sock.end('HTTP/1.1 401 Unauthorized\r\nconnection: close\r\n\r\n'); return; }
  sock.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: clarelay\r\nconnection: Upgrade\r\n\r\n');
  if (head?.length) sock.unshift(head);
  sock.setNoDelay(true);
  if (u.pathname === '/_device/control') {
    online.get(d.id)?.sock.destroy();
    const o = { sock, services: [], lastSeen: Date.now() };
    o.send = lineChannel(sock, m => {
      o.lastSeen = Date.now();
      if (m.t === 'services') { o.services = (Array.isArray(m.services) ? m.services : []).map(String).slice(0, 10); d.services = o.services; d.version = String(m.version || '').slice(0, 20); save(); devicesChanged(); }
      else if (m.t === 'notify' && d.status === 'active') onNotify(d.id, m);
      else if (m.t === 'read' && d.status === 'active') onRead(d.id, m);
      else if (m.t === 'acme') acmeAsk.get(m.id)?.(m.keyAuth);
      else if (m.t === 'ping') o.send({ t: 'pong' });
    });
    online.set(d.id, o); d.lastSeen = Date.now(); save();
    o.send({ t: 'hello', status: d.status, name: d.name, label: d.label, domain: DOMAIN, sids: activeSids(), enrolls: activeEnrolls(), snippetChars: S.settings.snippetChars, gatePub: S.signPub, version: DEVICE_VERSION });
    log('设备上线：' + d.name);
    devicesChanged();
    sock.on('close', () => { if (online.get(d.id) === o) { online.delete(d.id); d.lastSeen = Date.now(); save(); log('设备离线：' + d.name); devicesChanged(); } });
    sock.on('error', () => {});
    sock.setKeepAlive(true, 30e3);
    return;
  }
  if (u.pathname === '/_device/accept') {
    const j = pendingOpen.get(String(u.searchParams.get('id') || ''));
    if (!j || j.deviceId !== d.id) { sock.destroy(); return; }
    pendingOpen.delete(j.id); clearTimeout(j.timer);
    sock.write(`PROXY TCP4 ${j.ip.includes(':') ? '0.0.0.0' : j.ip} 0.0.0.0 ${j.port} ${HTTPS_PORT}\r\n`);
    sock.write(j.buf);
    j.sock.pipe(sock); sock.pipe(j.sock);
    const set = streams.get(d.id) || new Set(); streams.set(d.id, set); set.add(j.sock);
    const kill = () => { j.sock.destroy(); sock.destroy(); set.delete(j.sock); };
    j.sock.on('error', kill); sock.on('error', kill); j.sock.on('close', kill); sock.on('close', kill);
    j.sock.resume();
    return;
  }
  sock.destroy();
}

// ---------- 443：按域名分流 ----------
let ownCtx = tls.createSecureContext({ ...currentCert(), minVersion: 'TLSv1.2' });
const internal = http.createServer(handle);   // TLS 在 serveTls() 里做
internal.on('upgrade', upgrade);
internal.headersTimeout = 30e3; internal.requestTimeout = 0;
const front = net.createServer(sock => {
  let buf = Buffer.alloc(0);
  sock.on('error', () => {});
  const timer = setTimeout(() => sock.destroy(), 10e3);
  const onData = chunk => {
    buf = Buffer.concat([buf, chunk]);
    const r = parseSni(buf);
    if (r && r.need) return;
    clearTimeout(timer); sock.removeListener('data', onData); sock.pause();
    const sni = r?.sni || '';
    if (!r || sni === DOMAIN || sni === '') { serveTls(internal, prefixed(sock, buf), () => ownCtx, ipOf(sock)); return; }
    const label = sni.endsWith('.' + DOMAIN) ? sni.slice(0, -DOMAIN.length - 1) : '';
    const d = label && !label.includes('.') ? deviceByLabel(label) : null;
    const o = d && d.status === 'active' ? online.get(d.id) : null;
    if (!o) { sock.destroy(); return; }
    const id = rand(12);
    pendingOpen.set(id, { id, sock, buf, ip: ipOf(sock), port: sock.remotePort || 0, deviceId: d.id, timer: setTimeout(() => { pendingOpen.delete(id); sock.destroy(); }, 15e3) });
    o.send({ t: 'open', id });
  };
  sock.on('data', onData);
});

// ---------- 80：证书验证 + 跳转到 https ----------
const plain = http.createServer(async (req, res) => {
  const host = String(req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
  const m = req.url.match(/^\/\.well-known\/acme-challenge\/([A-Za-z0-9_-]+)$/);
  if (m) {
    if (host === DOMAIN) { const ka = acmeTokens.get(m[1]); if (ka) { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(ka); } }
    const label = host.endsWith('.' + DOMAIN) ? host.slice(0, -DOMAIN.length - 1) : '';
    const d = label && deviceByLabel(label), o = d && d.status === 'active' && online.get(d.id);
    if (o) {
      const id = rand(9);
      const ka = await new Promise(ok => { const t = setTimeout(() => { acmeAsk.delete(id); ok(null); }, 8000); acmeAsk.set(id, v => { clearTimeout(t); acmeAsk.delete(id); ok(v); }); o.send({ t: 'acme', id, token: m[1] }); });
      if (ka && ka.startsWith(m[1] + '.')) { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(ka); }
    }
    res.writeHead(404); return res.end();
  }
  if (host === DOMAIN || host.endsWith('.' + DOMAIN)) { res.writeHead(301, { location: 'https://' + host + (HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT) + req.url }); return res.end(); }
  res.writeHead(404); res.end();
});

// 心跳超时的设备算离线；清理过期邀请码
setInterval(() => {
  for (const [id, o] of online) if (Date.now() - o.lastSeen > 90e3) { o.sock.destroy(); online.delete(id); devicesChanged(); }
  let ch = false; for (const [c, v] of Object.entries(S.invites)) if (v.expires < Date.now() - 7 * 864e5) { delete S.invites[c]; ch = true; }
  if (ch) save();
}, 30e3).unref();

watchState();
front.listen(HTTPS_PORT, arg('bind'), () => log(`clarelay 设备组网 ${DEVICE_VERSION}：https://${DOMAIN}${HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT}（443 端口 ${HTTPS_PORT}，证书 ${ACME_MODE}）`));
if (HTTP_PORT) plain.listen(HTTP_PORT, arg('bind'), () => log('80 端口：' + HTTP_PORT));
if (!S.admin) log('还没设置管理员：node device/server.mjs admin --data ' + DIR);
setTimeout(ensureOwnCert, 1000);
setInterval(ensureOwnCert, 12 * 3600e3).unref();
process.on('SIGTERM', () => { saveNow(); process.exit(0); });
process.on('SIGINT', () => { saveNow(); process.exit(0); });
