#!/usr/bin/env node
// 中继（跑在一台外网能访问的服务器上）：让不在同一个局域网的电脑互相发 HTTP 请求。
// 只解决网络问题，不认识也不关心转发的内容——claclaw 协同也好，别的工具也好，原来在局域网里怎么请求，现在照样怎么请求。
//
// 原理（和 ngrok 一类工具一样）：
//   本地电脑跑 relay-tunnel.mjs，主动连到中继、领一个公开地址 https://服务器:端口/t/<名字>/…；
//   谁往这个地址发请求，中继就把请求交给那台电脑的隧道，隧道转给本地的服务（比如 http://192.168.1.x:8788），再把响应原样送回来。
//   家里、公司都不用开端口，只有中继这一台需要开放一个端口。
//
// 安全：
//   - 传输用 HTTPS（第一次启动自己生成自签证书）。没有域名也不要紧：启动时打印证书公钥指纹（pin），
//     连接方只认这个指纹（curl --pinnedpubkey、relay-tunnel --pin），换了证书就拒绝，比普通网站证书还严。
//   - 领地址要「注册口令」（启动时生成、打印），陌生人领不到地址。
//   - 地址里的名字是随机长串，相当于钥匙：只有拿到地址的人才能访问；访问之后还要过本地服务自己的验证（比如 claclaw 的配对钥匙）。
//
// 运行：node server.mjs --public https://服务器IP:8790 [--port 8790] [--data 目录] [--plain] [--print]
//   --public 外网访问这台中继用的地址（写进「中继邀请码」；不填就猜本机网卡 IP）
//   --data   放证书、口令、已登记名字的目录（默认和本文件同目录下的 relay-data/）
//   --plain  不用 HTTPS（只在测试时用）
//   --print  只打印地址、指纹和邀请码，然后退出（不启动服务）
// 启动时打印「中继邀请码」= 地址 + 证书指纹 + 注册口令，交给 tunnel.mjs / startTunnel() 就能接入。
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { makeInvite, VERSION } from './tunnel.mjs';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? (process.argv[i + 1] ?? true) : d; };
const PORT = Number(arg('port', 8790));
const PLAIN = process.argv.includes('--plain');
const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.resolve(arg('data', path.join(HERE, 'relay-data')));
// 公开提供下载：同事不用装任何东西；想自建中继的人也能直接拿到和这台一模一样的程序（不含任何数据和口令）
const PUBLIC_FILES = { '/tunnel.mjs': 'tunnel.mjs', '/server.mjs': 'server.mjs', '/package.json': 'package.json', '/README.md': 'README.md',
  '/PROTOCOL.md': 'PROTOCOL.md', '/deploy/install.sh': 'deploy/install.sh', '/deploy/clarelay.service': 'deploy/clarelay.service' };
const FILES = {};
for (const [k, f] of Object.entries(PUBLIC_FILES)) try { FILES[k] = fs.readFileSync(path.join(HERE, f)); } catch {}
FILES['/_relay/tunnel.mjs'] = FILES['/tunnel.mjs'];
const typeOf = k => k.endsWith('.mjs') ? 'text/javascript' : k.endsWith('.json') ? 'application/json' : k.endsWith('.md') ? 'text/markdown' : 'text/plain';
const MAX_BODY = 3 * 1024 * 1024;          // 单个请求 / 响应最多 3MB（端到端加密后体积会变大，内容实际约 1MB）
const REQ_TIMEOUT = 11 * 60 * 1000;        // 等本地服务回应最多 11 分钟（claclaw 协同一轮最多 10 分钟）
const POLL_WAIT = 25 * 1000;               // 隧道一次长轮询等多久
const ONLINE_GRACE = 60 * 1000;            // 隧道这么久没来取请求就算离线
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
const STATE = path.join(DIR, 'relay.json');
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
let state = {}; try { state = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch {}
if (!state.key) state.key = crypto.randomBytes(18).toString('base64url');   // 注册口令
state.names ||= {};                                                          // 名字 → 隧道密钥的哈希
const save = () => fs.writeFileSync(STATE, JSON.stringify(state, null, 2), { mode: 0o600 });
save();

// ---------- 证书：没有就用 openssl 生成一张自签的（10 年） ----------
let tls = null, pin = '';
if (!PLAIN) {
  const certF = path.join(DIR, 'cert.pem'), keyF = path.join(DIR, 'key.pem');
  if (!fs.existsSync(certF) || !fs.existsSync(keyF)) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '3650',
      '-subj', '/CN=relay', '-keyout', keyF, '-out', certF], { stdio: 'ignore' });
    fs.chmodSync(keyF, 0o600);
  }
  tls = { cert: fs.readFileSync(certF), key: fs.readFileSync(keyF) };
  const spki = new crypto.X509Certificate(tls.cert).publicKey.export({ type: 'spki', format: 'der' });
  pin = 'sha256//' + crypto.createHash('sha256').update(spki).digest('base64');
}

// ---------- 隧道和待转发的请求 ----------
const tunnels = new Map();   // 名字 → { lastPoll, waiting: [res…], queue: [job…] }
const jobs = new Map();      // 请求 id → { res, timer }
const tunnelOf = name => { let t = tunnels.get(name); if (!t) tunnels.set(name, t = { lastPoll: 0, waiting: [], queue: [] }); return t; };
function hand(t) {           // 有排队的请求、又有隧道在等：交出去
  while (t.queue.length && t.waiting.length) {
    const w = t.waiting.shift(); if (w.writableEnded) continue;
    clearTimeout(w.pollTimer);
    send(w, 200, t.queue.shift());
  }
}
function send(res, code, obj, headers = {}) {
  if (res.writableEnded) return;
  const body = obj === undefined ? '' : JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(body);
}
function readBody(req) {
  return new Promise((ok, bad) => {
    const chunks = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { bad(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => ok(Buffer.concat(chunks)));
    req.on('error', bad);
  });
}
const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const ipOf = req => (req.socket.remoteAddress || '').replace(/^::ffff:/, '');

// 公开地址的简单限流：每个来源 IP 每分钟最多 120 个请求
const hits = new Map();
function limited(ip) {
  const now = Date.now(), h = hits.get(ip) || { n: 0, t: now };
  if (now - h.t > 60e3) { h.n = 0; h.t = now; }
  h.n++; hits.set(ip, h);
  if (hits.size > 5000) hits.clear();
  return h.n > 120;
}

async function handler(req, res) {
  const u = new URL(req.url, 'http://x');
  try {
    // ---- 隧道这一侧：领地址、取请求、交响应（都要注册口令 + 这个名字的隧道密钥） ----
    if (FILES[u.pathname] && req.method === 'GET') {
      if (limited(ipOf(req))) return send(res, 429, { error: '请求太频繁' });
      res.writeHead(200, { 'content-type': typeOf(u.pathname) + '; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(FILES[u.pathname]);
    }
    if (u.pathname === '/_relay/version') return send(res, 200, { ok: true, name: 'clarelay', version: VERSION,
      files: Object.keys(FILES).filter(k => !k.startsWith('/_relay/')),
      sha256: Object.fromEntries(Object.entries(FILES).filter(([k]) => !k.startsWith('/_relay/')).map(([k, v]) => [k, crypto.createHash('sha256').update(v).digest('hex')])) });
    if (u.pathname.startsWith('/_relay/')) {
      if (!safeEq(req.headers['x-relay-key'], state.key) && limited(ipOf(req))) return send(res, 429, { error: '请求太频繁' });
      if (!safeEq(req.headers['x-relay-key'], state.key)) return send(res, 401, { error: '注册口令不对' });
      const name = String(u.searchParams.get('name') || '');
      if (!/^[A-Za-z0-9_-]{16,64}$/.test(name)) return send(res, 400, { error: '名字要 16–64 位字母数字' });
      const secret = String(req.headers['x-tunnel-secret'] || '');
      if (secret.length < 16) return send(res, 400, { error: '缺少隧道密钥' });
      if (state.names[name] && state.names[name] !== sha(secret)) return send(res, 403, { error: '这个名字已经被别的隧道占用' });
      if (!state.names[name]) { state.names[name] = sha(secret); save(); log('register', name.slice(0, 6) + '…', ipOf(req)); }
      const t = tunnelOf(name);
      if (u.pathname === '/_relay/register') { t.lastPoll = Date.now(); return send(res, 200, { ok: true, path: '/t/' + name }); }
      if (u.pathname === '/_relay/poll') {
        t.lastPoll = Date.now();
        if (t.queue.length) return send(res, 200, t.queue.shift());
        res.pollTimer = setTimeout(() => { t.waiting = t.waiting.filter(w => w !== res); send(res, 204); }, POLL_WAIT);
        req.on('close', () => { clearTimeout(res.pollTimer); t.waiting = t.waiting.filter(w => w !== res); });
        t.waiting.push(res);
        return;
      }
      if (u.pathname === '/_relay/reply' && req.method === 'POST') {
        t.lastPoll = Date.now();
        const job = jobs.get(String(u.searchParams.get('id') || ''));
        if (!job || job.name !== name) return send(res, 404, { error: '这个请求已经超时或不存在' });
        let r; try { r = JSON.parse((await readBody(req)).toString('utf8')); } catch { return send(res, 400, { error: '响应格式不对' }); }
        jobs.delete(job.id); clearTimeout(job.timer);
        const h = {};
        for (const [k, v] of Object.entries(r.headers || {})) if (!/^(connection|transfer-encoding|content-length|keep-alive)$/i.test(k)) h[k] = v;
        const body = Buffer.from(String(r.body || ''), 'base64');
        if (!job.res.writableEnded) { job.res.writeHead(Number(r.status) || 502, h); job.res.end(body); }
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'not found' });
    }
    // ---- 公开地址：/t/<名字>/<后面原样转给本地服务> ----
    const m = u.pathname.match(/^\/t\/([A-Za-z0-9_-]{16,64})(\/.*)?$/);
    if (!m || !state.names[m[1]]) return send(res, 404, { error: 'not found' });
    if (limited(ipOf(req))) return send(res, 429, { error: '请求太频繁' });
    const t = tunnelOf(m[1]);
    if (Date.now() - t.lastPoll > ONLINE_GRACE) return send(res, 502, { ok: false, error: '对方不在线（隧道没连着中继）' });
    let body; try { body = await readBody(req); } catch { return send(res, 413, { error: '请求太大（最多 3MB）' }); }
    const id = crypto.randomBytes(9).toString('base64url');
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!/^(host|connection|transfer-encoding|content-length|keep-alive|x-forwarded-for)$/i.test(k)) headers[k] = v;
    headers['x-forwarded-for'] = ipOf(req);
    const job = { id, name: m[1], res, timer: setTimeout(() => { jobs.delete(id); send(res, 504, { ok: false, error: '对方超时没有回应' }); }, REQ_TIMEOUT) };
    jobs.set(id, job);
    req.on('close', () => { if (!res.writableEnded) { jobs.delete(id); clearTimeout(job.timer); } });
    t.queue.push({ id, method: req.method, path: (m[2] || '/') + u.search, headers, body: body.toString('base64') });
    hand(t);
  } catch (e) { send(res, 500, { error: e.message }); }
}

const srv = PLAIN ? http.createServer(handler) : https.createServer(tls, handler);
srv.requestTimeout = 0; srv.headersTimeout = 60e3;   // 请求可能要等很久（对方回复慢）
function guessPublic() {
  for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) if (a.family === 'IPv4' && !a.internal) return a.address;
  return '<服务器IP>';
}
const PUBLIC = String(arg('public', '') || (PLAIN ? 'http' : 'https') + '://' + guessPublic() + ':' + PORT).replace(/\/+$/, '');
if (process.argv.includes('--print')) {   // 只打印邀请码就退出（服务已在跑时找回邀请码）
  console.log('地址：' + PUBLIC + '\n证书指纹（pin）：' + (pin || '（--plain，无）') + '\n中继邀请码：\n' + makeInvite({ relay: PUBLIC, pin, key: state.key }));
  process.exit(0);
}
srv.listen(PORT, () => {
  console.log('clarelay ' + VERSION + ' 中继已启动：' + PUBLIC + (arg('public') ? '' : '（猜的地址；云服务器请用 --public https://公网IP:' + PORT + ' 指定）'));
  if (pin) console.log('证书指纹（pin）：' + pin);
  console.log('注册口令：' + state.key + '（数据目录 ' + DIR + '）');
  console.log('中继邀请码（只给要接入的人，内含注册口令）：\n' + makeInvite({ relay: PUBLIC, pin, key: state.key }));
});
