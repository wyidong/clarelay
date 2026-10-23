#!/usr/bin/env node
// clarelay 隧道（跑在你自己的电脑上）：主动连到中继，领一个公开地址，把别人发到这个地址的请求转给本机服务。
// 单文件、零依赖，既是命令行工具，也可以被 import：
//
//   命令行：node tunnel.mjs <中继邀请码> --to http://127.0.0.1:8788 [--state ~/.relay-tunnel.json]
//          （旧写法也行：--relay https://服务器IP:8790 --pin sha256//… --key 注册口令 --to …）
//   代码里：import { startTunnel } from 'clarelay';
//          const t = await startTunnel({ invite, to: 'http://127.0.0.1:8788' });
//          t.publicUrl  // https://服务器IP:8790/t/<名字>   t.pin  // sha256//…   await t.stop();
//
// 中继服务器（server.mjs）也会公开提供这个文件：https://中继/tunnel.mjs，同事不用装任何东西。
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';

export const VERSION = '0.2.0';
const INVITE_PREFIX = 'clarelay1.';
const MAX_BODY = 1024 * 1024;

// ---------- 中继邀请码：地址 + 证书指纹 + 注册口令，打包成一串 ----------
export function makeInvite({ relay, pin = '', key }) {
  const j = { r: String(relay).replace(/\/+$/, ''), k: key };
  if (pin) j.p = pin;
  return INVITE_PREFIX + Buffer.from(JSON.stringify(j)).toString('base64url');
}
export function parseInvite(invite) {
  const s = String(invite || '').trim().replace(/\s+/g, '');
  const i = s.indexOf(INVITE_PREFIX);          // 容忍前后带了别的字
  if (i < 0) throw new Error('不是 clarelay 中继邀请码');
  let j; try { j = JSON.parse(Buffer.from(s.slice(i + INVITE_PREFIX.length).match(/^[A-Za-z0-9_-]+/)[0], 'base64url').toString('utf8')); }
  catch { throw new Error('中继邀请码不完整或损坏'); }
  if (!/^https?:\/\//.test(j.r || '') || !j.k) throw new Error('中继邀请码内容不对');
  if (j.r.startsWith('https:') && !/^sha256\/\/[A-Za-z0-9+/=]{40,}$/.test(j.p || '')) throw new Error('中继邀请码缺少证书指纹');
  return { relay: j.r, pin: j.p || '', key: j.k };
}
// 给同事的 AI 照着跑的命令：从中继下载本文件（核对指纹）再连隧道，同事不用装任何东西。
// to 填同事本机要暴露的服务，例如他的 claclaw 协同地址 http://127.0.0.1:8788
export function tunnelCommand(invite, to = 'http://127.0.0.1:8788') {
  const { relay, pin } = parseInvite(invite);
  const get = pin ? `curl -fsSk --pinnedpubkey '${pin}'` : 'curl -fsS';
  return `${get} ${relay}/tunnel.mjs -o clarelay-tunnel.mjs && node clarelay-tunnel.mjs '${String(invite).trim()}' --to ${to}`;
}
export const isInvite = s => { try { parseInvite(s); return true; } catch { return false; } };

// ---------- 证书指纹核对：握手完成后、发出任何数据之前 ----------
// 注意：rejectUnauthorized:false 时 checkServerIdentity 不会被调用，所以必须自己在 secureConnect 里核。
export const pinOf = cert => 'sha256//' + crypto.createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
export function pinnedConnector(pin) {
  return (opts, cb) => {
    const s = tls.connect({ host: opts.host, port: opts.port, servername: opts.servername, rejectUnauthorized: false });
    s.once('secureConnect', () => {
      const got = pinOf(s.getPeerX509Certificate());
      if (got === pin) cb(null, s);
      else { s.destroy(); cb(new Error('中继证书指纹对不上（' + got + '），拒绝连接')); }
    });
    s.once('error', e => cb(e));
  };
}

// ---------- 端到端加密 ----------
// 隧道有一把长期的 X25519 密钥，公钥放在地址的 #key= 里（和 #pin= 一样随地址带外传递，中继改不了）。
// 每个请求：发起方临时生成 X25519 密钥 → ECDH → HKDF-SHA256 得到请求、响应两把 AES-256-GCM 密钥，
// 把 {方法, 路径, 头, 体, 时间} 整个加密后 POST 到 /t/<名字>/_e2e；隧道解密、转给本机服务，再把响应加密送回。
// 中继只能看到：名字、密文大小、时间、来源 IP。重放：隧道拒绝 5 分钟外的请求和重复的临时公钥。
export const E2E_PATH = '/_e2e';
export const E2E_TYPE = 'application/x-clarelay-e2e';
const E2E_SKEW = 5 * 60e3, E2E_INFO = 'clarelay e2e v1';
const rawPub = k => k.export({ format: 'jwk' }).x;
const pubFromRaw = x => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x }, format: 'jwk' });
function e2eDerive(privateKey, peerRaw, ephRaw, tunRaw) {
  const shared = crypto.diffieHellman({ privateKey, publicKey: pubFromRaw(peerRaw) });
  const salt = Buffer.concat([Buffer.from(ephRaw, 'base64url'), Buffer.from(tunRaw, 'base64url')]);
  const k = Buffer.from(crypto.hkdfSync('sha256', shared, salt, E2E_INFO, 64));
  return { req: k.subarray(0, 32), res: k.subarray(32) };
}
function seal(key, obj) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj)), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}
function unseal(key, buf) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(buf.length - 16));
  return JSON.parse(Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString('utf8'));
}
// 地址：https://中继/t/<名字>/路径#pin=sha256//…&key=…（pin 里有 + / =，不能用 URLSearchParams 解析）
export function parseAddress(address) {
  const u = new URL(address), frag = {};
  for (const kv of u.hash.slice(1).split('&')) { const i = kv.indexOf('='); if (i > 0) frag[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1)); }
  u.hash = '';
  return { url: u.toString(), pin: frag.pin || '', key: frag.key || '' };
}

/**
 * 发请求到中继上的地址：自动核对 #pin=，地址带 #key= 时自动端到端加密。
 * @returns {Promise<{status:number, headers:object, body:Buffer, e2e:boolean, text:()=>string, json:()=>any}>}
 *   端到端模式下，中继自己回的错误（对方不在线 502、超时 504 等）以明文原样返回，e2e=false；
 *   明文的成功响应一律当作被篡改，直接 reject。
 */
export function relayRequest(address, { method = 'GET', headers = {}, body, timeout = 11 * 60e3 } = {}) {
  const { url, pin, key } = parseAddress(address);
  const u = new URL(url);
  let send = body == null ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  let reqHeaders = { ...headers }, reqMethod = method, target = u, keys = null;
  if (key) {
    const m = u.pathname.match(/^(\/t\/[A-Za-z0-9_-]{16,64})(\/.*)?$/);
    if (!m) return Promise.reject(new Error('带 #key= 的地址要是 https://中继/t/<名字>/… 的形式'));
    const eph = crypto.generateKeyPairSync('x25519'), ephRaw = rawPub(eph.publicKey);
    try { keys = e2eDerive(eph.privateKey, key, ephRaw, key); } catch { return Promise.reject(new Error('地址里的 #key= 无效')); }
    const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    if (send.length && !lower['content-type'] && !Buffer.isBuffer(body) && typeof body !== 'string') lower['content-type'] = 'application/json';
    const inner = { t: Date.now(), m: method, p: (m[2] || '/') + u.search, h: lower, b: send.toString('base64') };
    send = Buffer.concat([Buffer.from([1]), Buffer.from(ephRaw, 'base64url'), seal(keys.req, inner)]);
    reqMethod = 'POST'; reqHeaders = { 'content-type': E2E_TYPE };
    target = new URL(u.origin + m[1] + E2E_PATH);
  }
  const mod = target.protocol === 'https:' ? https : http;
  return new Promise((ok, bad) => {
    const req = mod.request(target, {
      method: reqMethod, timeout, headers: { ...reqHeaders, 'content-length': send.length },
      ...(target.protocol === 'https:' && pin ? { createConnection: pinnedConnector(pin) } : {}),
    }, res => {
      const chunks = []; res.on('data', c => chunks.push(c));
      res.on('end', () => {
        let out = { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), e2e: false };
        if (keys) {
          if (String(res.headers['content-type'] || '').startsWith(E2E_TYPE)) {
            try { const r = unseal(keys.res, out.body); out = { status: r.s, headers: r.h || {}, body: Buffer.from(r.b || '', 'base64'), e2e: true }; }
            catch { return bad(new Error('端到端解密失败：响应被篡改或对方密钥不对')); }
          } else if (res.statusCode < 400) return bad(new Error('对方返回了未加密的响应，拒绝（可能被中继篡改）'));
        }
        out.text = () => out.body.toString('utf8');
        out.json = () => JSON.parse(out.body.toString('utf8'));
        ok(out);
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', bad);
    req.end(send);
  });
}

const defaultState = () => path.join(os.homedir(), '.relay-tunnel.json');

/**
 * 连上中继，开始转发。
 * @param {object} o
 * @param {string} [o.invite]   中继邀请码（或者分别给 relay / pin / key）
 * @param {string} o.to         本机服务地址，例如 http://127.0.0.1:8788
 * @param {string} [o.state]    记名字和隧道密钥的文件（默认 ~/.relay-tunnel.json），重启后公开地址不变
 * @param {number} [o.pollers]  同时等几个请求（默认 4）
 * @param {boolean} [o.plain]   也接受不加密的请求（默认 false：只接受端到端加密的请求）
 * @param {(s:{online:boolean,error?:string})=>void} [o.onStatus]  在线状态变化
 * @param {(...a)=>void} [o.log]
 * @returns {Promise<{publicUrl:string, address:string, urlFor:(p:string)=>string, relay:string, pin:string, key:string, name:string, online:boolean, stop:()=>Promise<void>}>}
 *   address = publicUrl#pin=…&key=…；urlFor('/claclaw-peer') = publicUrl/claclaw-peer#pin=…&key=…
 *   连不上 / 口令不对 / 指纹不对时 reject（不会自动重试）；连上之后断线会自己重连。
 */
export async function startTunnel(o = {}) {
  const inv = o.invite ? parseInvite(o.invite) : { relay: o.relay, pin: o.pin || '', key: o.key };
  const RELAY = String(inv.relay || '').replace(/\/+$/, ''), PIN = inv.pin, KEY = inv.key;
  const TO = String(o.to || '').replace(/\/+$/, '');
  if (!RELAY || !KEY) throw new Error('缺少中继地址或注册口令');
  if (!/^https?:\/\//.test(TO)) throw new Error('to 要是 http(s):// 开头的本机服务地址');
  if (RELAY.startsWith('https:') && !PIN) throw new Error('中继是 https，缺少证书指纹（pin）');
  const log = o.log || (() => {});
  const STATE = o.state || defaultState();

  // 名字 + 隧道密钥：每个中继一份，第一次生成后存下来
  let st = {}; try { st = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch {}
  if (!st[RELAY]) {
    st[RELAY] = { name: crypto.randomBytes(15).toString('base64url'), secret: crypto.randomBytes(24).toString('base64url') };
    fs.mkdirSync(path.dirname(STATE), { recursive: true });
    fs.writeFileSync(STATE, JSON.stringify(st, null, 2), { mode: 0o600 });
  }
  if (!st[RELAY].e2e) {   // 端到端加密的长期密钥（老的状态文件补上）
    const kp = crypto.generateKeyPairSync('x25519');
    st[RELAY].e2e = { priv: kp.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'), pub: rawPub(kp.publicKey) };
    fs.mkdirSync(path.dirname(STATE), { recursive: true });
    fs.writeFileSync(STATE, JSON.stringify(st, null, 2), { mode: 0o600 });
  }
  const { name, secret } = st[RELAY];
  const E2E_PRIV = crypto.createPrivateKey({ key: Buffer.from(st[RELAY].e2e.priv, 'base64'), format: 'der', type: 'pkcs8' });
  const E2E_PUB = st[RELAY].e2e.pub;
  const seen = new Map();   // 用过的临时公钥 → 时间（防重放）

  let stopped = false;
  const live = new Set();   // 进行中的请求，stop() 时全部掐断
  const connector = RELAY.startsWith('https:') ? pinnedConnector(PIN) : null;
  function relayCall(method, p, body, ms) {
    const u = new URL(RELAY + p);
    const mod = u.protocol === 'https:' ? https : http;
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    return new Promise((ok, bad) => {
      if (stopped) return bad(new Error('stopped'));
      const req = mod.request(u, {
        method, timeout: ms,
        headers: { 'x-relay-key': KEY, 'x-tunnel-secret': secret, ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}) },
        ...(connector ? { createConnection: connector } : {}),
      }, res => {
        const chunks = []; res.on('data', c => chunks.push(c));
        res.on('end', () => { live.delete(req); const t = Buffer.concat(chunks).toString('utf8'); let j = null; try { j = t ? JSON.parse(t) : null; } catch {} ok({ status: res.statusCode, j }); });
      });
      live.add(req);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', e => { live.delete(req); bad(e); });
      req.end(data || undefined);
    });
  }
  function local(job) {
    const u = new URL(TO + job.path);
    const mod = u.protocol === 'https:' ? https : http;
    const body = Buffer.from(job.body || '', 'base64');
    const fail = msg => ({ status: 502, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ ok: false, error: msg })).toString('base64') });
    return new Promise(ok => {
      const req = mod.request(u, { method: job.method, headers: { ...job.headers, host: u.host, 'content-length': body.length }, timeout: 11 * 60 * 1000 }, res => {
        const chunks = []; let n = 0;
        res.on('data', c => { n += c.length; if (n <= MAX_BODY) chunks.push(c); });
        res.on('end', () => { live.delete(req); ok(n > MAX_BODY ? fail('响应太大（最多 1MB）') : { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('base64') }); });
      });
      live.add(req);
      req.on('timeout', () => req.destroy(new Error('本地服务超时')));
      req.on('error', e => { live.delete(req); ok(fail('本地服务连不上：' + e.message)); });
      req.end(body);
    });
  }

  const plainFail = (status, msg) => ({ status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ ok: false, error: msg })).toString('base64') });
  async function serve(job) {
    if (job.path.split('?')[0] !== E2E_PATH) return o.plain ? local(job) : plainFail(403, '这个地址只接受端到端加密的请求（地址要带 #key=）');
    const buf = Buffer.from(job.body || '', 'base64');
    if (job.method !== 'POST' || buf.length < 1 + 32 + 12 + 16 || buf[0] !== 1) return plainFail(400, '加密请求格式不对');
    const ephRaw = buf.subarray(1, 33).toString('base64url');
    let inner, keys;
    try { keys = e2eDerive(E2E_PRIV, ephRaw, ephRaw, E2E_PUB); inner = unseal(keys.req, buf.subarray(33)); }
    catch { return plainFail(400, '解密失败（地址里的 #key= 不对？）'); }
    const now = Date.now();
    for (const [k, t] of seen) if (now - t > 2 * E2E_SKEW) seen.delete(k);
    if (Math.abs(now - Number(inner.t)) > E2E_SKEW) return plainFail(400, '请求时间和本机相差超过 5 分钟（检查两边的系统时间）');
    if (seen.has(ephRaw)) return plainFail(400, '重复的请求（重放），拒绝');
    seen.set(ephRaw, now);
    if (typeof inner.p !== 'string' || !inner.p.startsWith('/')) return plainFail(400, '加密请求格式不对');
    const h = {};
    for (const [k, v] of Object.entries(inner.h || {})) if (!/^(host|connection|transfer-encoding|content-length|keep-alive|x-forwarded-for)$/i.test(k)) h[k] = v;
    if (job.headers['x-forwarded-for']) h['x-forwarded-for'] = job.headers['x-forwarded-for'];   // 来源 IP 是中继给的（中继可以撒谎）
    const res = await local({ method: String(inner.m || 'GET'), path: inner.p, headers: h, body: inner.b || '' });
    const rh = {};
    for (const [k, v] of Object.entries(res.headers || {})) if (!/^(connection|transfer-encoding|content-length|keep-alive)$/i.test(k)) rh[k] = v;
    return { status: 200, headers: { 'content-type': E2E_TYPE }, body: seal(keys.res, { s: res.status, h: rh, b: res.body }).toString('base64') };
  }

  const q = '?name=' + encodeURIComponent(name);
  const r = await relayCall('POST', '/_relay/register' + q, {}, 15e3);
  if (r.status !== 200) throw new Error('登记失败：' + (r.j?.error || 'HTTP ' + r.status));

  let online = true;
  const setOnline = (v, error) => { if (v !== online) { online = v; o.onStatus?.(v ? { online } : { online, error }); } };
  const sleep = ms => new Promise(s => { const t = setTimeout(s, ms); if (stopped) { clearTimeout(t); s(); } });
  async function poller() {
    while (!stopped) {
      try {
        const r = await relayCall('GET', '/_relay/poll' + q, null, 40e3);
        if (r.status === 200 && r.j?.id) {
          setOnline(true);
          const out = await serve(r.j);
          await relayCall('POST', '/_relay/reply' + q + '&id=' + encodeURIComponent(r.j.id), out, 30e3).catch(e => log('交回响应失败', e.message));
        } else if (r.status === 204) setOnline(true);
        else { log('中继返回', r.status, r.j?.error || ''); setOnline(false, r.j?.error || 'HTTP ' + r.status); await sleep(5000); }
      } catch (e) {
        if (stopped) break;
        log('连不上中继：', e.message, '，5 秒后重试'); setOnline(false, e.message); await sleep(5000);
      }
    }
  }
  const loops = Array.from({ length: o.pollers || 4 }, poller);

  return {
    publicUrl: RELAY + r.j.path, relay: RELAY, pin: PIN, key: E2E_PUB, name,
    urlFor: (p = '') => RELAY + r.j.path + p + '#' + (PIN ? 'pin=' + PIN + '&' : '') + 'key=' + E2E_PUB,
    get address() { return this.urlFor(''); },
    get online() { return online; },
    async stop() { stopped = true; for (const req of live) req.destroy(); live.clear(); await Promise.allSettled(loops); },
  };
}

// ---------- 命令行 ----------
const isMain = (() => { try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (isMain) {
  const argv = process.argv.slice(2);
  const arg = k => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : undefined; };
  const invite = argv.find(a => a.includes(INVITE_PREFIX)) || arg('invite');
  const ts = () => new Date().toISOString().slice(11, 19);
  if ((!invite && !arg('relay')) || !arg('to')) {
    console.log('clarelay 隧道 ' + VERSION + '\n用法：node tunnel.mjs <中继邀请码> --to http://127.0.0.1:端口 [--state 文件] [--plain]');
    process.exit(1);
  }
  try {
    const t = await startTunnel({
      invite, relay: arg('relay'), pin: arg('pin'), key: arg('key'), to: arg('to'), state: arg('state'), plain: argv.includes('--plain'),
      log: (...a) => console.log(ts(), ...a),
      onStatus: s => console.log(ts(), s.online ? '已重新连上中继' : '和中继断开：' + s.error),
    });
    console.log('隧道已连上。公开地址：' + t.publicUrl + '  →  转给 ' + arg('to'));
    console.log('把这个地址给要访问你的人（带证书指纹和端到端加密公钥，整段复制）：\n' + t.address);
    if (argv.includes('--plain')) console.log('注意：--plain 也接受不加密的请求');
    const bye = () => t.stop().then(() => process.exit(0));
    process.on('SIGINT', bye); process.on('SIGTERM', bye);
  } catch (e) { console.log(e.message); process.exit(1); }
}
