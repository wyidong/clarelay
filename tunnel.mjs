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

export const VERSION = '0.1.0';
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

const defaultState = () => path.join(os.homedir(), '.relay-tunnel.json');

/**
 * 连上中继，开始转发。
 * @param {object} o
 * @param {string} [o.invite]   中继邀请码（或者分别给 relay / pin / key）
 * @param {string} o.to         本机服务地址，例如 http://127.0.0.1:8788
 * @param {string} [o.state]    记名字和隧道密钥的文件（默认 ~/.relay-tunnel.json），重启后公开地址不变
 * @param {number} [o.pollers]  同时等几个请求（默认 4）
 * @param {(s:{online:boolean,error?:string})=>void} [o.onStatus]  在线状态变化
 * @param {(...a)=>void} [o.log]
 * @returns {Promise<{publicUrl:string, relay:string, pin:string, name:string, stop:()=>Promise<void>}>}
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
  const { name, secret } = st[RELAY];

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
          const out = await local(r.j);
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
    publicUrl: RELAY + r.j.path, relay: RELAY, pin: PIN, name,
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
    console.log('clarelay 隧道 ' + VERSION + '\n用法：node tunnel.mjs <中继邀请码> --to http://127.0.0.1:端口 [--state 文件]');
    process.exit(1);
  }
  try {
    const t = await startTunnel({
      invite, relay: arg('relay'), pin: arg('pin'), key: arg('key'), to: arg('to'), state: arg('state'),
      log: (...a) => console.log(ts(), ...a),
      onStatus: s => console.log(ts(), s.online ? '已重新连上中继' : '和中继断开：' + s.error),
    });
    console.log('隧道已连上。公开地址：' + t.publicUrl + '  →  转给 ' + arg('to'));
    if (t.pin) console.log('证书指纹（pin）：' + t.pin + '\n带指纹的地址：' + t.publicUrl + '#pin=' + t.pin);
    const bye = () => t.stop().then(() => process.exit(0));
    process.on('SIGINT', bye); process.on('SIGTERM', bye);
  } catch (e) { console.log(e.message); process.exit(1); }
}
