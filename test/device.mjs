// 设备组网端到端测试：中继（测试 CA）+ 电脑端 + 假的本机应用；验证分流、门卫、通行票、转发头、WebSocket、提醒、撤销。
import { spawn, execFileSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { startDevice } from '../device/agent.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clarelay-dev-'));
const DOMAIN = 'circle.test', HP = 20000 + Math.floor(Math.random() * 5000), PP = HP + 1;
const S = path.join(root, 'device/server.mjs');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const until = async (f, ms = 8000, what = '') => { if (process.env.V) console.log('wait', what); const t = Date.now(); for (;;) { const v = await f(); if (v) return v; if (Date.now() - t > ms) throw new Error('等待超时：' + what); await sleep(100); } };

execFileSync(process.execPath, [S, 'admin', '--data', tmp], { input: 'boss\nsuper-secret-pass\n' });
const relay = spawn(process.execPath, [S, '--domain', DOMAIN, '--data', tmp, '--https-port', HP, '--http-port', PP, '--acme', 'devca']);
let relayLog = ''; relay.stdout.on('data', c => relayLog += c); relay.stderr.on('data', c => relayLog += c);
await until(() => fs.existsSync(path.join(tmp, 'devca.pem')) && relayLog.includes('设备组网'), 8000, 'relay start');
const CA = fs.readFileSync(path.join(tmp, 'devca.pem'), 'utf8');
await sleep(1500);   // 等中继拿到自己的证书

// 发请求：连 127.0.0.1，但 TLS 里的域名是 host（像真实浏览器一样校验证书）
function call(host, p, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((ok, bad) => {
    const r = https.request({ host: '127.0.0.1', port: HP, servername: host, method, path: p, ca: CA, headers: { host: host + ':' + HP, ...headers } }, res => {
      const cert = res.socket.getPeerCertificate?.();
      const c = []; res.on('data', d => c.push(d)); res.on('end', () => { const t = Buffer.concat(c).toString('utf8'); let j = null; try { j = JSON.parse(t); } catch {} ok({ status: res.statusCode, headers: res.headers, text: t, j, cert }); });
    });
    r.on('error', bad); r.end(body);
  });
}
const ORIGIN = 'https://' + DOMAIN + ':' + HP;
let ENR = '';
const api = (p, body, cookie) => call(DOMAIN, p, { method: body ? 'POST' : 'GET', headers: { origin: ORIGIN, 'content-type': 'application/json', cookie: [ENR, cookie].filter(Boolean).join('; ') }, body: body ? JSON.stringify(body) : undefined });

// 假的 claclaw
const seen = [];
const app = http.createServer((q, s) => { seen.push({ url: q.url, headers: q.headers });
  if (q.url === '/page') { s.writeHead(200, { 'content-type': 'text/html' }); return s.end('<html><head><link rel="manifest" href="/manifest.webmanifest"></head><body>claclaw</body></html>'); }
  if (q.url === '/manifest.webmanifest') { s.writeHead(200, { 'content-type': 'application/manifest+json' }); return s.end(JSON.stringify({ name: 'claclaw', start_url: '/?pwa=1' })); } s.writeHead(200, { 'content-type': 'application/json', 'x-frame-options': 'DENY' }); s.end(JSON.stringify({ hello: 'claclaw', url: q.url })); });
app.on('upgrade', (q, sock) => { sock.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n'); sock.on('data', d => sock.write('echo:' + d)); });
await new Promise(r => app.listen(0, '127.0.0.1', r));
const APP = 'http://127.0.0.1:' + app.address().port;

console.log('step 1');
// 0. 没授权的浏览器：一律 404，连登录接口都没有
assert.equal((await call(DOMAIN, '/')).status, 404);
assert.equal((await api('/api/login', { user: 'boss', pass: 'super-secret-pass' })).status, 404);
const enrollUrl = execFileSync(process.execPath, [S, 'enroll', '--data', tmp, '--domain', DOMAIN, '--https-port', HP], { encoding: 'utf8' }).match(/https:\/\/\S+/)[0];
await sleep(1500);   // 中继合并命令行写入的授权码
const eu = new URL(enrollUrl);
const en1 = await call(DOMAIN, eu.pathname + eu.search);
assert.equal(en1.status, 302);
ENR = en1.headers['set-cookie'][0].split(';')[0];
assert.match(ENR, /^__Host-clarelay-dev=/);
assert.equal((await call(DOMAIN, eu.pathname + eu.search)).status, 404, '授权链接只能用一次');
assert.equal((await call(DOMAIN, '/', { headers: { cookie: ENR } })).status, 200);
// 主屏幕 App 授权转移：manifest 的 start_url 带一次性凭证
const mf = JSON.parse((await call(DOMAIN, '/manifest.webmanifest', { headers: { cookie: ENR } })).text);
const tr = await call(DOMAIN, mf.start_url);
assert.equal(tr.status, 302); assert.match(tr.headers['set-cookie'][0], /__Host-clarelay-dev=/);
assert.equal((await call(DOMAIN, mf.start_url)).status, 404, '转移凭证只能用一次');

console.log('step 1');
// 1. 登录管理后台
assert.equal((await api('/api/login', { user: 'boss', pass: 'wrong' })).status, 401);
const lg = await api('/api/login', { user: 'boss', pass: 'super-secret-pass' });
assert.equal(lg.status, 200);
const cookie = lg.headers['set-cookie'][0].split(';')[0];
assert.match(cookie, /^__Host-clarelay=/);
assert.equal((await call(DOMAIN, '/api/login', { method: 'POST', headers: { origin: 'https://evil.example', 'content-type': 'application/json', cookie: ENR }, body: '{}' })).status, 403, '跨站 POST 被拒');

console.log('step 2');
// 2. 生成邀请码，电脑加入（要批准）
const inv = (await api('/api/admin/invite', { note: '测试' }, cookie)).j.invite;
assert.match(inv, /^clarelay-device1\./);
const statuses = [];
const dev = await startDevice({ invite: inv, name: '测试 Mac', state: path.join(tmp, 'agent.json'), services: { claclaw: APP }, acme: 'devca', ca: CA, connect: { host: '127.0.0.1', port: HP }, onStatus: s => statuses.push(s), log: process.env.V ? (...a) => console.log('[agent]', ...a) : undefined });
await until(() => dev.online, 8000, 'device online');
assert.equal(dev.status, 'pending');
await assert.rejects(startDevice({ invite: inv, name: 'x', state: path.join(tmp, 'agent2.json'), services: { a: APP }, ca: CA, connect: { host: '127.0.0.1', port: HP } }), /无效|用过/);
const host = new URL(dev.url).hostname;
await assert.rejects(call(host, '/'), '未批准时连不上');
const id = (await api('/api/devices', null, cookie)).j.devices[0].id;
assert.equal((await api('/api/ticket', { device: id }, cookie)).status, 404, '未批准不发通行票');
assert.equal((await api('/api/admin/device', { id, action: 'approve' }, cookie)).status, 200);
await until(() => dev.status === 'active' && dev.cert.ok, 8000, 'approved + cert');

console.log('step 3');
// 3. 端到端 TLS：证书是电脑自己的（中继不解开）
const r0 = await call(host, '/', { headers: { accept: 'text/html' } });
assert.equal(r0.cert.subject.CN, host);
assert.equal(r0.status, 404, '没过门卫：404');
assert.equal((await call(host, '/api/x')).status, 404, '没过门卫');
assert.equal(seen.length, 0, '门卫之前不能碰到应用');

console.log('step 4');
// 4. 通行票 → 门卫 cookie → 进应用
const tk = (await api('/api/ticket', { device: id, back: '/s/abc?x=1' }, cookie)).j.url;
const tu = new URL(tk);
const a1 = await call(host, tu.pathname + tu.search);
assert.equal(a1.status, 302); assert.equal(a1.headers.location, '/s/abc?x=1');
const gate = a1.headers['set-cookie'][0].split(';')[0];
assert.match(a1.headers['set-cookie'][0], /__Host-clarelay-gate=.*Secure.*HttpOnly.*SameSite=Lax/);
assert.equal((await call(host, tu.pathname + tu.search)).status, 404, '通行票只能用一次');
const r1 = await call(host, '/s/abc?x=1', { headers: { cookie: gate + '; mine=1', 'x-forwarded-for': '6.6.6.6', 'x-forwarded-proto': 'http' } });
assert.equal(r1.status, 200); assert.equal(r1.j.hello, 'claclaw');
assert.equal(r1.headers['x-frame-options'], undefined);
assert.match(r1.headers['content-security-policy'], /frame-ancestors 'self' https:\/\/circle\.test/);
const h = seen.at(-1).headers;
assert.equal(h['x-forwarded-for'], '127.0.0.1', '来源 IP 被覆盖成真实 IP');
assert.equal(h['x-forwarded-proto'], 'https');
assert.equal(h.host, host + ':' + HP, 'Host 原样保留');
assert.equal(h.cookie, 'mine=1', '门卫 cookie 不交给应用');

console.log('step 5');
// 4b. 独立主屏幕 App：页面里的 manifest 链接被改写；manifest 不带 cookie 也能取；start_url 换门卫 cookie（一次性）
const pg = await call(host, '/page', { headers: { cookie: gate, accept: 'text/html' } });
const mhref = pg.text.match(/href="([^"]*_clarelay\/manifest[^"]*)"/)[1].replace(/&amp;/g, '&');
const man = JSON.parse((await call(host, mhref)).text);
assert.equal(man.name, 'claclaw'); assert.match(man.start_url, /^\/_clarelay\/start\?t=.*back=%2F%3Fpwa%3D1/);
const stt = await call(host, man.start_url);
assert.equal(stt.status, 302); assert.equal(stt.headers.location, '/?pwa=1'); assert.match(stt.headers['set-cookie'][0], /__Host-clarelay-gate=.*Max-Age=34560000/);
assert.equal((await call(host, man.start_url)).status, 404, 'start 凭证只能用一次');
// 已授权设备的凭证（Domain=圈子域名）：直接打开电脑网址会被送去外壳；没有凭证 404
const shellPage = await call(DOMAIN, '/', { headers: { cookie: ENR } });
const proof = shellPage.headers['set-cookie'].find(c => c.startsWith('__Secure-clarelay-proof=')).split(';')[0];
assert.match(shellPage.headers['set-cookie'].find(c => c.startsWith('__Secure-clarelay-proof=')), /Domain=circle\.test/);
const dir = await call(host, '/s/x', { headers: { cookie: proof, accept: 'text/html' } });
assert.equal(dir.status, 302); assert.match(dir.headers.location, /\/_auth\?host=/);
assert.equal((await call(host, '/s/x', { headers: { accept: 'text/html' } })).status, 404);

console.log('step 5');
// 5. WebSocket（Upgrade）经门卫
const ws = await new Promise((ok, bad) => {
  const s = tls.connect({ host: '127.0.0.1', port: HP, servername: host, ca: CA }, () => {
    s.write(`GET /ws HTTP/1.1\r\nhost: ${host}\r\nconnection: Upgrade\r\nupgrade: websocket\r\ncookie: ${gate}\r\n\r\n`);
    let b = ''; s.on('data', d => { b += d; if (b.includes('\r\n\r\n') && !s.sent) { s.sent = 1; s.write('ping'); } if (b.includes('echo:ping')) { s.destroy(); ok(b); } });
  }); s.on('error', bad); setTimeout(() => bad(new Error('ws timeout')), 5000);
});
assert.match(ws, /101 Switching/);

console.log('step 6');
// 6. 提醒：摘要只留前 20 个字
const sse = await new Promise(ok => {
  const r = https.request({ host: '127.0.0.1', port: HP, servername: DOMAIN, path: '/api/events', ca: CA, headers: { host: DOMAIN, cookie: ENR + '; ' + cookie } }, res => { let b = ''; res.on('data', d => { b += d; if (b.includes('"target":"sess-1"')) { r.destroy(); ok(b); } }); });
  r.end();
  setTimeout(() => dev.notify({ app: 'claclaw', target: 'sess-1', kind: 'reply', title: '测试 Mac · 会话', snippet: '一二三四五六七八九十一二三四五六七八九十多出来的不该出现', unread: 2 }), 300);
});
assert.ok(sse.includes('一二三四五六七八九十一二三四五六七八九十'), sse.slice(-300));
assert.ok(!sse.includes('多出来'));
dev.read({ app: 'claclaw', target: 'sess-1' });
await until(async () => (await api('/api/devices', null, cookie)).j.unread.length === 0, 3000, 'read clears');

console.log('step 7');
// 7. 撤销浏览器登录：门卫立刻不认
const sid = (await api('/api/me', null, cookie)).j.sid;
// 用另一个登录去撤销第一个
const cookie2 = (await api('/api/login', { user: 'boss', pass: 'super-secret-pass' })).headers['set-cookie'][0].split(';')[0];
await api('/api/admin/session', { sid, action: 'revoke' }, cookie2);
await until(async () => (await call(host, '/x', { headers: { cookie: gate } })).status === 404, 3000, 'gate revoked');
assert.equal((await api('/api/me', null, cookie)).status, 401);

console.log('step 8');
// 7b. 取消授权：这台浏览器的登录跟着失效，再打开只有 404
const st7 = (await api('/api/admin/state', null, cookie2)).j;
const other = st7.enrolls.find(e => !e.current);
assert.ok(other, '应有第二个授权（主屏幕 App 转移来的）');
assert.equal((await api('/api/admin/enrollment', { id: other.id, action: 'revoke' }, cookie2)).status, 200);

// 8. 端口 80：跳转到 https
const p80 = await new Promise(ok => http.get({ host: '127.0.0.1', port: PP, path: '/a', headers: { host: host } }, r => { r.resume(); ok(r); }));
assert.equal(p80.statusCode, 301); assert.equal(p80.headers.location, `https://${host}:${HP}/a`);

console.log('step 9');
// 9. 撤销设备
await api('/api/admin/device', { id, action: 'revoke' }, cookie2);
await until(() => dev.status === 'revoked', 3000, 'device revoked');
await assert.rejects(call(host, '/'));

const mine = st7.enrolls.find(e => e.current);
await api('/api/admin/enrollment', { id: mine.id, action: 'revoke' }, cookie2);   // 自己也撤：之后全部 404
assert.equal((await api('/api/me', null, cookie2)).status, 404);
await dev.stop(); relay.kill(); app.close();
await sleep(300); try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
console.log('device ok');
process.exit(0);
process.on('exit', c => { if (c && process.env.V) console.log(relayLog); });
