// 端到端自测：起中继（https 自签）+ 本机假服务 + startTunnel，经公开地址发请求并核对指纹。
import { spawn } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { startTunnel, parseInvite, pinnedConnector } from '../tunnel.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clarelay-'));
const PORT = 18000 + Math.floor(Math.random() * 1000);

const svc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ path: req.url, method: req.method, body: b, xff: req.headers['x-forwarded-for'] })); });
}).listen(0);
const to = 'http://127.0.0.1:' + svc.address().port;

const relay = spawn(process.execPath, [path.join(root, 'server.mjs'), '--port', PORT, '--data', tmp, '--public', 'https://127.0.0.1:' + PORT]);
const invite = await new Promise((ok, bad) => {
  let out = ''; relay.stdout.on('data', c => { out += c; const m = out.match(/clarelay1\.[A-Za-z0-9_-]+/); if (m) ok(m[0]); });
  relay.on('exit', () => bad(new Error(out)));
});
const inv = parseInvite('请粘贴：' + invite + ' 谢谢');
const statuses = [];
const t = await startTunnel({ invite, to, state: path.join(tmp, 'tunnel.json'), onStatus: s => statuses.push(s) });
assert.match(t.publicUrl, /^https:\/\/127\.0\.0\.1:\d+\/t\/[A-Za-z0-9_-]{16,}$/);
assert.equal(t.pin, inv.pin);

const call = (url, pin, method = 'GET', body) => new Promise((ok, bad) => {
  const r = https.request(url, { method, createConnection: pinnedConnector(pin) }, res => { let s = ''; res.on('data', c => s += c); res.on('end', () => ok({ status: res.statusCode, text: s })); });
  r.on('error', bad); r.end(body);
});
const r1 = await call(t.publicUrl + '/claclaw-peer?x=1', t.pin, 'POST', 'hello');
assert.equal(r1.status, 200);
const j = JSON.parse(r1.text);
assert.deepEqual([j.path, j.method, j.body, j.xff], ['/claclaw-peer?x=1', 'POST', 'hello', '127.0.0.1']);

await assert.rejects(call(t.publicUrl + '/x', 'sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='), /指纹对不上/);
const src = await call('https://127.0.0.1:' + PORT + '/tunnel.mjs', t.pin);
assert.ok(src.text.includes('export async function startTunnel'));
await assert.rejects(startTunnel({ relay: inv.relay, pin: inv.pin, key: 'wrong', to, state: path.join(tmp, 't2.json') }), /注册口令不对/);

// 重启隧道，公开地址不变
await t.stop();
const t2 = await startTunnel({ invite, to, state: path.join(tmp, 'tunnel.json') });
assert.equal(t2.publicUrl, t.publicUrl);
await t2.stop();
relay.kill(); svc.close(); fs.rmSync(tmp, { recursive: true, force: true });
console.log('ok', statuses);
process.exit(0);
