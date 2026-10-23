// 端到端自测：起中继（https 自签）+ 本机假服务 + startTunnel，经公开地址发请求并核对指纹。
import { spawn, execFileSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { startTunnel, parseInvite, pinnedConnector, relayRequest } from '../tunnel.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clarelay-'));
const PORT = 18000 + Math.floor(Math.random() * 1000);

const svc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ path: req.url, method: req.method, body: b, xff: req.headers['x-forwarded-for'] })); });
}).listen(0);
const to = 'http://127.0.0.1:' + svc.address().port;

const relayArgs = ['--port', PORT, '--data', tmp, '--public', 'https://127.0.0.1:' + PORT];
const invite = execFileSync(process.execPath, [path.join(root, 'server.mjs'), ...relayArgs, '--print'], { encoding: 'utf8' }).match(/clarelay1\.[A-Za-z0-9_-]+/)[0];
const relay = spawn(process.execPath, [path.join(root, 'server.mjs'), ...relayArgs]);
let relayOut = ''; relay.stdout.on('data', c => relayOut += c);
await new Promise((ok, bad) => { relay.stdout.on('data', () => ok()); relay.on('exit', () => bad(new Error('relay exited'))); });
const inv = parseInvite('请粘贴：' + invite + ' 谢谢');
const statuses = [];
const t = await startTunnel({ invite, to, state: path.join(tmp, 'tunnel.json'), onStatus: s => statuses.push(s) });
assert.match(t.publicUrl, /^https:\/\/127\.0\.0\.1:\d+\/t\/[A-Za-z0-9_-]{16,}$/);
assert.equal(t.pin, inv.pin);

const call = (url, pin, method = 'GET', body) => new Promise((ok, bad) => {
  const r = https.request(url, { method, createConnection: pinnedConnector(pin) }, res => { let s = ''; res.on('data', c => s += c); res.on('end', () => ok({ status: res.statusCode, text: s })); });
  r.on('error', bad); r.end(body);
});
const r1 = await relayRequest(t.urlFor('/claclaw-peer?x=1'), { method: 'POST', body: 'hello' });
assert.equal(r1.status, 200); assert.equal(r1.e2e, true);
const j = r1.json();
assert.deepEqual([j.path, j.method, j.body, j.xff], ['/claclaw-peer?x=1', 'POST', 'hello', '127.0.0.1']);

await assert.rejects(relayRequest(t.publicUrl + '/x#pin=sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&key=' + t.key), /指纹对不上/);
const src = await call('https://127.0.0.1:' + PORT + '/tunnel.mjs', t.pin);
assert.ok(src.text.includes('export async function startTunnel'));
await assert.rejects(startTunnel({ relay: inv.relay, pin: inv.pin, key: 'wrong', to, state: path.join(tmp, 't2.json') }), /注册口令不对/);

// 重启隧道，公开地址不变
await t.stop();
const t2 = await startTunnel({ invite, to, state: path.join(tmp, 'tunnel.json') });
assert.equal(t2.publicUrl, t.publicUrl);
await t2.stop();
assert.ok(!relayOut.includes(inv.key) && !relayOut.includes('clarelay1.'), '注册口令进了服务日志');
relay.kill(); svc.close(); fs.rmSync(tmp, { recursive: true, force: true });
console.log('ok', statuses);
process.exit(0);
