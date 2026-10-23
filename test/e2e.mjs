// 端到端加密：把中继当成坏人（在它前面加一个能偷看、重放、篡改的中间层），确认它看不到、改不了、重放不了。
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { startTunnel, relayRequest } from '../tunnel.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clarelay-e2e-'));
const PORT = 19000 + Math.floor(Math.random() * 1000);
const SECRET = 'top-secret-' + Date.now();

let hits = 0;
const svc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => { hits++; res.writeHead(201, { 'content-type': 'application/json', 'x-a': '1' }); res.end(JSON.stringify({ path: req.url, method: req.method, body: b, ct: req.headers['content-type'], xff: req.headers['x-forwarded-for'], reply: SECRET })); });
}).listen(0);
const to = 'http://127.0.0.1:' + svc.address().port;

const relay = spawn(process.execPath, [path.join(root, 'server.mjs'), '--plain', '--port', PORT, '--data', tmp, '--public', 'http://127.0.0.1:' + PORT]);
const invite = await new Promise((ok, bad) => {
  let out = ''; relay.stdout.on('data', c => { out += c; const m = out.match(/clarelay1\.[A-Za-z0-9_-]+/); if (m) ok(m[0]); });
  relay.on('exit', () => bad(new Error(out)));
});
const t = await startTunnel({ invite, to, state: path.join(tmp, 'state.json') });

// 坏中继：所有流量经过它，记录、可篡改
let seen = [], lastReq = null, tamper = false;
const mitm = http.createServer((req, res) => {
  const chunks = []; req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks); seen.push(req.url + ' ' + body.toString('latin1'));
    if (req.url.endsWith('/_e2e')) lastReq = { url: req.url, headers: req.headers, body };
    const up = http.request('http://127.0.0.1:' + PORT + req.url, { method: req.method, headers: req.headers }, r => {
      const rc = []; r.on('data', c => rc.push(c));
      r.on('end', () => { let rb = Buffer.concat(rc); seen.push(rb.toString('latin1')); if (tamper) { rb = Buffer.from(rb); rb[rb.length - 1] ^= 1; } res.writeHead(r.statusCode, r.headers); res.end(rb); });
    });
    up.end(body);
  });
}).listen(0);
const via = addr => addr.replace('127.0.0.1:' + PORT, '127.0.0.1:' + mitm.address().port);

assert.match(t.address, /#key=[A-Za-z0-9_-]{43}$/);
const addr = via(t.urlFor('/claclaw-peer?x=1'));
const r = await relayRequest(addr, { method: 'POST', body: { msg: SECRET } });
assert.equal(r.e2e, true); assert.equal(r.status, 201); assert.equal(r.headers['x-a'], '1');
const j = r.json();
assert.deepEqual([j.path, j.method, j.body, j.ct, j.xff], ['/claclaw-peer?x=1', 'POST', JSON.stringify({ msg: SECRET }), 'application/json', '127.0.0.1']);
assert.ok(!seen.join('\n').includes(SECRET), '中继看到了明文');
assert.ok(!seen.join('\n').includes('claclaw-peer'), '中继看到了路径');

// 重放
const before = hits;
const replay = await new Promise(ok => http.request('http://127.0.0.1:' + PORT + lastReq.url, { method: 'POST', headers: lastReq.headers }, res => { let s = ''; res.on('data', c => s += c); res.on('end', () => ok({ status: res.statusCode, s })); }).end(lastReq.body));
assert.equal(replay.status, 400); assert.match(replay.s, /重放/); assert.equal(hits, before);

// 篡改响应
tamper = true;
await assert.rejects(relayRequest(addr, { method: 'GET' }), /解密失败/);
tamper = false;

// 明文请求被拒；--plain 时放行
const plain = await relayRequest(t.publicUrl + '/x');
assert.equal(plain.status, 403);
// 错的 key：对方解不开，返回明文 400
await assert.rejects(relayRequest(t.publicUrl + '/x#key=' + 'A'.repeat(43)), /无效/);
const other = (await import('node:crypto')).generateKeyPairSync('x25519').publicKey.export({ format: 'jwk' }).x;
const wrong = await relayRequest(t.publicUrl + '/x#key=' + other);
assert.equal(wrong.status, 400); assert.equal(wrong.e2e, false);
// 坏中继冒充成功的明文响应：拒绝
const fake = http.createServer((q, s) => { q.resume(); q.on('end', () => s.end('{"ok":true}')); }).listen(0);
await assert.rejects(relayRequest('http://127.0.0.1:' + fake.address().port + '/t/' + t.name + '/x#key=' + t.key), /未加密/);
fake.close();

await t.stop();
const t2 = await startTunnel({ invite, to, state: path.join(tmp, 'state.json'), plain: true });
assert.equal(t2.key, t.key);   // 重启后加密公钥不变
assert.equal((await relayRequest(t2.publicUrl + '/x')).status, 201);
await t2.stop();

relay.kill(); svc.close(); mitm.close(); fs.rmSync(tmp, { recursive: true, force: true });
console.log('e2e ok');
process.exit(0);
