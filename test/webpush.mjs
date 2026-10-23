// Web Push 加密自测：按 RFC 8291 用浏览器一侧的私钥解开，内容一致
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import http from 'node:http';
import { encrypt, sendPush, newVapid } from '../device/webpush.mjs';
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const ua = crypto.createECDH('prime256v1'); ua.generateKeys();
const auth = crypto.randomBytes(16);
const msg = JSON.stringify({ title: '办公室 Mac', body: '一二三四五' });
const body = encrypt(msg, ua.getPublicKey().toString('base64url'), auth.toString('base64url'));
// 解密
const salt = body.subarray(0, 16), rs = body.readUInt32BE(16), idlen = body[20], asPub = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen);
assert.equal(rs, 4096);
const shared = ua.computeSecret(asPub);
const ikm = hmac(hmac(auth, shared), Buffer.concat([Buffer.from('WebPush: info\0'), ua.getPublicKey(), asPub, Buffer.from([1])]));
const prk = hmac(salt, ikm);
const cek = hmac(prk, Buffer.from('Content-Encoding: aes128gcm\0\x01', 'latin1')).subarray(0, 16);
const nonce = hmac(prk, Buffer.from('Content-Encoding: nonce\0\x01', 'latin1')).subarray(0, 12);
const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce); d.setAuthTag(ct.subarray(-16));
const pt = Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]);
assert.equal(pt.at(-1), 2); assert.equal(pt.subarray(0, -1).toString(), msg);
// VAPID 头：JWT 签名能用公钥验证
const vapid = newVapid();
let got;
const srv = http.createServer((q, s) => { got = q.headers; q.resume(); q.on('end', () => { s.writeHead(201); s.end(); }); }).listen(0);
const st = await sendPush({ endpoint: 'http://127.0.0.1:' + srv.address().port + '/push/x', keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') } }, { a: 1 }, { vapid, subject: 'https://circle.test' });
assert.equal(st, 201);
const [, t, k] = got.authorization.match(/^vapid t=([^,]+), k=(.+)$/);
const [h, c, sig] = t.split('.');
const pub = Buffer.from(k, 'base64url');
const key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') }, format: 'jwk' });
assert.ok(crypto.verify('sha256', Buffer.from(h + '.' + c), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url')));
assert.equal(JSON.parse(Buffer.from(c, 'base64url')).aud, 'http://127.0.0.1:' + srv.address().port);
assert.equal(got['content-encoding'], 'aes128gcm');
srv.close();
console.log('webpush ok');
