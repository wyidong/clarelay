// Web Push（RFC 8291 aes128gcm 加密 + RFC 8292 VAPID），零依赖
import crypto from 'node:crypto';

const b64u = b => Buffer.from(b).toString('base64url');
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();

export function newVapid() {
  const e = crypto.createECDH('prime256v1'); e.generateKeys();
  return { pub: b64u(e.getPublicKey()), priv: b64u(e.getPrivateKey()) };
}
function vapidKey({ pub, priv }) {
  const p = Buffer.from(pub, 'base64url');
  return crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: priv, x: b64u(p.subarray(1, 33)), y: b64u(p.subarray(33, 65)) }, format: 'jwk' });
}
function vapidAuth(endpoint, vapid, subject) {
  const aud = new URL(endpoint).origin;
  const h = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const c = b64u(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject }));
  const sig = crypto.sign('sha256', Buffer.from(h + '.' + c), { key: vapidKey(vapid), dsaEncoding: 'ieee-p1363' });
  return `vapid t=${h}.${c}.${b64u(sig)}, k=${vapid.pub}`;
}

export function encrypt(payload, p256dh, auth) {
  const uaPub = Buffer.from(p256dh, 'base64url'), authSecret = Buffer.from(auth, 'base64url');
  const as = crypto.createECDH('prime256v1'); as.generateKeys();
  const asPub = as.getPublicKey(), shared = as.computeSecret(uaPub);
  const prkKey = hmac(authSecret, shared);
  const ikm = hmac(prkKey, Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub, Buffer.from([1])]));
  const salt = crypto.randomBytes(16), prk = hmac(salt, ikm);
  const cek = hmac(prk, Buffer.from('Content-Encoding: aes128gcm\0\x01', 'latin1')).subarray(0, 16);
  const nonce = hmac(prk, Buffer.from('Content-Encoding: nonce\0\x01', 'latin1')).subarray(0, 12);
  const c = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ct = Buffer.concat([c.update(Buffer.concat([Buffer.from(payload), Buffer.from([2])])), c.final(), c.getAuthTag()]);
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPub.length]), asPub, ct]);
}

/** 发一条推送。返回 HTTP 状态码（404 / 410 表示订阅已失效，应删除） */
export async function sendPush(sub, payload, { vapid, subject, ttl = 86400, urgency = 'high' }) {
  const body = encrypt(typeof payload === 'string' ? payload : JSON.stringify(payload), sub.keys.p256dh, sub.keys.auth);
  const r = await fetch(sub.endpoint, {
    method: 'POST', body,
    headers: { 'content-encoding': 'aes128gcm', 'content-type': 'application/octet-stream', ttl: String(ttl), urgency, authorization: vapidAuth(sub.endpoint, vapid, subject) },
  });
  await r.arrayBuffer().catch(() => {});
  return r.status;
}
