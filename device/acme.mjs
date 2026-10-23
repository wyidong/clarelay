// 精简 ACME 客户端（RFC 8555，HTTP-01 验证）：向 Let's Encrypt 申请证书。零依赖（用 Node 自带的 fetch 和 crypto）。
import crypto from 'node:crypto';
import { csr, newKey, keyPem } from './x509.mjs';

export const LETSENCRYPT = 'https://acme-v02.api.letsencrypt.org/directory';
export const LETSENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

const b64u = b => Buffer.from(b).toString('base64url');
const jwkOf = key => { const j = crypto.createPublicKey(key).export({ format: 'jwk' }); return { crv: j.crv, kty: j.kty, x: j.x, y: j.y }; };
export const thumbprint = key => { const j = jwkOf(key); return b64u(crypto.createHash('sha256').update(JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x, y: j.y })).digest()); };

/**
 * 申请一张证书。
 * @param {object} o
 * @param {string} o.directory      ACME 目录地址（默认 Let's Encrypt 正式环境）
 * @param {crypto.KeyObject} o.accountKey  账号密钥（P-256），要长期保存
 * @param {string} [o.email]
 * @param {string[]} o.hosts        域名
 * @param {crypto.KeyObject} [o.certKey]   证书私钥（不给就新生成）
 * @param {(token:string, keyAuth:string)=>Promise<void>} o.respond   把 HTTP-01 验证内容放好（/.well-known/acme-challenge/<token> → keyAuth）
 * @param {(token:string)=>void} [o.cleanup]
 * @returns {Promise<{ cert: string, key: string }>}  PEM 证书链 + PEM 私钥
 */
export async function acmeIssue(o) {
  const dirUrl = o.directory || LETSENCRYPT, accountKey = o.accountKey, log = o.log || (() => {});
  const certKey = o.certKey || newKey();
  const dir = await (await fetch(dirUrl)).json();
  let nonce = null, kid = null;
  const getNonce = async () => { const r = await fetch(dir.newNonce, { method: 'HEAD' }); return r.headers.get('replay-nonce'); };
  async function post(url, payload, { useJwk = false, accept } = {}) {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (!nonce) nonce = await getNonce();
      const prot = { alg: 'ES256', nonce, url, ...(useJwk ? { jwk: jwkOf(accountKey) } : { kid }) };
      const p64 = b64u(JSON.stringify(prot)), b64 = payload === '' ? '' : b64u(JSON.stringify(payload));
      const sig = crypto.sign('sha256', Buffer.from(p64 + '.' + b64), { key: accountKey, dsaEncoding: 'ieee-p1363' });
      const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/jose+json', ...(accept ? { accept } : {}) }, body: JSON.stringify({ protected: p64, payload: b64, signature: b64u(sig) }) });
      nonce = r.headers.get('replay-nonce');
      const text = await r.text();
      let body = text; try { body = JSON.parse(text); } catch {}
      if (r.status === 400 && body?.type === 'urn:ietf:params:acme:error:badNonce') { nonce = null; continue; }
      if (r.status >= 400) throw new Error('ACME ' + r.status + '：' + (body?.detail || text.slice(0, 200)));
      return { status: r.status, headers: r.headers, body };
    }
    throw new Error('ACME：nonce 反复失效');
  }
  const sleep = ms => new Promise(s => setTimeout(s, ms));
  async function poll(url, done, what) {
    for (let i = 0; i < 40; i++) {
      const r = await post(url, '');
      if (done(r.body)) return r.body;
      if (r.body.status === 'invalid') throw new Error(what + '失败：' + JSON.stringify(r.body.error || r.body.challenges?.find(c => c.error)?.error || r.body).slice(0, 300));
      await sleep(Math.min(1000 * (i + 1), 5000));
    }
    throw new Error(what + '超时');
  }

  const acct = await post(dir.newAccount, { termsOfServiceAgreed: true, ...(o.email ? { contact: ['mailto:' + o.email] } : {}) }, { useJwk: true });
  kid = acct.headers.get('location');
  const order = await post(dir.newOrder, { identifiers: o.hosts.map(h => ({ type: 'dns', value: h })) });
  const orderUrl = order.headers.get('location');
  const thumb = thumbprint(accountKey), tokens = [];
  try {
    for (const authzUrl of order.body.authorizations) {
      const az = (await post(authzUrl, '')).body;
      if (az.status === 'valid') continue;
      const ch = az.challenges.find(c => c.type === 'http-01');
      if (!ch) throw new Error('ACME 没有提供 http-01 验证');
      await o.respond(ch.token, ch.token + '.' + thumb); tokens.push(ch.token);
      log('证书验证：' + az.identifier.value);
      await post(ch.url, {});
      await poll(authzUrl, b => b.status === 'valid', '域名验证（' + az.identifier.value + '）');
    }
    await post(order.body.finalize, { csr: b64u(csr(certKey, o.hosts)) });
    const fin = await poll(orderUrl, b => b.status === 'valid' && b.certificate, '签发');
    const cert = (await post(fin.certificate, '', { accept: 'application/pem-certificate-chain' })).body;
    return { cert: String(cert), key: keyPem(certKey) };
  } finally { for (const t of tokens) o.cleanup?.(t); }
}
