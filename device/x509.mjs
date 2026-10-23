// 最小 ASN.1 / X.509：生成 P-256 密钥、CSR（给 ACME）、自签证书和测试 CA 签发的证书。零依赖，不需要 openssl。
import crypto from 'node:crypto';

const len = n => n < 128 ? Buffer.from([n]) : (() => { const b = []; while (n) { b.unshift(n & 255); n >>= 8; } return Buffer.from([0x80 | b.length, ...b]); })();
const tlv = (tag, ...parts) => { const c = Buffer.concat(parts.map(p => Buffer.isBuffer(p) ? p : Buffer.from(p))); return Buffer.concat([Buffer.from([tag]), len(c.length), c]); };
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const int = b => { b = Buffer.from(b); let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return tlv(0x02, b); };
const oid = s => { const a = s.split('.').map(Number), out = [40 * a[0] + a[1]]; for (const v of a.slice(2)) { const t = []; let x = v; do { t.unshift(x & 127); x = Math.floor(x / 128); } while (x); for (let i = 0; i < t.length - 1; i++) t[i] |= 128; out.push(...t); } return tlv(0x06, Buffer.from(out)); };
const utf8 = s => tlv(0x0c, Buffer.from(s, 'utf8'));
const bits = (b, unused = 0) => tlv(0x03, Buffer.from([unused]), b);
const octet = b => tlv(0x04, b);
const bool = v => tlv(0x01, Buffer.from([v ? 0xff : 0]));
const ctx = (n, ...p) => tlv(0xa0 | n, ...p);
const time = d => { const y = d.getUTCFullYear(), p = x => String(x).padStart(2, '0'); const s = p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + 'Z'; return y < 2050 ? tlv(0x17, Buffer.from(String(y).slice(2) + s)) : tlv(0x18, Buffer.from(y + s)); };
const name = cn => seq(set(seq(oid('2.5.4.3'), utf8(cn))));
const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));
const ext = (id, critical, value) => critical ? seq(oid(id), bool(true), octet(value)) : seq(oid(id), octet(value));
const san = hosts => ext('2.5.29.17', false, seq(...hosts.map(h => tlv(0x82, Buffer.from(h)))));

export function newKey() { return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey; }
export const keyPem = k => k.export({ type: 'pkcs8', format: 'pem' });
export const loadKey = pem => crypto.createPrivateKey(pem);
const spki = k => crypto.createPublicKey(k).export({ type: 'spki', format: 'der' });
const pem = (label, der) => `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;

// PKCS#10 证书请求（DER），CN = 第一个域名，SAN = 全部域名
export function csr(key, hosts) {
  const info = seq(int([0]), name(hosts[0]), spki(key),
    ctx(0, seq(oid('1.2.840.113549.1.9.14'), set(seq(san(hosts))))));
  return seq(info, ECDSA_SHA256, bits(crypto.sign('sha256', info, key)));
}

// 签一张证书。issuer 不给就是自签。ca=true 签 CA 证书。
export function certificate({ key, hosts = [], cn, issuerKey, issuerCn, ca = false, days = 90 }) {
  const now = new Date(Date.now() - 60e3), end = new Date(Date.now() + days * 864e5);
  const exts = [ext('2.5.29.19', true, seq(...(ca ? [bool(true)] : [])))];
  if (ca) exts.push(ext('2.5.29.15', true, bits(Buffer.from([0x06]), 1)));
  else { exts.push(ext('2.5.29.15', true, bits(Buffer.from([0x80]), 7))); exts.push(ext('2.5.29.37', false, seq(oid('1.3.6.1.5.5.7.3.1')))); }
  if (hosts.length) exts.push(san(hosts));
  const subj = cn || hosts[0];
  const tbs = seq(ctx(0, int([2])), int(crypto.randomBytes(16)), ECDSA_SHA256, name(issuerCn || subj),
    seq(time(now), time(end)), name(subj), spki(key), ctx(3, seq(...exts)));
  const der = seq(tbs, ECDSA_SHA256, bits(crypto.sign('sha256', tbs, issuerKey || key)));
  return pem('CERTIFICATE', der);
}

// 证书还剩多少毫秒过期（读 PEM 链里的第一张）
export function expiresIn(certPem) {
  try { return new Date(new crypto.X509Certificate(certPem).validTo).getTime() - Date.now(); } catch { return -1; }
}

// 测试 CA：从 CSR 里取公钥和域名签一张证书（只给本地测试 / 内网用；正式环境用 Let's Encrypt）
export function signCsrWithCa(csrDer, caKey, caCn, days = 30) {
  // 解析我们自己生成的 CSR：取出 SPKI 和 SAN 里的域名
  const { spkiDer, hosts } = parseOwnCsr(csrDer);
  const now = new Date(Date.now() - 60e3), end = new Date(Date.now() + days * 864e5);
  const exts = [ext('2.5.29.19', true, seq()), ext('2.5.29.15', true, bits(Buffer.from([0x80]), 7)), ext('2.5.29.37', false, seq(oid('1.3.6.1.5.5.7.3.1'))), san(hosts)];
  const tbs = seq(ctx(0, int([2])), int(crypto.randomBytes(16)), ECDSA_SHA256, name(caCn), seq(time(now), time(end)), name(hosts[0]), spkiDer, ctx(3, seq(...exts)));
  return pem('CERTIFICATE', seq(tbs, ECDSA_SHA256, bits(crypto.sign('sha256', tbs, caKey))));
}

// 读 DER：返回 [tag, 内容起点, 内容终点, 下一个起点]
function rd(b, p) { const tag = b[p]; let l = b[p + 1], q = p + 2; if (l & 0x80) { const n = l & 127; l = 0; for (let i = 0; i < n; i++) l = l * 256 + b[q + i]; q += n; } return [tag, q, q + l, q + l]; }
function parseOwnCsr(der) {
  der = Buffer.from(der);
  const [, c0] = rd(der, 0);           // CSR SEQUENCE
  const [, c1, e1] = rd(der, c0);       // info SEQUENCE
  let p = c1;
  p = rd(der, p)[3];                    // version
  p = rd(der, p)[3];                    // subject
  const s = rd(der, p); const spkiDer = der.subarray(p, s[3]); p = s[3];
  const hosts = [];
  // SAN 里的 dNSName（tag 0x82）
  const buf = der.subarray(p, e1);
  for (let i = 0; i < buf.length - 2; i++) if (buf[i] === 0x82 && buf[i + 1] < 128) { const h = buf.subarray(i + 2, i + 2 + buf[i + 1]).toString('latin1'); if (/^[a-z0-9.-]+$/i.test(h) && h.includes('.')) { hosts.push(h); i += 1 + buf[i + 1]; } }
  if (!hosts.length) throw new Error('CSR 里没有域名');
  return { spkiDer, hosts };
}
