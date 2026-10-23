// 设备组网：中继和电脑共用的小工具（零依赖）
import crypto from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';

export const DEVICE_VERSION = '0.3.3';
export const INVITE_PREFIX = 'clarelay-device1.';
export const b64u = b => Buffer.from(b).toString('base64url');
export const unb64u = s => Buffer.from(String(s), 'base64url');
export const sha256 = s => crypto.createHash('sha256').update(s).digest();
export const rand = (n = 18) => crypto.randomBytes(n).toString('base64url');
export const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
// 设备的网址名：小写字母 + 数字（DNS 不区分大小写），10 位
export const randLabel = () => { const a = 'abcdefghijkmnpqrstuvwxyz23456789'; let s = ''; for (const b of crypto.randomBytes(10)) s += a[b % a.length]; return s; };

// ---------- 设备邀请码 ----------
// clarelay-device1.<base64url JSON {d: 圈子域名, c: 一次性邀请码, p?: 端口（默认 443）}>
export function makeDeviceInvite({ domain, code, port }) {
  const j = { d: domain, c: code }; if (port && port !== 443) j.p = port;
  return INVITE_PREFIX + b64u(JSON.stringify(j));
}
export function parseDeviceInvite(s) {
  s = String(s || '').trim().replace(/\s+/g, '');
  const i = s.indexOf(INVITE_PREFIX);
  if (i < 0) throw new Error('不是 clarelay 设备邀请码（应以 ' + INVITE_PREFIX + ' 开头）');
  let j; try { j = JSON.parse(unb64u(s.slice(i + INVITE_PREFIX.length).match(/^[A-Za-z0-9_-]+/)[0]).toString('utf8')); } catch { throw new Error('设备邀请码不完整或损坏'); }
  if (!/^[a-z0-9.-]+$/i.test(j.d || '') || !j.c) throw new Error('设备邀请码内容不对');
  return { domain: j.d.toLowerCase(), code: j.c, port: j.p || 443 };
}

// ---------- 通行票：中继用 Ed25519 签，门卫核对 ----------
// 票 = base64url(JSON {aud: 设备网址名, sid: 浏览器会话 id, exp: 毫秒, n: 随机}) + '.' + base64url(签名)
export function signTicket(privateKey, body) {
  const p = b64u(JSON.stringify(body));
  return p + '.' + b64u(crypto.sign(null, Buffer.from(p), privateKey));
}
export function verifyTicket(publicKeyPem, ticket) {
  const [p, s] = String(ticket || '').split('.');
  if (!p || !s) return null;
  try {
    if (!crypto.verify(null, Buffer.from(p), crypto.createPublicKey(publicKeyPem), unb64u(s))) return null;
    return JSON.parse(unb64u(p).toString('utf8'));
  } catch { return null; }
}

// ---------- 一行一条 JSON 的消息通道 ----------
export function lineChannel(sock, onMsg) {
  let buf = '';
  const dec = new StringDecoder('utf8');
  sock.on('data', d => {
    buf += typeof d === 'string' ? d : dec.write(d);
    if (buf.length > 4 * 1024 * 1024) { sock.destroy(); return; }
    let i; while ((i = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); if (line.trim()) { let m; try { m = JSON.parse(line); } catch { continue; } onMsg(m); } }
  });
  return m => { if (!sock.destroyed) sock.write(JSON.stringify(m) + '\n'); };
}

// ---------- TLS ClientHello 里的 SNI（中继按网址分流用，不解开 TLS） ----------
// 返回 { need: true } 表示数据还不够；{ sni: '…' | '' } 表示解析完成；null 表示不是 TLS
export function parseSni(buf) {
  if (buf.length < 5) return { need: true };
  if (buf[0] !== 22) return null;
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen) return buf.length > 16389 ? null : { need: true };
  let p = 5;
  if (buf[p] !== 1) return null;
  p += 4 + 2 + 32;                                  // 握手头、版本、随机数
  p += 1 + buf[p];                                  // session id
  p += 2 + buf.readUInt16BE(p);                     // cipher suites
  p += 1 + buf[p];                                  // compression
  if (p + 2 > 5 + recLen) return { sni: '' };
  const end = p + 2 + buf.readUInt16BE(p); p += 2;
  while (p + 4 <= end) {
    const type = buf.readUInt16BE(p), len = buf.readUInt16BE(p + 2); p += 4;
    if (type === 0) {
      let q = p + 2;
      while (q + 3 <= p + len) {
        const nt = buf[q], nl = buf.readUInt16BE(q + 1); q += 3;
        if (nt === 0) return { sni: buf.slice(q, q + nl).toString('ascii').toLowerCase() };
        q += nl;
      }
    }
    p += len;
  }
  return { sni: '' };
}

// ---------- 简单限流：key → 窗口内次数 ----------
export function limiter(max, windowMs) {
  const m = new Map();
  return key => {
    const now = Date.now(), h = m.get(key) || { n: 0, t: now };
    if (now - h.t > windowMs) { h.n = 0; h.t = now; }
    h.n++; m.set(key, h);
    if (m.size > 10000) m.clear();
    return h.n > max;
  };
}

// ---------- 把「已经读出来的开头几个字节 + 剩下的连接」包成一条新流 ----------
// Node 的 TLS 会直接从底层句柄读数据，socket.unshift() 塞回去的字节它看不到，所以要包一层。
import { Duplex } from 'node:stream';
export function prefixed(sock, head, extra = {}) {
  const d = new Duplex({
    read() { sock.resume(); },
    write(chunk, enc, cb) { sock.write(chunk, enc, cb); },
    final(cb) { sock.end(); cb(); },
    destroy(err, cb) { sock.destroy(); cb(err); },
  });
  if (head?.length) d.push(head);
  sock.on('data', c => { if (!d.push(c)) sock.pause(); });
  sock.on('end', () => d.push(null));
  sock.on('close', () => d.destroy());
  sock.on('error', () => d.destroy());
  sock.resume();
  Object.assign(d, { remoteAddress: sock.remoteAddress, remotePort: sock.remotePort, remoteFamily: sock.remoteFamily,
    setNoDelay() { sock.setNoDelay?.(true); return d; }, setKeepAlive(...a) { sock.setKeepAlive?.(...a); return d; },
    setTimeout(ms, cb) { sock.setTimeout?.(ms, cb); return d; }, ref() { return d; }, unref() { return d; } }, extra);
  return d;
}

// 在一条（已包装的）流上做 TLS 服务端，交给普通的 http.Server：req.socket 就是这里的 TLSSocket，可以直接挂上来源 IP
import tls from 'node:tls';
export function serveTls(httpServer, stream, getContext, ip) {
  const t = new tls.TLSSocket(stream, { isServer: true, secureContext: getContext() });
  t.clarelayIp = ip;
  t.on('error', () => stream.destroy?.());
  httpServer.emit('connection', t);
  return t;
}
export const realIp = sock => sock?.clarelayIp || String(sock?.remoteAddress || '').replace(/^::ffff:/, '');
