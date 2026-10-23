# clarelay 中继协议（v1）

照这份约定，任何语言都能自己实现中继服务端、隧道端或发起方，和 clarelay 的实现互通。所有路径、头名都区分大小写的地方按原样写。

## 1. 传输和证书指纹

- 中继用 HTTPS，证书通常是自签的。连接方**不走 CA 校验**，改成在 TLS 握手完成、发出任何数据之前，核对**证书指纹**：
  `pin = "sha256//" + base64( SHA-256( 证书公钥的 SPKI DER ) )`（和 `curl --pinnedpubkey` 的格式相同）。指纹对不上就断开连接。
- 测试时可以用纯 http，这时没有 pin。

## 2. 中继邀请码

`"clarelay1." + base64url( JSON )`，JSON 是 `{"r": 中继地址, "k": 注册口令, "p": pin}`。`p` 在 http 时省略；base64url 不带填充。

## 3. 隧道端 ↔ 中继

每个隧道自己生成：
- `name`：16–64 位，字符为 `[A-Za-z0-9_-]`；
- `secret`：长度 ≥ 16 的随机串。

第一次登记时，中继记下 `name → SHA-256(secret)`，以后同一个名字只认这个 secret。

所有请求都要带两个头：`x-relay-key: <注册口令>` 和 `x-tunnel-secret: <secret>`。

| 请求 | 说明 |
| --- | --- |
| `POST /_relay/register?name=<name>` | 登记。返回 `200 {"ok":true,"path":"/t/<name>"}`。错误：401 口令不对，403 名字被别的 secret 占用，400 参数不对 |
| `GET /_relay/poll?name=<name>` | 长轮询，最多等 25 秒。有请求时返回 `200 {"id","method","path","headers","body"}`，其中 `body` 是 base64、`path` 含查询串、`headers` 里已带好 `x-forwarded-for`；没有请求时返回 `204`。可以同时开几个 poll |
| `POST /_relay/reply?name=<name>&id=<id>` | 交回响应，请求体是 JSON `{"status", "headers", "body"(base64)}`。返回 `200 {"ok":true}`；返回 404 表示这个请求已经超时 |

隧道 60 秒内没有 poll / reply，中继就把它算作离线。

## 4. 公开地址（发起方 → 中继）

`<任意方法> https://中继/t/<name>/<path>` 会被原样排进这个隧道的队列：去掉 `host`、`connection`、`content-length` 等逐跳头；`x-forwarded-for` 由中继用真实来源 IP 覆盖。

中继自己返回的错误（都是明文 JSON `{"error"}`）：

| 状态码 | 含义 |
| --- | --- |
| 404 | 没有这个名字 |
| 429 | 同一 IP 超过每分钟 120 次 |
| 413 | 请求体超过 3MB |
| 502 | 隧道离线 |
| 504 | 11 分钟内没有回应 |

## 5. 端到端加密

**地址格式**：`https://中继/t/<name>/<path>#pin=<pin>&key=<K>`

- `K` 是目标隧道长期 X25519 公钥的原始 32 字节，用 base64url 编码。
- `#` 后面的参数要自己按 `&` 和第一个 `=` 拆开。**不能用 URLSearchParams 这类解析器**：pin 里有 `+`，会被当成空格。

### 发起方

1. 生成临时 X25519 密钥对 `(e, E)`，其中 `E` 为原始 32 字节公钥。
2. 计算 `shared = X25519(e, K)`。
3. 派生密钥：`okm = HKDF-SHA256(ikm=shared, salt=E‖K, info="clarelay e2e v1", L=64)`，取 `kreq = okm[0..32]`、`kres = okm[32..64]`。
4. 组织明文 JSON：
   - `t`：当前毫秒时间戳
   - `m`：方法
   - `p`：`/<path>?query`，必须以 `/` 开头
   - `h`：请求头对象，头名小写
   - `b`：请求体，base64
5. 用 AES-256-GCM 和 `kreq` 加密，IV 取 12 字节随机数，tag 取 16 字节。
6. 发送 `POST https://中继/t/<name>/_e2e`：
   - 头：`content-type: application/x-clarelay-e2e`
   - 请求体：`0x01 ‖ E(32) ‖ IV(12) ‖ 密文 ‖ tag(16)`

### 隧道端（接收方）

1. 用自己的私钥和 `E` 算出同样的 `kreq` / `kres`，解密。解密失败时返回明文 400。
2. 以下请求一律拒绝，返回明文 400：
   - `|t − 现在| > 5 分钟`；
   - 同一个 `E` 在 10 分钟内出现第二次（重放）。
3. 用 `m`、`p`、`h`、`b` 请求本机服务：去掉 `h` 里的 host、逐跳头和 `x-forwarded-for`，`x-forwarded-for` 改用中继给的值。
4. 把本机服务的响应组织成明文 JSON `{"s": 状态码, "h": 响应头, "b": base64 响应体}`，用 `kres` 和新的随机 IV 加密。
5. 返回 `200`，头为 `content-type: application/x-clarelay-e2e`，响应体为 `IV(12) ‖ 密文 ‖ tag(16)`。
6. 建议：不是 `/_e2e` 的明文请求一律返回 403。

### 发起方收到响应

| 收到的响应 | 处理 |
| --- | --- |
| `content-type` 是 `application/x-clarelay-e2e` | 用 `kres` 解密，得到真正的 `s` / `h` / `b`；解密失败就当作被篡改 |
| 明文，状态码 ≥ 400 | 中继或隧道报的错，可以原样展示 |
| 明文，状态码 < 400 | **必须拒绝**（可能是中继伪造的） |

## 6. 参考实现

本仓库的 `tunnel.mjs` 包含隧道端和发起方（`relayRequest`），`server.mjs` 是中继服务端。中继也会在 `GET /tunnel.mjs` 提供 `tunnel.mjs` 下载，`GET /_relay/version` 返回版本号。
