# clarelay：让不在同一个局域网的电脑互相访问

零依赖（只要 Node.js 18+），两个文件：

| 文件 | 跑在哪 | 干什么 |
| --- | --- | --- |
| `server.mjs` | 一台外网能访问的服务器（开一个端口，不需要域名和证书） | 中转请求 |
| `tunnel.mjs` | 每台要被别人访问的电脑 | 主动连中继，领一个公开地址，把请求转给本机服务。也可以 `import` |

```
别人 ── https://中继:8790/t/<名字>/路径 ──▶ server.mjs ◀── 一直连着 ── tunnel.mjs ──▶ 本机服务/路径
```

## 1. 服务器：运行中继

```sh
git clone https://github.com/wyidong/clarelay.git && cd clarelay
node server.mjs --public https://服务器公网IP:8790 --port 8790
```

第一次启动生成自签证书和注册口令（存 `relay-data/`，重启不变），打印：

```
clarelay 0.1.0 中继已启动：https://服务器公网IP:8790
证书指纹（pin）：sha256//…
注册口令：…
中继邀请码（只给要接入的人，内含注册口令）：
clarelay1.eyJy…
```

**中继邀请码**＝地址＋证书指纹＋注册口令。拿到它就能接入，只给信任的人。
防火墙放行端口（`ufw allow 8790/tcp` 或云安全组）。

systemd 开机自启：

```ini
# /etc/systemd/system/clarelay.service
[Unit]
Description=clarelay
After=network-online.target
[Service]
User=用户
WorkingDirectory=/home/用户/clarelay
ExecStart=/usr/bin/node /home/用户/clarelay/server.mjs --public https://服务器公网IP:8790 --port 8790
Restart=always
[Install]
WantedBy=multi-user.target
```

`sudo systemctl enable --now clarelay`；`journalctl -u clarelay -n 20` 看邀请码。

## 2. 自己电脑：连隧道

```sh
node tunnel.mjs <中继邀请码> --to http://127.0.0.1:8788
```

打印公开地址和带指纹的地址（`…/t/<名字>#pin=sha256//…`）。名字存在 `~/.relay-tunnel.json`（`--state` 可改），重启后不变。

**不装任何东西的写法**（给同事的 AI 照着跑）——中继自己提供 `tunnel.mjs` 下载，先核对指纹：

```sh
curl -fsSk --pinnedpubkey 'sha256//…' https://中继:8790/tunnel.mjs -o clarelay-tunnel.mjs \
  && node clarelay-tunnel.mjs '<中继邀请码>' --to http://127.0.0.1:8788
```

这条命令可以用 `tunnelCommand(invite, to)` 生成。

## 3. 在代码里用

```js
import { startTunnel, parseInvite, makeInvite, isInvite, tunnelCommand, pinnedConnector, pinOf, VERSION } from 'clarelay';

const t = await startTunnel({
  invite,                          // 或 { relay, pin, key }
  to: 'http://127.0.0.1:8788',     // 本机服务
  state: '/path/state.json',       // 可选，默认 ~/.relay-tunnel.json
  onStatus: s => {},               // 可选，{ online, error? } 断线 / 重连时调用
  log: console.log,                // 可选
});
t.publicUrl   // https://中继:8790/t/<名字>
t.pin         // sha256//…（http 中继时为空）
t.online      // 当前是否连着
await t.stop();
```

- 邀请码错、口令错、指纹不对、中继连不上：`startTunnel` 直接 reject，不重试；连上之后断线会每 5 秒自动重连。
- 访问中继时自己核对指纹：`https.request(url, { createConnection: pinnedConnector(pin) })`（别加 `agent: false`，否则 Node 会忽略 `createConnection`）。
- 经隧道进来的请求带 `x-forwarded-for`＝真实来源 IP（中继会覆盖对方伪造的值）。

## 4. 别人怎么访问

```sh
curl -k --pinnedpubkey 'sha256//…' https://中继:8790/t/<名字>/路径
```

## 安全和限制

- 传输是 HTTPS，证书指纹钉死：网络上的中间人看不到内容，也冒充不了中继。
- **中继能看到经过它的全部内容**：TLS 在中继这里终止，请求和响应在中继上是明文（转发需要）。中继只放在你信任的服务器上；目前没有端到端加密。
- 公开地址里的名字是 20 位随机串，等于钥匙；之后还要过本机服务自己的验证。
- 注册口令错误的请求、公开地址的请求：每个来源 IP 每分钟最多 120 次。
- 单个请求 / 响应最多 1MB；最多等 11 分钟回应；隧道 60 秒没来取请求就算离线（返回 502「对方不在线」）。
- `--plain`：不用 HTTPS，只用于测试。

## 测试

```sh
npm test   # 本机起中继 + 隧道 + 假服务，跑通转发、指纹、口令、重启地址不变
```
