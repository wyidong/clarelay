# clarelay：在自己的服务器上搭一个私有中继，让不在同一个局域网的电脑互相访问

用 clarelay 可以在自己的服务器上搭一个只有你和你信任的人能用的中继，效果类似 ngrok，但不经过任何第三方服务。家里、公司的电脑都不用开端口，只需要一台外网能访问的服务器开放**一个端口**。不需要域名，也不需要申请证书。

- **零依赖**：只要 Node.js 18 以上，不用 `npm install`。
- **私有**：拿到「中继邀请码」的人才能接入；它不是开放代理，只能访问已经接入的电脑。
- **端到端加密**：请求在发起方加密、在目标电脑上解密，中继只转发密文。
- 协议公开（[PROTOCOL.md](PROTOCOL.md)）：可以不用本仓库的代码，按约定自己实现服务端或客户端。
- 由两个文件组成：

| 文件 | 跑在哪 | 干什么 |
| --- | --- | --- |
| `server.mjs` | 你的服务器（中继） | 中转请求 |
| `tunnel.mjs` | 每台要被别人访问的电脑 | 主动连上中继、领一个公开地址，把收到的请求转给本机服务；也可以在代码里 `import` |

```
发起方 ──(加密)── https://中继:8790/t/<名字>/_e2e ──▶ server.mjs ◀── 一直连着 ── tunnel.mjs ──(解密)──▶ 本机服务
```

---

## 一、在自己的服务器上部署中继

### 1. 准备

- 一台外网能访问的 Linux 服务器（任意云厂商、VPS 都行），内存 100MB 左右就够。
- Node.js 18 以上，以及 `openssl`（大多数系统自带）。检查：`node -v`、`openssl version`。
- 没有 Node 时可以这样装（任选一种）：
  - Debian / Ubuntu：`curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash - && sudo apt install -y nodejs`
  - CentOS / Alibaba Cloud Linux / RHEL：`curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash - && sudo yum install -y nodejs`
  - 也可以到 https://nodejs.org 下载二进制包。

### 2. 安装（推荐：一键脚本，系统用 systemd）

```sh
git clone https://github.com/wyidong/clarelay.git
cd clarelay
sudo sh deploy/install.sh https://<服务器公网IP或域名>:8790
```

脚本会做这些事：

1. 新建系统用户 `clarelay`，以普通权限运行。
2. 把程序复制到 `/opt/clarelay`，数据放在 `/var/lib/clarelay`。
3. 安装 `clarelay.service`：开机自启，崩溃后 10 秒重启，限制内存，加固了文件系统权限。
4. 打印**中继邀请码**。

```
已启动：https://<服务器公网IP>:8790
地址：https://<服务器公网IP>:8790
证书指纹（pin）：sha256//…
中继邀请码：
clarelay1.eyJy…
```

> **注意**：`--public` 要写**别人从外网访问时用的地址**。云服务器的网卡上通常只有内网 IP，所以一定要手动写公网 IP 或域名。

### 3. 放行端口

中继要能从外网访问，需要放行 **TCP 8790**（或你选的端口）：

- **云服务器**：在控制台的「安全组 / 防火墙规则」里加一条入方向规则：TCP 8790，来源 0.0.0.0/0。
- **服务器自己的防火墙**（如果开着）：`sudo ufw allow 8790/tcp`，或者 `sudo firewall-cmd --add-port=8790/tcp --permanent && sudo firewall-cmd --reload`。

在自己电脑上检查能不能连上（把指纹换成上一步打印的）：

```sh
curl -k --pinnedpubkey 'sha256//…' https://<服务器公网IP>:8790/_relay/version
# {"ok":true,"name":"clarelay","version":"…"}
```

### 4. 日常管理

| 要做什么 | 命令 |
| --- | --- |
| 看状态 / 日志 | `systemctl status clarelay`、`journalctl -u clarelay -n 50` |
| 重新查看邀请码 | `sudo -u clarelay node /opt/clarelay/server.mjs --data /var/lib/clarelay --public https://<地址>:8790 --print` |
| 升级 | `cd clarelay && git pull && sudo sh deploy/install.sh https://<地址>:8790`（证书、口令、已接入的隧道都保留） |
| 停止 / 启动 | `sudo systemctl stop clarelay` / `sudo systemctl start clarelay` |
| **换掉证书和口令**（邀请码泄露时） | `sudo systemctl stop clarelay && sudo rm -rf /var/lib/clarelay/* && sudo systemctl start clarelay`，之后重新查看邀请码。旧邀请码、旧地址全部作废，所有人都要用新邀请码重新接入 |
| 卸载 | `sudo systemctl disable --now clarelay && sudo rm -rf /etc/systemd/system/clarelay.service /opt/clarelay /var/lib/clarelay && sudo userdel clarelay`，再在安全组里关掉端口 |

### 从一台已有的中继直接拿程序

每台中继都会公开提供自己正在跑的程序和文档。这些文件里没有任何数据和口令：`/server.mjs`、`/tunnel.mjs`、`/package.json`、`/README.md`、`/PROTOCOL.md`、`/deploy/install.sh`、`/deploy/clarelay.service`。`/_relay/version` 会列出版本号和每个文件的 SHA-256。没法访问 GitHub 时：

```sh
P='sha256//…'; R=https://<已有中继>:8790
mkdir -p clarelay/deploy && cd clarelay
for f in server.mjs tunnel.mjs package.json README.md PROTOCOL.md deploy/install.sh deploy/clarelay.service; do
  curl -fsSk --pinnedpubkey "$P" "$R/$f" -o "$f"; done
sudo sh deploy/install.sh https://<自己服务器公网IP>:8790
```

### 不用 systemd 的手动运行方式

可以先用这种方式临时试一下：

```sh
node server.mjs --public https://<服务器公网IP>:8790 --port 8790          # 数据放在 ./relay-data/
```

参数：`--public` 是对外地址；`--port` 是监听端口（默认 8790）；`--data` 是数据目录；`--print` 只打印邀请码然后退出；`--plain` 不用 HTTPS，只能在测试时用。

---

## 二、让一台电脑通过中继被访问（隧道）

把中继邀请码交给要接入的人。在他的电脑上运行：

```sh
node tunnel.mjs '<中继邀请码>' --to http://127.0.0.1:8788
```

运行后会打印一个**地址**，要整段复制，包括 `#` 后面的部分：

```
https://<中继>:8790/t/<名字>#pin=sha256//…&key=…
```

- `#pin=` 是中继的证书指纹，`#key=` 是这台电脑的端到端加密公钥。把这个地址交给要访问你的人，他发请求时会自动核对证书指纹，并自动加密。
- 名字和密钥都存在 `~/.relay-tunnel.json`（可以用 `--state` 换位置），重启后地址不变。
- 默认**只接受端到端加密的请求**。加上 `--plain` 也会接受不加密的请求（比如用 curl 调试时）。

**对方什么都不用装的写法**：中继自己提供 `tunnel.mjs` 下载，下载时会先核对指纹。

```sh
curl -fsSk --pinnedpubkey 'sha256//…' https://<中继>:8790/tunnel.mjs -o clarelay-tunnel.mjs \
  && node clarelay-tunnel.mjs '<中继邀请码>' --to http://127.0.0.1:8788
```

这条命令可以用 `tunnelCommand(invite, to)` 生成，直接复制给对方（或者对方的 AI）运行即可。

---

## 三、在代码里使用

```js
import { startTunnel, relayRequest, parseInvite, isInvite, makeInvite, tunnelCommand, parseAddress, pinnedConnector, VERSION } from 'clarelay';

// 被访问的一方：连隧道
const t = await startTunnel({
  invite,                          // 中继邀请码（也可以分开传 { relay, pin, key }）
  to: 'http://127.0.0.1:8788',     // 本机服务
  state: '/path/state.json',       // 可选，默认 ~/.relay-tunnel.json
  plain: false,                    // 可选，true 时也接受不加密的请求
  onStatus: s => {},               // 可选，{ online, error? }，断线 / 重连时调用
  log: console.log,                // 可选
});
t.address                    // https://中继/t/<名字>#pin=…&key=…  ← 交给访问方
t.urlFor('/claclaw-peer')    // https://中继/t/<名字>/claclaw-peer#pin=…&key=…
t.publicUrl / t.pin / t.key / t.online
await t.stop();

// 访问的一方：发请求（自动核对 #pin、自动按 #key 加解密）
const r = await relayRequest(address, { method: 'POST', headers: {}, body: { hello: 1 }, timeout: 60e3 });
r.status; r.headers; r.body /* Buffer */; r.text(); r.json(); r.e2e /* 是否经过端到端解密 */
```

- `startTunnel`：邀请码错、口令错、指纹不对、连不上中继时直接 reject，不会重试；连上之后如果断线，每 5 秒自动重连。
- `relayRequest`：中继自己返回的错误（对方不在线 502、超时 504、限流 429）会以明文返回，此时 `e2e=false`。**如果收到的是明文的成功响应，一律当作被篡改，直接 reject。**
- 本机服务收到的请求带 `x-forwarded-for`，值是中继看到的来源 IP（这个值由中继提供，见下文）。
- 自己用 `pinnedConnector(pin)` 发 https 请求时，不要加 `agent: false`，否则 Node 会忽略 `createConnection`，指纹就不核对了。

---

### 其他语言调用（不用自己实现加密）

```sh
echo '{"text":"hi"}' | node tunnel.mjs request '<地址#pin=…&key=…>' -X POST -H 'authorization: Bearer …' -H 'content-type: application/json' --stdin [--timeout 秒]
# 标准输出一行 JSON：{"status","headers","e2e","body"}；失败时退出码 1，原因写在标准错误
```

Python：`subprocess.run(['node', 'tunnel.mjs', 'request', addr, '-X', 'POST', '--stdin'], input=data, capture_output=True)`。

## 超时：几处数字要放在一起看

| 位置 | 默认 | 说明 |
| --- | --- | --- |
| 中继等隧道回应 | 11 分钟 | 超过返回明文 504 |
| 隧道等本机服务 | 11 分钟 | 超过返回 502「本地服务超时」 |
| `relayRequest` 的 `timeout` | 11 分钟 | 发起方自己放弃 |
| 应用自己的超时 | 由应用定 | 例如 claclaw 对方回复约 5 分钟 |

实际生效的是最短的那个。排查时先看是谁先放弃：自己代码抛出 `timeout` 是发起方放弃；收到 504 是中继放弃；收到加密的 502 是隧道等本机服务超时。建议应用把 `relayRequest` 的 `timeout` 设成略大于自己的业务超时。

## 四、安全

**中继能看到什么**

| | 中继能看到 | 中继能做到 |
| --- | --- | --- |
| 请求 / 响应内容、路径、请求头 | ❌ 看不到（AES-256-GCM 加密） | ❌ 改不了（改了对方会解密失败） |
| 隧道名字、数据大小、时间、来源 IP | ✅ 看得到 | 可以谎报来源 IP |
| 重放捕获到的请求 | — | ❌ 不行（目标电脑会拒绝重复的请求和 5 分钟以前的请求） |
| 丢弃请求、不转发 | — | ✅ 可以（这只影响能不能连上，泄露不了内容） |

**加密方式**：每台隧道电脑有一把长期的 X25519 密钥，公钥放在地址的 `#key=` 里。发起方每发一个请求都临时生成一把新密钥，用 ECDH 加上 HKDF-SHA256 算出请求和响应各自的密钥，再用 AES-256-GCM 加密。方法、路径、请求头、请求体都在密文里。

**前提**：地址（含 `#key=`）要通过可信的渠道交给对方，比如自己复制粘贴发给同事。拿到地址的方式可信，加密才可信。

**其他**

- 中继和隧道之间用 HTTPS，证书指纹钉死（自签证书，换了证书就拒绝连接），所以注册口令不会被别人截走。
- 只有拿到邀请码的人才能领地址。邀请码里包含注册口令，只发给你信任的人；泄露了就按上面的方法换掉。
- 公开地址里的名字是 20 位随机串；就算知道了名字，没有 `#key=` 也只能发出对方解不开的请求。
- 限制：注册口令错误的请求和公开地址的请求，每个来源 IP 每分钟最多 120 次。单个请求或响应的内容最多约 1MB。对方最多等 11 分钟回应。隧道 60 秒没连着中继就算离线。

---

## 测试

```sh
npm test   # 在本机起中继、隧道和一个假服务，测转发、指纹、口令、重启后地址不变，
           # 以及加密（模拟一个恶意中继：偷看、重放、篡改都要失败）
```
