# clarelay 设备组网（开发中，0.3.0-dev）

用一台自己的外网服务器把你的电脑和手机组成一个私有的设备圈：手机上只装一个 clarelay 主屏幕 App，就能进入任何一台电脑上的应用（比如 claclaw）。设计见 [../DESIGN-device-network.md](../DESIGN-device-network.md)。

## 部署中继（服务器）

前提：
1. 一个圈子域名，**它本身和 `*.它` 都解析到服务器**。推荐 DuckDNS（免费，例如 `myrelay.duckdns.org`），或者用自己的域名加一条泛解析。
2. 安全组放行 TCP **80** 和 **443**。
3. 服务器上有 Node 18 以上。

```sh
git clone -b device-network https://github.com/wyidong/clarelay.git && cd clarelay
sudo sh deploy/install-device.sh myrelay.duckdns.org --acme staging   # 先用 Let's Encrypt 测试环境试通
sudo sh deploy/install-device.sh myrelay.duckdns.org                  # 通了再换正式证书（重复运行就是升级，数据保留）
```

- 第一次安装会让你设置管理员账号。
- 之后在手机上打开 `https://myrelay.duckdns.org`，登录，然后「添加到主屏幕」。

## 电脑加入

外壳 →「管理」→ 生成邀请码。在电脑上运行：

```sh
node device/agent.mjs '<设备邀请码>' --name 办公室Mac --to http://127.0.0.1:8787
```

- 如果后台开着「新设备要我批准」，要先在外壳的「管理」里批准这台电脑。
- 批准后电脑会自己申请证书，然后出现在设备列表里。

## 给应用（claclaw）的接口

```js
import { startDevice } from 'clarelay/device';      // 或 '…/clarelay/device/agent.mjs'

const dev = await startDevice({
  invite,                                  // 第一次加入时给；之后从 state 文件读，不用再给
  state: '<数据目录>/clarelay-device.json', // 设备身份和证书（权限 600）
  name: '办公室 Mac',
  services: { claclaw: 'http://127.0.0.1:8787' },
  onStatus: s => {},   // { online, status: 'pending'|'active'|'revoked', url, cert: { ok, expires, error? }, error? }
  log,
});
dev.url        // 本机网址 https://<随机名>.<圈子域名>
dev.shellUrl   // 手机打开的地址 https://<圈子域名>
dev.online; dev.status; dev.cert
dev.on('status', s => {})
dev.notify({ app: 'claclaw', target: '<会话 id>', kind: 'reply', title: '办公室 Mac · 会话名', snippet: '回复正文', unread: 3 })
dev.read({ app: 'claclaw', target: '<会话 id>' })
await dev.stop()
```

- `startDevice` 在邀请码无效时会 reject。连上之后断线会自动重连。
- `snippet` 在本机就按管理员设置截成前 N 个字（默认 20）再交给中继，其余内容不会离开本机。
- `unread` 是这个对象当前的未读数，为 0 等于已读。

### 应用收到的请求
- 只有过了门卫（登录过设备圈）的请求才会到应用；门卫的 cookie 不会转给应用。
- 请求头：
  - `x-forwarded-for`：真实来源 IP，访问者自己带的值会被覆盖；
  - `x-forwarded-proto: https`；
  - `x-forwarded-host`；
  - `Host`：原样保留，是电脑的网址，不是 127.0.0.1。
- WebSocket 原样转发。
- 门卫会删掉应用响应里的 `X-Frame-Options`，并加上 `Content-Security-Policy: frame-ancestors 'self' https://<圈子域名>`：只有外壳能嵌入应用。

### 嵌入在外壳里（postMessage）
所有消息都带 `clarelay: 1`。应用只认 `embedded` 消息里给出的外壳 origin；外壳只认它自己嵌入的那台电脑。

| 方向 | 消息 | 说明 |
| --- | --- | --- |
| 应用 → 外壳 | `{ type: 'ready', app, version }` | 加载好后发，发给 `parent`，origin 用 `'*'`，因为这时还不知道外壳的 origin |
| 外壳 → 应用 | `{ type: 'embedded', shell, version }` | 告诉应用它在外壳里：隐藏自己的宿主切换和推送设置，记下 `shell` 作为之后发消息的目标 origin |
| 应用 → 外壳 | `{ type: 'title', text }` | 外壳顶栏显示「电脑名 · text」 |
| 应用 → 外壳 | `{ type: 'viewing', target }` | 用户正在看哪个对象；看着的对象不会被推送。离开时发 `target: ''` |
| 外壳 → 应用 | `{ type: 'open', target }` | 打开某个对象（比如点了一条通知） |

iframe 的权限：`allow="clipboard-read; clipboard-write; microphone; autoplay; fullscreen"`。

## 本地测试

```sh
node test/device.mjs     # 中继（测试 CA）+ 电脑端 + 假应用：分流、门卫、通行票、转发头、WebSocket、提醒、撤销
node test/webpush.mjs    # Web Push 加密和 VAPID 签名
```
