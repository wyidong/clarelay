#!/bin/sh
# clarelay 中继一键安装（Linux + systemd）。在服务器上、clarelay 目录里用 root 运行：
#   sudo sh deploy/install.sh https://你的服务器公网IP或域名:8790
#   NODE=/path/to/node sudo -E sh deploy/install.sh …   # 指定 Node（默认 node 太旧、新版装在别处时）
# 做的事：建系统用户 clarelay → 复制程序到 /opt/clarelay → 数据放 /var/lib/clarelay → 装 systemd 服务并开机自启 → 显示中继邀请码。
# 重复运行 = 升级程序（证书、注册口令、已登记的隧道都保留）。
set -eu
PUBLIC="${1:-}"
case "$PUBLIC" in http://*|https://*) ;; *) echo "用法：sudo sh deploy/install.sh https://服务器公网IP:8790"; exit 1 ;; esac
PORT=$(echo "$PUBLIC" | sed -nE 's#^https?://[^/]*:([0-9]+).*#\1#p'); PORT=${PORT:-8790}
[ "$(id -u)" = 0 ] || { echo "要用 root 运行（sudo）"; exit 1; }

# ---- 找 Node 18+：先看 NODE=，再找常见位置 ----
ok_node() { [ -x "$1" ] && "$1" -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' 2>/dev/null; }
NODE_FOUND=""
for n in ${NODE:-} $(command -v node 2>/dev/null || true) /usr/local/bin/node /usr/bin/node /opt/node*/bin/node /usr/local/node*/bin/node /opt/rh/rh-nodejs*/root/usr/bin/node /opt/rh/nodejs*/root/usr/bin/node; do
  if ok_node "$n"; then NODE_FOUND="$n"; break; fi
done
if [ -z "$NODE_FOUND" ]; then
  echo "没找到 Node 18 以上。默认的 node：$(command -v node 2>/dev/null && node -v 2>/dev/null || echo 无)"
  echo "已装了新版但不在默认路径：NODE=/新版/bin/node sudo -E sh deploy/install.sh $PUBLIC"
  echo "（Node 不能放在 /root 或 /home 下面：服务以 clarelay 用户运行，读不到）"
  exit 1
fi
case "$NODE_FOUND" in /root/*|/home/*) echo "Node 在 $NODE_FOUND：服务以 clarelay 用户运行读不到 /root、/home，请装到 /usr/local 或 /opt"; exit 1 ;; esac
NODE="$NODE_FOUND"
echo "使用 Node：$NODE（$("$NODE" -v)）"

command -v openssl >/dev/null || { echo "没有 openssl：先装（apt install openssl / yum install openssl）"; exit 1; }
SRC=$(cd "$(dirname "$0")/.." && pwd)

id clarelay >/dev/null 2>&1 || useradd --system --home-dir /var/lib/clarelay --shell /usr/sbin/nologin clarelay 2>/dev/null || useradd -r -d /var/lib/clarelay -s /sbin/nologin clarelay
install -d -m 755 /opt/clarelay
install -m 644 "$SRC/server.mjs" "$SRC/tunnel.mjs" "$SRC/package.json" /opt/clarelay/
for f in README.md PROTOCOL.md; do [ -f "$SRC/$f" ] && install -m 644 "$SRC/$f" /opt/clarelay/; done
install -d -m 755 /opt/clarelay/deploy && install -m 644 "$SRC/deploy/install.sh" "$SRC/deploy/clarelay.service" /opt/clarelay/deploy/
install -d -m 700 -o clarelay -g clarelay /var/lib/clarelay

sed -e "s#@NODE@#$NODE#g" -e "s#@PUBLIC@#$PUBLIC#g" -e "s#@PORT@#$PORT#g" "$SRC/deploy/clarelay.service" > /etc/systemd/system/clarelay.service

# ---- 老 systemd（< 232，例如 CentOS 7 的 219）会静默忽略 MemoryMax / ProtectSystem=strict / ReadWritePaths / StartLimitIntervalSec ----
SDV=$(systemctl --version | head -1 | awk '{print $2}' | tr -dc 0-9)
install -d /etc/systemd/system/clarelay.service.d
if [ "${SDV:-0}" -lt 232 ]; then
  cat > /etc/systemd/system/clarelay.service.d/compat-old-systemd.conf <<CONF
# 自动生成：systemd $SDV 不认新写法，这里用老写法拿到等效保护
[Service]
MemoryLimit=150M
ProtectSystem=full
StartLimitInterval=300
StartLimitBurst=5
CONF
  echo "systemd $SDV 较旧：已加兼容配置 /etc/systemd/system/clarelay.service.d/compat-old-systemd.conf"
else
  rm -f /etc/systemd/system/clarelay.service.d/compat-old-systemd.conf
fi

systemctl daemon-reload
systemctl enable clarelay >/dev/null 2>&1
systemctl restart clarelay
sleep 2
systemctl is-active --quiet clarelay || { echo "启动失败，看日志：journalctl -u clarelay -n 50"; exit 1; }
echo "已启动：$PUBLIC （端口 $PORT，记得在防火墙 / 云安全组放行 TCP $PORT）"

# ---- 邀请码含注册口令：只显示在交互终端上；输出被重定向时存进只有 root 能读的文件 ----
SHOW="runuser -u clarelay -- $NODE /opt/clarelay/server.mjs --data /var/lib/clarelay --public $PUBLIC --port $PORT --print"
if [ -t 1 ]; then
  $SHOW
else
  umask 077; $SHOW > /root/clarelay-invite.txt
  echo "中继邀请码（含注册口令）已存到 /root/clarelay-invite.txt（600），没有输出到这里"
fi
echo "以后再看邀请码：sudo $SHOW"
