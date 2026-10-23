#!/bin/sh
# clarelay 中继一键安装（Linux + systemd）。在服务器上、clarelay 目录里用 root 运行：
#   sudo sh deploy/install.sh https://你的服务器公网IP或域名:8790
# 做的事：建系统用户 clarelay → 复制程序到 /opt/clarelay → 数据放 /var/lib/clarelay → 装 systemd 服务并开机自启 → 打印中继邀请码。
# 重复运行 = 升级程序（证书、注册口令、已登记的隧道都保留）。
set -eu
PUBLIC="${1:-}"
case "$PUBLIC" in http://*|https://*) ;; *) echo "用法：sudo sh deploy/install.sh https://服务器公网IP:8790"; exit 1 ;; esac
PORT=$(echo "$PUBLIC" | sed -nE 's#^https?://[^/]*:([0-9]+).*#\1#p'); PORT=${PORT:-8790}
[ "$(id -u)" = 0 ] || { echo "要用 root 运行（sudo）"; exit 1; }
NODE=$(command -v node || true)
[ -n "$NODE" ] || { echo "没有 Node.js：先装 Node 18 以上（见 README）"; exit 1; }
"$NODE" -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' || { echo "Node 版本太旧：$($NODE -v)，要 18 以上"; exit 1; }
command -v openssl >/dev/null || { echo "没有 openssl：先装（apt install openssl / yum install openssl）"; exit 1; }
SRC=$(cd "$(dirname "$0")/.." && pwd)

id clarelay >/dev/null 2>&1 || useradd --system --home-dir /var/lib/clarelay --shell /usr/sbin/nologin clarelay 2>/dev/null || useradd -r -d /var/lib/clarelay -s /sbin/nologin clarelay
install -d -m 755 /opt/clarelay
install -m 644 "$SRC/server.mjs" "$SRC/tunnel.mjs" "$SRC/package.json" /opt/clarelay/
for f in README.md PROTOCOL.md; do [ -f "$SRC/$f" ] && install -m 644 "$SRC/$f" /opt/clarelay/; done
install -d -m 755 /opt/clarelay/deploy && install -m 644 "$SRC/deploy/install.sh" "$SRC/deploy/clarelay.service" /opt/clarelay/deploy/
install -d -m 700 -o clarelay -g clarelay /var/lib/clarelay

sed -e "s#@NODE@#$NODE#g" -e "s#@PUBLIC@#$PUBLIC#g" -e "s#@PORT@#$PORT#g" "$SRC/deploy/clarelay.service" > /etc/systemd/system/clarelay.service
systemctl daemon-reload
systemctl enable clarelay >/dev/null 2>&1
systemctl restart clarelay
sleep 2
systemctl is-active --quiet clarelay || { echo "启动失败，看日志：journalctl -u clarelay -n 50"; exit 1; }
echo "已启动：$PUBLIC （端口 $PORT，记得在防火墙 / 云安全组放行 TCP $PORT）"
runuser -u clarelay -- "$NODE" /opt/clarelay/server.mjs --data /var/lib/clarelay --public "$PUBLIC" --port "$PORT" --print
