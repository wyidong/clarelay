#!/bin/sh
# clarelay 设备组网中继一键安装（Linux + systemd）。在服务器上、clarelay 目录里用 root 运行：
#   sudo sh deploy/install-device.sh myrelay.duckdns.org [--acme staging] [--email 你@例子.com]
#   NODE=/path/to/node sudo -E sh deploy/install-device.sh …   # 指定 Node
# 前提：域名（含 *.域名）已解析到这台服务器；安全组放行 TCP 80、443。
# 重复运行 = 升级（证书、管理员、设备都保留）。
set -eu
DOMAIN="${1:-}"; shift || true
case "$DOMAIN" in *.*) ;; *) echo "用法：sudo sh deploy/install-device.sh 圈子域名 [--acme staging] [--email 邮箱]"; exit 1 ;; esac
EXTRA="$*"
[ "$(id -u)" = 0 ] || { echo "要用 root 运行（sudo）"; exit 1; }
ok_node() { [ -x "$1" ] && "$1" -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' 2>/dev/null; }
NODE_FOUND=""
for n in ${NODE:-} $(command -v node 2>/dev/null || true) /usr/local/bin/node /usr/bin/node /opt/node*/bin/node /usr/local/node*/bin/node /opt/rh/rh-nodejs*/root/usr/bin/node; do
  if ok_node "$n"; then NODE_FOUND="$n"; break; fi
done
[ -n "$NODE_FOUND" ] || { echo "没找到 Node 18 以上：NODE=/新版/bin/node sudo -E sh deploy/install-device.sh $DOMAIN"; exit 1; }
case "$NODE_FOUND" in /root/*|/home/*) echo "Node 不能放在 /root 或 /home 下（服务用户读不到）"; exit 1 ;; esac
NODE="$NODE_FOUND"; echo "使用 Node：$NODE（$("$NODE" -v)）"
for p in 80 443; do
  if (ss -ltnH "sport = :$p" 2>/dev/null || netstat -ltn 2>/dev/null | grep ":$p ") | grep -q .; then
    systemctl is-active --quiet clarelay-device && continue
    echo "端口 $p 已被别的程序占用，先停掉它"; exit 1
  fi
done
SRC=$(cd "$(dirname "$0")/.." && pwd)
id clarelay >/dev/null 2>&1 || useradd --system --home-dir /var/lib/clarelay-device --shell /usr/sbin/nologin clarelay 2>/dev/null || useradd -r -d /var/lib/clarelay-device -s /sbin/nologin clarelay
install -d -m 755 /opt/clarelay /opt/clarelay/device /opt/clarelay/device/shell
install -m 644 "$SRC"/device/*.mjs /opt/clarelay/device/
install -m 644 "$SRC"/device/shell/* /opt/clarelay/device/shell/
install -m 644 "$SRC/package.json" /opt/clarelay/
install -d -m 700 -o clarelay -g clarelay /var/lib/clarelay-device
sed -e "s#@NODE@#$NODE#g" -e "s#@DOMAIN@#$DOMAIN#g" -e "s#@EXTRA@#$EXTRA#g" "$SRC/deploy/clarelay-device.service" > /etc/systemd/system/clarelay-device.service
SDV=$(systemctl --version | head -1 | awk '{print $2}' | tr -dc 0-9)
install -d /etc/systemd/system/clarelay-device.service.d
if [ "${SDV:-0}" -lt 232 ]; then
  printf '[Service]\nMemoryLimit=300M\nProtectSystem=full\nStartLimitInterval=300\nStartLimitBurst=5\n' > /etc/systemd/system/clarelay-device.service.d/compat-old-systemd.conf
fi
systemctl daemon-reload
if ! runuser -u clarelay -- "$NODE" -e "const s=require('/var/lib/clarelay-device/state.json');process.exit(s.admin?0:1)" 2>/dev/null; then
  echo "设置管理员账号（登录外壳和管理后台用）："
  runuser -u clarelay -- "$NODE" /opt/clarelay/device/server.mjs admin --data /var/lib/clarelay-device
fi
systemctl enable clarelay-device >/dev/null 2>&1
systemctl restart clarelay-device
sleep 3
systemctl is-active --quiet clarelay-device || { echo "启动失败：journalctl -u clarelay-device -n 50"; exit 1; }
echo "已启动：https://$DOMAIN （证书申请可能要几十秒；进度：journalctl -u clarelay-device -f）"
echo "改管理员密码：sudo runuser -u clarelay -- $NODE /opt/clarelay/device/server.mjs admin --data /var/lib/clarelay-device"
