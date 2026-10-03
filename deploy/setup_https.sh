#!/bin/bash
set -e

# 1. 生成自签证书（10 年，含 SAN）
mkdir -p /etc/frp/certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout /etc/frp/certs/yy.720820.xyz.key \
  -out /etc/frp/certs/yy.720820.xyz.crt \
  -subj "/CN=yy.720820.xyz" \
  -addext "subjectAltName=DNS:yy.720820.xyz,DNS:*.yy.720820.xyz,IP:155.103.158.76" 2>/dev/null
echo "cert generated:"
openssl x509 -in /etc/frp/certs/yy.720820.xyz.crt -noout -subject -dates -ext subjectAltName | head -5

# 2. 追加 https 代理（与 http 代理分属 frps 两个 vhost 路由器，互不冲突）
cat > /etc/frp/keypool-frpc.toml <<'EOF'
# KeyPool 反向接入（由部署脚本生成）
serverAddr = "127.0.0.1"
serverPort = 7000
auth.token = "frp-720820-token"

[[proxies]]
name = "keypool-web"
type = "http"
localIP = "127.0.0.1"
localPort = 8787
customDomains = ["yy.720820.xyz"]

[[proxies]]
name = "keypool-https"
type = "https"
localIP = "127.0.0.1"
localPort = 8787
customDomains = ["yy.720820.xyz"]

[proxies.plugin]
type = "https2http"
localAddr = "127.0.0.1:8787"
crtPath = "/etc/frp/certs/yy.720820.xyz.crt"
keyPath = "/etc/frp/certs/yy.720820.xyz.key"
EOF

chmod 600 /etc/frp/certs/yy.720820.xyz.key

# 3. 重启隧道
systemctl restart keypool-frpc.service
sleep 3
systemctl is-active keypool-frpc keypool

echo "=== https local (direct frpc plugin, via 127.0.0.1 vhost) ==="
curl -sk --max-time 8 --resolve yy.720820.xyz:443:127.0.0.1 https://yy.720820.xyz/health || echo HTTPS_FAIL
echo
echo "=== frpc journal ==="
journalctl -u keypool-frpc -n 8 --no-pager | cat
