#!/bin/bash
set -e

# 1. frpc 隧道配置：把 http://yy.720820.xyz (frps vhostHTTPPort 80) 路由到本机 KeyPool
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
EOF

# 2. KeyPool 主服务
cat > /etc/systemd/system/keypool.service <<'EOF'
[Unit]
Description=KeyPool API Key rotation pool
After=network.target

[Service]
WorkingDirectory=/usr/local/keypool
ExecStart=/usr/local/keypool/node/bin/node /usr/local/keypool/server.js --host 127.0.0.1 --port 8787 --data-dir /usr/local/keypool/data
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# 3. frpc 隧道服务
cat > /etc/systemd/system/keypool-frpc.service <<'EOF'
[Unit]
Description=frpc tunnel for KeyPool (yy.720820.xyz)
After=network.target keypool.service

[Service]
ExecStart=/etc/frp/dist/frpc_linux_amd64 -c /etc/frp/keypool-frpc.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now keypool.service
sleep 1
systemctl enable --now keypool-frpc.service
sleep 3

echo "=== service status ==="
systemctl is-active keypool keypool-frpc

echo "=== local health (8787) ==="
curl -s --max-time 5 http://127.0.0.1:8787/health || echo FAIL
echo

echo "=== via frps vhost :80 (Host: yy.720820.xyz) ==="
curl -s --max-time 5 -H "Host: yy.720820.xyz" http://127.0.0.1:80/health || echo FAIL
echo

echo "=== keypool journal ==="
journalctl -u keypool -n 4 --no-pager | cat

echo "=== frpc journal ==="
journalctl -u keypool-frpc -n 6 --no-pager | cat
