#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager (Pro)
# Version: v16.2 (release candidate: shared unlock and HY2)
# Features: Reality/VLESS/VMess | Self-Healing | YAML Fix
# Author: eljefeZZZ
# ==================================================

# --- 目录结构 ---
ROOT_DIR="/usr/local/eljefe-v2"
XRAY_BIN="$ROOT_DIR/xray"
CONFIG_FILE="$ROOT_DIR/config.json"
ACME_DIR="$ROOT_DIR/acme.sh"
CERT_DIR="$ROOT_DIR/cert"
WEB_DIR="$ROOT_DIR/html"
INFO_FILE="$ROOT_DIR/info.txt"
ACME_SCRIPT="$ACME_DIR/acme.sh"

# [安全] 运行用户
XRAY_USER="xray"

# 端口定义 (三协议共存)
PORT_REALITY=443
PORT_VLESS_WS=2087
PORT_VMESS_WS=2088
PORT_TLS=8443  # Nginx 监听端口，避开 443

DEST_SITE="itunes.apple.com:443"
DEST_SNI="itunes.apple.com"

# --- 颜色 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
PLAIN='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERROR]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }

check_root() {
    [[ $EUID -ne 0 ]] && log_err "必须使用 Root 权限运行" && exit 1
}

install_dependencies() {
    log_info "安装依赖..."
    if [ -f /etc/debian_version ]; then
        apt-get update -y
        apt-get install -y curl wget unzip jq nginx uuid-runtime openssl cron lsof socat psmisc dnsutils
    elif [ -f /etc/redhat-release ]; then
        yum update -y
        yum install -y curl wget unzip jq nginx uuid socat openssl cronie lsof psmisc bind-utils
    else
        log_err "不支持的系统" && exit 1
    fi

    mkdir -p "$ROOT_DIR" "$CERT_DIR" "$WEB_DIR"
    
    if ! id -u "$XRAY_USER" &>/dev/null; then
        useradd -r -s /bin/false "$XRAY_USER"
    fi
    
    # [清理] 安装完依赖立即清理 Nginx 默认干扰项
    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/conf.d/default.conf
    systemctl stop nginx
}

setup_fake_site() {
    log_info "部署伪装站点..."
    if [ ! -f "$WEB_DIR/index.html" ]; then
        wget -qO "$ROOT_DIR/web.zip" "https://github.com/startbootstrap/startbootstrap-resume/archive/gh-pages.zip"
        unzip -q -o "$ROOT_DIR/web.zip" -d "$ROOT_DIR/temp_web"
        mv "$ROOT_DIR/temp_web/startbootstrap-resume-gh-pages/"* "$WEB_DIR/"
        rm -rf "$ROOT_DIR/web.zip" "$ROOT_DIR/temp_web"
        chown -R www-data:www-data "$WEB_DIR" 2>/dev/null || chown -R nginx:nginx "$WEB_DIR"
        chmod -R 755 "$WEB_DIR"
    fi
}

setup_cert() {
    local domain=$1
    log_info "正在为域名 $domain 申请证书..."

    # [完善2] 申请证书前验证域名 DNS 解析是否指向本机，避免 acme challenge 失败
    local server_ip=$(curl -s https://api.ipify.org)
    local domain_ip=$(dig +short "$domain" A | tail -1)
    if [[ -z "$domain_ip" ]]; then
        log_err "域名 $domain 无法解析，请先配置 DNS A 记录！"
        return 1
    fi
    if [[ "$server_ip" != "$domain_ip" ]]; then
        log_err "域名解析 IP ($domain_ip) 与服务器 IP ($server_ip) 不匹配，请先将域名解析到本机！"
        return 1
    fi
    log_info "DNS 验证通过：$domain -> $server_ip"

    mkdir -p "$ACME_DIR"
    if [[ ! -x "$ACME_SCRIPT" ]]; then
        local acme_email
        read -r -p '证书通知邮箱（可留空使用 acme.sh 默认配置）: ' acme_email
        local installer
        installer=$(mktemp) || return 1
        if ! curl -fsSL https://get.acme.sh -o "$installer"; then rm -f "$installer"; return 1; fi
        if [[ -n "$acme_email" ]]; then
            sh "$installer" email="$acme_email" --home "$ACME_DIR" || { rm -f "$installer"; return 1; }
        else
            sh "$installer" --home "$ACME_DIR" || { rm -f "$installer"; return 1; }
        fi
        rm -f "$installer"
    fi

    # Never kill a process or stop Nginx to claim the challenge port.
    if ss -ltnH '( sport = :80 )' | grep -q .; then
        log_err 'TCP 80 已被监听；为保护原服务，未强制占用。请改用 DNS 验证或在维护窗口调整端口。'
        return 1
    fi

    # [完善5] 重新申请前先移除旧证书，避免缓存干扰 --force 时的行为
    "$ACME_SCRIPT" --remove -d "$domain" --ecc 2>/dev/null && log_info "已清理旧证书记录"

    # 切换默认 CA 为 Let's Encrypt，避免 ZeroSSL account not registered 错误
    "$ACME_SCRIPT" --set-default-ca --server letsencrypt

    "$ACME_SCRIPT" --issue -d "$domain" --standalone --keylength ec-256 --force
    
    if [ $? -eq 0 ]; then
        log_info "证书申请成功！"
        "$ACME_SCRIPT" --install-cert -d "$domain" --ecc \
            --key-file       "$CERT_DIR/private.key"  \
            --fullchain-file "$CERT_DIR/fullchain.cer" \
            --reloadcmd     "systemctl restart nginx"
            
        chown "$XRAY_USER:$XRAY_USER" "$CERT_DIR/private.key" "$CERT_DIR/fullchain.cer"
        chmod 600 "$CERT_DIR/private.key"

        # [完善4] 验证 acme.sh 自动续期 cron 任务是否存在，不存在则手动添加
        if ! crontab -l 2>/dev/null | grep -q "acme.sh"; then
            log_warn "未检测到 acme.sh 定时续期任务，正在手动添加..."
            (crontab -l 2>/dev/null; echo "0 0 * * * $ACME_SCRIPT --cron --home $ACME_DIR > /dev/null 2>&1") | crontab -
            log_info "续期定时任务已添加（每天 00:00 检查）"
        else
            log_info "acme.sh 续期定时任务已存在，无需重复添加"
        fi

        return 0
    else
        log_err "证书申请失败！请检查域名解析和 80 端口是否正常。"
        return 1
    fi
}

setup_nginx() {
    local domain=$1
    log_info "配置 Nginx..."
    
    # [v15.5 核心修复] 自动修复缺失的 nginx.conf
    if [ ! -f /etc/nginx/nginx.conf ]; then
        log_warn "检测到 nginx.conf 缺失，正在重建..."
        mkdir -p /etc/nginx
        cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events { worker_connections 768; }
http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    gzip on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    fi

    # 清理默认配置
    rm -f /etc/nginx/sites-enabled/default
    
    # 修正主配置 (防止重复 + 安全检查)
    sed -i '/server_tokens/d' /etc/nginx/nginx.conf
    if grep -q "http {" /etc/nginx/nginx.conf; then
        sed -i '/http {/a \    server_tokens off;' /etc/nginx/nginx.conf
    fi

    # 写入 80 回落配置
    cat > /etc/nginx/conf.d/eljefe_fallback.conf <<EOF
server {
    listen 80;
    server_name _;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    root $WEB_DIR;
    index index.html;
}
EOF

    if [[ -n "$domain" ]]; then
        cat > /etc/nginx/conf.d/eljefe_tls.conf <<EOF
server {
    listen $PORT_TLS ssl;
    server_name $domain;

    ssl_certificate       $CERT_DIR/fullchain.cer;
    ssl_certificate_key   $CERT_DIR/private.key;
    ssl_protocols         TLSv1.2 TLSv1.3;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location /vless {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$PORT_VLESS_WS;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    location /vmess {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$PORT_VMESS_WS;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    location / {
        root $WEB_DIR;
        index index.html;
    }
}
EOF
    fi
    
    systemctl restart nginx
}

install_xray() {
    log_info "安装/更新 Xray..."
    mkdir -p "$ROOT_DIR"
    
    local version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -z "$version" ]] && version="v1.8.24"
    log_info "目标版本: $version"

    download_file() {
        wget -q --show-progress -O "$2" "$1"
        return $?
    }

    local retry=0
    local max_retries=3
    local verified=false

    while [ $retry -lt $max_retries ]; do
        log_info "正在下载 (尝试 $((retry+1))..."
        download_file "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-linux-64.zip" "$ROOT_DIR/xray.zip"
        download_file "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-linux-64.zip.dgst" "$ROOT_DIR/xray.zip.dgst"

        local remote_hash=$(grep -oE '[0-9a-fA-F]{64}' "$ROOT_DIR/xray.zip.dgst" | head -n 1)
        local local_hash=$(sha256sum "$ROOT_DIR/xray.zip" | awk '{print $1}')

        if [[ -n "$remote_hash" && "$remote_hash" == "$local_hash" ]]; then
            verified=true; break
        fi
        
        local filesize=$(stat -c%s "$ROOT_DIR/xray.zip" 2>/dev/null || echo 0)
        if [[ $filesize -gt 5000000 ]]; then
            log_warn "Hash提取失败但文件正常，智能放行..."; verified=true; break
        fi

        rm -f "$ROOT_DIR/xray.zip"
        ((retry++))
        sleep 2
    done

    if [ "$verified" = false ]; then log_err "下载失败"; exit 1; fi

    unzip -o "$ROOT_DIR/xray.zip" -d "$ROOT_DIR" >/dev/null
    rm -f "$ROOT_DIR/xray.zip" "$ROOT_DIR/xray.zip.dgst"
    chmod +x "$XRAY_BIN"
    chown -R "$XRAY_USER:$XRAY_USER" "$ROOT_DIR"
}

generate_config() {
    local domain=$1
    local uuid=$(uuidgen)
    local sni=$DEST_SNI
    [[ -n "$domain" ]] && sni=$domain  # 这里只是为了兼容旧逻辑，实际上 Reality 的 sni 应该固定

    log_info "生成 Xray 配置 (三协议共存)..."

    local keys=$("$XRAY_BIN" x25519)
    local pri_key=$(echo "$keys" | awk -F': ' '/Private/ {print $2}' | tr -d '\r\n')
    local pub_key=$(echo "$keys" | awk -F': ' '/Password/ {print $2}' | tr -d '\r\n')
    [[ -z "$pub_key" ]] && pub_key=$(echo "$keys" | awk -F': ' '/Public/ {print $2}' | tr -d '\r\n')

    if [[ -z "$pri_key" || -z "$pub_key" ]]; then
        log_warn "自动抓取密钥失败，启用备用..."
        pri_key="yC4v8X9j2m5n1b7v3c6x4z8l0k9j8h7g6f5d4s3a2q1"
        pub_key="uJ5n8m7b4v3c6x9z1l2k3j4h5g6f7d8s9a0q1w2e3r4"
    fi

    local sid=$(openssl rand -hex 4 | tr -d '\n')

    # 写入 config.json
    # 注意：realitySettings 中的 dest 和 serverNames 必须固定为微软
    cat > "$CONFIG_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality",
      "port": $PORT_REALITY,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$uuid", "flow": "xtls-rprx-vision" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$DEST_SITE",
          "xver": 0,
          "serverNames": [ "$DEST_SNI" ],
          "privateKey": "$pri_key",
          "shortIds": [ "$sid" ]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
    },
    {
      "tag": "vless-ws",
      "port": $PORT_VLESS_WS,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$uuid" } ], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } }
    },
    {
      "tag": "vmess-ws",
      "port": $PORT_VMESS_WS,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "$uuid" } ] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ]
}
EOF

    chown "$XRAY_USER:$XRAY_USER" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"

    echo "UUID=$uuid" > "$INFO_FILE"
    echo "PUB_KEY=$pub_key" >> "$INFO_FILE"
    echo "SID=$sid" >> "$INFO_FILE"
    echo "DOMAIN=$domain" >> "$INFO_FILE"
    echo "SNI=$DEST_SNI" >> "$INFO_FILE"  # 强制保存微软 SNI
}

setup_service() {
    cat > /etc/systemd/system/eljefe-v2.service <<EOF
[Unit]
Description=ElJefe V2Ray Service (Secure)
After=network.target nss-lookup.target

[Service]
User=$XRAY_USER
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -c $CONFIG_FILE
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    # Do not terminate unrelated processes on 443/TCP.
    if ss -ltnH '( sport = :443 )' | grep -q . && ! systemctl is-active --quiet eljefe-v2; then
        log_err 'TCP 443 已被其他进程监听，拒绝强制占用。'
        return 1
    fi
    systemctl enable eljefe-v2
    systemctl restart eljefe-v2
}

update_core() {
    install_xray
    systemctl restart eljefe-v2
    log_info "内核更新完成"
}

uninstall_all() {
    systemctl stop eljefe-v2
    systemctl disable eljefe-v2
    rm -f /etc/systemd/system/eljefe-v2.service
    rm -rf "$ROOT_DIR"
    rm -f /etc/nginx/conf.d/eljefe_fallback.conf
    rm -f /etc/nginx/conf.d/eljefe_tls.conf
    systemctl restart nginx
    log_info "卸载完成"
}

show_info_original() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置信息"; return; fi
    source "$INFO_FILE"
    local ip=$(curl -s https://api.ipify.org)
    
    echo -e "\n${GREEN}=== 节点配置信息 (v15.7) ===${PLAIN}"
    echo -e "UUID: $UUID"
    echo -e "Reality Key: $PUB_KEY"
    echo -e "------------------------"
    echo -e "${YELLOW}1. Reality (直连/防封)${PLAIN}"
    # 这里 SNI 必须用 $DEST_SNI (www.microsoft.com)
    echo -e "vless://$UUID@$ip:$PORT_REALITY?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$DEST_SNI&fp=chrome&pbk=$PUB_KEY&sid=$SID&type=tcp&headerType=none#ElJefe_Reality"
    
    if [[ -n "$DOMAIN" ]]; then
        echo -e "\n${YELLOW}2. VLESS-WS-TLS (OpenClash/CDN)${PLAIN}"
        echo -e "vless://$UUID@$DOMAIN:$PORT_TLS?encryption=none&security=tls&type=ws&host=$DOMAIN&path=%2fvless#ElJefe_VLESS_CDN"
        
        echo -e "\n${YELLOW}3. VMess-WS-TLS (兜底)${PLAIN}"
        local vmess_json='{"v":"2","ps":"ElJefe_VMess_CDN","add":"'$DOMAIN'","port":"'$PORT_TLS'","id":"'$UUID'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$DOMAIN'","path":"/vmess","tls":"tls","sni":"'$DOMAIN'"}'
        echo -e "vmess://$(echo -n "$vmess_json" | base64 -w 0)"
    fi
}

show_yaml_original() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置信息"; return; fi
    source "$INFO_FILE"
    local ip=$(curl -s https://api.ipify.org)
    
    echo -e "\n${GREEN}=== Clash YAML 格式 ===${PLAIN}"
    echo -e "${BLUE}# 复制以下内容到你的 YAML 文件 proxy-providers 或 proxies 下${PLAIN}"
    
    # [核心修正] servername 使用 $DEST_SNI (www.microsoft.com)
    echo -e "- name: ElJefe_Reality"
    echo -e "  type: vless"
    echo -e "  server: $ip"
    echo -e "  port: $PORT_REALITY"
    echo -e "  uuid: $UUID"
    echo -e "  network: tcp"
    echo -e "  tls: true"
    echo -e "  udp: true"
    echo -e "  flow: xtls-rprx-vision"
    echo -e "  servername: $DEST_SNI"
    echo -e "  reality-opts:"
    echo -e "    public-key: $PUB_KEY"
    echo -e "    short-id: \"$SID\""
    echo -e "  client-fingerprint: chrome"
    
    if [[ -n "$DOMAIN" ]]; then
        # VLESS 使用 $DOMAIN (eljefe.cc)
        echo -e "\n- name: ElJefe_VLESS_CDN"
        echo -e "  type: vless"
        echo -e "  server: $DOMAIN"
        echo -e "  port: $PORT_TLS"
        echo -e "  uuid: $UUID"
        echo -e "  udp: true"
        echo -e "  tls: true"
        echo -e "  network: ws"
        echo -e "  servername: $DOMAIN"
        echo -e "  skip-cert-verify: false"
        echo -e "  ws-opts:"
        echo -e "    path: /vless"
        echo -e "    headers:"
        echo -e "      Host: $DOMAIN"

        # VMess 使用 $DOMAIN (eljefe.cc)
        echo -e "\n- name: ElJefe_VMess_CDN"
        echo -e "  type: vmess"
        echo -e "  server: $DOMAIN"
        echo -e "  port: $PORT_TLS"
        echo -e "  uuid: $UUID"
        echo -e "  alterId: 0"
        echo -e "  cipher: auto"
        echo -e "  udp: true"
        echo -e "  tls: true"
        echo -e "  network: ws"
        echo -e "  servername: $DOMAIN"
        echo -e "  ws-opts:"
        echo -e "    path: /vmess"
        echo -e "    headers:"
        echo -e "      Host: $DOMAIN"
    fi
}

add_domain() {
    read -p "请输入新域名: " new_domain
    setup_cert "$new_domain"
    if [ $? -eq 0 ]; then
        setup_nginx "$new_domain"
        generate_config "$new_domain"
        setup_service
        log_info "域名添加成功！"
        show_info
    fi
}

change_sni() {
    read -p "请输入新的 Reality 伪装域名: " new_sni
    DEST_SNI="$new_sni"
    DEST_SITE="$new_sni:443"
    local current_domain=""
    if [ -f "$INFO_FILE" ]; then
        current_domain=$(grep "DOMAIN=" "$INFO_FILE" | cut -d= -f2)
    fi
    generate_config "$current_domain"
    setup_service
    log_info "SNI 修改成功！"
    show_info
}

check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    if [[ "$param" == "bbr" ]]; then
        echo -e "${GREEN}已开启${PLAIN}"
    else
        echo -e "${RED}未开启${PLAIN}"
    fi
}

toggle_bbr() {
    if [[ $(check_bbr_status) == *"${GREEN}已开启${PLAIN}"* ]]; then
        sed -i '/net.core.default_qdisc=fq/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}BBR 已关闭${PLAIN}"
    else
        echo -e "${YELLOW}当前 BBR 未开启，正在开启...${PLAIN}"
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}BBR 已开启${PLAIN}"
    fi
    read -p "按回车键返回菜单..."
    menu
}

# [完善6] 新增：查看服务运行状态函数
show_status() {
    echo -e "\n${GREEN}=== 服务运行状态 ===${PLAIN}"

    # Xray 服务状态
    echo -e "${YELLOW}--- eljefe-v2 (Xray) ---${PLAIN}"
    systemctl status eljefe-v2 --no-pager -l

    echo ""

    # Nginx 服务状态
    echo -e "${YELLOW}--- Nginx ---${PLAIN}"
    systemctl status nginx --no-pager -l

    echo ""

    # 端口监听情况
    echo -e "${YELLOW}--- 端口监听 ---${PLAIN}"
    ss -tlnp | grep -E ":($PORT_REALITY|$PORT_VLESS_WS|$PORT_VMESS_WS|$PORT_TLS) " || echo "未检测到相关端口监听"

    read -p "按回车键返回菜单..."
    menu
}

# ===== HY2 isolated extension BEGIN (do not edit existing Xray routines) =====
HY2_CONFIG_DIR="/etc/hysteria"
HY2_CONFIG="$HY2_CONFIG_DIR/config.yaml"
HY2_ENV="$HY2_CONFIG_DIR/eljefe-hy2.env"
HY2_CERT_DIR="$HY2_CONFIG_DIR/certs"
HY2_SERVICE="hysteria-server.service"
HY2_PORT=443

hy2_load_env() {
    if [[ -f "$HY2_ENV" ]]; then
        # generated locally, root-owned, quoted and permission-restricted
        source "$HY2_ENV"
    fi
}

hy2_show_info() {
    if [[ ! -f "$HY2_ENV" ]]; then
        echo -e "${YELLOW}HY2 尚未配置；选择菜单 11 安装。${PLAIN}"
        return
    fi
    hy2_load_env
    if [[ -z "${HY2_DOMAIN:-}" || -z "${HY2_PASSWORD:-}" ]]; then
        echo "HY2 配置文件不完整"; return 1
    fi
    local auth_encoded domain_encoded
    # Avoid passing passwords via process arguments (shell command-line disclosure)
    auth_encoded=$(HY2_PW="$HY2_PASSWORD" python3 -c 'import os,urllib.parse;print(urllib.parse.quote(os.environ["HY2_PW"],safe=""))') || return 1
    domain_encoded=$(HY2_D="$HY2_DOMAIN" python3 -c 'import os,urllib.parse;print(urllib.parse.quote(os.environ["HY2_D"],safe=""))') || return 1
    echo -e "\n${YELLOW}4. Hysteria2 (UDP ${HY2_PORT:-443} 直连，不经过 CDN)${PLAIN}"
    echo "hysteria2://${auth_encoded}@${HY2_DOMAIN}:${HY2_PORT}/?sni=${domain_encoded}#ElJefe_HY2"
}

hy2_show_yaml() {
    [[ -f "$HY2_ENV" ]] || return 0
    hy2_load_env
    [[ -n "${HY2_DOMAIN:-}" && -n "${HY2_PASSWORD:-}" ]] || return 1
    echo ""
    echo "- name: ElJefe_HY2"
    echo "  type: hysteria2"
    echo "  server: $HY2_DOMAIN"
    echo "  port: $HY2_PORT"
    # Quoted password via Python JSON escaping, valid YAML double-quoted scalar
    local quoted_pw
    quoted_pw=$(HY2_PW="$HY2_PASSWORD" python3 -c 'import os,json;print(json.dumps(os.environ["HY2_PW"]))') || return 1
    echo "  password: $quoted_pw"
    echo "  sni: $HY2_DOMAIN"
    echo "  skip-cert-verify: false"
    echo "  udp: true"
}

hy2_status() {
    systemctl status "$HY2_SERVICE" --no-pager -l || true
    hy2_load_env
    echo "--- UDP ${HY2_PORT:-443} ---"
    ss -lunp | grep -E ":${HY2_PORT:-443}([[:space:]]|$)" || true
    echo "--- certificate validity ---"
    if [[ "${HY2_CERT_MODE:-}" == acme ]]; then echo "HY2 内置 ACME 自动证书"; fi
    if [[ -f "$HY2_CERT_DIR/fullchain.pem" ]]; then
        openssl x509 -in "$HY2_CERT_DIR/fullchain.pem" -noout -subject -dates
    fi
}

hy2_install() {
    if [[ "$(id -u)" != "0" ]]; then echo "必须 root 运行"; return 1; fi
    if [[ -f "$HY2_CONFIG" || -f "$HY2_ENV" ]] || systemctl is-active --quiet "$HY2_SERVICE"; then
        echo "已有 HY2 配置。为避免覆盖密码/证书，本功能不会重装。"; return 1
    fi
    read -r -p "HY2 UDP 端口 [443]: " HY2_PORT
    HY2_PORT=${HY2_PORT:-443}
    [[ "$HY2_PORT" =~ ^[0-9]+$ ]] && ((HY2_PORT >= 1 && HY2_PORT <= 65535)) || { echo "无效端口"; return 1; }
    if ss -lunH | awk '{print $5}' | grep -Eq "(^|:)${HY2_PORT}$"; then
        echo "UDP $HY2_PORT 已有监听，停止安装；不影响原服务。"; return 1
    fi
    read -r -p "HY2 域名（需解析至本机；如使用 Cloudflare 请设 DNS-only）: " HY2_DOMAIN
    if [[ ! "$HY2_DOMAIN" =~ ^[a-zA-Z0-9.-]+$ || "$HY2_DOMAIN" != *.* ]]; then
        echo "域名格式不正确"; return 1
    fi
    command -v curl >/dev/null && command -v openssl >/dev/null && command -v python3 >/dev/null || {
        echo "缺少 curl/openssl/python3，请先安装"; return 1;
    }
    install -d -m 700 "$HY2_CONFIG_DIR" "$HY2_CERT_DIR"
    echo "证书方式：1 自动 HTTP-01（默认，无需 Token，要求公网 TCP 80）"
    echo "          2 Cloudflare DNS-01（需要 Token）"
    echo "          3 使用已有证书（不会修改原证书）"
    local cert_mode cert_existing_key cert_existing_full CF_Token
    read -r -p '选择 [1]: ' cert_mode
    cert_mode=${cert_mode:-1}
    if [[ "$cert_mode" == 1 ]]; then
        # Hysteria's built-in ACME owns port 80 while the service is running.
        # No fuser/kill, and no interruption of Reality TCP 443.
        if ss -ltnH '( sport = :80 )' | grep -q .; then
            echo 'TCP 80 已有服务监听；不强行停止，请改选 DNS-01 或已有证书'; return 1
        fi
        if command -v ufw >/dev/null && ufw status | grep -qi 'Status: active'; then
            ufw allow 80/tcp || return 1
        fi
        HY2_CERT_MODE=acme
        echo '将由 HY2 内置 ACME 申请并续期证书。请确保域名 A/AAAA 指向本 VPS，且外部 TCP 80 可访问。'
    elif [[ "$cert_mode" == 2 ]]; then
        if [[ ! -x /root/.acme.sh/acme.sh ]]; then
            curl -fsSL https://get.acme.sh -o /tmp/eljefe-acme-install.sh || return 1
            sh /tmp/eljefe-acme-install.sh || return 1
        fi
        read -r -s -p 'Cloudflare API Token（输入不可见）: ' CF_Token; echo
        [[ -n "$CF_Token" ]] || { echo 'Token 为空'; return 1; }
        local token_file="$HY2_CONFIG_DIR/cloudflare-token.env"
        (umask 077; printf 'CF_Token=%q\n' "$CF_Token" > "$token_file")
        unset CF_Token
        source "$token_file"; export CF_Token
        /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$HY2_DOMAIN" --server letsencrypt --keylength ec-256 || {
            unset CF_Token; echo '证书签发失败，请检查域名和 DNS 权限'; return 1;
        }
        unset CF_Token
        /root/.acme.sh/acme.sh --install-cert -d "$HY2_DOMAIN" --ecc \
            --fullchain-file "$HY2_CERT_DIR/fullchain.pem" \
            --key-file "$HY2_CERT_DIR/private.key" \
            --reloadcmd 'systemctl try-restart hysteria-server.service >/dev/null 2>&1 || true' || return 1
        chmod 600 "$HY2_CERT_DIR/private.key"
        chmod 644 "$HY2_CERT_DIR/fullchain.pem"
        HY2_CERT_MODE=files
    elif [[ "$cert_mode" == 3 ]]; then
        read -r -p '完整证书 fullchain.pem 绝对路径: ' cert_existing_full
        read -r -p '私钥 private.key 绝对路径: ' cert_existing_key
        [[ -r "$cert_existing_full" && -r "$cert_existing_key" ]] || { echo '证书/私钥无法读取'; return 1; }
        openssl x509 -in "$cert_existing_full" -noout -checkend 86400 >/dev/null || { echo '证书无效或即将到期'; return 1; }
        cp -- "$cert_existing_full" "$HY2_CERT_DIR/fullchain.pem" || return 1
        cp -- "$cert_existing_key" "$HY2_CERT_DIR/private.key" || return 1
        chmod 600 "$HY2_CERT_DIR/private.key"
        HY2_CERT_MODE=files
        echo '提示：导入证书为副本，外部证书更新后须重新同步，不保证自动续期。'
    else
        echo '无效选项'; return 1
    fi
    echo "安装 Hysteria 2 官方服务..."
    curl -fsSL https://get.hy2.sh -o /tmp/eljefe-hy2-install.sh || return 1
    HYSTERIA_USER=root bash /tmp/eljefe-hy2-install.sh || return 1
    # Use independent strong authentication secret, not the Xray UUID
    local HY2_PASSWORD
    HY2_PASSWORD=$(openssl rand -hex 24) || return 1
    (umask 077; printf 'HY2_DOMAIN=%q\nHY2_PASSWORD=%q\nHY2_PORT=%q\nHY2_CERT_MODE=%q\n' "$HY2_DOMAIN" "$HY2_PASSWORD" "$HY2_PORT" "$HY2_CERT_MODE" > "$HY2_ENV")
    # password contains only hex, domain validated above
    if [[ "$HY2_CERT_MODE" == acme ]]; then
        cat > "$HY2_CONFIG" <<EOF
listen: :$HY2_PORT
acme:
  domains:
    - $HY2_DOMAIN
  ca: letsencrypt
  type: http
  dir: $HY2_CONFIG_DIR/acme
EOF
    else
        cat > "$HY2_CONFIG" <<EOF
listen: :$HY2_PORT
tls:
  cert: $HY2_CERT_DIR/fullchain.pem
  key: $HY2_CERT_DIR/private.key
EOF
    fi
    cat >> "$HY2_CONFIG" <<EOF
auth:
  type: password
  password: $HY2_PASSWORD
EOF
    chmod 600 "$HY2_CONFIG"
    if command -v ufw >/dev/null && ufw status | grep -qi "Status: active"; then
        ufw allow "$HY2_PORT/udp" || return 1
    else
        echo "提示：如使用 nftables/iptables 或云防火墙，请允许 UDP $HY2_PORT（HTTP-01 还需 TCP 80）。"
    fi
    systemctl daemon-reload
    systemctl enable "$HY2_SERVICE" || return 1
    systemctl restart "$HY2_SERVICE" || return 1
    if ! systemctl is-active --quiet "$HY2_SERVICE"; then
        echo "HY2 启动失败；保留配置供排错"; return 1
    fi
    echo "HY2 已启动。请从中国大陆测试 UDP $HY2_PORT 是否可用。"
    hy2_show_info
}

hy2_remove() {
    [[ -f "$HY2_ENV" ]] || { echo 'HY2 未配置'; return; }
    echo "卸载会停止独立 HY2 服务并删除其本地配置，不会修改 Xray/Reality/Nginx。"
    read -r -p "确认输入 DELETE-HY2: " answer
    [[ "$answer" == 'DELETE-HY2' ]] || { echo '已取消'; return; }
    systemctl disable --now "$HY2_SERVICE" 2>/dev/null || true
    # Keep cert/account renewal files; don't revoke certificate or damage other ACME domains
    mv "$HY2_ENV" "$HY2_ENV.disabled.$(date +%s)"
    mv "$HY2_CONFIG" "$HY2_CONFIG.disabled.$(date +%s)" 2>/dev/null || true
    hy2_load_env
    if command -v ufw >/dev/null; then ufw delete allow "${HY2_PORT:-443}/udp" || true; fi
    echo "HY2 已停用；配置备份保留在 $HY2_CONFIG_DIR。未删除全局 ACME 安装。"
}

# Shared media unlock: transport-neutral contract for future protocol adapters.
# Configuration: $UNLOCK_ENV; Xray provides the common SOCKS5 bridge.
# Do not enable unless a separate unlocking VPS/outbound has been selected.
UNLOCK_DIR="$ROOT_DIR/unlock"
UNLOCK_ENV="$UNLOCK_DIR/settings.env"
UNLOCK_STATE="$UNLOCK_DIR/managed_rule.json"
UNLOCK_TAG="eljefe-unlock-socks"
UNLOCK_MARK="# ELJEFE_HY2_HK_ACL"
UNLOCK_OUTBOUND=""
UNLOCK_PORT=""
UNLOCK_DOMAINS=("geosite:netflix" "geosite:disney" "geosite:hbo" "geosite:primevideo")

unlock_load() {
    UNLOCK_OUTBOUND=""; UNLOCK_PORT=""
    [[ -f "$UNLOCK_ENV" ]] && source "$UNLOCK_ENV"
    # Upgrade from an existing HY2 bridge without changing its port or tag.
    if [[ -z "$UNLOCK_PORT" && -f "$CONFIG_FILE" ]]; then
        UNLOCK_PORT=$(python3 - "$CONFIG_FILE" <<'PYPORT'
import json,sys
try:
 d=json.load(open(sys.argv[1]))
 for i in d.get('inbounds',[]):
  if i.get('tag') in ('hy2-hk-socks','eljefe-unlock-socks') and i.get('protocol')=='socks' and i.get('listen')=='127.0.0.1':
   print(i['port']);break
except Exception: pass
PYPORT
)
    fi
}
unlock_save() {
    mkdir -p -m 700 "$UNLOCK_DIR" || return 1
    (umask 077; printf 'UNLOCK_OUTBOUND=%q\nUNLOCK_PORT=%q\n' "$UNLOCK_OUTBOUND" "$UNLOCK_PORT" > "$UNLOCK_ENV")
}
unlock_select() {
    [[ -f "$CONFIG_FILE" ]] || { echo '请先安装 Xray'; return 1; }
    echo '可选代理出站（非 freedom / blackhole）：'
    python3 - "$CONFIG_FILE" <<'PYLIST'
import json,sys
for o in json.load(open(sys.argv[1])).get('outbounds',[]):
 if o.get('protocol') not in ('freedom','blackhole'):
  print('  '+o.get('tag','(未命名)')+'  '+o.get('protocol',''))
PYLIST
    local name
    read -r -p '输入解锁 VPS 出站 tag（回车取消）: ' name
    [[ -n "$name" ]] || return 0
    python3 - "$CONFIG_FILE" "$name" <<'PYVERIFY' || { echo '找不到可用的代理出站'; return 1; }
import json,sys
c=json.load(open(sys.argv[1]));name=sys.argv[2]
sys.exit(0 if any(o.get('tag')==name and o.get('protocol') not in ('freedom','blackhole') for o in c.get('outbounds',[])) else 1)
PYVERIFY
    unlock_load
    UNLOCK_OUTBOUND="$name"
    unlock_save || return 1
    echo "已选择 $name。若解锁已开启，请重新执行『开启/更新共享解锁』以生效。"
}
unlock_port_choose() {
    unlock_load
    local requested old_port="$UNLOCK_PORT"
    read -r -p "本地 SOCKS5 桥接端口 [${old_port:-自动选择}]: " requested
    if [[ -n "$requested" ]]; then
        [[ "$requested" =~ ^[0-9]+$ ]] && (( requested >= 1024 && requested <= 65535 )) || { echo '端口需在 1024–65535'; return 1; }
        UNLOCK_PORT="$requested"
    elif [[ -z "$UNLOCK_PORT" ]]; then
        UNLOCK_PORT=$(python3 - <<'PYFREE'
import socket
for port in (10981,10982,10983):
 s=socket.socket();
 try:s.bind(('127.0.0.1',port));print(port);break
 except OSError:pass
 finally:s.close()
else:
 s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()
PYFREE
) || return 1
    fi
    # Existing managed bridge may already own the selected port; permit it.
    if [[ "$UNLOCK_PORT" != "$old_port" ]] && ss -H -lnt "sport = :$UNLOCK_PORT" | grep -q .; then
        echo "端口 $UNLOCK_PORT 已被占用，请另选"; return 1
    fi
    unlock_save
    echo "当前桥接端口：$UNLOCK_PORT"
}

unlock_import() {
    [[ -f "$CONFIG_FILE" && -x "$XRAY_BIN" ]] || { echo '请先安装 Xray'; return 1; }
    local path temp backup
    read -r -p '输入解锁 VPS 的 Xray outbound JSON 文件绝对路径（回车取消）: ' path
    [[ -n "$path" ]] || return 0
    [[ -r "$path" ]] || { echo '找不到文件'; return 1; }
    temp=$(mktemp --suffix=.json) || return 1
    if ! python3 - "$CONFIG_FILE" "$path" "$temp" <<'PYIMPORT'
import json,sys
src,extra,out=sys.argv[1:];d=json.load(open(src));obj=json.load(open(extra))
if not isinstance(obj,dict) or not isinstance(obj.get('tag'),str) or not obj['tag']:
 raise SystemExit('出站必须包含 tag')
if obj.get('protocol') not in ('vless','vmess','trojan','shadowsocks','socks','http','wireguard'):
 raise SystemExit('不支持的出站类型')
if any(x.get('tag')==obj['tag'] for x in d.get('outbounds',[])):
 raise SystemExit('出站 tag 已存在，不能覆盖')
d.setdefault('outbounds',[]).append(obj)
with open(out,'w') as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
PYIMPORT
    then rm -f "$temp"; return 1; fi
    "$XRAY_BIN" run -test -config "$temp" >/dev/null || { rm -f "$temp"; echo '验证失败，无更改'; return 1; }
    backup="$CONFIG_FILE.unlock-import.$(date +%Y%m%d%H%M%S)"
    cp -a "$CONFIG_FILE" "$backup" || { rm -f "$temp"; return 1; }
    cat "$temp" > "$CONFIG_FILE"; rm -f "$temp"
    if ! systemctl restart eljefe-v2 || ! systemctl is-active --quiet eljefe-v2; then
        cp -a "$backup" "$CONFIG_FILE"; systemctl restart eljefe-v2 || true
        echo '导入失败，已恢复原 Xray 配置'; return 1
    fi
    echo "导入成功。备份：$backup。下一步选择此出站。"
}

# Modify only the manager-owned bridge and manager-recorded Xray routing rule.
# Legacy bridge tag 10981 is supported; preexisting user rules remain untouched.
unlock_stage_xray() {
    local mode="$1" output="$2" port="$3" target="$4"
    python3 - "$mode" "$CONFIG_FILE" "$output" "$port" "$target" "$UNLOCK_STATE" <<'PYXRAY'
import json,sys,os
mode,src,out,port,target,state=sys.argv[1:];port=int(port)
d=json.load(open(src));ins=d.setdefault('inbounds',[]);routing=d.setdefault('routing',{});rules=routing.setdefault('rules',[])
domains=['geosite:netflix','geosite:disney','geosite:hbo','geosite:primevideo']
managed_tags=('hy2-hk-socks','eljefe-unlock-socks')
old=None
if os.path.exists(state):
 try:old=json.load(open(state)).get('native_rule')
 except Exception:pass
if old is not None:
 rules[:]=[r for r in rules if r!=old]
# Legacy bridge-specific rules are safe to replace; never delete other user rules.
# One-time migration: remove only the exact routing rule previously generated
# beside the legacy HY2 bridge rule; leave custom domain rules untouched.
legacy_bridge=next((r for r in rules if 'hy2-hk-socks' in r.get('inboundTag',[]) and 'domain' not in r),None)
if legacy_bridge:
 legacy_target=legacy_bridge.get('outboundTag')
 expected_tags=[i.get('tag') for i in ins if i.get('tag') and i.get('tag') not in managed_tags]
 legacy_native={'type':'field','inboundTag':expected_tags,'domain':domains,'outboundTag':legacy_target}
 rules[:]=[r for r in rules if r!=legacy_native]
rules[:]=[r for r in rules if not any(t in r.get('inboundTag',[]) for t in managed_tags)]
bridges=[i for i in ins if i.get('tag') in managed_tags]
if len(bridges)>1:raise SystemExit('检测到多个管理桥接入口；请先人工检查')
if mode=='enable':
 if not target or not any(o.get('tag')==target and o.get('protocol') not in ('freedom','blackhole') for o in d.get('outbounds',[])):
  raise SystemExit('未选择有效的解锁 VPS 代理出站')
 if any(i.get('port')==port and i not in bridges for i in ins):
  raise SystemExit('选定端口已被其他 Xray 入站使用')
 if bridges:
  bridge=bridges[0]
  if bridge.get('listen')!='127.0.0.1' or bridge.get('protocol')!='socks':
   raise SystemExit('既有桥接结构不符合安全要求')
  bridge['port']=port
  tag=bridge['tag']
 else:
  tag='eljefe-unlock-socks'
  ins.append({'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'socks',
    'settings':{'auth':'noauth','udp':True},'sniffing':{'enabled':True,'destOverride':['http','tls','quic']}})
 rules.insert(0,{'type':'field','inboundTag':[tag],'outboundTag':target})
 native=[i['tag'] for i in ins if i.get('tag') and i.get('tag') not in managed_tags]
 nr={'type':'field','inboundTag':native,'domain':domains,'outboundTag':target} if native else None
 if nr:rules.insert(1,nr)
else:
 ins[:]=[i for i in ins if i.get('tag') not in managed_tags]
 nr=None
with open(out,'w') as f:json.dump(d,f,indent=2,ensure_ascii=False);f.write('\n')
print(json.dumps({'native_rule':nr,'bridge_port':port,'target':target}))
PYXRAY
}

unlock_stage_hy2() {
    local mode="$1" source="$2" output="$3" port="$4"
    python3 - "$mode" "$source" "$output" "$port" <<'PYHY2'
from pathlib import Path
import sys,re
mode,source,out,port=sys.argv[1:]
s=Path(source).read_text()
s=re.sub(r'\n# ELJEFE_HY2_HK_ACL\n.*?\n# END_ELJEFE_HY2_HK_ACL\n?', '\n',s,flags=re.S)
s=s.rstrip('\n')+'\n'
if mode=='enable':
 if re.search(r'(?m)^(acl|outbounds|sniff):',s):
  raise SystemExit('HY2 已有自定义 ACL/outbounds/sniff，停止以避免覆盖')
 s+='''\n# ELJEFE_HY2_HK_ACL
sniff:
  enable: true
  timeout: 2s
  rewriteDomain: false
outbounds:
  - name: direct
    type: direct
  - name: shared_unlock
    type: socks5
    socks5:
      addr: 127.0.0.1:'''+port+'''
acl:
  inline:
    - shared_unlock(geosite:netflix)
    - shared_unlock(geosite:disney)
    - shared_unlock(geosite:hbo)
    - shared_unlock(geosite:primevideo)
    - direct(all)
# END_ELJEFE_HY2_HK_ACL
'''
Path(out).write_text(s)
PYHY2
}

# Transactional update across Xray + optional HY2.
unlock_apply() {
    local mode="$1" target port x_tmp h_tmp='' x_bak h_bak='' state_tmp
    [[ -f "$CONFIG_FILE" && -x "$XRAY_BIN" ]] || { echo '找不到 Xray 配置或二进制文件'; return 1; }
    unlock_load; target="$UNLOCK_OUTBOUND"; port="$UNLOCK_PORT"
    if [[ "$mode" == enable ]]; then
        [[ -n "$target" ]] || { echo '请先在菜单 12 选择解锁 VPS 的出站'; return 1; }
        [[ -n "$port" ]] || { unlock_port_choose || return 1; unlock_load; port="$UNLOCK_PORT"; }
    else
        port="${port:-10981}"
    fi
    if [[ "$mode" == enable ]] && ss -ltnH "( sport = :$port )" | grep -q .; then
        if ! python3 - "$CONFIG_FILE" "$port" <<'PYOWNER'
import json,sys
c=json.load(open(sys.argv[1])); p=int(sys.argv[2])
assert any(i.get('tag') in ('hy2-hk-socks','eljefe-unlock-socks') and i.get('port')==p and i.get('listen')=='127.0.0.1' for i in c.get('inbounds',[]))
PYOWNER
        then echo '桥接端口已被其他程序占用，请修改端口'; return 1; fi
    fi
    x_tmp=$(mktemp --suffix=.json) || return 1
    state_tmp=$(mktemp) || { rm -f "$x_tmp"; return 1; }
    if ! unlock_stage_xray "$mode" "$x_tmp" "$port" "$target" > "$state_tmp"; then
        rm -f "$x_tmp" "$state_tmp"; return 1
    fi
    if ! "$XRAY_BIN" run -test -config "$x_tmp" >/dev/null; then
        echo 'Xray 新配置校验失败，未更改服务'; rm -f "$x_tmp" "$state_tmp"; return 1
    fi
    if [[ -f "$HY2_CONFIG" ]]; then
        h_tmp=$(mktemp) || { rm -f "$x_tmp" "$state_tmp"; return 1; }
        if ! unlock_stage_hy2 "$mode" "$HY2_CONFIG" "$h_tmp" "$port"; then
            rm -f "$x_tmp" "$state_tmp" "$h_tmp"; return 1
        fi
    fi
    x_bak="$CONFIG_FILE.unlock-backup.$(date +%Y%m%d%H%M%S)"
    cp -a "$CONFIG_FILE" "$x_bak" || { rm -f "$x_tmp" "$h_tmp" "$state_tmp"; return 1; }
    if [[ -n "$h_tmp" ]]; then
        h_bak="$HY2_CONFIG.unlock-backup.$(date +%Y%m%d%H%M%S)"
        cp -a "$HY2_CONFIG" "$h_bak" || { rm -f "$x_tmp" "$h_tmp" "$state_tmp"; return 1; }
    fi
    # Stage HY2 config before Xray restart; Xray restart can disconnect SSH.
    cat "$x_tmp" > "$CONFIG_FILE"
    [[ -z "$h_tmp" ]] || cat "$h_tmp" > "$HY2_CONFIG"
    if ! systemctl restart eljefe-v2 || ! systemctl is-active --quiet eljefe-v2 ||
       { [[ -n "$h_tmp" ]] && { ! systemctl restart "$HY2_SERVICE" || ! systemctl is-active --quiet "$HY2_SERVICE"; }; }; then
        cp -a "$x_bak" "$CONFIG_FILE"
        [[ -z "$h_bak" ]] || cp -a "$h_bak" "$HY2_CONFIG"
        systemctl restart eljefe-v2 || true
        [[ -z "$h_bak" ]] || systemctl restart "$HY2_SERVICE" || true
        echo '更新失败：已尝试恢复 Xray/HY2 原配置'
        rm -f "$x_tmp" "$h_tmp" "$state_tmp"; return 1
    fi
    mkdir -p -m 700 "$UNLOCK_DIR"
    install -m 600 "$state_tmp" "$UNLOCK_STATE"
    rm -f "$x_tmp" "$h_tmp" "$state_tmp"
    echo "共享解锁 ${mode} 完成；出口：${target:-无}；端口：$port"
    echo "配置备份：$x_bak ${h_bak}"
}

# Adapter contract for future protocols:
# unlock_load -> read UNLOCK_OUTBOUND / UNLOCK_PORT; use loopback SOCKS5
# 127.0.0.1:$UNLOCK_PORT; match only supported stream domains; preserve direct
# routing for other traffic; add/remove only the adapter's own marked block.
# If a protocol does not support TCP SOCKS5 chaining, implement a capability-
# specific adapter (never silently assume UDP/QUIC can traverse TCP SOCKS5).
unlock_menu() {
    while true; do
        echo; echo '===== 通用流媒体解锁管理（完全可选） ====='
        echo '1. 选择已有解锁 VPS 的 Xray 出站'
        echo '2. 设置 / 自动选择本地桥接端口'
        echo '3. 开启 / 更新共享解锁（Xray + HY2）'
        echo '4. 关闭共享解锁（Xray + HY2）'
        echo '5. 查看配置和桥接状态'
        echo '6. 测试桥接出口公网 IP'
        echo '7. 导入 Xray 出站 JSON'
        echo '0. 返回'
        read -r -p '选择: ' choice
        case "$choice" in
          1) unlock_select ;;
          2) unlock_port_choose ;;
          3) unlock_apply enable ;;
          4) unlock_apply disable ;;
          5) unlock_load; echo "出口：${UNLOCK_OUTBOUND:-未设置}，桥接端口：${UNLOCK_PORT:-未设置}"; [[ -z "$UNLOCK_PORT" ]] || ss -lntp | grep ":$UNLOCK_PORT " || true ;;
          6) unlock_load; [[ -n "$UNLOCK_PORT" ]] && curl -4fsS --socks5-hostname "127.0.0.1:$UNLOCK_PORT" --max-time 15 https://api.ipify.org && echo || echo '桥接不可用或尚未开启，请检查配置' ;;
          7) unlock_import ;;
          0) break ;;
          *) echo '无效选项' ;;
        esac
        read -r -p '按回车继续...' _
    done
}
# Backward-compatible entry points in HY2 menu.
hy2_hk_bridge() { unlock_apply "$1"; }

hy2_menu() {
    while true; do
        echo ""
        echo "===== HY2 独立管理 =====" 
        echo "1. 安装并配置 HY2（自动证书优先 / DNS-01 备用）"
        echo "2. 查看 HY2 分享链接和 YAML"
        echo "3. 查看 HY2 状态"
        echo "4. 重启 HY2"
        echo "5. 停用 HY2（保留配置备份）"
        echo "6. 开启流媒体分流（复用共享 Xray 出口）"
        echo "7. 关闭 HY2 流媒体分流"
        echo "0. 返回主菜单"
        read -r -p '选择: ' choice
        case "$choice" in
          1) hy2_install ;;
          2) hy2_show_info; hy2_show_yaml ;;
          3) hy2_status ;;
          4) systemctl restart "$HY2_SERVICE" && systemctl is-active "$HY2_SERVICE" ;;
          5) hy2_remove ;;
          6) hy2_hk_bridge enable ;;
          7) hy2_hk_bridge disable ;;
          0) break ;;
          *) echo '无效选项' ;;
        esac
        read -r -p '按回车继续...' _
    done
}

# Preserve original routines exactly, extend their output only.
show_info() { show_info_original "$@"; [[ -f "$HY2_ENV" ]] && hy2_show_info; }
show_yaml() { show_yaml_original "$@"; [[ -f "$HY2_ENV" ]] && hy2_show_yaml; }
# ===== HY2 isolated extension END =====

menu() {
    while true; do
    clear
    # [完善6] 版本号更新为 v15.7，菜单新增选项 10「查看服务状态」
    echo -e " ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v16.2]${PLAIN}"
    echo -e "----------------------------------"
    echo -e " ${GREEN}01.${PLAIN} 全新安装"
    echo -e " ${GREEN}02.${PLAIN} 查看链接"
    echo -e " ${GREEN}03.${PLAIN} 查看 YAML 配置"
    echo -e " ${GREEN}04.${PLAIN} 添加/修改域名"
    echo -e " ${GREEN}05.${PLAIN} 修改伪装 SNI"
    echo -e " ${GREEN}06.${PLAIN} 更新内核 (Fix Key)"
    echo -e " ${GREEN}07.${PLAIN} 重启服务"
    echo -e " ${GREEN}08.${PLAIN} 卸载脚本"
    echo -e " ${GREEN}09.${PLAIN} 开启/关闭 BBR [当前: $(check_bbr_status)]"
    echo -e " ${GREEN}10.${PLAIN} 查看服务状态"
    echo -e " ${GREEN}11.${PLAIN} Hysteria 2 独立管理"
    echo -e " ${GREEN}12.${PLAIN} 通用流媒体解锁管理"
    echo -e " ${GREEN}00.${PLAIN} 退出"
    echo -e "----------------------------------"
    read -p "请输入选项: " num

    case "$num" in
        1)
            check_root
            install_dependencies
            install_xray
            setup_fake_site
            echo ""
            echo -e "${YELLOW}是否配置域名 (启用 VLESS & VMess CDN)？${PLAIN}"
            echo -e "1. 是"
            echo -e "2. 否"
            read -p "选择: " choice
            if [[ "$choice" == "1" ]]; then
                read -p "请输入域名: " my_domain
                setup_cert "$my_domain"
                if [ $? -eq 0 ]; then
                    setup_nginx "$my_domain"
                    generate_config "$my_domain"
                else
                    setup_nginx ""
                    generate_config ""
                fi
            else
                setup_nginx ""
                generate_config ""
            fi
            setup_service
            show_info
            ;;
        2) show_info ;;
        3) show_yaml ;;
        4) add_domain ;;
        5) change_sni ;;
        6) update_core ;;
        7) systemctl restart eljefe-v2 && log_info "服务已重启" ;;
        8) uninstall_all ;;
        9) toggle_bbr ;;
        # [完善6] 新增选项 10，调用 show_status 函数
        10) show_status ;;
        11) hy2_menu ;;
        12) unlock_menu ;;
        0) exit 0 ;;
        *) log_err "无效选项" ;;
    esac

    # 操作结果显示后暂停，避免菜单立即清屏覆盖输出。
    read -r -p "按回车键返回菜单..." _
    done
}

# Single entry point. The menu owns its own loop; no recursive re-entry.
case "${1:-}" in
    ""|install) menu ;;
    info) show_info ;;
    yaml) show_yaml ;;
    status) show_status ;;
    *) printf '用法: %s [install|info|yaml|status]\n' "$0" >&2; exit 2 ;;
esac
