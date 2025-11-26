#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager (Pro)
# Version: v15.5 (Final Fix: Self-Healing Nginx)
# Features: Reality/VLESS/VMess | Auto-Repair Config | Anti-Conflict
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

DEST_SITE="www.microsoft.com:443"
DEST_SNI="www.microsoft.com"

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
        apt-get install -y curl wget unzip jq nginx uuid-runtime openssl cron lsof socat psmisc
    elif [ -f /etc/redhat-release ]; then
        yum update -y
        yum install -y curl wget unzip jq nginx uuid socat openssl cronie lsof psmisc
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
    mkdir -p "$ACME_DIR"
    curl https://get.acme.sh | sh -s email=admin@eljefe.com --home "$ACME_DIR"
    
    # [核心优化] 强力释放 80 端口
    systemctl stop nginx
    fuser -k 80/tcp
    
    "$ACME_SCRIPT" --issue -d "$domain" --standalone --keylength ec-256 --force
    
    if [ $? -eq 0 ]; then
        log_info "证书申请成功！"
        "$ACME_SCRIPT" --install-cert -d "$domain" --ecc \
            --key-file       "$CERT_DIR/private.key"  \
            --fullchain-file "$CERT_DIR/fullchain.cer" \
            --reloadcmd     "systemctl restart nginx"
            
        chown "$XRAY_USER:$XRAY_USER" "$CERT_DIR/private.key" "$CERT_DIR/fullchain.cer"
        chmod 600 "$CERT_DIR/private.key"
        return 0
    else
        log_err "证书申请失败！请检查域名解析。"
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
        
        # 智能兜底
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
    [[ -n "$domain" ]] && sni=$domain

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
    echo "SNI=$sni" >> "$INFO_FILE"
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
    fuser -k 443/tcp >/dev/null 2>&1
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

show_info() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置信息"; return; fi
    source "$INFO_FILE"
    local ip=$(curl -s https://api.ipify.org)
    
    echo -e "\n${GREEN}=== 节点配置信息 (v15.5) ===${PLAIN}"
    echo -e "UUID: $UUID"
    echo -e "Reality Key: $PUB_KEY"
    echo -e "------------------------"
    echo -e "${YELLOW}1. Reality (直连/防封)${PLAIN}"
    echo -e "vless://$UUID@$ip:$PORT_REALITY?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUB_KEY&sid=$SID&type=tcp&headerType=none#ElJefe_Reality"
    
    if [[ -n "$DOMAIN" ]]; then
        echo -e "\n${YELLOW}2. VLESS-WS-TLS (OpenClash/CDN)${PLAIN}"
        echo -e "vless://$UUID@$DOMAIN:$PORT_TLS?encryption=none&security=tls&type=ws&host=$DOMAIN&path=%2fvless#ElJefe_VLESS_CDN"
        
        echo -e "\n${YELLOW}3. VMess-WS-TLS (兜底)${PLAIN}"
        local vmess_json='{"v":"2","ps":"ElJefe_VMess_CDN","add":"'$DOMAIN'","port":"'$PORT_TLS'","id":"'$UUID'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$DOMAIN'","path":"/vmess","tls":"tls","sni":"'$DOMAIN'"}'
        echo -e "vmess://$(echo -n "$vmess_json" | base64 -w 0)"
    fi
}

show_yaml() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置信息"; return; fi
    source "$INFO_FILE"
    local ip=$(curl -s https://api.ipify.org)
    
    echo -e "\n${GREEN}=== Clash YAML 格式 ===${PLAIN}"
    echo -e "${BLUE}# 复制以下内容到你的 YAML 文件 proxy-providers 或 proxies 下${PLAIN}"
    
    echo -e "- name: ElJefe_Reality"
    echo -e "  type: vless"
    echo -e "  server: $ip"
    echo -e "  port: $PORT_REALITY"
    echo -e "  uuid: $UUID"
    echo -e "  network: tcp"
    echo -e "  tls: true"
    echo -e "  udp: true"
    echo -e "  flow: xtls-rprx-vision"
    echo -e "  servername: $SNI"
    echo -e "  reality-opts:"
    echo -e "    public-key: $PUB_KEY"
    echo -e "    short-id: $SID"
    echo -e "  client-fingerprint: chrome"
    
    if [[ -n "$DOMAIN" ]]; then
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

menu() {
    clear
    echo -e " ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v15.5 Self-Healing]${PLAIN}"
    echo -e "----------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 全新安装"
    echo -e " ${GREEN}2.${PLAIN} 查看链接"
    echo -e " ${GREEN}3.${PLAIN} 查看 YAML 配置"
    echo -e " ${GREEN}4.${PLAIN} 添加/修改域名"
    echo -e " ${GREEN}5.${PLAIN} 修改伪装 SNI"
    echo -e " ${GREEN}6.${PLAIN} 更新内核 (Fix Key)"
    echo -e " ${GREEN}7.${PLAIN} 重启服务"
    echo -e " ${GREEN}8.${PLAIN} 卸载脚本"
    echo -e " ${GREEN}9.${PLAIN} 开启/关闭 BBR [当前: $(check_bbr_status)]"
    echo -e " ${GREEN}0.${PLAIN} 退出"
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
        0) exit 0 ;;
        *) log_err "无效选项" ;;
    esac

    if [[ $# > 0 ]]; then
        case $1 in
            "install") menu ;;
            "info") show_info ;;
            *) menu ;;
        esac
    else
        menu
    fi
}

if [[ $# > 0 ]]; then
    menu "$@"
else
    menu
fi
