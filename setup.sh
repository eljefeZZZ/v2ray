#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager (Smart DNS)
# Version: v19.6 (Default: Localhost & Interactive DNS)
# Author: eljefeZZZ & 代码小天才
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
LOG_FILE="/tmp/eljefe_install.log"
XRAY_USER="xray"

# 默认端口
PORT_REALITY=443
PORT_VLESS_WS=2087
PORT_VMESS_WS=2088
PORT_TLS=8443

DEST_SITE="itunes.apple.com:443"
DEST_SNI="itunes.apple.com"

# --- 🎨 颜色与UI ---
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; PURPLE='\033[35m'; CYAN='\033[36m'; PLAIN='\033[0m'; BOLD='\033[1m'
ICON_OK="${GREEN}✔${PLAIN}"; ICON_ERR="${RED}✖${PLAIN}"; ICON_WAIT="${YELLOW}⏳${PLAIN}"; ICON_WARN="${YELLOW}⚠️${PLAIN}"; ICON_TIP="${CYAN}💡${PLAIN}"

# --- 🛠️ 交互函数 ---
log_info() { echo -e "${GREEN}[INFO]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERROR]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }

run_step() {
    local msg="$1"; local cmd="$2"
    echo -ne " ${ICON_WAIT} ${msg}..."
    eval "$cmd" > "$LOG_FILE" 2>&1 &
    local pid=$!; local delay=0.1; local spinstr='|/-\'
    while ps -p $pid > /dev/null; do
        local temp=${spinstr#?}; printf " [%c]  " "$spinstr"; local spinstr=$temp${spinstr%"$temp"}; sleep $delay; printf "\b\b\b\b\b\b"
    done
    wait $pid; local exit_code=$?; printf "      \b\b\b\b\b\b"
    if [ $exit_code -eq 0 ]; then echo -e "\r ${ICON_OK} ${msg} ${GREEN}[完成]${PLAIN}          "
    else echo -e "\r ${ICON_ERR} ${msg} ${RED}[失败]${PLAIN}          "; echo -e "${RED}=== 错误日志 ===${PLAIN}"; tail -n 10 "$LOG_FILE"; exit 1; fi
}
check_root() { [[ $EUID -ne 0 ]] && log_err "请使用 Root 用户运行！" && exit 1; }
show_banner() {
    clear
    echo -e "${PURPLE}========================================================${PLAIN}"
    echo -e "${BOLD}         ElJefe V2 Manager ${PLAIN}${CYAN}v19.6 Smart DNS${PLAIN}"
    echo -e "${PURPLE}========================================================${PLAIN}"
    echo -e " ${ICON_TIP} 作者: eljefeZZZ & 代码小天才"
    echo -e " ${ICON_TIP} 特性: 链式代理 | DNS分流(默认Localhost) | 自动修复"
    echo -e "${PURPLE}========================================================${PLAIN}"
    echo ""
}

# --- 0. 自动迁移补丁 ---
fix_legacy_config() {
    if [ -f "$CONFIG_FILE" ] && [ -f "$INFO_FILE" ]; then
        if ! grep -q "PRI_KEY" "$INFO_FILE"; then
            if ! command -v jq &> /dev/null; then if [ -f /etc/debian_version ]; then apt-get update -y >/dev/null && apt-get install -y jq >/dev/null; else yum install -y jq >/dev/null; fi; fi
            local old_key=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$CONFIG_FILE")
            if [[ -n "$old_key" ]]; then echo "PRI_KEY=$old_key" >> "$INFO_FILE"; fi
        fi
    fi
}

# --- 1. 基础安装模块 ---
install_dependencies() {
    echo -e "${ICON_TIP} 正在初始化系统环境..."
    local cmd_up="apt-get update -y"; local cmd_in="apt-get install -y curl wget unzip jq nginx uuid-runtime openssl cron lsof socat psmisc"
    if [ -f /etc/redhat-release ]; then cmd_up="yum update -y"; cmd_in="yum install -y curl wget unzip jq uuid openssl cronie lsof socat psmisc"; fi
    run_step "更新系统软件源" "$cmd_up"
    run_step "安装必要依赖" "$cmd_in"
    mkdir -p "$ROOT_DIR" "$CERT_DIR" "$WEB_DIR"
    if ! id -u "$XRAY_USER" &>/dev/null; then useradd -r -s /bin/false "$XRAY_USER"; fi
    run_step "清理 Nginx 配置" "rm -f /etc/nginx/sites-enabled/default && rm -f /etc/nginx/conf.d/default.conf && systemctl stop nginx"
}

setup_fake_site() {
    if [ ! -f "$WEB_DIR/index.html" ]; then
        run_step "下载伪装站点" "wget -qO '$ROOT_DIR/web.zip' 'https://github.com/startbootstrap/startbootstrap-resume/archive/gh-pages.zip'"
        run_step "部署站点" "unzip -q -o '$ROOT_DIR/web.zip' -d '$ROOT_DIR/temp_web' && mv '$ROOT_DIR/temp_web/startbootstrap-resume-gh-pages/'* '$WEB_DIR/' && rm -rf '$ROOT_DIR/web.zip' '$ROOT_DIR/temp_web' && chown -R www-data:www-data '$WEB_DIR' 2>/dev/null || chown -R nginx:nginx '$WEB_DIR' && chmod -R 755 '$WEB_DIR'"
    else echo -e " ${ICON_OK} 伪装站点已存在 ${GREEN}[跳过]${PLAIN}"; fi
}

setup_cert() {
    local domain=$1; echo -e "\n${BOLD}>>> 开始申请 SSL 证书${PLAIN}"
    mkdir -p "$ACME_DIR"; run_step "安装 ACME.sh" "curl https://get.acme.sh | sh -s email=admin@eljefe.com --home '$ACME_DIR'"
    "$ACME_SCRIPT" --set-default-ca --server letsencrypt >/dev/null 2>&1
    systemctl stop nginx; fuser -k 80/tcp >/dev/null 2>&1
    echo -e " ${ICON_WAIT} 正在通信 Let's Encrypt..."
    "$ACME_SCRIPT" --issue -d "$domain" --standalone --keylength ec-256 --force --server letsencrypt
    if [ $? -eq 0 ]; then
        echo -e " ${ICON_OK} 证书申请成功！"
        run_step "安装证书" "$ACME_SCRIPT --install-cert -d '$domain' --ecc --key-file '$CERT_DIR/private.key' --fullchain-file '$CERT_DIR/fullchain.cer' --reloadcmd 'systemctl restart nginx' && chown '$XRAY_USER:$XRAY_USER' '$CERT_DIR/private.key' '$CERT_DIR/fullchain.cer'"
        return 0
    else echo -e " ${ICON_ERR} 证书申请失败！"; return 1; fi
}

setup_nginx() {
    local domain=$1
    run_step "配置 Nginx" "mkdir -p /etc/nginx && cat > /etc/nginx/conf.d/eljefe_fallback.conf <<EOF
server { listen 80; server_name _; root $WEB_DIR; index index.html; }
EOF"
    if [ ! -f /etc/nginx/nginx.conf ]; then
       cat > /etc/nginx/nginx.conf <<EOF
user www-data; worker_processes auto; pid /run/nginx.pid; include /etc/nginx/modules-enabled/*.conf; events { worker_connections 768; } http { sendfile on; tcp_nopush on; types_hash_max_size 2048; include /etc/nginx/mime.types; default_type application/octet-stream; ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers on; access_log /var/log/nginx/access.log; error_log /var/log/nginx/error.log; gzip on; include /etc/nginx/conf.d/*.conf; include /etc/nginx/sites-enabled/*; }
EOF
    fi
    if grep -q "user nginx;" /etc/nginx/nginx.conf; then sed -i 's/user nginx;/user www-data;/g' /etc/nginx/nginx.conf; fi
    if [[ -n "$domain" ]]; then
        cat > /etc/nginx/conf.d/eljefe_tls.conf <<EOF
server {
    listen $PORT_TLS ssl; server_name $domain;
    ssl_certificate $CERT_DIR/fullchain.cer; ssl_certificate_key $CERT_DIR/private.key;
    location /vless { if (\$http_upgrade != "websocket") { return 404; } proxy_redirect off; proxy_pass http://127.0.0.1:$PORT_VLESS_WS; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$http_host; }
    location /vmess { if (\$http_upgrade != "websocket") { return 404; } proxy_redirect off; proxy_pass http://127.0.0.1:$PORT_VMESS_WS; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$http_host; }
    location / { root $WEB_DIR; index index.html; }
}
EOF
    fi
    run_step "重启 Nginx" "systemctl restart nginx"
}

install_xray() {
    if [ -f "$XRAY_BIN" ]; then echo -e " ${ICON_OK} Xray 已安装 ${GREEN}[跳过]${PLAIN}"; return; fi
    local version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -z "$version" ]] && version="v1.8.24"
    echo -e " ${ICON_WAIT} 下载 Xray 内核 ($version)..."
    mkdir -p "$ROOT_DIR"
    wget -q --show-progress -O "$ROOT_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-linux-64.zip"
    if [ $? -ne 0 ] || [ ! -s "$ROOT_DIR/xray.zip" ]; then echo -e " ${ICON_ERR} 下载失败！"; exit 1; fi
    run_step "安装 Xray" "unzip -o '$ROOT_DIR/xray.zip' -d '$ROOT_DIR' >/dev/null && rm -f '$ROOT_DIR/xray.zip' && chmod +x '$XRAY_BIN' && chown -R '$XRAY_USER:$XRAY_USER' '$ROOT_DIR'"
}

# --- 2. 核心功能 ---

urldecode() { : "${*//+/ }"; echo -e "${_//%/\\x}"; }
parse_chain_link() {
    local link=$1
    if [[ "$link" != vless://* ]]; then log_err "仅支持 vless:// 链接"; return 1; fi
    echo -e " ${ICON_WAIT} 解析 Reality 链接..."
    local temp=${link#vless://}
    local uuid=$(echo "$temp" | awk -F'@' '{print $1}')
    local host_port_temp=$(echo "$temp" | awk -F'@' '{print $2}')
    local host_port=$(echo "$host_port_temp" | awk -F'?' '{print $1}')
    local addr=$(echo "$host_port" | awk -F':' '{print $1}')
    local port=$(echo "$host_port" | awk -F':' '{print $2}')
    local query=$(echo "$temp" | awk -F'?' '{print $2}' | awk -F'#' '{print $1}')
    get_param() { echo "$query" | grep -oE "(^|&)$1=[^&]*" | cut -d= -f2; }
    local sni=$(get_param "sni"); sni=$(urldecode "$sni")
    local pbk=$(get_param "pbk")
    local sid=$(get_param "sid")
    local fp=$(get_param "fp"); fp=$(urldecode "$fp")
    local flow=$(get_param "flow"); flow=$(urldecode "$flow")
    local security=$(get_param "security")
    [[ -z "$fp" ]] && fp="chrome"; [[ -z "$security" ]] && security="reality"
    sed -i '/^CHAIN_/d' "$INFO_FILE" 2>/dev/null
    echo "CHAIN_ENABLE=true" >> "$INFO_FILE"; echo "CHAIN_UUID=$uuid" >> "$INFO_FILE"
    echo "CHAIN_ADDR=$addr" >> "$INFO_FILE"; echo "CHAIN_PORT=$port" >> "$INFO_FILE"
    echo "CHAIN_SNI=$sni" >> "$INFO_FILE"; echo "CHAIN_PBK=$pbk" >> "$INFO_FILE"
    echo "CHAIN_SID=$sid" >> "$INFO_FILE"; echo "CHAIN_FP=$fp" >> "$INFO_FILE"
    echo "CHAIN_FLOW=$flow" >> "$INFO_FILE"; echo "CHAIN_SEC=$security" >> "$INFO_FILE"
    echo -e " ${ICON_OK} 解析成功: ${CYAN}$addr:$port${PLAIN}"
    return 0
}

generate_config() {
    local domain=$1
    if [ -f "$INFO_FILE" ]; then source "$INFO_FILE"; fi
    if [[ -z "$UUID" ]]; then
        UUID=$(uuidgen); local keys=$("$XRAY_BIN" x25519)
        PUB_KEY=$(echo "$keys" | awk -F': ' '/Public/ {print $2}' | tr -d '\r\n')
        PRI_KEY=$(echo "$keys" | awk -F': ' '/Private/ {print $2}' | tr -d '\r\n')
        SID=$(openssl rand -hex 4 | tr -d '\n')
        echo "UUID=$UUID" > "$INFO_FILE"; echo "PUB_KEY=$PUB_KEY" >> "$INFO_FILE"; echo "PRI_KEY=$PRI_KEY" >> "$INFO_FILE"; echo "SID=$SID" >> "$INFO_FILE"; echo "DOMAIN=$domain" >> "$INFO_FILE"; echo "SNI=$DEST_SNI" >> "$INFO_FILE"
    fi
    
    # 链式代理模块
    local CHAIN_OUTBOUND=""; local CHAIN_RULE=""
    if [[ "$CHAIN_ENABLE" == "true" ]]; then
        local CHAIN_STREAM="{ \"network\": \"tcp\", \"security\": \"none\" }"
        if [[ "$CHAIN_SEC" == "reality" ]]; then
            CHAIN_STREAM="{ \"network\": \"tcp\", \"security\": \"reality\", \"realitySettings\": { \"serverNames\": [ \"$CHAIN_SNI\" ], \"publicKey\": \"$CHAIN_PBK\", \"shortId\": \"$CHAIN_SID\", \"fingerprint\": \"$CHAIN_FP\" } }"
        fi
        CHAIN_OUTBOUND=",{ \"tag\": \"lisa_unlock\", \"protocol\": \"vless\", \"settings\": { \"vnext\": [ { \"address\": \"$CHAIN_ADDR\", \"port\": $CHAIN_PORT, \"users\": [ { \"id\": \"$CHAIN_UUID\", \"flow\": \"$CHAIN_FLOW\", \"encryption\": \"none\" } ] } ] }, \"streamSettings\": $CHAIN_STREAM }"
        CHAIN_RULE=",{ \"type\": \"field\", \"outboundTag\": \"lisa_unlock\", \"domain\": [ \"geosite:netflix\", \"geosite:disney\", \"geosite:hbo\", \"geosite:primevideo\", \"geosite:openai\" ] }"
    fi

    # [v19.6] DNS 策略：默认 localhost
    local BASIC_DNS='"localhost"'
    local UNLOCK_BLOCK=""

    if [[ -n "$DNS_BASIC" ]]; then BASIC_DNS="$DNS_BASIC"; fi

    if [[ -n "$DNS_UNLOCK_IP" ]]; then
        UNLOCK_BLOCK=",{ \"address\": \"$DNS_UNLOCK_IP\", \"port\": 53, \"domains\": [ \"geosite:netflix\", \"geosite:disney\", \"geosite:hbo\", \"geosite:primevideo\", \"geosite:openai\" ] }"
    fi

    cat > "$CONFIG_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality",
      "port": $PORT_REALITY,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "show": false, "dest": "$DEST_SITE", "xver": 0, "serverNames": [ "$DEST_SNI" ], "privateKey": "$PRI_KEY", "shortIds": [ "$SID" ] } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
    },
    { "tag": "vless-ws", "port": $PORT_VLESS_WS, "listen": "127.0.0.1", "protocol": "vless", "settings": { "clients": [ { "id": "$UUID" } ], "decryption": "none" }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } } },
    { "tag": "vmess-ws", "port": $PORT_VMESS_WS, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [ { "id": "$UUID" } ] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct", "settings": { "domainStrategy": "UseIPv4" } },
    { "protocol": "blackhole", "tag": "block" }
    $CHAIN_OUTBOUND
  ],
  "dns": { 
    "servers": [ 
        $BASIC_DNS
        $UNLOCK_BLOCK
    ] 
  },
  "routing": { "domainStrategy": "IPOnDemand", "rules": [ { "type": "field", "outboundTag": "block", "ip": [ "geoip:private" ] } $CHAIN_RULE ] }
}
EOF
}

setup_service() {
    run_step "配置服务" "cat > /etc/systemd/system/eljefe-v2.service <<EOF
[Unit]
Description=ElJefe V2Ray Service
After=network.target
[Service]
User=$XRAY_USER
ExecStart=$XRAY_BIN run -c $CONFIG_FILE
Restart=on-failure
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable eljefe-v2 && systemctl restart eljefe-v2"
}

# --- 3. 辅助功能 ---
check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    if [[ "$param" == "bbr" ]]; then echo -e "${GREEN}ON${PLAIN}"; else echo -e "${RED}OFF${PLAIN}"; fi
}
toggle_bbr() {
    if [[ $(check_bbr_status) == *"${GREEN}ON${PLAIN}"* ]]; then
        run_step "关闭 BBR" "sed -i '/net.core.default_qdisc=fq/d' /etc/sysctl.conf && sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf && sysctl -p"
        echo -e " ${ICON_OK} BBR 已关闭"
    else
        run_step "开启 BBR" "echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf && echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf && sysctl -p"
        echo -e " ${ICON_OK} BBR 已开启"
    fi
    read -p " 按回车键返回..."
}
add_domain() {
    echo -e "\n${CYAN}➜ 请输入要绑定的域名:${PLAIN}"; read -p "  域名: " new_domain
    if [[ -z "$new_domain" ]]; then return; fi
    setup_cert "$new_domain"
    if [ $? -eq 0 ]; then setup_nginx "$new_domain"; generate_config "$new_domain"; setup_service; echo -e " ${ICON_OK} 域名添加成功！"; fi
}
change_sni() {
    echo -e "\n${CYAN}➜ 请输入新的伪装域名 (SNI):${PLAIN}"; read -p "  SNI: " new_sni
    if [[ -z "$new_sni" ]]; then return; fi
    DEST_SNI="$new_sni"; DEST_SITE="$new_sni:443"
    generate_config "$(grep 'DOMAIN=' $INFO_FILE | cut -d= -f2 2>/dev/null)"; run_step "应用配置" "systemctl restart eljefe-v2"
}
manage_chain_proxy() {
    echo -e "\n${BOLD}${PURPLE}=== ⛓️ 链式代理管理 ===${PLAIN}"
    echo -e " ${GREEN}1.${PLAIN} 配置下一跳节点 (粘贴链接)"
    echo -e " ${RED}2.${PLAIN} 关闭链式代理 (直连)"
    echo -e " ${GREEN}0.${PLAIN} 返回"
    read -p " 选项: " cp_choice
    if [[ "$cp_choice" == "1" ]]; then
        echo -e "\n${CYAN}➜ 粘贴 VLESS 链接:${PLAIN}"; read -p "  链接: " v_link
        parse_chain_link "$v_link" && generate_config "$(grep 'DOMAIN=' $INFO_FILE | cut -d= -f2 2>/dev/null)" && run_step "应用配置" "systemctl restart eljefe-v2"
    elif [[ "$cp_choice" == "2" ]]; then
        sed -i '/^CHAIN_/d' "$INFO_FILE"; echo "CHAIN_ENABLE=false" >> "$INFO_FILE"
        generate_config "$(grep 'DOMAIN=' $INFO_FILE | cut -d= -f2 2>/dev/null)"; run_step "应用配置" "systemctl restart eljefe-v2"
    fi
}

manage_dns() {
    echo -e "\n${BOLD}${PURPLE}=== 🖍️ DNS 策略管理 ===${PLAIN}"
    echo -e " ${CYAN}当前基础 DNS:${PLAIN} $(grep 'DNS_BASIC=' $INFO_FILE 2>/dev/null | cut -d= -f2 || echo 'localhost')"
    echo -e " ${CYAN}当前解锁 DNS:${PLAIN} $(grep 'DNS_UNLOCK_IP=' $INFO_FILE 2>/dev/null | cut -d= -f2 || echo '未设置')"
    echo -e "----------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 修改 基础全局 DNS (例如 \"1.1.1.1\")"
    echo -e " ${GREEN}2.${PLAIN} 设置 解锁专用 DNS (例如 203.9...)"
    echo -e " ${YELLOW}3.${PLAIN} 清除 解锁 DNS (恢复默认)"
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo ""
    read -p " 请输入选项: " dns_opt
    case "$dns_opt" in
        1)
            echo -e "\n${CYAN}➜ 请输入新的 DNS 列表 (注意引号):${PLAIN}"
            echo -e "  默认为 \"localhost\"。如需修改，请输入如: \"8.8.8.8\", \"1.1.1.1\""
            read -p "  输入: " new_basic
            if [[ -n "$new_basic" ]]; then
                sed -i '/^DNS_BASIC=/d' "$INFO_FILE"
                echo "DNS_BASIC='$new_basic'" >> "$INFO_FILE"
                generate_config "$(grep 'DOMAIN=' $INFO_FILE | cut -d= -f2 2>/dev/null)"
                run_step "应用 DNS 配置" "systemctl restart eljefe-v2"
            fi
            ;;
        2)
            echo -e "\n${CYAN}➜ 请输入解锁服务的 DNS IP:${PLAIN}"
            read -p "  IP: " unlock_ip
            if [[ -n "$unlock_ip" ]]; then
                sed -i '/^DNS_UNLOCK_IP=/d' "$INFO_FILE"
                echo "DNS_UNLOCK_IP=$unlock_ip" >> "$INFO_FILE"
                generate_config "$(grep 'DOMAIN=' $INFO_FILE | cut -d= -f2 2>/dev/null)"
                run_step "应用 DNS 配置" "systemctl restart eljefe-v2"
            fi
            ;;
        3)
            sed -i '/^DNS_UNLOCK_IP=/d' "$INFO_FILE"
            generate_config "$(grep 'DOMAIN=' $INFO_FILE | cut -d= -f2 2>/dev/null)"
            run_step "清除 DNS 配置" "systemctl restart eljefe-v2"
            echo -e " ${ICON_OK} 已清除解锁 DNS"
            ;;
    esac
}

show_info() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置信息"; return; fi
    source "$INFO_FILE"
    local ip=$(curl -s https://api.ipify.org)
    echo -e "\n${BOLD}${GREEN}=== 🚀 节点配置 (v19.6) ===${PLAIN}"
    echo -e " ${ICON_TIP} UUID: ${CYAN}$UUID${PLAIN}"
    echo -e " ${ICON_TIP} Reality Key: ${CYAN}$PUB_KEY${PLAIN}"
    echo -e "----------------------------------------------------"
    echo -e "${YELLOW}1. Reality (直连)${PLAIN}"
    echo -e "${CYAN}vless://$UUID@$ip:$PORT_REALITY?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$DEST_SNI&fp=chrome&pbk=$PUB_KEY&sid=$SID&type=tcp&headerType=none#ElJefe_Reality${PLAIN}"
    if [[ -n "$DOMAIN" ]]; then
        echo -e "\n${YELLOW}2. VLESS-WS-TLS${PLAIN}"
        echo -e "${CYAN}vless://$UUID@$DOMAIN:$PORT_TLS?encryption=none&security=tls&type=ws&host=$DOMAIN&path=%2fvless#ElJefe_VLESS_CDN${PLAIN}"
        echo -e "\n${YELLOW}3. VMess-WS-TLS${PLAIN}"
        local vmess_json='{"v":"2","ps":"ElJefe_VMess_CDN","add":"'$DOMAIN'","port":"'$PORT_TLS'","id":"'$UUID'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$DOMAIN'","path":"/vmess","tls":"tls","sni":"'$DOMAIN'"}'
        echo -e "${CYAN}vmess://$(echo -n "$vmess_json" | base64 -w 0)${PLAIN}"
    fi
    echo -e "----------------------------------------------------"
}
show_yaml() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置"; return; fi
    source "$INFO_FILE"; local ip=$(curl -s https://api.ipify.org)
    echo -e "\n${BOLD}${GREEN}=== Clash YAML ===${PLAIN}"
    echo -e "- name: ElJefe_Reality\n  type: vless\n  server: $ip\n  port: $PORT_REALITY\n  uuid: $UUID\n  network: tcp\n  tls: true\n  udp: true\n  flow: xtls-rprx-vision\n  servername: $DEST_SNI\n  reality-opts:\n    public-key: $PUB_KEY\n    short-id: \"$SID\"\n  client-fingerprint: chrome"
    if [[ -n "$DOMAIN" ]]; then
        echo -e "\n- name: ElJefe_VLESS_CDN\n  type: vless\n  server: $DOMAIN\n  port: $PORT_TLS\n  uuid: $UUID\n  udp: true\n  tls: true\n  network: ws\n  servername: $DOMAIN\n  skip-cert-verify: false\n  ws-opts:\n    path: /vless\n    headers:\n      Host: $DOMAIN"
        echo -e "\n- name: ElJefe_VMess_CDN\n  type: vmess\n  server: $DOMAIN\n  port: $PORT_TLS\n  uuid: $UUID\n  alterId: 0\n  cipher: auto\n  udp: true\n  tls: true\n  network: ws\n  servername: $DOMAIN\n  ws-opts:\n    path: /vmess\n    headers:\n      Host: $DOMAIN"
    fi; echo ""
}

# --- 菜单 ---
menu() {
    fix_legacy_config; show_banner
    if [ -f "$INFO_FILE" ]; then source "$INFO_FILE"; fi
    
    if [[ "$CHAIN_ENABLE" == "true" ]]; then 
        echo -e " ${BOLD}状态:${PLAIN} ${GREEN}● 链式代理${PLAIN} ${CYAN}➜ $CHAIN_ADDR${PLAIN}"
    else echo -e " ${BOLD}状态:${PLAIN} ${YELLOW}○ 直连模式${PLAIN}"; fi
    if [[ -n "$DNS_UNLOCK_IP" ]]; then
         echo -e " ${BOLD}DNS :${PLAIN} ${GREEN}● 解锁开启${PLAIN} ${CYAN}➜ $DNS_UNLOCK_IP${PLAIN}"
    fi
    echo ""
    
    echo -e " ${GREEN}1.${PLAIN}  ✨ 全新安装"
    echo -e " ${GREEN}2.${PLAIN}  🔗 查看链接"
    echo -e " ${GREEN}3.${PLAIN}  📄 查看 YAML"
    echo -e " ${GREEN}4.${PLAIN}  ⛓️ 链式代理管理"
    echo -e " ${GREEN}5.${PLAIN}  🌐 域名与证书"
    echo -e " ${GREEN}6.${PLAIN}  🎭 修改 SNI"
    echo -e " ${GREEN}7.${PLAIN}  🔄 重启服务"
    echo -e " ${GREEN}8.${PLAIN}  🗑️ 卸载脚本"
    echo -e " ${GREEN}9.${PLAIN}  🚀 BBR [$(check_bbr_status)]"
    echo -e " ${GREEN}10.${PLAIN} 🖍️ DNS 策略管理"
    echo -e " ${GREEN}0.${PLAIN}  🚪 退出"
    echo ""
    
    read -p " 请输入选项: " num
    case "$num" in
        1) check_root; install_dependencies; install_xray; setup_fake_site
           echo -e "\n${CYAN}➜ 是否配置链式代理 (推荐 LisaHost 等家宽)？${PLAIN}"; read -p "  输入 [y/n]: " chain_opt
           if [[ "$chain_opt" == "y" ]]; then read -p "  粘贴 VLESS 链接: " v_link; parse_chain_link "$v_link"; fi
           
           # [v19.6] 新增询问 DNS
           echo -e "\n${CYAN}➜ 是否配置流媒体解锁 DNS (例如 203.9...)?${PLAIN}"
           echo -e "  默认不配置(n)。如果您有专用的解锁DNS，请选 y。"
           read -p "  输入 [y/n]: " dns_opt
           if [[ "$dns_opt" == "y" ]]; then
               read -p "  请输入 DNS IP: " input_dns_ip
               if [[ -n "$input_dns_ip" ]]; then sed -i '/^DNS_UNLOCK_IP=/d' "$INFO_FILE"; echo "DNS_UNLOCK_IP=$input_dns_ip" >> "$INFO_FILE"; fi
           fi
           
           setup_service; echo -e "\n${ICON_OK} ${BOLD}安装完成！${PLAIN}" ;;
        2) show_info; read -p " 按回车继续..." ;;
        3) show_yaml; read -p " 按回车继续..." ;;
        4) manage_chain_proxy ;;
        5) add_domain ;;
        6) change_sni ;;
        7) run_step "重启服务" "systemctl restart eljefe-v2" ;;
        8) run_step "停止服务" "systemctl stop eljefe-v2 && systemctl disable eljefe-v2 && rm -rf '$ROOT_DIR' && rm -f /etc/systemd/system/eljefe-v2.service && rm -f /etc/nginx/conf.d/eljefe*"
           run_step "重启 Nginx" "systemctl restart nginx"; echo -e " ${ICON_OK} 卸载完成" ;;
        9) toggle_bbr; menu ;;
        10) manage_dns ;;
        0) exit 0 ;;
        *) echo -e " ${ICON_ERR} 无效选项"; sleep 1; menu ;;
    esac
}
if [[ $# > 0 ]]; then menu "$@"; else menu; fi
