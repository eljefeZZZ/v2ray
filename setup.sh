#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager
# Author: eljefeZZZ
# Description: v9.0 (Add Domain Feature Added)
# ==================================================

# --- 目录结构 ---
ROOT_DIR="/usr/local/eljefe-v2"
XRAY_BIN="$ROOT_DIR/xray"
CONFIG_FILE="$ROOT_DIR/config.json"
ACME_DIR="$ROOT_DIR/acme.sh"
CERT_DIR="$ROOT_DIR/cert"
WEB_DIR="$ROOT_DIR/html"

ACME_SCRIPT="$ACME_DIR/acme.sh"
DEST_SITE="www.microsoft.com:443"
DEST_SNI="www.microsoft.com"
PORT_REALITY=443
PORT_WS_LOCAL=2087
PORT_TLS=8443

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

# --- 核心逻辑 ---
install_dependencies() {
    log_info "安装依赖..."
    if [ -f /etc/debian_version ]; then
        apt-get update -y
        apt-get install -y curl wget unzip jq nginx uuid-runtime openssl cron lsof socat
    elif [ -f /etc/redhat-release ]; then
        yum update -y
        yum install -y curl wget unzip jq nginx uuid socat openssl cronie lsof
    else
        log_err "不支持的系统" && exit 1
    fi
    
    mkdir -p "$ROOT_DIR"
    mkdir -p "$CERT_DIR"
    mkdir -p "$WEB_DIR"
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
    
    log_info "释放 80 端口..."
    systemctl stop nginx
    if lsof -i :80 > /dev/null; then
        kill -9 $(lsof -t -i:80)
    fi
    
    "$ACME_SCRIPT" --issue -d "$domain" --standalone --keylength ec-256 --force
    
    if [ $? -eq 0 ]; then
        log_info "证书申请成功！"
        "$ACME_SCRIPT" --install-cert -d "$domain" --ecc \
            --key-file       "$CERT_DIR/private.key" \
            --fullchain-file "$CERT_DIR/fullchain.cer" \
            --reloadcmd     "systemctl restart nginx"
        return 0
    else
        log_err "证书申请失败！请检查域名解析。"
        return 1
    fi
}

setup_nginx() {
    local domain=$1
    log_info "配置 Nginx..."

    cat > /etc/nginx/conf.d/eljefe_fallback.conf <<EOF
server {
    listen 127.0.0.1:8080;
    server_name _;
    root $WEB_DIR;
    index index.html;
    access_log off;
}
EOF

    if [[ -n "$domain" ]]; then
        cat > /etc/nginx/conf.d/eljefe_tls.conf <<EOF
server {
    listen $PORT_TLS ssl http2;
    server_name $domain;

    ssl_certificate       $CERT_DIR/fullchain.cer;
    ssl_certificate_key   $CERT_DIR/private.key;
    ssl_protocols         TLSv1.2 TLSv1.3;
    ssl_ciphers           HIGH:!aNULL:!MD5;

    root $WEB_DIR;
    index index.html;

    location /eljefe {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$PORT_WS_LOCAL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    else
        rm -f /etc/nginx/conf.d/eljefe_tls.conf
    fi
    systemctl restart nginx
}

install_xray() {
    log_info "安装 Xray..."
    XRAY_REPO="XTLS/Xray-core"
    LATEST_VER=$(curl -s https://api.github.com/repos/$XRAY_REPO/releases/latest | jq -r .tag_name)
    
    wget -O "$ROOT_DIR/xray.zip" "https://github.com/$XRAY_REPO/releases/download/$LATEST_VER/Xray-linux-64.zip"
    unzip -q -o "$ROOT_DIR/xray.zip" -d "$ROOT_DIR" && rm "$ROOT_DIR/xray.zip"
    chmod +x "$XRAY_BIN"
}

generate_config() {
    local domain=$1
    local sni=$2
    [[ -z "$sni" ]] && sni="$DEST_SNI"
    
    log_info "生成 Xray 配置 (SNI: $sni)..."
    
    UUID=$(uuidgen | tr -d '\n')
    KEYS=$($XRAY_BIN x25519)
    PRI_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $3}' | tr -d '\n')
    PUB_KEY=$(echo "$KEYS" | grep "Public" | awk '{print $3}' | tr -d '\n')
    SID=$(openssl rand -hex 4 | tr -d '\n')

    cat > "$CONFIG_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "reality_in",
      "port": $PORT_REALITY,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$sni:443",
          "xver": 0,
          "serverNames": ["$sni"],
          "privateKey": "$PRI_KEY",
          "shortIds": ["$SID"],
          "fingerprint": "chrome"
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    },
    {
      "tag": "vmess_in",
      "listen": "127.0.0.1",
      "port": $PORT_WS_LOCAL,
      "protocol": "vmess", 
      "settings": {
        "clients": [{ "id": "$UUID", "alterId": 0 }]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/eljefe" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF
    echo "UUID=$UUID" > "$ROOT_DIR/info.txt"
    echo "PUB_KEY=$PUB_KEY" >> "$ROOT_DIR/info.txt"
    echo "SID=$SID" >> "$ROOT_DIR/info.txt"
    echo "DOMAIN=$domain" >> "$ROOT_DIR/info.txt"
    echo "SNI=$sni" >> "$ROOT_DIR/info.txt"
}

setup_service() {
    cat > /etc/systemd/system/eljefe-v2.service <<EOF
[Unit]
Description=ElJefe-V2
After=network.target

[Service]
User=root
ExecStart=$XRAY_BIN run -config $CONFIG_FILE
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable eljefe-v2
    systemctl restart eljefe-v2
}

show_info() {
    [ ! -f "$ROOT_DIR/info.txt" ] && log_err "未找到配置" && return
    source "$ROOT_DIR/info.txt"
    IP=$(curl -s4 https://api.ipify.org | tr -d '\n')
    UUID=$(echo $UUID | tr -d '\n')
    PUB_KEY=$(echo $PUB_KEY | tr -d '\n')
    SID=$(echo $SID | tr -d '\n')
    DOMAIN=$(echo $DOMAIN | tr -d '\n')
    SNI=$(echo $SNI | tr -d '\n')
    [[ -z "$SNI" ]] && SNI="$DEST_SNI"

    LINK_REALITY="vless://${UUID}@${IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUB_KEY}&sid=${SID}&type=tcp&headerType=none#ElJefe_Reality"
    
    if [[ -n "$DOMAIN" ]]; then
        VMESS_BASE="auto:${UUID}@${DOMAIN}:${PORT_TLS}"
        VMESS_BASE_B64=$(echo -n "$VMESS_BASE" | base64 -w 0)
        PARAMS="path=/eljefe&remarks=ElJefe_VMess_CDN&obfsParam=${DOMAIN}&obfs=websocket&tls=1&peer=${DOMAIN}&alterId=0"
        LINK_VMESS="vmess://${VMESS_BASE_B64}?${PARAMS}"
    fi

    echo ""
    echo -e "${BLUE}=== ElJefe-V2 信息面板 ===${PLAIN}"
    echo -e "${YELLOW}[主通道] Reality${PLAIN}"
    echo -e "${GREEN}$LINK_REALITY${PLAIN}"
    echo ""
    if [[ -n "$DOMAIN" ]]; then
        echo -e "${YELLOW}[备用通道] VMess-WS-TLS${PLAIN}"
        echo -e "${GREEN}$LINK_VMESS${PLAIN}"
    else
        echo -e "${RED}[备用通道] 未配置域名${PLAIN}"
    fi
    echo ""
}

change_sni() {
    read -p "请输入新的偷取目标 (例如 www.apple.com): " new_sni
    [[ -z "$new_sni" ]] && return
    source "$ROOT_DIR/info.txt"
    generate_config "$DOMAIN" "$new_sni"
    systemctl restart eljefe-v2
    show_info
}

# --- 新增功能: 添加/修改域名 ---
add_domain() {
    log_warn "此操作将重新申请证书并覆盖当前配置。"
    read -p "请输入你的域名 (例如 v2.example.com): " new_domain
    [[ -z "$new_domain" ]] && return
    
    source "$ROOT_DIR/info.txt" # 读取旧 SNI 配置
    
    setup_cert "$new_domain"
    if [ $? -eq 0 ]; then
        setup_nginx "$new_domain"
        generate_config "$new_domain" "$SNI"
        systemctl restart eljefe-v2
        log_info "域名添加成功！"
        show_info
    else
        log_err "证书申请失败，保留原有配置。"
    fi
}

update_core() {
    log_info "正在更新 Xray 内核..."
    install_xray
    systemctl restart eljefe-v2
    log_info "更新完成！"
}

uninstall_all() {
    read -p "确定要卸载吗？(y/n): " confirm
    [[ "$confirm" != "y" ]] && return
    systemctl stop eljefe-v2
    systemctl disable eljefe-v2
    rm /etc/systemd/system/eljefe-v2.service
    rm -f /etc/nginx/conf.d/eljefe_*.conf
    rm -rf "$ROOT_DIR"
    systemctl restart nginx
    systemctl daemon-reload
    log_info "卸载完成！"
}

menu() {
    clear
    echo -e "  ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v9.0 Final]${PLAIN}"
    echo -e "----------------------------------"
    echo -e "  ${GREEN}1.${PLAIN} 全新安装 (Install)"
    echo -e "  ${GREEN}2.${PLAIN} 查看链接 (Show Info)"
    echo -e "  ${GREEN}3.${PLAIN} 添加/修改域名 (Add Domain)"
    echo -e "  ${GREEN}4.${PLAIN} 修改伪装 SNI (Change SNI)"
    echo -e "  ${GREEN}5.${PLAIN} 更新内核 (Update Core)"
    echo -e "  ${GREEN}6.${PLAIN} 重启服务 (Restart)"
    echo -e "  ${GREEN}7.${PLAIN} 卸载脚本 (Uninstall)"
    echo -e "  ${GREEN}0.${PLAIN} 退出 (Exit)"
    echo -e "----------------------------------"
    read -p "请输入选项: " num

    case "$num" in
        1)
            check_root
            install_dependencies
            install_xray
            setup_fake_site
            echo ""
            echo -e "${YELLOW}是否配置域名 (VMess-WS-TLS)？${PLAIN}"
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
                    log_warn "证书失败，回退到单协议"
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
        3) add_domain ;;
        4) change_sni ;;
        5) update_core ;;
        6) systemctl restart eljefe-v2 && log_info "服务已重启" ;;
        7) uninstall_all ;;
        0) exit 0 ;;
        *) log_err "无效选项" ;;
    esac
}

if [[ $# > 0 ]]; then
    case $1 in
        "install") menu ;;
        "info") show_info ;;
        *) menu ;;
    esac
else
    menu
fi
