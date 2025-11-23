#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager
# Author: eljefeZZZ
# Description: Full Featured (Old VMess Format Fix)
# ==================================================

# --- 核心参数 ---
XRAY_REPO="XTLS/Xray-core"
INSTALL_DIR="/usr/local/eljefe-v2"
XRAY_BIN="$INSTALL_DIR/xray"
CONFIG_FILE="$INSTALL_DIR/config.json"
WEB_DIR="/var/www/html/camouflag"
ACME_SH="$INSTALL_DIR/acme.sh/acme.sh"

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

# --- 依赖安装 ---
install_dependencies() {
    log_info "更新系统源并安装依赖..."
    if [ -f /etc/debian_version ]; then
        apt-get update -y
        apt-get install -y curl wget unzip jq nginx uuid-runtime openssl cron lsof socat
        if ! command -v socat &> /dev/null; then
            apt-get update --fix-missing && apt-get install -y socat
        fi
    elif [ -f /etc/redhat-release ]; then
        yum update -y && yum install -y curl wget unzip jq nginx uuid socat openssl cronie lsof
        if ! command -v socat &> /dev/null; then
            yum install -y epel-release && yum install -y socat
        fi
    else
        log_err "不支持的系统" && exit 1
    fi
    
    if ! command -v socat &> /dev/null; then
        log_err "socat 安装失败，脚本无法继续。" && exit 1
    fi
    systemctl stop nginx
}

setup_fake_site() {
    log_info "部署伪装站点..."
    mkdir -p "$WEB_DIR"
    if [ ! -f "$WEB_DIR/index.html" ]; then
        wget -qO web.zip "https://github.com/startbootstrap/startbootstrap-resume/archive/gh-pages.zip"
        unzip -q -o web.zip -d temp_web
        mv temp_web/startbootstrap-resume-gh-pages/* "$WEB_DIR/"
        rm -rf web.zip temp_web
        chown -R www-data:www-data "$WEB_DIR" 2>/dev/null || chown -R nginx:nginx "$WEB_DIR"
    fi
}

setup_cert() {
    local domain=$1
    log_info "正在为域名 $domain 申请证书..."
    mkdir -p "$INSTALL_DIR/acme.sh"
    curl https://get.acme.sh | sh -s email=admin@eljefe.com --home "$INSTALL_DIR/acme.sh"
    
    log_info "释放 80 端口..."
    systemctl stop nginx
    if lsof -i :80 > /dev/null; then
        kill -9 $(lsof -t -i:80)
    fi
    
    "$ACME_SH" --issue -d "$domain" --standalone --keylength ec-256 --force
    
    if [ $? -eq 0 ]; then
        log_info "证书申请成功！"
        mkdir -p "$INSTALL_DIR/cert"
        "$ACME_SH" --install-cert -d "$domain" --ecc \
            --key-file       "$INSTALL_DIR/cert/private.key" \
            --fullchain-file "$INSTALL_DIR/cert/fullchain.cer" \
            --reloadcmd     "systemctl restart nginx"
        return 0
    else
        log_err "证书申请失败！"
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

    ssl_certificate       $INSTALL_DIR/cert/fullchain.cer;
    ssl_certificate_key   $INSTALL_DIR/cert/private.key;
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
    fi
    systemctl restart nginx
}

install_xray() {
    log_info "安装 Xray..."
    LATEST_VER=$(curl -s https://api.github.com/repos/$XRAY_REPO/releases/latest | jq -r .tag_name)
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) DOWNLOAD_ARCH="64" ;;
        aarch64) DOWNLOAD_ARCH="arm64-v8a" ;;
        *) log_err "架构不支持" && exit 1 ;;
    esac
    
    mkdir -p "$INSTALL_DIR"
    wget -O xray.zip "https://github.com/$XRAY_REPO/releases/download/$LATEST_VER/Xray-linux-${DOWNLOAD_ARCH}.zip"
    unzip -q -o xray.zip -d "$INSTALL_DIR" && rm xray.zip
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
    echo "UUID=$UUID" > "$INSTALL_DIR/info.txt"
    echo "PUB_KEY=$PUB_KEY" >> "$INSTALL_DIR/info.txt"
    echo "SID=$SID" >> "$INSTALL_DIR/info.txt"
    echo "DOMAIN=$domain" >> "$INSTALL_DIR/info.txt"
    echo "SNI=$sni" >> "$INSTALL_DIR/info.txt"
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

# --- 链接生成模块 (兼容性终极修复) ---
show_info() {
    [ ! -f "$INSTALL_DIR/info.txt" ] && log_err "未找到配置" && return
    source "$INSTALL_DIR/info.txt"
    IP=$(curl -s4 https://api.ipify.org | tr -d '\n')
    UUID=$(echo $UUID | tr -d '\n')
    PUB_KEY=$(echo $PUB_KEY | tr -d '\n')
    SID=$(echo $SID | tr -d '\n')
    DOMAIN=$(echo $DOMAIN | tr -d '\n')
    SNI=$(echo $SNI | tr -d '\n')
    [[ -z "$SNI" ]] && SNI="$DEST_SNI"

    # 1. Reality Link (标准化)
    LINK_REALITY="vless://${UUID}@${IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUB_KEY}&sid=${SID}&type=tcp&headerType=none#ElJefe_Reality"
    
    # 2. VMess Link (仿旧版格式 - 参数拼接型)
    if [[ -n "$DOMAIN" ]]; then
        # 构造核心认证信息: auto:UUID@Host:Port
        VMESS_BASE="auto:${UUID}@${DOMAIN}:${PORT_TLS}"
        # Base64 编码核心部分
        VMESS_BASE_B64=$(echo -n "$VMESS_BASE" | base64 -w 0)
        
        # 拼接 URL 参数
        # 这里的 path, tls, peer, obfs 等参数完全模仿你提供的样本
        PARAMS="path=/eljefe&remarks=ElJefe_VMess_CDN&obfsParam=${DOMAIN}&obfs=websocket&tls=1&peer=${DOMAIN}&alterId=0"
        
        LINK_VMESS="vmess://${VMESS_BASE_B64}?${PARAMS}"
    fi

    echo ""
    echo -e "${BLUE}=== ElJefe-V2 信息面板 ===${PLAIN}"
    echo -e "${YELLOW}[主通道] Reality${PLAIN}"
    echo -e "${GREEN}$LINK_REALITY${PLAIN}"
    echo ""
    if [[ -n "$DOMAIN" ]]; then
        echo -e "${YELLOW}[备用通道] VMess-WS-TLS (兼容格式)${PLAIN}"
        echo -e "${GREEN}$LINK_VMESS${PLAIN}"
    else
        echo -e "${RED}[备用通道] 未配置域名${PLAIN}"
    fi
    echo ""
}

change_sni() {
    read -p "请输入新的偷取目标 (例如 www.apple.com): " new_sni
    [[ -z "$new_sni" ]] && return
    source "$INSTALL_DIR/info.txt"
    generate_config "$DOMAIN" "$new_sni"
    systemctl restart eljefe-v2
    show_info
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
    rm -rf "$INSTALL_DIR"
    rm -f /etc/nginx/conf.d/eljefe_*.conf
    systemctl restart nginx
    log_info "卸载完成！"
}

menu() {
    clear
    echo -e "  ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v5.0 Final]${PLAIN}"
    echo -e "----------------------------------"
    echo -e "  ${GREEN}1.${PLAIN} 全新安装 (Install)"
    echo -e "  ${GREEN}2.${PLAIN} 查看链接 (Show Info)"
    echo -e "  ${GREEN}3.${PLAIN} 更新内核 (Update Core)"
    echo -e "  ${GREEN}4.${PLAIN} 修改伪装 SNI (Change SNI)"
    echo -e "  ${GREEN}5.${PLAIN} 重启服务 (Restart)"
    echo -e "  ${GREEN}6.${PLAIN} 卸载脚本 (Uninstall)"
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
        3) update_core ;;
        4) change_sni ;;
        5) systemctl restart eljefe-v2 && log_info "服务已重启" ;;
        6) uninstall_all ;;
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
