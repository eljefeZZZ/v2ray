#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager
# Author: eljefeZZZ
# Description: Reality (Main) + VMess-WS-TLS (Backup)
# ==================================================

# --- 核心参数 ---
XRAY_REPO="XTLS/Xray-core"
INSTALL_DIR="/usr/local/eljefe-v2"
XRAY_BIN="$INSTALL_DIR/xray"
CONFIG_FILE="$INSTALL_DIR/config.json"
WEB_DIR="/var/www/html/camouflag"
ACME_SH="$INSTALL_DIR/acme.sh/acme.sh"

# Reality 偷取目标
DEST_SITE="www.microsoft.com:443"
DEST_SNI="www.microsoft.com"

# 端口定义
PORT_REALITY=443      # 主通道 (Reality)
PORT_WS_LOCAL=2087    # 备用通道 (VMess) 本地监听
PORT_TLS=8443         # 备用通道 (TLS) 对外端口

# --- 颜色 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
PLAIN='\033[0m'

# --- 日志函数 ---
log_info() { echo -e "${GREEN}[INFO]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERROR]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }

check_root() {
    [[ $EUID -ne 0 ]] && log_err "必须使用 Root 权限运行" && exit 1
}

# --- 1. 依赖安装 ---
install_dependencies() {
    log_info "安装依赖..."
    if [ -f /etc/debian_version ]; then
        apt-get update -y && apt-get install -y curl wget unzip jq nginx uuid-runtime socat openssl cron
    elif [ -f /etc/redhat-release ]; then
        yum update -y && yum install -y curl wget unzip jq nginx uuid socat openssl cronie
    else
        log_err "不支持的系统" && exit 1
    fi
    systemctl enable nginx
}

# --- 2. 伪装站 ---
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

# --- 3. 证书申请 (仅当有域名时) ---
setup_cert() {
    local domain=$1
    log_info "正在为域名 $domain 申请证书..."
    mkdir -p "$INSTALL_DIR/acme.sh"
    curl https://get.acme.sh | sh -s email=admin@eljefe.com --home "$INSTALL_DIR/acme.sh"
    systemctl stop nginx
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
        log_err "证书申请失败，请检查域名解析"
        systemctl start nginx
        return 1
    fi
}

# --- 4. Nginx 配置 ---
setup_nginx() {
    local domain=$1
    log_info "配置 Nginx..."

    # 默认回落
    cat > /etc/nginx/conf.d/eljefe_fallback.conf <<EOF
server {
    listen 127.0.0.1:8080;
    server_name _;
    root $WEB_DIR;
    index index.html;
    access_log off;
}
EOF

    # VMess TLS 反代
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

# --- 5. Xray 安装 ---
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

# --- 6. 生成配置 (VMess 修改版) ---
generate_config() {
    local domain=$1
    log_info "生成 Xray 配置..."
    
    # 变量准备
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
          "dest": "$DEST_SITE",
          "xver": 0,
          "serverNames": ["$DEST_SNI"],
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
}

# --- 7. 服务 ---
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

# --- 8. 信息展示 (修复 VMess 链接) ---
show_info() {
    [ ! -f "$INSTALL_DIR/info.txt" ] && return
    source "$INSTALL_DIR/info.txt"
    # 清理所有换行符
    IP=$(curl -s4 https://api.ipify.org | tr -d '\n')
    UUID=$(echo $UUID | tr -d '\n')
    PUB_KEY=$(echo $PUB_KEY | tr -d '\n')
    SID=$(echo $SID | tr -d '\n')
    DOMAIN=$(echo $DOMAIN | tr -d '\n')

    # 1. Reality Link
    LINK_REALITY="vless://${UUID}@${IP}:443?security=reality&encryption=none&pbk=${PUB_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${DEST_SNI}&sid=${SID}#ElJefe_Reality"
    
    # 2. VMess Link
    if [[ -n "$DOMAIN" ]]; then
        # 严格的 JSON 格式，确保无多余空格
        VMESS_JSON='{"v":"2","ps":"ElJefe_VMess_CDN","add":"'"$DOMAIN"'","port":"'"$PORT_TLS"'","id":"'"$UUID"'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'"$DOMAIN"'","path":"/eljefe","tls":"tls","sni":"'"$DOMAIN"'"}'
        
        # 修复：Base64 编码强制为单行
        VMESS_B64=$(echo -n "$VMESS_JSON" | base64 -w 0)
        LINK_VMESS="vmess://$VMESS_B64"
    fi

    echo ""
    echo -e "${BLUE}=== ElJefe-V2 安装完成 ===${PLAIN}"
    echo -e "${YELLOW}[主通道] Reality (直连高速)${PLAIN}"
    echo -e "链接: ${GREEN}$LINK_REALITY${PLAIN}"
    echo ""
    if [[ -n "$DOMAIN" ]]; then
        echo -e "${YELLOW}[备用通道] VMess-WS-TLS (CDN兼容)${PLAIN}"
        echo -e "域名: $DOMAIN (端口 $PORT_TLS)"
        echo -e "链接: ${GREEN}$LINK_VMESS${PLAIN}"
    else
        echo -e "${RED}[提示] 未配置域名，备用通道不可用。${PLAIN}"
    fi
    echo ""
}

# --- 菜单 ---
main_install() {
    check_root
    install_dependencies
    install_xray
    setup_fake_site
    
    echo ""
    echo -e "${YELLOW}是否拥有域名并配置 VMess-WS-TLS？${PLAIN}"
    echo -e "1. 是 (我已解析域名)"
    echo -e "2. 否 (仅 Reality)"
    read -p "请选择: " choice
    
    if [[ "$choice" == "1" ]]; then
        read -p "请输入域名: " my_domain
        setup_cert "$my_domain"
        if [ $? -eq 0 ]; then
            setup_nginx "$my_domain"
            generate_config "$my_domain"
        else
            log_warn "证书失败，仅安装 Reality"
            setup_nginx ""
            generate_config ""
        fi
    else
        setup_nginx ""
        generate_config ""
    fi
    
    setup_service
    show_info
}

case $1 in
    "install") main_install ;;
    "info") show_info ;;
    *) 
        echo "1. Install"
        echo "2. Show Info"
        read -p "Select: " opt
        [[ "$opt" == "1" ]] && main_install
        [[ "$opt" == "2" ]] && show_info
        ;;
esac
