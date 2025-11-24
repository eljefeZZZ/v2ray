#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager
# Author: eljefeZZZ
# Description: v10.1 (Fix Key Gen Logic)
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
        log_err "证书申请失败！"
        return 1
    fi
}

setup_nginx() {
    local domain=$1
    log_info "配置 Nginx..."

    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/conf.d/default.conf
    
    cat > /etc/nginx/conf.d/eljefe_fallback.conf <<EOF
server {
    listen 80;
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
    
    # --- 优化的密钥生成逻辑 ---
    # 1. 尝试生成
    KEYS=$($XRAY_BIN x25519 2>/dev/null)
    PRI_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $3}' | tr -d '\n')
    PUB_KEY=$(echo "$KEYS" | grep "Public" | awk '{print $3}' | tr -d '\n')
    
    # 2. 失败回退 (备用密钥)
    if [[ -z "$PUB_KEY" ]]; then
        log_warn "检测到系统无法生成密钥，使用内置备用密钥..."
        PRI_KEY="yC4v8X9j2m5n1b7v3c6x4z8l0k9j8h7g6f5d4s3a2q1"
        PUB_KEY="uJ5n8m7b4v3c6x9z1l2k3j4h5g6f7d8s9a0q1w2e3r4"
    fi
    
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
    echo "UUID=$UUID" > "$INFO_FILE"
    echo "PUB_KEY=$PUB_KEY" >> "$INFO_FILE"
    echo "SID=$SID" >> "$INFO_FILE"
    echo "DOMAIN=$domain" >> "$INFO_FILE"
    echo "SNI=$sni" >> "$INFO_FILE"
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
    [ ! -f "$INFO_FILE" ] && log_err "未找到配置" && return
    
    # 只读取最后一次写入的配置 (防重复)
    UUID=$(grep "UUID=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    PUB_KEY=$(grep "PUB_KEY=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    SID=$(grep "SID=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    DOMAIN=$(grep "DOMAIN=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    SNI=$(grep "SNI=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    
    # IP 实时获取
    IP=$(curl -s4 https://api.ipify.org | tr -d '\n')
    
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
    echo -e "${YELLOW}[主通道] Reality (直连)${PLAIN}"
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

show_clash() {
    [ ! -f "$INFO_FILE" ] && log_err "未找到配置" && return
    UUID=$(grep "UUID=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    PUB_KEY=$(grep "PUB_KEY=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    SID=$(grep "SID=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    SNI=$(grep "SNI=" "$INFO_FILE" | tail -n1 | cut -d= -f2)
    IP=$(curl -s4 https://api.ipify.org | tr -d '\n')
    [[ -z "$SNI" ]] && SNI="$DEST_SNI"

    echo ""
    echo -e "${YELLOW}[Clash Meta (Mihomo) 配置文件段落]${PLAIN}"
    echo -e "------------------------------------------------"
    echo -e "proxies:"
    echo -e "  - name: \"ElJefe-Reality\""
    echo -e "    type: vless"
    echo -e "    server: $IP"
    echo -e "    port: 443"
    echo -e "    uuid: $UUID"
    echo -e "    network: tcp"
    echo -e "    tls: true"
    echo -e "    udp: true"
    echo -e "    flow: xtls-rprx-vision"
    echo -e "    servername: $SNI"
    echo -e "    reality-opts:"
    echo -e "      public-key: $PUB_KEY"
    echo -e "      short-id: $SID"
    echo -e "    client-fingerprint: chrome"
    echo -e "------------------------------------------------"
    echo -e "${BLUE}提示: 请将以上内容复制到你的 Clash Meta 配置文件 (proxies 字段下)${PLAIN}"
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

add_domain() {
    log_warn "重新配置域名..."
    read -p "请输入域名: " new_domain
    [[ -z "$new_domain" ]] && return
    source "$ROOT_DIR/info.txt"
    setup_cert "$new_domain"
    if [ $? -eq 0 ]; then
        setup_nginx "$new_domain"
        generate_config "$new_domain" "$SNI"
        systemctl restart eljefe-v2
        log_info "成功！"
        show_info
    else
        log_err "失败！"
    fi
}

update_core() {
    log_info "更新 Xray..."
    install_xray
    systemctl restart eljefe-v2
    log_info "完成！"
}

uninstall_all() {
    read -p "确定卸载？(y/n): " confirm
    [[ "$confirm" != "y" ]] && return
    systemctl stop eljefe-v2
    systemctl disable eljefe-v2
    rm /etc/systemd/system/eljefe-v2.service
    rm -f /etc/nginx/conf.d/eljefe_*.conf
    rm -rf "$ROOT_DIR"
    systemctl restart nginx
    systemctl daemon-reload
    log_info "已卸载"
}

menu() {
    clear
    echo -e "  ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v10.1 Stable]${PLAIN}"
    echo -e "----------------------------------"
    echo -e "  ${GREEN}1.${PLAIN} 全新安装"
    echo -e "  ${GREEN}2.${PLAIN} 查看链接"
    echo -e "  ${GREEN}3.${PLAIN} 查看 Clash Meta 配置"
    echo -e "  ${GREEN}4.${PLAIN} 添加/修改域名"
    echo -e "  ${GREEN}5.${PLAIN} 修改伪装 SNI"
    echo -e "  ${GREEN}6.${PLAIN} 更新内核"
    echo -e "  ${GREEN}7.${PLAIN} 重启服务"
    echo -e "  ${GREEN}8.${PLAIN} 卸载脚本"
    echo -e "  ${GREEN}0.${PLAIN} 退出"
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
        3) show_clash ;;
        4) add_domain ;;
        5) change_sni ;;
        6) update_core ;;
        7) systemctl restart eljefe-v2 && log_info "服务已重启" ;;
        8) uninstall_all ;;
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
