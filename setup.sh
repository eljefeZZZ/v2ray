#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager (Pro)
# Version: v15.7 (Add: DNS Check / Cert Renew / Clean / Status)
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
