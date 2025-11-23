#!/bin/bash

# ==================================================
# Project: elJefe-V2 Manager
# Author: eljefeZZZ
# Description: Secure, modular Xray+Nginx deployment
# ==================================================

# --- 配置参数 ---
XRAY_REPO="XTLS/Xray-core"
INSTALL_DIR="/usr/local/jefe-v2"
XRAY_BIN="$INSTALL_DIR/xray"
CONFIG_FILE="$INSTALL_DIR/config.json"
WEB_DIR="/var/www/html/camouflag"
# 伪装用的目标网站 (用于 Reality 偷取证书特征，建议选国外大厂)
DEST_SITE="www.microsoft.com:443"
DEST_SNI="www.microsoft.com"

# --- 颜色定义 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
PLAIN='\033[0m'

# --- 基础函数 ---
log_info() { echo -e "${GREEN}[INFO]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERROR]${PLAIN} $1"; }

check_root() {
    [[ $EUID -ne 0 ]] && log_err "必须使用 Root 权限运行此脚本" && exit 1
}

# --- 1. 环境准备 ---
install_dependencies() {
    log_info "正在更新系统并安装依赖..."
    if [ -f /etc/debian_version ]; then
        apt-get update -y && apt-get install -y curl wget unzip jq nginx uuid-runtime socat openssl
    elif [ -f /etc/redhat-release ]; then
        yum update -y && yum install -y curl wget unzip jq nginx uuid socat openssl
    else
        log_err "不支持的操作系统" && exit 1
    fi
}

# --- 2. 伪装站点部署 ---
setup_fake_site() {
    log_info "正在部署伪装站点..."
    mkdir -p "$WEB_DIR"
    
    # 下载一个简单的 HTML 模板作为伪装
    # 这里使用一个开源的简历模板，看起来很真实
    if [ ! -f "$WEB_DIR/index.html" ]; then
        wget -qO "$INSTALL_DIR/web.zip" "https://github.com/startbootstrap/startbootstrap-resume/archive/gh-pages.zip"
        unzip -q -o "$INSTALL_DIR/web.zip" -d "$INSTALL_DIR/temp_web"
        mv "$INSTALL_DIR/temp_web/startbootstrap-resume-gh-pages/"* "$WEB_DIR/"
        rm -rf "$INSTALL_DIR/web.zip" "$INSTALL_DIR/temp_web"
        
        # 修正权限
        chown -R www-data:www-data "$WEB_DIR" 2>/dev/null || chown -R nginx:nginx "$WEB_DIR"
    fi

    # 配置 Nginx (监听 8080，仅供回落使用，不对外开放)
    cat > /etc/nginx/conf.d/jefe_camouflage.conf <<EOF
server {
    listen 127.0.0.1:8080;
    server_name _;
    root $WEB_DIR;
    index index.html;
    access_log off;
}
EOF
    systemctl restart nginx
    log_info "伪装站点部署完成 (Local Port: 8080)"
}

# --- 3. 核心安装与更新 ---
install_xray() {
    log_info "正在获取最新 Xray 内核版本..."
    LATEST_VER=$(curl -s https://api.github.com/repos/$XRAY_REPO/releases/latest | jq -r .tag_name)
    if [[ -z "$LATEST_VER" || "$LATEST_VER" == "null" ]]; then
        log_err "无法获取 Xray 版本，请检查网络" && exit 1
    fi
    
    log_info "检测到最新版本: $LATEST_VER，开始下载..."
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) DOWNLOAD_ARCH="64" ;;
        aarch64) DOWNLOAD_ARCH="arm64-v8a" ;;
        *) log_err "不支持的架构: $ARCH" && exit 1 ;;
    esac

    DOWNLOAD_URL="https://github.com/$XRAY_REPO/releases/download/$LATEST_VER/Xray-linux-${DOWNLOAD_ARCH}.zip"
    
    mkdir -p "$INSTALL_DIR"
    wget -O "$INSTALL_DIR/xray.zip" "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        log_err "下载失败" && exit 1
    fi

    unzip -q -o "$INSTALL_DIR/xray.zip" -d "$INSTALL_DIR"
    chmod +x "$XRAY_BIN"
    rm "$INSTALL_DIR/xray.zip"
    
    log_info "Xray 内核安装完成"
}

# --- 4. 生成配置 (核心逻辑) ---
generate_config() {
    log_info "正在生成配置文件..."
    
    # 生成必要的密钥
    UUID=$(uuidgen)
    # 使用 xray 自带命令生成密钥对
    KEYS=$($XRAY_BIN x25519)
    PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEYS" | grep "Public" | awk '{print $3}')
    SHORT_ID=$(openssl rand -hex 4)

    cat > "$CONFIG_FILE" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$DEST_SITE",
          "xver": 0,
          "serverNames": [
            "$DEST_SNI"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ],
          "fingerprint": "chrome"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF
    # 保存配置信息以便后续查看
    echo "UUID=$UUID" > "$INSTALL_DIR/user_info.txt"
    echo "PUBLIC_KEY=$PUBLIC_KEY" >> "$INSTALL_DIR/user_info.txt"
    echo "SHORT_ID=$SHORT_ID" >> "$INSTALL_DIR/user_info.txt"
    echo "SNI=$DEST_SNI" >> "$INSTALL_DIR/user_info.txt"
}

# --- 5. 系统服务配置 ---
setup_service() {
    cat > /etc/systemd/system/jefe-v2.service <<EOF
[Unit]
Description=Jefe-V2 Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -config $CONFIG_FILE
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable jefe-v2
    systemctl restart jefe-v2
}

# --- 6. 输出客户端连接信息 ---
show_info() {
    if [ ! -f "$INSTALL_DIR/user_info.txt" ]; then
        log_err "未找到配置文件，请先安装" && return
    fi
    
    source "$INSTALL_DIR/user_info.txt"
    IP=$(curl -s4 https://api.ipify.org)
    
    # 构造 VLESS 链接
    LINK="vless://$UUID@$IP:443?security=reality&encryption=none&pbk=$PUBLIC_KEY&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$SNI&sid=$SHORT_ID#Jefe_V2_Node"
    
    echo ""
    echo -e "${BLUE}========================================${PLAIN}"
    echo -e "${GREEN}       Jefe-V2 部署成功 / 信息面板${PLAIN}"
    echo -e "${BLUE}========================================${PLAIN}"
    echo -e "地址 (Address): ${PLAIN}$IP"
    echo -e "端口 (Port)   : ${PLAIN}443"
    echo -e "用户ID (UUID) : ${PLAIN}$UUID"
    echo -e "流控 (Flow)   : ${PLAIN}xtls-rprx-vision"
    echo -e "加密 (Sec)    : ${PLAIN}reality"
    echo -e "伪装域名 (SNI): ${PLAIN}$SNI"
    echo -e "公钥 (Public K):${PLAIN}$PUBLIC_KEY"
    echo -e "${BLUE}----------------------------------------${PLAIN}"
    echo -e "通用导入链接 (VLESS):"
    echo -e "${YELLOW}$LINK${PLAIN}"
    echo -e "${BLUE}========================================${PLAIN}"
    echo ""
}

# --- 菜单逻辑 ---
menu() {
    clear
    echo -e "  ${GREEN}elJefe-V2 自用管理脚本${PLAIN} ${YELLOW}[v1.0]${PLAIN}"
    echo -e "  -----------------------------------"
    echo -e "  ${GREEN}1.${PLAIN} 全新安装 (Install)"
    echo -e "  ${GREEN}2.${PLAIN} 更新内核 (Update Core)"
    echo -e "  ${GREEN}3.${PLAIN} 查看配置 (Show Info)"
    echo -e "  ${GREEN}4.${PLAIN} 重启服务 (Restart)"
    echo -e "  ${GREEN}5.${PLAIN} 卸载脚本 (Uninstall)"
    echo -e "  ${GREEN}0.${PLAIN} 退出脚本 (Exit)"
    echo -e ""
    read -p "  请输入选项 [0-5]: " num

    case "$num" in
        1)
            check_root
            install_dependencies
            install_xray
            setup_fake_site
            generate_config
            setup_service
            show_info
            ;;
        2)
            check_root
            install_xray
            systemctl restart jefe-v2
            log_info "内核更新完成"
            ;;
        3)
            show_info
            ;;
        4)
            systemctl restart jefe-v2
            log_info "服务已重启"
            ;;
        5)
            systemctl stop jefe-v2
            systemctl disable jefe-v2
            rm /etc/systemd/system/jefe-v2.service
            rm -rf "$INSTALL_DIR"
            systemctl daemon-reload
            log_info "卸载完成"
            ;;
        0)
            exit 0
            ;;
        *)
            log_err "请输入正确数字"
            ;;
    esac
}

# 入口
if [[ $# > 0 ]]; then
    # 支持命令行参数: ./setup.sh install
    case $1 in
        "install") menu 1 ;;
        "update") menu 2 ;;
        "info") menu 3 ;;
        *) menu ;;
    esac
else
    menu
fi
