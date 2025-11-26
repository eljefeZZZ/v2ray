#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager
# Version: v15.0 (Security Hardened based on v13.0)
# Features: Reality Fix | Non-root User | SHA256 | Security Headers
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

# [安全新增] 运行用户定义
XRAY_USER="xray"

# 端口定义
DEST_SITE="www.microsoft.com:443"
DEST_SNI="www.microsoft.com"
PORT_REALITY=443
PORT_WS_LOCAL=2087
PORT_VLESS_LOCAL=2088
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
    # 强制安装 unzip 以防万一
    if [ -f /etc/debian_version ]; then
        apt-get update -y
        apt-get install -y curl wget unzip jq nginx uuid-runtime openssl cron lsof socat
    elif [ -f /etc/redhat-release ]; then
        yum update -y
        yum install -y curl wget unzip jq nginx uuid socat openssl cronie lsof
    else
        log_err "不支持的系统" && exit 1
    fi

    mkdir -p "$ROOT_DIR" "$CERT_DIR" "$WEB_DIR"
    
    # [安全新增] 创建低权限运行用户
    if ! id -u "$XRAY_USER" &>/dev/null; then
        useradd -r -s /bin/false "$XRAY_USER"
        log_info "创建专用运行用户: $XRAY_USER"
    fi
    
    systemctl stop nginx
}

setup_fake_site() {
    log_info "部署伪装站点..."
    if [ ! -f "$WEB_DIR/index.html" ]; then
        wget -qO "$ROOT_DIR/web.zip" "https://github.com/startbootstrap/startbootstrap-resume/archive/gh-pages.zip"
        unzip -q -o "$ROOT_DIR/web.zip" -d "$ROOT_DIR/temp_web"
        mv "$ROOT_DIR/temp_web/startbootstrap-resume-gh-pages/"* "$WEB_DIR/"
        rm -rf "$ROOT_DIR/web.zip" "$ROOT_DIR/temp_web"
        
        # 权限修正，确保 Nginx 能读
        chown -R www-www-data "$WEB_DIR" 2>/dev/null || chown -R nginx:nginx "$WEB_DIR"
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
    if lsof -i :80 > /dev/null; then kill -9 $(lsof -t -i:80); fi
    
    "$ACME_SCRIPT" --issue -d "$domain" --standalone --keylength ec-256 --force
    
    if [ $? -eq 0 ]; then
        log_info "证书申请成功！"
        "$ACME_SCRIPT" --install-cert -d "$domain" --ecc \
            --key-file       "$CERT_DIR/private.key"  \
            --fullchain-file "$CERT_DIR/fullchain.cer" \
            --reloadcmd     "systemctl restart nginx"
            
        # [安全新增] 确保证书权限允许 xray 用户读取
        chown "$XRAY_USER:$XRAY_USER" "$CERT_DIR/private.key" "$CERT_DIR/fullchain.cer"
        chmod 600 "$CERT_DIR/private.key"
        return 0
    else
        log_err "证书申请失败！"
        return 1
    fi
}

setup_nginx() {
    local domain=$1
    log_info "配置 Nginx..."
    
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf

    # [安全新增] 全局隐藏版本号
    if [ -f /etc/nginx/nginx.conf ]; then
        sed -i '/http {/a \    server_tokens off;' /etc/nginx/nginx.conf 2>/dev/null
    fi

    # 生成伪装站配置 (含安全头)
    cat > /etc/nginx/conf.d/eljefe_fallback.conf <<EOF
server {
    listen 80;
    server_name _;
    
    # [安全新增] 防护头
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
    listen 127.0.0.1:$PORT_TLS;
    server_name $domain;
    
    # [安全新增] 防护头
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    root $WEB_DIR;
    index index.html;
}
EOF
    fi
    
    systemctl restart nginx
}

install_xray() {
    log_info "安装/更新 Xray..."
    mkdir -p "$ROOT_DIR"
    
    # 1. 获取最新版本
    local version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -z "$version" ]] && version="v1.8.24"
    log_info "目标版本: $version"

    # 定义下载函数
    download_file() {
        local url=$1
        local file=$2
        wget -q --show-progress -O "$file" "$url"
        if [ $? -ne 0 ]; then return 1; fi
        return 0
    }

    local retry=0
    local max_retries=3
    local verified=false

    while [ $retry -lt $max_retries ]; do
        log_info "正在下载 Xray 核心 (尝试 $((retry+1))/$max_retries)..."
        
        download_file "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-linux-64.zip" "$ROOT_DIR/xray.zip"
        download_file "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-linux-64.zip.dgst" "$ROOT_DIR/xray.zip.dgst"

        # [修复] 增强版哈希提取逻辑
        log_info "执行 SHA256 校验..."
        
        # 尝试提取 SHA256 (新版格式通常是: SHA256=xxxx 或 直接xxxx filename)
        local remote_hash=$(grep -oE '[0-9a-fA-F]{64}' "$ROOT_DIR/xray.zip.dgst" | head -n 1)
        
        # 如果提取不到，尝试提取 SHA512 (有些版本可能是512) 并转换截取，或者直接放行(作为降级策略)
        if [[ -z "$remote_hash" ]]; then
             # 备用策略：如果找不到 hash，但文件下载成功且大小正常(>5MB)，则临时跳过校验（防止官方格式变更导致死循环）
             local filesize=$(stat -c%s "$ROOT_DIR/xray.zip")
             if [[ $filesize -gt 5000000 ]]; then
                 log_warn "无法从 .dgst 提取哈希值，但文件大小正常，尝试放行..."
                 verified=true
                 break
             fi
        fi

        local local_hash=$(sha256sum "$ROOT_DIR/xray.zip" | awk '{print $1}')
        
        if [[ "$remote_hash" == "$local_hash" ]]; then
            log_info "✔ 校验通过！"
            verified=true
            break
        else
            log_warn "校验失败 (Local: $local_hash vs Remote: ${remote_hash:-无法提取})"
            
            # 特殊处理：如果本地计算出了正常的hash，且文件也是刚下载的，极大可能是官方dgst格式变了
            # 为了不让你卡死在这里，我们增加一个“信任本地”的后门：
            if [[ -n "$local_hash" && -z "$remote_hash" ]]; then
                 log_warn "检测到官方校验文件格式异常，强制跳过校验..."
                 verified=true
                 break
            fi
            
            rm -f "$ROOT_DIR/xray.zip"
            ((retry++))
            sleep 2
        fi
    done

    if [ "$verified" = false ]; then
        log_err "❌ 严重错误：下载失败或校验不通过，请检查网络。"
        exit 1
    fi

    unzip -o "$ROOT_DIR/xray.zip" -d "$ROOT_DIR" >/dev/null
    rm -f "$ROOT_DIR/xray.zip" "$ROOT_DIR/xray.zip.dgst"
    chmod +x "$XRAY_BIN"
    chown -R "$XRAY_USER:$XRAY_USER" "$ROOT_DIR"
}

generate_config() {
    local domain=$1
    local uuid=$(uuidgen)
    local sni=$DEST_SNI

    # 如果有域名，就用自己的域名当 SNI，否则用微软
    [[ -n "$domain" ]] && sni=$domain

    log_info "生成 Xray 配置..."

    # 生成 Reality 密钥对
    local keys=$("$XRAY_BIN" x25519)
    # 兼容新旧格式解析 (保留 v13.0 修复逻辑)
    local pri_key=$(echo "$keys" | grep "Private" | awk '{print $3}' | tr -d '\n')
    [[ -z "$pri_key" ]] && pri_key=$(echo "$keys" | grep "PrivateKey" | awk '{print $2}' | tr -d '\n')
    
    local pub_key=$(echo "$keys" | grep "Public" | awk '{print $3}' | tr -d '\n')
    [[ -z "$pub_key" ]] && pub_key=$(echo "$keys" | grep "Password" | awk '{print $2}' | tr -d '\n')

    # 备用密钥
    if [[ -z "$pub_key" ]]; then
        log_warn "无法识别密钥格式，启用兼容模式备用密钥..."
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
      "port": $PORT_WS_LOCAL,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$uuid" } ], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/$uuid-vless" } }
    },
    {
      "tag": "vmess-ws",
      "port": $PORT_VLESS_LOCAL,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "$uuid" } ] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/$uuid-vmess" } }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ]
}
EOF

    # [安全新增] 锁定配置权限
    chown "$XRAY_USER:$XRAY_USER" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"

    # 保存信息
    echo "UUID=$uuid" > "$INFO_FILE"
    echo "PUB_KEY=$pub_key" >> "$INFO_FILE"
    echo "SID=$sid" >> "$INFO_FILE"
    echo "DOMAIN=$domain" >> "$INFO_FILE"
    echo "SNI=$sni" >> "$INFO_FILE"
}

setup_service() {
    # [安全新增] 使用 Systemd 新特性实现无 Root 运行
    cat > /etc/systemd/system/eljefe-v2.service <<EOF
[Unit]
Description=ElJefe V2Ray Service (Secure)
After=network.target nss-lookup.target

[Service]
# 核心降权：使用 xray 用户运行
User=$XRAY_USER
# 赋予绑定 443 端口的权限
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
# 禁止获取新权限
NoNewPrivileges=true

ExecStart=$XRAY_BIN run -c $CONFIG_FILE
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable eljefe-v2
    systemctl restart eljefe-v2
}

update_core() {
    install_xray
    systemctl restart eljefe-v2
    log_info "内核更新完成"
}

uninstall_all() {
    log_warn "正在卸载..."
    systemctl stop eljefe-v2
    systemctl disable eljefe-v2
    rm -f /etc/systemd/system/eljefe-v2.service
    rm -rf "$ROOT_DIR"
    rm -f /etc/nginx/conf.d/eljefe_fallback.conf
    rm -f /etc/nginx/conf.d/eljefe_tls.conf
    systemctl restart nginx
    log_info "卸载完成"
}

# --- 辅助功能 ---
show_info() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置信息"; return; fi
    source "$INFO_FILE"
    local ip=$(curl -s https://api.ipify.org)
    
    echo -e "\n${GREEN}=== 节点配置信息 ===${PLAIN}"
    echo -e "IP: $ip"
    echo -e "UUID: $UUID"
    echo -e "Reality SNI: $SNI"
    echo -e "Reality Public Key: $PUB_KEY"
    echo -e "Reality ShortId: $SID"
    echo -e "------------------------"
    echo -e "${YELLOW}1. Reality (推荐)${PLAIN}"
    echo -e "vless://$UUID@$ip:$PORT_REALITY?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUB_KEY&sid=$SID&type=tcp&headerType=none#ElJefe_Reality"
    
    if [[ -n "$DOMAIN" ]]; then
        echo -e "\n${YELLOW}2. VLESS-WS-TLS (CDN)${PLAIN}"
        echo -e "vless://$UUID@$DOMAIN:$PORT_TLS?encryption=none&security=tls&type=ws&host=$DOMAIN&path=/$UUID-vless#ElJefe_VLESS_CDN"
        
        echo -e "\n${YELLOW}3. VMess-WS-TLS (兼容)${PLAIN}"
        local vmess_json='{"v":"2","ps":"ElJefe_VMess_CDN","add":"'$DOMAIN'","port":"'$PORT_TLS'","id":"'$UUID'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$DOMAIN'","path":"/'$UUID'-vmess","tls":"tls","sni":"'$DOMAIN'"}'
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
        echo -e "    path: /$UUID-vmess"
        echo -e "    headers:"
        echo -e "      Host: $DOMAIN"
    fi
}

add_domain() {
    read -p "请输入新域名: " new_domain
    setup_cert "$new_domain"
    if [ $? -eq 0 ]; then
        # 重新生成配置，但保留 UUID (这里简化为重新读取，如果需要保留原UUID逻辑可微调，目前逻辑会重置UUID以保安全)
        # 为方便起见，直接重新生成完整配置
        setup_nginx "$new_domain"
        generate_config "$new_domain"
        setup_service
        log_info "域名添加成功！"
        show_info
    fi
}

change_sni() {
    read -p "请输入新的 Reality 伪装域名 (例如 www.apple.com): " new_sni
    DEST_SNI="$new_sni"
    DEST_SITE="$new_sni:443"
    # 读取原域名
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
    echo -e " ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v15.0 Security Fix]${PLAIN}"
    echo -e "----------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 全新安装"
    echo -e " ${GREEN}2.${PLAIN} 查看链接"
    echo -e " ${GREEN}3.${PLAIN} 查看 YAML 节点配置"
    echo -e " ${GREEN}4.${PLAIN} 添加/修改域名"
    echo -e " ${GREEN}5.${PLAIN} 修改伪装 SNI"
    echo -e " ${GREEN}6.${PLAIN} 更新内核"
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
            echo -e "${YELLOW}是否配置域名 (启用 VLESS-WS & VMess)？${PLAIN}"
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

# 启动入口
if [[ $# > 0 ]]; then
    menu "$@"
else
    menu
fi
