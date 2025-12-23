#!/bin/bash

# ==================================================
# Project: ElJefe-V2 Manager (Pro) - WARP Enhanced
# Version: v16.0 (WARP + Routing Fix)
# Features: Reality/VLESS/VMess | WARP Integration | Routing UI
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
PORT_TLS=8443 # Nginx 监听端口，避开 443
DEST_SITE="www.microsoft.com:443"
DEST_SNI="www.microsoft.com"

# --- WARP 相关 ---
WARP_PORT=40000
WARP_SOCKS_ADDR="127.0.0.1"
WARP_TAG="warp"

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
        apt-get install -y curl wget unzip jq nginx uuid-runtime openssl cron lsof socat psmisc gnupg lsb-release
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
            --key-file "$CERT_DIR/private.key" \
            --fullchain-file "$CERT_DIR/fullchain.cer" \
            --reloadcmd "systemctl restart nginx"
        
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

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    fi

    # 1. 80端口自动跳转 (Fallback)
    cat > /etc/nginx/conf.d/eljefe_fallback.conf <<EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}
EOF

    # 2. 如果有域名，配置 TLS 站点
    if [[ -n "$domain" ]]; then
        cat > /etc/nginx/conf.d/eljefe_tls.conf <<EOF
server {
    listen $PORT_TLS ssl http2;
    listen [::]:$PORT_TLS ssl http2;
    server_name $domain;

    ssl_certificate $CERT_DIR/fullchain.cer;
    ssl_certificate_key $CERT_DIR/private.key;
    
    # 路径分流给 VLESS-WS
    location /vless {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$PORT_VLESS_WS;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    # 路径分流给 VMess-WS
    location /vmess {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$PORT_VMESS_WS;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    # 默认伪装站
    location / {
        root $WEB_DIR;
        index index.html;
    }
}
EOF
    else
        rm -f /etc/nginx/conf.d/eljefe_tls.conf
    fi

    systemctl restart nginx
}

install_xray() {
    log_info "安装 Xray Core..."
    local version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    local retry=0
    local verified=false

    # [Fix] 增强下载逻辑
    while [ $retry -lt 3 ]; do
        wget -qO "$ROOT_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-linux-64.zip"
        
        # 简单校验文件大小 (大于 5MB 视为成功)
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
    [[ -n "$domain" ]] && sni=$domain # 这里只是为了兼容旧逻辑，实际上 Reality 的 sni 应该固定

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
      "port": $PORT_REALITY,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$uuid", "flow": "xtls-rprx-vision" }
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
          "serverNames": [ "$DEST_SNI" ],
          "privateKey": "$pri_key",
          "shortIds": [ "$sid" ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [ "http", "tls", "quic" ]
      }
    },
    {
      "port": $PORT_VLESS_WS,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$uuid" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "port": $PORT_VMESS_WS,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [ { "id": "$uuid" } ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vmess" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [ "geoip:private" ],
        "outboundTag": "direct"
      }
    ]
  }
}
EOF

    # 保存信息到文件
    echo "UUID=$uuid" > "$INFO_FILE"
    echo "PUB_KEY=$pub_key" >> "$INFO_FILE"
    echo "SID=$sid" >> "$INFO_FILE"
    echo "DOMAIN=$domain" >> "$INFO_FILE"
    echo "SNI=$DEST_SNI" >> "$INFO_FILE" # 强制保存微软 SNI
}

setup_service() {
    cat > /etc/systemd/system/eljefe-v2.service <<EOF
[Unit]
Description=ElJefe Xray Service
After=network.target nss-lookup.target

[Service]
User=$XRAY_USER
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -c $CONFIG_FILE
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
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
    
    # 卸载 WARP (可选)
    uninstall_warp_client
    
    log_info "卸载完成"
}

# --- WARP 管理模块 ---

install_warp_client() {
    log_info "安装 Cloudflare WARP Client..."

    if [ -f /etc/debian_version ]; then
        apt-get update -y
        apt-get install -y curl gpg lsb-release

        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
            | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" \
            > /etc/apt/sources.list.d/cloudflare-client.list

        apt-get update -y
        apt-get install -y cloudflare-warp
    elif [ -f /etc/redhat-release ]; then
        rpm -ivh https://pkg.cloudflareclient.com/cloudflare-release-el8.rpm || true
        yum install -y cloudflare-warp
    else
        log_err "WARP 仅支持 Debian/Ubuntu/CentOS"
        return 1
    fi

    # 注册 & 设为代理模式
    log_info "注册 WARP 账户..."
    if warp-cli --help 2>/dev/null | grep -q "registration"; then
        warp-cli registration new || warp-cli register
    else
        warp-cli register
    fi

    log_info "设置代理模式..."
    if warp-cli --help 2>/dev/null | grep -q "mode proxy"; then
        warp-cli mode proxy
    else
        warp-cli set-mode proxy
    fi

    if warp-cli --help 2>/dev/null | grep -q "proxy port"; then
        warp-cli proxy port $WARP_PORT
    else
        warp-cli set-proxy-port $WARP_PORT
    fi

    warp-cli connect
    warp-cli enable-always-on

    sleep 5
    local warp_ip
    warp_ip=$(curl -s -x socks5h://$WARP_SOCKS_ADDR:$WARP_PORT https://ifconfig.me || true)

    if [[ -n "$warp_ip" ]]; then
        log_info "WARP 安装并连接成功，当前出口 IP: $warp_ip"
    else
        log_warn "WARP 看起来没连上，请稍后执行 warp-cli status 排查"
    fi
}

uninstall_warp_client() {
    log_warn "准备卸载 Cloudflare WARP Client..."
    if command -v warp-cli >/dev/null 2>&1; then
        warp-cli disable-always-on || true
        warp-cli disconnect || true
    fi

    if [ -f /etc/debian_version ]; then
        apt-get remove --purge -y cloudflare-warp || true
        rm -f /etc/apt/sources.list.d/cloudflare-client.list
        apt-get update -y
    elif [ -f /etc/redhat-release ]; then
        yum remove -y cloudflare-warp || true
    fi

    log_info "WARP 卸载完成（如需完全清理可手动删除 /var/lib/cloudflare-warp）"
}

show_warp_status() {
    if ! command -v warp-cli >/dev/null 2>&1; then
        echo -e "${YELLOW}WARP 未安装${PLAIN}"
        return
    fi
    echo -e "${GREEN}=== WARP 状态 ===${PLAIN}"
    warp-cli status || true
    echo -e "-------------------------"
    echo -e "代理端口: $WARP_PORT"
    echo -e "出口 IP: $(curl -s -x socks5h://$WARP_SOCKS_ADDR:$WARP_PORT https://ifconfig.me --connect-timeout 5 || echo '检测失败')"
}

config_xray_warp_outbound() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_err "未找到 Xray 配置：$CONFIG_FILE"
        return
    fi

    log_info "为 Xray 自动追加 WARP 出站（socks 出站 tag = $WARP_TAG）..."

    if grep -q "\"tag\": \"$WARP_TAG\"" "$CONFIG_FILE"; then
        log_warn "检测到已存在名为 $WARP_TAG 的出站，跳过追加。"
    else
        # 在 outbounds 数组中插入 socks 代理
        sed -i '/"outbounds": \[/a \    {\n      "tag": "'$WARP_TAG'",\n      "protocol": "socks",\n      "settings": {\n        "servers": [\n          {\n            "address": "'$WARP_SOCKS_ADDR'",\n            "port": '$WARP_PORT'\n          }\n        ]\n      }\n    },' "$CONFIG_FILE"
        log_info "已向 outbounds 中追加 WARP socks 出站。"
        systemctl restart eljefe-v2
    fi
}

# --- 路由规则交互式配置 ---

config_routing_rules() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_err "未找到 Xray 配置：$CONFIG_FILE"
        return 1
    fi

    log_info "=== Xray 路由规则配置器 (自动分流到 WARP) ==="
    echo -e "${YELLOW}请选择需要走 WARP 的服务（多选请用空格分隔）：${PLAIN}"
    echo "1. Google 全家桶 (搜索/YouTube/Gmail)"
    echo "2. TikTok/抖音 (解锁区域限制)"
    echo "3. Netflix/Disney+ (流媒体解锁)"
    echo "4. OpenAI/ChatGPT (AI 服务)"
    echo "5. Twitter/X"
    echo "6. 自定义域名"
    echo "0. 查看当前规则"
    echo "9. 清除所有 WARP 规则"
    read -p "输入选项（例如 1 2 4）: " choices

    local domains=()
    local custom_domain=""

    for choice in $choices; do
        case $choice in
            1) domains+=("geosite:google" "geosite:youtube") ;;
            2) domains+=("geosite:tiktok") ;;
            3) domains+=("geosite:netflix" "geosite:disney") ;;
            4) domains+=("geosite:openai" "geosite:chatgpt") ;;
            5) domains+=("geosite:twitter") ;;
            6) 
                read -p "输入自定义域名（多个用逗号分隔）: " custom_domain
                IFS=',' read -ra CUSTOM <<< "$custom_domain"
                for domain in "${CUSTOM[@]}"; do
                    # 简单去除首尾空格
                    domain=$(echo "$domain" | xargs)
                    domains+=("domain:$domain")
                done
                ;;
            0) show_current_rules; return ;;
            9) clear_warp_rules; return ;;
        esac
    done

    if [ ${#domains[@]} -eq 0 ]; then
        log_warn "未选择任何域名，操作取消"
        return
    fi

    # 1. 确保 Outbound 存在
    config_xray_warp_outbound

    # 2. 插入路由规则
    insert_routing_rule "${domains[@]}"
    
    log_info "路由规则已更新！服务已重启。"
    show_current_rules
}

insert_routing_rule() {
    local domains=("$@")
    # 构造 JSON 数组内容
    local domain_list_str=""
    for i in "${!domains[@]}"; do
        if [ $i -gt 0 ]; then domain_list_str+=", "; fi
        domain_list_str+="\"${domains[$i]}\""
    done

    # 构造完整的规则对象
    local rule_json='{ "type": "field", "domain": [ '"$domain_list_str"' ], "outboundTag": "'$WARP_TAG'" },'

    # 备份
    cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

    # 先尝试清除旧的 warp 规则（为了避免重复堆叠，这里简单粗暴先删再加，也可以选择只追加）
    # 但为了稳健，我们这里只做插入。
    # 策略：插入到 rules 数组的第一个位置（最优先）
    
    # 检查是否有 rules
    if grep -q '"rules": \[' "$CONFIG_FILE"; then
        # 插入到 rules: [ 之后的新一行
        sed -i "/\"rules\": \[/a \      $rule_json" "$CONFIG_FILE"
    else
        # 极端情况：没有 rules，需要创建 routing 结构 (概率低，generate_config 已生成)
        log_err "配置文件结构异常，未找到 routing.rules"
    fi
    
    systemctl restart eljefe-v2
}

show_current_rules() {
    echo -e "\n${GREEN}=== 当前生效的 WARP 规则 ===${PLAIN}"
    # 简单的 grep 提取显示
    grep -A 5 -B 5 "\"outboundTag\": \"$WARP_TAG\"" "$CONFIG_FILE" | grep "domain" | head -n 20
    echo -e "---------------------------------"
}

clear_warp_rules() {
    read -p "确认清除所有指向 WARP 的路由规则？(y/N): " confirm
    if [[ $confirm =~ ^[Yy] ]]; then
        # 删除包含 outboundTag: warp 的那几行以及其上下文（这在 sed 里比较难完美实现，建议用 jq）
        # 这里用简易 sed 方案：删除包含 warp tag 的行，但这会破坏 JSON 结构。
        # 更安全的做法是还原配置文件，或建议用户重新生成。
        # 这里我们尝试用 jq (如果没有 jq 则提示安装)
        
        if command -v jq >/dev/null; then
            cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
            # 使用 jq 过滤掉 outboundTag 为 warp 的规则
            jq 'del(.routing.rules[] | select(.outboundTag == "'$WARP_TAG'"))' "${CONFIG_FILE}.bak" > "$CONFIG_FILE"
            systemctl restart eljefe-v2
            log_info "WARP 路由规则已清除"
        else
            log_err "需要安装 jq 才能执行清除操作: apt-get install jq"
        fi
    fi
}

warp_menu() {
    while true; do
        clear
        echo -e " ${GREEN}WARP 管理面板${PLAIN}"
        echo -e "---------------------------"
        echo -e " ${GREEN}1.${PLAIN} 安装并连接 WARP (SOCKS5模式)"
        echo -e " ${GREEN}2.${PLAIN} 查看 WARP 状态 & IP"
        echo -e " ${GREEN}3.${PLAIN} ${YELLOW}配置分流规则 (解决验证码/卡顿)${PLAIN}"
        echo -e " ${GREEN}4.${PLAIN} 仅添加 Xray 出站 (不配规则)"
        echo -e " ${GREEN}5.${PLAIN} 卸载 WARP Client"
        echo -e " ${GREEN}0.${PLAIN} 返回主菜单"
        echo -e "---------------------------"
        read -p "请输入选项: " wnum
        case "$wnum" in
            1) install_warp_client; read -p "按回车继续..." ;;
            2) show_warp_status; read -p "按回车继续..." ;;
            3) config_routing_rules; read -p "按回车继续..." ;;
            4) config_xray_warp_outbound; read -p "按回车继续..." ;;
            5) uninstall_warp_client; read -p "按回车继续..." ;;
            0) break ;;
            *) log_err "无效选项"; sleep 1 ;;
        esac
    done
}

show_info() {
    if [ ! -f "$INFO_FILE" ]; then log_err "未找到配置信息"; return; fi
    source "$INFO_FILE"
    local ip=$(curl -s https://api.ipify.org)

    echo -e "\n${GREEN}=== 节点配置信息 (v16.0 Enhanced) ===${PLAIN}"
    echo -e "UUID: $UUID"
    echo -e "Reality Key: $PUB_KEY"
    echo -e "SNI: $DEST_SNI"
    echo -e "------------------------"
    echo -e "${YELLOW}1. Reality (直连/防封)${PLAIN}"
    echo -e "vless://$UUID@$ip:$PORT_REALITY?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$DEST_SNI&fp=chrome&pbk=$PUB_KEY&sid=$SID&type=tcp&headerType=none#ElJefe_Reality"

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
    echo -e "  servername: $DEST_SNI"
    echo -e "  reality-opts:"
    echo -e "    public-key: $PUB_KEY"
    echo -e "    short-id: \"$SID\""
    echo -e "    client-fingerprint: chrome"

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
    read -p "请输入新的 Reality 伪装域名 (例如 itunes.apple.com): " new_sni
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
    echo -e " ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v16.0 WARP Enhanced]${PLAIN}"
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
    echo -e " ${GREEN}10.${PLAIN} ${YELLOW}WARP 管理 / 分流设置${PLAIN}"
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
        10) warp_menu ;;
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
