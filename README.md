# v2ray
v2ray一键部署脚本，你所看到的一切均由Gmini3 Pro编写
```
wget -O setup.sh https://github.com/eljefeZZZ/v2ray/raw/refs/heads/main/setup.sh && sed -i 's/\r$//' setup.sh && chmod +x setup.sh && ./setup.sh
```
# ElJefe-V2 Manager

<p align="center">
  <img src="https://img.shields.io/badge/Xray-Core-blue?style=for-the-badge&logo=protect" alt="Xray Core">
  <img src="https://img.shields.io/badge/Protocol-VLESS%20%2B%20Reality-success?style=for-the-badge" alt="Protocol">
  <img src="https://img.shields.io/badge/Security-High-red?style=for-the-badge&logo=security" alt="Security">
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge&logo=linux" alt="Platform">
</p>

<p align="center">
  <strong>🚀 一款现代、安全、模块化的 Xray + Nginx 自动化管理脚本</strong>
  <br>
  专为追求极致速度与隐蔽性的小白打造。
</p>

---

## ✨ 核心特性 (Features)

- **🔒 极致隐蔽 (Stealth Mode)**
  - **主通道**: 采用最先进的 `VLESS-Reality` 协议，无域名、无证书，流量特征完美伪装成 Microsoft/Apple。
  - **智能伪装**: 自动部署真实的静态简历/博客网站，探测者访问你的 IP 只会看到一个普通的英文个人主页。

- **🛡️ 双重保险 (Dual Protocol)**
  - **主线路**: VLESS-Reality (TCP-Vision) -> 直连速度最快，低延迟。
  - **备用线路**: VMess-WS-TLS -> 专为 **CDN** 设计。当 IP 被墙时，可配合 Cloudflare 复活。

- **📦 模块化架构 (Modular Design)**
  - 所有的核心组件（Xray 内核、证书、配置文件）统一安装在 `/usr/local/eljefe-v2`，不污染系统目录。
  - 即使重装系统，也只需备份这一个文件夹即可保留所有配置。

- **🛠️ 自动化运维 (Auto Ops)**
  - **自动修复依赖**: 智能检测并解决 `socat`、`nginx` 等安装失败问题（兼容老旧 Debian 9 系统）。
  - **自动证书管理**: 内置 `acme.sh`，自动申请、续期 SSL 证书，无需人工干预。
  - **一键管理**: 提供全功能菜单，支持更新内核、修改伪装 SNI、查看分享链接等。

---

## 🚀 快速开始 (Quick Start)

### 1. 环境要求
- **OS**: Debian 10+ / Ubuntu 20.04+ (推荐全新系统)
- **Root**: 必须使用 root 用户执行

### 2. 一键安装
复制以下命令并粘贴到终端中执行：

```
wget -O setup.sh https://github.com/eljefeZZZ/v2ray/raw/refs/heads/main/setup.sh && sed -i 's/\r$//' setup.sh && chmod +x setup.sh && ./setup.sh install
```

### 3. 安装选项说明
脚本运行后会自动安装依赖、Xray 内核和 Nginx。最后会询问你：

```
[INFO] 部署伪装站点...
是否配置域名 (VMess-WS-TLS)？
1. 是
2. 否
```

- **如果你没有域名**：输入 `2` 并回车。
  - *脚本将只安装 Reality 主协议，通过 IP 直连，速度最快。*
- **如果你有域名**：
  1. 先去域名服务商（如 Namesilo/Cloudflare）添加一条 **A 记录**，指向你 VPS 的 IP。
  2. 输入 `1` 并回车。
  3. 输入你的域名（例如 `www.example.com`）。
  - *脚本会自动申请 SSL 证书并开启备用 VMess 通道。*

---

## 📱 客户端配置指南 (Usage Guide)

安装完成后，屏幕上会显示如下信息面板：

```
=== ElJefe-V2 信息面板 ===
[主通道] Reality
vless://uuid@ip:443?encryption=none&flow=xtls-rprx-vision...

[备用通道] VMess-WS-TLS
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzI...
```

### 🍎 iOS (Shadowrocket / 小火箭)
1. **复制链接**：在 SSH 终端里选中 `vless://...` 开头的整段链接并复制。
2. **自动识别**：打开 Shadowrocket，它通常会自动弹窗提示“检测到剪贴板内容”，点击“导入”即可。
3. **手动添加 (如果没弹窗)**：
   - 点击右上角 `+` 号。
   - 类型选择 `VLESS`。
   - **地址**: 填写你的 VPS IP。
   - **端口**: `443`。
   - **UUID**: 填写面板里的 UUID。
   - **传输方式**: `TCP`。
   - **Reality**: 开启。
   - **SNI**: `www.microsoft.com` (或你设置的其他伪装域名)。
   - **Fingerprint**: `chrome`。
   - **Public Key**: 填写面板里的 pbk。
   - **Short ID**: 填写面板里的 sid。

### 💻 Windows (v2rayN)
1. **导入链接**：复制 `vless://` 链接。
2. 打开 v2rayN，按 `Ctrl+V` 或点击“从剪贴板导入”。
3. **核心设置**：确保你的 v2rayN 客户端核心（Xray-core）是最新版，否则可能不支持 Reality。

---

## 🛠️ 维护手册 (Maintenance)

以后任何时候，你只需输入以下命令即可唤出管理菜单：

```
./setup.sh
```

### 常用功能
- **添加/修改域名 (Add Domain)**
  - *场景*：如果你第一次安装时选了“否”，后来买了个域名想加上。
  - *操作*：选择菜单 `3`，输入新域名。脚本会自动补全证书和备用通道，无需重装。

- **修改伪装 SNI (Change SNI)**
  - *场景*：你觉得 `microsoft.com` 用的太多了，想换成 `apple.com` 或 `amazon.com` 来偷取它们的证书特征。
  - *操作*：选择菜单 `4`，输入 `www.apple.com`。
  - *注意*：修改后，记得在客户端（小火箭）里同步修改 **SNI** 字段。

- **救急模式 (Cloudflare CDN)**
  - *场景*：你的 VPS IP 被墙了，Reality 主通道连不上了。
  - *操作*：
    1. 确保你已经配置了备用通道（域名）。
    2. 去 Cloudflare 后台，把那个域名的云朵点成 **橙色 (Proxied)**。
    3. 在小火箭里，切换到 **[备用通道] VMess** 节点即可复活。

- **卸载 (Uninstall)**
  - *操作*：选择菜单 `7`。
  - *效果*：脚本会彻底删除 `/usr/local/eljefe-v2` 文件夹和所有服务，干干净净，不留痕迹。

---

## 📂 目录结构 (File Structure)

安装后的所有文件均位于 `/usr/local/eljefe-v2`：

```
/usr/local/eljefe-v2/
├── xray             # Xray 核心二进制文件
├── config.json      # 核心配置文件
├── cert/            # SSL 证书存放目录 (private.key, fullchain.cer)
├── acme.sh/         # acme.sh 证书申请工具
├── html/            # 伪装网站源码 (自动下载的简历模板)
└── info.txt         # 用户配置信息备份 (UUID, Keys)
```

---

## ⚠️ 免责声明 (Disclaimer)

本项目仅供网络技术研究与学习交流使用，请勿用于任何非法用途。使用者在使用过程中产生的一切后果由使用者自行承担。

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/eljefeZZZ">eljefeZZZ</a>
</p>
```
