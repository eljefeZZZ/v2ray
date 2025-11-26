# v2ray
v2ray一键部署脚本，你所看到的一切均由Gmini3 Pro编写

```
wget -O setup.sh https://github.com/eljefeZZZ/v2ray/raw/refs/heads/main/setup.sh && sed -i 's/\r$//' setup.sh && chmod +x setup.sh && ./setup.sh
```

# ElJefe-V2 Manager

<p align="center">
  <img src="https://img.shields.io/badge/Xray-Core-blue?style=for-the-badge&logo=protect" alt="Xray Core">
  <img src="https://img.shields.io/badge/Protocol-Reality%20%2B%20VLESS%20%2B%20VMess-success?style=for-the-badge" alt="Protocol">
  <img src="https://img.shields.io/badge/Security-High-red?style=for-the-badge&logo=security" alt="Security">
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge&logo=linux" alt="Platform">
</p>

<p align="center">
  <strong>🚀 一款现代、安全、模块化的 Xray + Nginx 自动化管理脚本</strong>
  <br>
  专为追求极致速度、隐蔽性与多平台兼容性的小白打造。
</p>

---

## ✨ 核心特性 (Features)

- **🔒 三重保险 (Triple Protocol)**
  - **主线路**: `VLESS-Reality` (TCP-Vision) -> 直连速度最快，低延迟，无域名无证书，完美伪装成 Microsoft/Apple。
  - **兼容线路**: `VLESS-WS-TLS` -> 完美支持 **OpenClash**、**Clash Meta** 等软路由插件，支持 CDN。
  - **备用线路**: `VMess-WS-TLS` -> 经典的 WebSocket + TLS 组合，兼容所有老旧客户端，防封底牌。

- **📦 智能配置 (Smart Config)**
  - **YAML 生成器**: 一键生成适配 **Clash / Nikki / OpenClash** 的标准配置文件，复制即用，从此告别手写配置错误。
  - **Nginx 自愈**: 即使误删 Nginx 配置，脚本也能自动检测并重建，确保 Web 服务和伪装站点永远在线。
  - **端口防冲突**: 智能检测并处理 443/80 端口占用，确保 Reality 协议独占核心通道。

- **🛠️ 自动化运维 (Auto Ops)**
  - **密钥适配**: 完美适配新版 Xray (v25+) 的密钥输出格式，自动匹配 UUID 和 Key。
  - **自动证书**: 内置 `acme.sh`，自动申请、续期 SSL 证书，无需人工干预。
  - **模块化架构**: 所有组件（Xray, Nginx, Cert）安装在 `/usr/local/eljefe-v2`，不污染系统环境，卸载无残留。

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
是否配置域名 (启用 VLESS & VMess CDN)？

是

否
```

- **如果你没有域名**：输入 `2` 并回车。
  - *脚本将只安装 Reality 主协议，通过 IP 直连，速度最快。*
- **如果你有域名**：
  1. 先去域名服务商（如 Namesilo/Cloudflare）添加一条 **A 记录**，指向你 VPS 的 IP。
  2. 输入 `1` 并回车。
  3. 输入你的域名（例如 `www.example.com`）。
  - *脚本会自动申请 SSL 证书并开启 VLESS-WS-TLS 和 VMess-WS-TLS 双备用通道。*

---

## 📱 客户端配置指南 (Usage Guide)

安装完成后，屏幕上会显示信息面板。

### 🍎 iOS (Shadowrocket / 小火箭)
1. **一键导入**：复制脚本输出的 `vless://` (Reality) 链接，打开小火箭自动识别。
2. **备用通道**：复制 `vmess://` 或 `vless://` (WS-TLS) 链接导入。

### 🤖 OpenClash / Nikki (软路由)
不要手写配置！不要手写配置！
1. 运行脚本：`./setup.sh`
2. 选择菜单 **`3. 查看 YAML 配置`**
3. 脚本会自动生成标准的 YAML 片段（包含正确的 UUID、Key、SNI）。
4. 直接复制片段到你的 `config.yaml` 或 Gist 中即可。

### 💻 Windows (v2rayN)
1. 复制链接，在 v2rayN 中按 `Ctrl+V` 导入。
2. **注意**：确保客户端核心（Xray-core）是最新版，否则可能不支持 Reality。

---

## 🛠️ 维护手册 (Maintenance)

以后任何时候，你只需输入以下命令即可唤出管理菜单：

```
./setup.sh
```

### 常用功能
- **查看 YAML 配置 (Show YAML)**
  - *操作*：选择菜单 `3`。获取最准确的、适配软路由的配置片段。

- **添加/修改域名 (Add Domain)**
  - *场景*：如果你第一次安装时选了“否”，后来买了个域名想加上。
  - *操作*：选择菜单 `4`，输入新域名。脚本会自动补全证书和备用通道。

- **修改伪装 SNI (Change SNI)**
  - *场景*：想更换 Reality 偷取的证书目标（默认 `www.microsoft.com`）。
  - *操作*：选择菜单 `5`，输入 `www.apple.com` 或 `www.amazon.com`。

- **救急模式 (Cloudflare CDN)**
  - *场景*：VPS IP 被墙。
  - *操作*：
    1. 在 Cloudflare 后台把域名的云朵点成 **橙色 (Proxied)**。
    2. 客户端切换到 **[备用通道] VLESS/VMess** 节点即可复活。

- **卸载 (Uninstall)**
  - *操作*：选择菜单 `8`。
  - *效果*：彻底删除所有文件和服务，干干净净。

---

## 📂 目录结构 (File Structure)

安装后的所有文件均位于 `/usr/local/eljefe-v2`：

/usr/local/eljefe-v2/

├── xray # Xray 核心二进制文件

├── config.json # 核心配置文件

├── cert/ # SSL 证书存放目录 (private.key, fullchain.cer)


├── acme.sh/ # acme.sh 证书申请工具

├── html/ # 伪装网站源码

└── info.txt # 用户配置信息备份 (UUID, Keys, Domain)


---

## ⚠️ 免责声明 (Disclaimer)

本项目仅供网络技术研究与学习交流使用，请勿用于任何非法用途。使用者在使用过程中产生的一切后果由使用者自行承担。

---
