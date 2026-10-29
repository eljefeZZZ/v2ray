        echo '3. 开启 / 更新共享解锁（Xray + HY2）'
        echo '4. 关闭共享解锁（Xray + HY2）'
        echo '5. 查看配置和桥接状态'
        echo '6. 测试桥接出口公网 IP'
        echo '7. 导入 Xray 出站 JSON'
        echo '0. 返回'
        read -r -p '选择: ' choice
        case "$choice" in
          1) unlock_select ;;
          2) unlock_port_choose ;;
          3) unlock_apply enable ;;
          4) unlock_apply disable ;;
          5) unlock_load; echo "出口：${UNLOCK_OUTBOUND:-未设置}，桥接端口：${UNLOCK_PORT:-未设置}"; [[ -z "$UNLOCK_PORT" ]] || ss -lntp | grep ":$UNLOCK_PORT " || true ;;
          6) unlock_load; [[ -n "$UNLOCK_PORT" ]] && curl -4fsS --socks5-hostname "127.0.0.1:$UNLOCK_PORT" --max-time 15 https://api.ipify.org && echo || echo '桥接不可用或尚未开启，请检查配置' ;;
          7) unlock_import ;;
          0) break ;;
          *) echo '无效选项' ;;
        esac
        read -r -p '按回车继续...' _
    done
}
# Backward-compatible entry points in HY2 menu.
hy2_hk_bridge() { unlock_apply "$1"; }

hy2_menu() {
    while true; do
        echo ""
        echo "===== HY2 独立管理 =====" 
        echo "1. 安装并配置 HY2（自动证书优先 / DNS-01 备用）"
        echo "2. 查看 HY2 分享链接和 YAML"
        echo "3. 查看 HY2 状态"
        echo "4. 重启 HY2"
        echo "5. 停用 HY2（保留配置备份）"
        echo "6. 开启流媒体分流（复用共享 Xray 出口）"
        echo "7. 关闭 HY2 流媒体分流"
        echo "0. 返回主菜单"
        read -r -p '选择: ' choice
        case "$choice" in
          1) hy2_install ;;
          2) hy2_show_info; hy2_show_yaml ;;
          3) hy2_status ;;
          4) systemctl restart "$HY2_SERVICE" && systemctl is-active "$HY2_SERVICE" ;;
          5) hy2_remove ;;
          6) hy2_hk_bridge enable ;;
          7) hy2_hk_bridge disable ;;
          0) break ;;
          *) echo '无效选项' ;;
        esac
        read -r -p '按回车继续...' _
    done
}

# Preserve original routines exactly, extend their output only.
show_info() { show_info_original "$@"; [[ -f "$HY2_ENV" ]] && hy2_show_info; }
show_yaml() { show_yaml_original "$@"; [[ -f "$HY2_ENV" ]] && hy2_show_yaml; }
# ===== HY2 isolated extension END =====

menu() {
    while true; do
    clear
    # [完善6] 版本号更新为 v15.7，菜单新增选项 10「查看服务状态」
    echo -e " ${GREEN}ElJefe-V2 管理面板${PLAIN} ${YELLOW}[v16.2]${PLAIN}"
    echo -e "----------------------------------"
    echo -e " ${GREEN}01.${PLAIN} 全新安装"
    echo -e " ${GREEN}02.${PLAIN} 查看链接"
    echo -e " ${GREEN}03.${PLAIN} 查看 YAML 配置"
    echo -e " ${GREEN}04.${PLAIN} 添加/修改域名"
    echo -e " ${GREEN}05.${PLAIN} 修改伪装 SNI"
    echo -e " ${GREEN}06.${PLAIN} 更新内核 (Fix Key)"
    echo -e " ${GREEN}07.${PLAIN} 重启服务"
    echo -e " ${GREEN}08.${PLAIN} 卸载脚本"
    echo -e " ${GREEN}09.${PLAIN} 开启/关闭 BBR [当前: $(check_bbr_status)]"
    echo -e " ${GREEN}10.${PLAIN} 查看服务状态"
    echo -e " ${GREEN}11.${PLAIN} Hysteria 2 独立管理"
    echo -e " ${GREEN}12.${PLAIN} 通用流媒体解锁管理"
    echo -e " ${GREEN}00.${PLAIN} 退出"
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
        # [完善6] 新增选项 10，调用 show_status 函数
        10) show_status ;;
        11) hy2_menu ;;
        12) unlock_menu ;;
        0) exit 0 ;;
        *) log_err "无效选项" ;;
    esac

    # 操作结果显示后暂停，避免菜单立即清屏覆盖输出。
    read -r -p "按回车键返回菜单..." _
    done
}
