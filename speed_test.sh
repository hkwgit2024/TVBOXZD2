#!/bin/bash

# ==============================================================================
# 脚本配置
# ==============================================================================
# 定义输出目录
OUTPUT_DIR="data"

# 定义日志文件和成功节点文件的路径
LOG_FILE="$OUTPUT_DIR/node_connectivity_results.log"
OUTPUT_FILE="$OUTPUT_DIR/sub.txt" # 成功节点输出文件
MERGED_NODES_TEMP_FILE="all_merged_nodes_temp.txt" # 临时文件，用于合并所有来源

# DNS 缓存文件的路径
DNS_CACHE_FILE="$OUTPUT_DIR/dns_cache.json"
# DNS 缓存的有效期（秒），例如 24 小时 = 86400 秒
CACHE_EXPIRATION_SECONDS=$((24 * 60 * 60)) # 24 hours

# 定义同时进行的连接测试数量 (并发数)
MAX_CONCURRENT_TESTS=10 # 示例：20 个并发连接测试

# 定义单个节点连接测试的超时时间（秒）。
NODE_CONNECT_TIMEOUT=2 # 示例：2 秒超时

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

# ==============================================================================
# 全局变量（主进程和子进程共享，子进程只读 DNS_CACHE_FILE）
# ==============================================================================
# 主进程的 DNS 缓存（用于加载、清理和最终保存）
declare -A DNS_CACHE
# 定义一个集合来存储所有发现的域名，避免重复解析
declare -A ALL_DOMAINS_TO_RESOLVE

# ==============================================================================
# 函数定义
# ==============================================================================

# 函数：检查一个字符串是否为有效的 IPv4 或 IPv6 地址
is_ip_address() {
    local host="$1"
    # 简单的 IPv4 和 IPv6 检查
    # 考虑到 IPv6 地址可能被方括号包围，正则表达式需要处理
    if [[ "$host" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then # IPv4
        return 0
    elif [[ "$host" =~ ^\[?([0-9a-fA-F:]+)\]?$ ]]; then # IPv6 (可能带方括号)
        # 进一步验证 IPv6 格式是否有效（这里仅做基本匹配，不完全验证）
        return 0
    else
        return 1
    fi
}

# 函数：从节点链接中解析出协议、主机和端口
# 更新：此函数将只解析，不进行 DNS 解析，DNS 解析将在主进程中统一完成
parse_node_link_details() {
    local link="$1"
    local parsed_host=""
    local parsed_port=""
    local type="" # 用于识别协议类型

    # 统一移除链接末尾可能的回车符
    link=$(echo "$link" | tr -d '\r')

    # 从链接中提取协议类型
    if [[ "$link" =~ ^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/ ]]; then
        type="${BASH_REMATCH[1]}"
    else
        echo "警告：无法识别的节点链接格式或协议: $link" >&2 # 输出到标准错误
        echo "," # 返回空值
        return
    fi

    # 根据协议类型进行解析
    case "$type" in
        vless|vmess|trojan|ss)
            # 现有逻辑，从 @ 符号后或 // 协议头后提取 host:port
            # 移除协议头
            local temp_link="${link#*://}"
            local host_port_part=""

            if [[ "$temp_link" == *"@"* ]]; then
                # 提取 @ 符号后面的部分，直到 ? 或 #
                host_port_part=$(echo "$temp_link" | sed -E 's/^[^@]*@([^/?#]+).*$/\1/')
            else
                # 提取 // 协议头后面的部分，直到 ? 或 #
                host_port_part=$(echo "$temp_link" | sed -E 's/^([^/?#]+).*$/\1/')
            fi

            # 从 host:port 部分提取主机和端口
            if [[ "$host_port_part" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)$ ]]; then
                parsed_host="${BASH_REMATCH[1]}"
                parsed_port="${BASH_REMATCH[2]}"
            fi
            ;;
        hy2|hysteria2)
            local temp_link="${link#*://}" # 移除协议头
            local host_port_part=""

            # Hysteria2 链接可能包含 @ 符号用于 auth 信息
            if [[ "$temp_link" == *"@"* ]]; then
                # 提取 @ 符号后面的部分，直到 ? 或 #
                host_port_part=$(echo "$temp_link" | sed -E 's/^[^@]*@([^/?#]+).*$/\1/')
            else
                # 提取 // 协议头后面的部分，直到 ? 或 #
                host_port_part=$(echo "$temp_link" | sed -E 's/^([^/?#]+).*$/\1/')
            fi

            # 从 host:port 部分提取主机和端口
            if [[ "$host_port_part" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)$ ]]; then
                parsed_host="${BASH_REMATCH[1]}"
                parsed_port="${BASH_REMATCH[2]}"
            fi
            ;;
        *)
            # 其他未知协议，这里已经由前面的if语句捕获
            ;;
    esac

    # 移除端口中的回车符（虽然上面已经统一移除链接的回车符，这里是双重保险）
    parsed_port=$(echo "$parsed_port" | tr -d '\r')
    parsed_host=$(echo "$parsed_host" | tr -d '\r')

    # 确保 parsed_host 和 parsed_port 不为空
    if [[ -z "$parsed_host" || -z "$parsed_port" ]]; then
        echo "警告：无法从链接中解析 IP 或端口: $link (解析结果: host='$parsed_host', port='$parsed_port')" >&2 # 输出到标准错误
        echo "," # 返回空值
        return
    fi

    echo "$parsed_host,$parsed_port" # 通过标准输出返回 host 和 port
}

# (其余部分保持不变)
# ... （从 test_node_connectivity_parallel 函数往下到脚本结束都保持不变）
