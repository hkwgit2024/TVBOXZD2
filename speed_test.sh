#!/bin/bash

# 定义常量
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"
MERGED_NODES_TEMP_FILE=$(mktemp) # 使用 mktemp 创建唯一的临时文件
SUCCESS_TEMP_FILE=$(mktemp) # 新增：用于存储本次运行的成功节点

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
   # "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
  #  "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
  #  "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

# --- 函数定义 ---

# 日志函数，输出到控制台和日志文件
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# 检查依赖函数
check_dependencies() {
    local deps=("dig" "nc" "curl" "base64" "sort" "wc")
    for dep in "${deps[@]}"; do
        command -v "$dep" >/dev/null 2>&1 || {
            log "ERROR: 命令 '$dep' 未找到。请确保已安装。"
            exit 1
        }
    done
}

# 核心函数：测试单个节点连接性并解析链接
test_node_connectivity() {
    local node_link="$1"
    local ip=""
    local port=""
    local hostname_or_ip=""

    # 跳过空行、注释和分隔符
    [[ -z "$node_link" || "$node_link" =~ ^# || "$node_link" =~ ^-*$ ]] && return 1

    # 尝试提取 IP/Hostname 和 Port (统一解析逻辑)
    if [[ "$node_link" =~ ^(hysteria2|vless|vmess|trojan):\/\/(.+@)?([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
        hostname_or_ip="${BASH_REMATCH[3]}"
        port="${BASH_REMATCH[4]}"
    elif [[ "$node_link" =~ ^ss:// ]]; then
        local part_after_ss=$(echo "$node_link" | sed 's/^ss:\/\///')
        if [[ "$part_after_ss" =~ @([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
            hostname_or_ip="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        else # 尝试 base64 解码
            local base64_part=$(echo "$part_after_ss" | cut -d'@' -f1)
            local decoded_auth=$(echo "$base64_part" | tr '_-' '+/' | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$decoded_auth" =~ ([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
                hostname_or_ip="${BASH_REMATCH[1]}"
                port="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    if [ -z "$hostname_or_ip" ] || [ -z "$port" ]; then
        log "WARN: 无法从链接中解析 IP 或端口: $node_link"
        return 1
    fi

    local target_host="$hostname_or_ip"
    if [[ "$hostname_or_ip" =~ ^\[([0-9a-fA-F:]+)\]$ ]]; then # IPv6 with brackets
        ip="${BASH_REMATCH[1]}"
    elif [[ "$hostname_or_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then # IPv4
        ip="$hostname_or_ip"
    else # Domain
        log "INFO: 尝试解析域名: $hostname_or_ip"
        resolved_ip=$(dig +short "$hostname_or_ip" A | head -n 1) # Prefer IPv4
        [ -z "$resolved_ip" ] && resolved_ip=$(dig +short "$hostname_or_ip" AAAA | head -n 1) # Then IPv6

        if [ -n "$resolved_ip" ]; then
            ip="$resolved_ip"
            [[ "$ip" =~ : ]] && target_host="[$ip]" # For nc, IPv6 needs brackets
            log "INFO: 解析结果: $hostname_or_ip -> $ip"
        else
            log "WARN: 无法解析域名: $hostname_or_ip (原始链接: $node_link)"
            return 1
        fi
    fi

    log "INFO: 正在测试节点连接: $target_host:$port (来自 $node_link)"
    nc -z -w 5 "$target_host" "$port" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log "INFO: 成功连接到 $target_host:$port"
        echo "$node_link" >> "$SUCCESS_TEMP_FILE" # 将成功连接的节点写入临时文件
        return 0
    else
        log "WARN: 无法连接到 $target_host:$port (可能被防火墙阻止或服务未运行)"
        return 1
    fi
}

# --- 主逻辑开始 ---

# 1. 初始化
log "INFO: 开始节点连接性测试..."
log "INFO: 测试时间: $(date)"

mkdir -p "$OUTPUT_DIR"
# 注意：这里不再清空 SUCCESS_FILE，改为在合并后处理

# 2. 检查依赖
check_dependencies

# 3. 下载并合并节点配置文件
log "INFO: 下载并合并节点配置文件..."
for url in "${NODE_SOURCES[@]}"; do
    log "INFO: 正在下载: $url"
    curl -sL --retry 3 --retry-delay 2 "$url" >> "$MERGED_NODES_TEMP_FILE"
    if [ $? -ne 0 ]; then
        log "WARN: 未能从 $url 下载文件。"
    fi
done

# 检查合并后的临时文件是否为空
if [ ! -s "$MERGED_NODES_TEMP_FILE" ]; then
    log "ERROR: 未能下载任何节点配置文件，或所有文件都为空。"
    rm -f "$MERGED_NODES_TEMP_FILE"
    rm -f "$SUCCESS_TEMP_FILE" # 确保清理所有临时文件
    exit 1
fi

# 去重合并后的节点
sort -u "$MERGED_NODES_TEMP_FILE" -o "$MERGED_NODES_TEMP_FILE"
TOTAL_UNIQUE_NODES=$(grep -vE '^(#|--|$)' "$MERGED_NODES_TEMP_FILE" 2>/dev/null | wc -l || echo 0)
log "INFO: 所有配置文件下载并合并成功（去重后），共计 ${TOTAL_UNIQUE_NODES} 个节点，开始解析节点并测试连接性..."

# 4. 逐个测试节点
while IFS= read -r node_link; do
    test_node_connectivity "$node_link"
done < "$MERGED_NODES_TEMP_FILE"

# 5. 清理临时文件
rm -f "$MERGED_NODES_TEMP_FILE"

log "INFO: 所有节点连接性测试完成。"

# --- 合并和去重成功节点 ---
log "INFO: 合并并去重成功节点..."
# 将旧的成功节点（如果存在且有效）追加到本次运行的临时成功文件
if [ -f "$SUCCESS_FILE" ]; then
    # 排除头部注释和分隔符，只追加节点内容
    grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null >> "$SUCCESS_TEMP_FILE"
fi

# 清空最终的成功文件，写入新头部，然后将去重后的所有节点写入
echo "# Successful Nodes (Updated by GitHub Actions at $(date '+%Y-%m-%d %H:%M:%S %Z'))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
sort -u "$SUCCESS_TEMP_FILE" >> "$SUCCESS_FILE" # 去重后写入最终文件

log "INFO: 成功连接的节点已保存到 $SUCCESS_FILE"

# 清理本次运行的临时成功文件
rm -f "$SUCCESS_TEMP_FILE"

log "INFO: 节点连接性测试流程完成。"

