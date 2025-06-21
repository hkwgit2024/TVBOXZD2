#!/bin/bash

# ==============================================================================
# 脚本配置
# ==============================================================================

# 定义日志文件和成功节点文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data" # 输出目录
OUTPUT_FILE="$OUTPUT_DIR/sub.txt" # 成功节点输出文件
MERGED_NODES_TEMP_FILE="all_merged_nodes_temp.txt" # 临时文件，用于合并所有来源

# DNS 缓存文件的路径
DNS_CACHE_FILE="$OUTPUT_DIR/dns_cache.json"
# DNS 缓存的有效期（秒），例如 24 小时 = 86400 秒
CACHE_EXPIRATION_SECONDS=$((24 * 60 * 60)) # 24 hours

# 定义同时进行的连接测试数量 (并发数)
# 根据你的服务器配置（CPU核心数，网络带宽）调整此值。
# 通常设置为 10-50 之间是一个合理的开始。
MAX_CONCURRENT_TESTS=20 # 示例：20 个并发连接测试

# 定义单个节点连接测试的超时时间（秒）。更短的超时可以更快筛选出不可达节点。
NODE_CONNECT_TIMEOUT=2 # 示例：2 秒超时

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
  #  "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
   # "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
   # "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

# ==============================================================================
# 函数定义
# ==============================================================================

# 定义一个函数来处理单个节点的连接性测试
# 这个函数将在 xargs 调用的子 shell 中运行，因此它需要访问一些全局变量
test_node_connectivity_parallel() {
    local NODE_LINK="$1"
    local LOG_FILE_PATH="$2" # 日志文件路径
    local OUTPUT_FILE_PATH="$3" # 成功节点文件路径
    local CACHE_FILE_PATH="$4" # DNS 缓存文件路径
    local EXPIRATION_SECONDS="$5" # 缓存有效期
    local CONNECT_TIMEOUT="$6" # 连接超时

    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""
    local CURRENT_TIME=$(date +%s)

    # 子进程独立维护一个 DNS 缓存（只读，不更新主进程的缓存文件）
    declare -A CHILD_DNS_CACHE
    if [ -f "$CACHE_FILE_PATH" ]; then
        mapfile -t CACHE_ENTRIES_CHILD < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip) \(.[$key].timestamp)"' "$CACHE_FILE_PATH" 2>/dev/null)
        for entry in "${CACHE_ENTRIES_CHILD[@]}"; do
            key=$(echo "$entry" | cut -d' ' -f1)
            ip_value=$(echo "$entry" | cut -d' ' -f2)
            timestamp_value=$(echo "$entry" | cut -d' ' -f3)
            if [[ -n "$key" && -n "$ip_value" && "$timestamp_value" =~ ^[0-9]+$ ]]; then
                # 子进程只加载未过期的缓存，不进行清理写入
                if (( CURRENT_TIME - timestamp_value < EXPIRATION_SECONDS )); then
                    CHILD_DNS_CACHE["$key"]="$ip_value" # 子进程只关心 IP，不关心时间戳
                fi
            fi
        done
    fi

    # 解析 NODE_LINK 以提取 HOSTNAME_OR_IP 和 PORT
    if [[ "$NODE_LINK" =~ ^(vless|vmess|trojan|hy2):\/\/(.+@)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)(\/?.*) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" == ss://* ]]; then
        SS_HOST_PORT=$(echo "$NODE_LINK" | grep -oE '@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)' | head -n 1)
        if [ -n "$SS_HOST_PORT" ]; then
            HOSTNAME_OR_IP=$(echo "$SS_HOST_PORT" | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$SS_HOST_PORT" | cut -d':' -f2)
        else
            BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_PART" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
        echo "警告：[PID $$] 无法从链接中解析 IP 或端口: $NODE_LINK" >> "$LOG_FILE_PATH"
        echo "-------------------------------------" >> "$LOG_FILE_PATH"
        return
    fi

    # 获取实际的 IP 地址（可能是域名解析）
    if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
        IP="$HOSTNAME_OR_IP"
    else
        # 优先从子进程的缓存中获取
        if [[ -n "${CHILD_DNS_CACHE[$HOSTNAME_OR_IP]}" ]]; then
            IP="${CHILD_DNS_CACHE[$HOSTNAME_OR_IP]}"
            echo "  - [PID $$] 从子进程缓存获取解析: $HOSTNAME_OR_IP -> $IP" >> "$LOG_FILE_PATH"
        else
            # 如果缓存中没有，则进行实时 dig 解析
            echo "  - [PID $$] 尝试解析域名: $HOSTNAME_OR_IP" >> "$LOG_FILE_PATH"
            RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
            if [ -n "$RESOLVED_IP" ]; then
                IP="$RESOLVED_IP"
                # 子进程不更新主缓存文件，所以这里只显示解析结果
                echo "  - [PID $$] 解析结果: $HOSTNAME_OR_IP -> $IP" >> "$LOG_FILE_PATH"
            else
                echo "  - [PID $$] 警告: 无法解析域名 $HOSTNAME_OR_IP" >> "$LOG_FILE_PATH"
            fi
        fi
    fi

    if [ -z "$IP" ]; then
        echo "警告：[PID $$] 无法确定 IP 地址进行连接测试: $NODE_LINK" >> "$LOG_FILE_PATH"
        echo "-------------------------------------" >> "$LOG_FILE_PATH"
        return
    fi

    echo "正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)" >> "$LOG_FILE_PATH"

    # 使用 nc 命令测试连接性，使用定义的超时时间
    nc -z -w "$CONNECT_TIMEOUT" "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  - 结果: [PID $$] 成功连接到 $IP:$PORT" >> "$LOG_FILE_PATH"
        echo "$NODE_LINK" >> "$OUTPUT_FILE_PATH" # 将成功连接的完整节点链接保存到指定的输出文件
    else
        echo "  - 结果: [PID $$] 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)" >> "$LOG_FILE_PATH"
    fi
    echo "-------------------------------------" >> "$LOG_FILE_PATH"
}

# 导出函数和必要的变量，以便 xargs 调用的子 shell 可以访问
export -f test_node_connectivity_parallel
export LOG_FILE
export OUTPUT_FILE
export DNS_CACHE_FILE
export CACHE_EXPIRATION_SECONDS
export NODE_CONNECT_TIMEOUT

# ==============================================================================
# 脚本核心逻辑
# ==============================================================================

# ... (脚本开头部分，确保输出目录存在，清空成功节点文件，下载合并节点配置，安装 dnsutils 和 jq 部分保持不变) ...

echo "所有配置文件下载并合并成功。开始解析节点并测试连接性..." | tee -a "$LOG_FILE"

# 主进程的 DNS 缓存（用于加载、清理和最终保存）
declare -A DNS_CACHE

# 尝试从缓存文件加载旧的 DNS 缓存
if [ -f "$DNS_CACHE_FILE" ]; then
    echo "从 $DNS_CACHE_FILE 加载 DNS 缓存并清理过期条目..." | tee -a "$LOG_FILE"
    CURRENT_TIME=$(date +%s) # 获取当前 Unix 时间戳

    mapfile -t CACHE_ENTRIES < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip) \(.[$key].timestamp)"' "$DNS_CACHE_FILE" 2>/dev/null)
    
    LOADED_COUNT=0
    CLEANED_COUNT=0

    for entry in "${CACHE_ENTRIES[@]}"; do
        key=$(echo "$entry" | cut -d' ' -f1)
        ip_value=$(echo "$entry" | cut -d' ' -f2)
        timestamp_value=$(echo "$entry" | cut -d' ' -f3)

        if [[ -n "$key" && -n "$ip_value" && "$timestamp_value" =~ ^[0-9]+$ ]]; then
            if (( CURRENT_TIME - timestamp_value < CACHE_EXPIRATION_SECONDS )); then
                DNS_CACHE["$key"]="$ip_value,$timestamp_value" # 存入主进程缓存
                ((LOADED_COUNT++))
            else
                echo "  - 清理过期缓存: $key (过期于 $(date -d "@$timestamp_value"))" | tee -a "$LOG_FILE"
                ((CLEANED_COUNT++))
            fi
        else
            echo "  - 警告: 缓存文件 $DNS_CACHE_FILE 中发现无效条目: $entry" | tee -a "$LOG_FILE"
        fi
    done
    echo "加载了 $LOADED_COUNT 个有效缓存条目，清理了 $CLEANED_COUNT 个过期条目。" | tee -a "$LOG_FILE"
else
    echo "未找到 DNS 缓存文件 $DNS_CACHE_FILE，将创建新缓存。" | tee -a "$LOG_FILE"
fi

# ==============================================================================
# 并行执行节点测试
# ==============================================================================

echo "开始并行测试节点连接，并发数: $MAX_CONCURRENT_TESTS..." | tee -a "$LOG_FILE"

# 使用 xargs 并行处理
# 每个节点链接作为单独的参数传递给 test_node_connectivity_parallel 函数
cat "$MERGED_NODES_TEMP_FILE" | xargs -P "$MAX_CONCURRENT_TESTS" -I {} \
    bash -c 'test_node_connectivity_parallel "$@"' _ "{}" "$LOG_FILE" "$OUTPUT_FILE" "$DNS_CACHE_FILE" "$CACHE_EXPIRATION_SECONDS" "$NODE_CONNECT_TIMEOUT"

# ==============================================================================
# 更新并保存主进程的 DNS 缓存
# ==============================================================================
# 注意：由于并行子进程不会更新主进程的 DNS_CACHE 数组，
# 所以这里保存的缓存只包含最初加载的有效条目，以及如果主进程在其他地方
# 进行了同步解析（本脚本中未体现）新增的条目。
# 如果想让子进程的解析结果也写入缓存，需要更复杂的并发控制（如文件锁）或更复杂的预处理。
# 对于简单的“加速”目的，当前的主进程加载和保存已足够，子进程只读。

# 如果某个域名在子进程中重新解析了（因为缓存过期或首次解析），
# 它的新 IP 并没有自动回到主进程的 DNS_CACHE 数组。
# 为了让新解析的 IP 也能被缓存，你需要：
# 1. 在 `test_node_connectivity_parallel` 函数中，将新解析的 IP 回传。
# 2. 或者，在主进程中，在 xargs 之前预先对所有域名进行解析，并利用主进程的 DNS_CACHE。
# 考虑到 Bash 并发的复杂性，目前版本保持子进程只读取缓存，主进程负责缓存的加载和保存。
# 这意味着，如果一个缓存条目过期，它将在主进程的下一轮加载时被清除，并由某个子进程重新解析，
# 但这个新解析的 IP 不会立刻被缓存到文件中，直到下次主进程重新构建并保存缓存。
# 为了完整性，这里我们直接保存主进程现有（加载的+未过期的）缓存。

echo "保存 DNS 缓存到 $DNS_CACHE_FILE..." | tee -a "$LOG_FILE"
json_output="{"
first_entry=true
for key in "${!DNS_CACHE[@]}"; do
    if [ "$first_entry" = true ]; then
        first_entry=false
    else
        json_output+=","
    fi
    cached_data="${DNS_CACHE[$key]}"
    ip_val=$(echo "$cached_data" | cut -d',' -f1)
    timestamp_val=$(echo "$cached_data" | cut -d',' -f2)

    json_output+="\"$key\":{\"ip\":\"$ip_val\",\"timestamp\":$timestamp_val}"
done
json_output+="}"
# 使用 jq 格式化并写入文件，2>/dev/null 隐藏可能的 jq 错误信息
echo "$json_output" | jq . > "$DNS_CACHE_FILE" 2>/dev/null
echo "DNS 缓存保存完成。" | tee -a "$LOG_FILE"


# 清理临时文件
rm "$MERGED_NODES_TEMP_FILE"

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
echo "成功连接的节点已保存到 $OUTPUT_FILE" | tee -a "$LOG_FILE"
