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
# 你可以根据需要调整这个值，如果希望更频繁地获取最新解析，可以设小一点
CACHE_EXPIRATION_SECONDS=$((24 * 60 * 60)) # 24 hours

# 定义同时进行的连接测试数量 (并发数)
# 根据你的服务器配置（CPU核心数，网络带宽）调整此值。
# 通常设置为 10-50 之间是一个合理的开始。
MAX_CONCURRENT_TESTS=20 # 示例：20 个并发连接测试

# 定义单个节点连接测试的超时时间（秒）。更短的超时可以更快筛选出不可达节点。
NODE_CONNECT_TIMEOUT=2 # 示例：2 秒超时

# 定义所有节点来源URL的数组
# 你可以在这里添加/删除/修改你的节点来源网址
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
   # "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
   # "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
   # "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

# ==============================================================================
# 函数定义
# ==============================================================================

# 定义一个函数来处理单个节点的连接性测试
# 这个函数将在 xargs 调用的子 shell 中运行，因此它需要访问一些通过 export 导出的全局变量
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
        # 捕获 jq 错误，避免因缓存文件格式问题导致子进程失败
        mapfile -t CACHE_ENTRIES_CHILD < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip) \(.[$key].timestamp)"' "$CACHE_FILE_PATH" 2>/dev/null)
        for entry in "${CACHE_ENTRIES_CHILD[@]}"; do
            local key=$(echo "$entry" | cut -d' ' -f1)
            local ip_value=$(echo "$entry" | cut -d' ' -f2)
            local timestamp_value=$(echo "$entry" | cut -d' ' -f3)
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
        # 处理 ss:// 链接，特别是 base64 编码的
        local SS_HOST_PORT=$(echo "$NODE_LINK" | grep -oE '@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)' | head -n 1)
        if [ -n "$SS_HOST_PORT" ]; then
            HOSTNAME_OR_IP=$(echo "$SS_HOST_PORT" | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$SS_HOST_PORT" | cut -d':' -f2)
        else
            # 尝试解码 base64 部分来获取 host:port
            local BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            local DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
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
            local RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
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

echo "开始节点连接性测试..." | tee "$LOG_FILE"
echo "测试时间: $(date)" | tee -a "$LOG_FILE"
echo "-------------------------------------" | tee -a "$LOG_FILE"

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 清空并初始化成功节点文件
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$OUTPUT_FILE"
echo "-------------------------------------" >> "$OUTPUT_FILE"

# 确保临时合并文件是空的，并在每次运行前创建/清空
# 使用 > 创建或清空文件
> "$MERGED_NODES_TEMP_FILE"

echo "下载并合并节点配置文件..." | tee -a "$LOG_FILE"
DOWNLOAD_SUCCESS=false # Flag to track if any download was successful
for url in "${NODE_SOURCES[@]}"; do
    echo "正在下载: $url" | tee -a "$LOG_FILE"
    # 使用 curl -sL --fail-with-body 来确保下载失败时返回非零状态码，并且错误信息在 stdout
    # 将内容追加到临时文件
    if curl -sL --fail-with-body "$url" >> "$MERGED_NODES_TEMP_FILE"; then
        DOWNLOAD_SUCCESS=true
    else
        echo "警告：未能从 $url 下载文件或文件内容为空。" | tee -a "$LOG_FILE"
    fi
done

# 再次检查合并后的临时文件是否为空或未成功下载任何内容
# -s 检查文件是否非空。如果文件不存在或为空，则为假。
# -f 检查文件是否存在且为常规文件。
if [ ! -f "$MERGED_NODES_TEMP_FILE" ] || [ ! -s "$MERGED_NODES_TEMP_FILE" ] || [ "$DOWNLOAD_SUCCESS" = false ]; then
    echo "错误：未能下载任何节点配置文件，或所有文件都为空，或者下载完全失败。请检查 NODE_SOURCES URL 和网络连接。" | tee -a "$LOG_FILE"
    # Clean up the temp file if it was created but is empty
    if [ -f "$MERGED_NODES_TEMP_FILE" ]; then
        rm -f "$MERGED_NODES_TEMP_FILE"
    fi
    exit 1 # Exit with an error code to stop the workflow
fi


echo "所有配置文件下载并合并成功。开始解析节点并测试连接性..." | tee -a "$LOG_FILE"

# 确保安装了 dnsutils (用于 dig 命令) 和 jq (用于处理 JSON)
echo "检查并安装 dnsutils 和 jq..." | tee -a "$LOG_FILE"
# 为了避免输出过多信息到日志，将 apt-get 的输出重定向到 /dev/null
# 增加错误检查，如果安装失败则退出脚本
sudo apt-get update >/dev/null 2>&1 || { echo "ERROR: apt-get update failed. Cannot proceed with dependency installation." | tee -a "$LOG_FILE"; exit 1; }
sudo apt-get install -y dnsutils jq >/dev/null 2>&1 || { echo "ERROR: apt-get install dnsutils or jq failed. Please ensure your package manager is configured correctly." | tee -a "$LOG_FILE"; exit 1; }
echo "dnsutils 和 jq 检查/安装完成。" | tee -a "$LOG_FILE"

# 主进程的 DNS 缓存（用于加载、清理和最终保存）
declare -A DNS_CACHE

# 尝试从缓存文件加载旧的 DNS 缓存
if [ -f "$DNS_CACHE_FILE" ]; then
    echo "从 $DNS_CACHE_FILE 加载 DNS 缓存并清理过期条目..." | tee -a "$LOG_FILE"
    CURRENT_TIME=$(date +%s) # 获取当前 Unix 时间戳

    # 使用 jq 解析 JSON 文件并填充 Bash 关联数组
    # 2>/dev/null 用于抑制可能的 jq 错误信息（例如 JSON 格式不正确）
    mapfile -t CACHE_ENTRIES < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip) \(.[$key].timestamp)"' "$DNS_CACHE_FILE" 2>/dev/null)
    
    LOADED_COUNT=0
    CLEANED_COUNT=0

    for entry in "${CACHE_ENTRIES[@]}"; do
        local key=$(echo "$entry" | cut -d' ' -f1)
        local ip_value=$(echo "$entry" | cut -d' ' -f2)
        local timestamp_value=$(echo "$entry" | cut -d' ' -f3)

        # 验证提取的值是否有效，防止无效条目导致后续错误
        if [[ -n "$key" && -n "$ip_value" && "$timestamp_value" =~ ^[0-9]+$ ]]; then
            # 检查时间戳是否过期
            if (( CURRENT_TIME - timestamp_value < CACHE_EXPIRATION_SECONDS )); then
                DNS_CACHE["$key"]="$ip_value,$timestamp_value" # 存入主进程缓存
                ((LOADED_COUNT++))
            else
                echo "  - 清理过期缓存: $key (过期于 $(date -d "@$timestamp_value"))" | tee -a "$LOG_FILE"
                ((CLEANED_COUNT++))
            fi
        else
            echo "  - 警告: 缓存文件 $DNS_CACHE_FILE 中发现无效条目: '$entry'，已忽略。" | tee -a "$LOG_FILE"
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

# 确保 MERGED_NODES_TEMP_FILE 确实有内容才会传递给 xargs
if [ -s "$MERGED_NODES_TEMP_FILE" ]; then
    # 使用 xargs 并行处理，将每行 NODE_LINK 作为参数传递给 test_node_connectivity_parallel 函数
    # 注意：子进程写入 LOG_FILE 和 OUTPUT_FILE 时，虽然 >> 是原子操作，但日志顺序可能乱。
    # 如果需要严格顺序，考虑更复杂的临时文件和最终合并机制。
    cat "$MERGED_NODES_TEMP_FILE" | xargs -P "$MAX_CONCURRENT_TESTS" -I {} \
        bash -c 'test_node_connectivity_parallel "$@"' _ "{}" "$LOG_FILE" "$OUTPUT_FILE" "$DNS_CACHE_FILE" "$CACHE_EXPIRATION_SECONDS" "$NODE_CONNECT_TIMEOUT"
else
    echo "警告：合并后的节点文件为空，没有节点可供测试。" | tee -a "$LOG_FILE"
fi

# ==============================================================================
# 更新并保存主进程的 DNS 缓存
# ==============================================================================
# 注意：由于并行子进程不会更新主进程的 DNS_CACHE 数组，
# 所以这里保存的缓存只包含最初加载的有效条目，以及如果主进程在其他地方
# 进行了同步解析（本脚本中未体现）新增的条目。
# 如果想让子进程的解析结果也写入缓存，需要更复杂的并发控制（如文件锁）或更复杂的预处理。
# 对于简单的“加速”目的，当前的主进程加载和保存已足够，子进程只读。

echo "保存 DNS 缓存到 $DNS_CACHE_FILE..." | tee -a "$LOG_FILE"
json_output="{"
first_entry=true
for key in "${!DNS_CACHE[@]}"; do
    if [ "$first_entry" = true ]; then
        first_entry=false
    else
        json_output+=","
    fi
    local cached_data="${DNS_CACHE[$key]}"
    local ip_val=$(echo "$cached_data" | cut -d',' -f1)
    local timestamp_val=$(echo "$cached_data" | cut -d',' -f2)

    # 格式化为 JSON 对象
    json_output+="\"$key\":{\"ip\":\"$ip_val\",\"timestamp\":$timestamp_val}"
done
json_output+="}"
# 使用 jq 格式化并写入文件，2>/dev/null 隐藏可能的 jq 错误信息
echo "$json_output" | jq . > "$DNS_CACHE_FILE" 2>/dev/null
echo "DNS 缓存保存完成。" | tee -a "$LOG_FILE"


# 清理临时文件，使用 -f 避免文件不存在时报错
rm -f "$MERGED_NODES_TEMP_FILE"

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
echo "成功连接的节点已保存到 $OUTPUT_FILE" | tee -a "$LOG_FILE"
