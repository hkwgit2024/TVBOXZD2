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
    #"https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
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
    if [[ "$host" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ || "$host" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
        return 0 # 是 IP 地址
    else
        return 1 # 不是 IP 地址
    fi
}

# 函数：从节点链接中解析出协议、主机和端口
# 更新：此函数将只解析，不进行 DNS 解析，DNS 解析将在主进程中统一完成
parse_node_link_details() {
    local link="$1"
    local parsed_host=""
    local parsed_port=""

    if [[ "$link" =~ ^(vless|vmess|trojan|ss):\/\/(.+@)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)(\/?.*) ]]; then
        parsed_host="${BASH_REMATCH[3]}"
        parsed_port="${BASH_REMATCH[4]}"
    elif [[ "$link" == hysteria2://* ]]; then
        # 尝试匹配 hysteria2://<host>:<port> 格式
        # 提取 hysteria2:// 和 ? 或 # 之间的部分
        local host_port_part=$(echo "$link" | sed -E 's|hysteria2://([^/?#]+).*|\1|')
        # 进一步分割 host 和 port
        if [[ "$host_port_part" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)$ ]]; then
            parsed_host="${BASH_REMATCH[1]}"
            parsed_port="${BASH_REMATCH[2]}"
        fi
    fi

    # 通过标准输出返回 host 和 port
    echo "$parsed_host,$parsed_port"
}


# 定义一个函数来处理单个节点的连接性测试（供 xargs 调用）
test_node_connectivity_parallel() {
    local NODE_LINK="$1"
    local LOG_FILE_PATH="$2" # 日志文件路径
    local OUTPUT_FILE_PATH="$3" # 成功节点文件路径
    local CACHE_FILE_PATH="$4" # DNS 缓存文件路径
    local CONNECT_TIMEOUT="$5" # 连接超时

    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""
    local PARSED_DETAILS=""

    # 子进程独立加载一个只读的 DNS 缓存
    declare -A CHILD_DNS_CACHE
    if [ -f "$CACHE_FILE_PATH" ]; then
        # 捕获 jq 错误，避免因缓存文件格式问题导致子进程失败
        mapfile -t CACHE_ENTRIES_CHILD < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip)"' "$CACHE_FILE_PATH" 2>/dev/null)
        for entry in "${CACHE_ENTRIES_CHILD[@]}"; do
            local key=$(echo "$entry" | cut -d' ' -f1)
            local ip_value=$(echo "$entry" | cut -d' ' -f2)
            if [[ -n "$key" && -n "$ip_value" ]]; then
                CHILD_DNS_CACHE["$key"]="$ip_value"
            fi
        done
    fi

    # 解析 NODE_LINK 以提取 HOSTNAME_OR_IP 和 PORT
    PARSED_DETAILS=$(parse_node_link_details "$NODE_LINK")
    HOSTNAME_OR_IP=$(echo "$PARSED_DETAILS" | cut -d',' -f1)
    PORT=$(echo "$PARSED_DETAILS" | cut -d',' -f2)

    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
        echo "警告：[PID $$] 无法从链接中解析 IP 或端口: $NODE_LINK" >> "$LOG_FILE_PATH"
        echo "-------------------------------------" >> "$LOG_FILE_PATH"
        return
    fi

    # 获取实际的 IP 地址（优先从缓存获取）
    if is_ip_address "$HOSTNAME_OR_IP"; then
        IP="$HOSTNAME_OR_IP"
    else
        # 它是域名，优先从子进程的缓存中获取预解析的 IP
        if [[ -n "${CHILD_DNS_CACHE[$HOSTNAME_OR_IP]}" ]]; then
            IP="${CHILD_DNS_CACHE[$HOSTNAME_OR_IP]}"
            echo "  - [PID $$] 从主进程预解析缓存获取 IP: $HOSTNAME_OR_IP -> $IP" >> "$LOG_FILE_PATH"
        else
            # 这种情况不应该发生，除非主进程预解析失败或有新的未预解析域名
            # 为了健壮性，这里也进行一次实时解析，但会打印警告
            echo "  - [PID $$] 警告: 未在预解析缓存中找到域名 $HOSTNAME_OR_IP，尝试实时解析..." >> "$LOG_FILE_PATH"
            local RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A  | head -n 1) # 使用 1.1.1.1 DNS
            if [ -n "$RESOLVED_IP" ]; then
                IP="$RESOLVED_IP"
                echo "  - [PID $$] 实时解析结果: $HOSTNAME_OR_IP -> $IP" >> "$LOG_FILE_PATH"
            else
                echo "  - [PID $$] 警告: 无法实时解析域名 $HOSTNAME_OR_IP" >> "$LOG_FILE_PATH"
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
        echo "  - 结果: [PID $$] 成功连接到 $IP:$PORT" >> "$LOG_FILE_PATH"
        echo "$NODE_LINK" >> "$OUTPUT_FILE_PATH" # 将成功连接的完整节点链接保存到指定的输出文件
    else
        echo "  - 结果: [PID $$] 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)" >> "$LOG_FILE_PATH"
    fi
    echo "-------------------------------------" >> "$LOG_FILE_PATH"
}

# 导出函数和必要的变量，以便 xargs 调用的子 shell 可以访问
export -f test_node_connectivity_parallel parse_node_link_details is_ip_address
export LOG_FILE OUTPUT_FILE DNS_CACHE_FILE NODE_CONNECT_TIMEOUT # 移除 CACHE_EXPIRATION_SECONDS，子进程不再清理过期

# ==============================================================================
# 脚本核心逻辑
# ==============================================================================

echo "开始节点连接性测试..." | tee "$LOG_FILE"
echo "测试时间: $(date '+%Y-%m-%d %H:%M:%S JST')" | tee -a "$LOG_FILE"
echo "-------------------------------------" | tee -a "$LOG_FILE"

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 清空并初始化成功节点文件
echo "# Successful Nodes (Updated by GitHub Actions at $(date '+%Y-%m-%d %H:%M:%S JST'))" > "$OUTPUT_FILE"
echo "-------------------------------------" >> "$OUTPUT_FILE"

# 确保临时合并文件是空的，并在每次运行前创建/清空
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
if [ ! -f "$MERGED_NODES_TEMP_FILE" ] || [ ! -s "$MERGED_NODES_TEMP_FILE" ] || [ "$DOWNLOAD_SUCCESS" = false ]; then
    echo "错误：未能下载任何节点配置文件，或所有文件都为空，或者下载完全失败。请检查 NODE_SOURCES URL 和网络连接。" | tee -a "$LOG_FILE"
    if [ -f "$MERGED_NODES_TEMP_FILE" ]; then
        rm -f "$MERGED_NODES_TEMP_FILE"
    fi
    exit 1 # Exit with an error code to stop the workflow
fi

echo "所有配置文件下载并合并成功。开始解析节点并测试连接性..." | tee -a "$LOG_FILE"

# 确保安装了 dnsutils (用于 dig 命令) 和 jq (用于处理 JSON)
echo "检查并安装 dnsutils 和 jq..." | tee -a "$LOG_FILE"
sudo apt-get update >/dev/null 2>&1 || { echo "ERROR: apt-get update failed. Cannot proceed with dependency installation." | tee -a "$LOG_FILE"; exit 1; }
sudo apt-get install -y dnsutils jq >/dev/null 2>&1 || { echo "ERROR: apt-get install dnsutils or jq failed. Please ensure your package manager is configured correctly." | tee -a "$LOG_FILE"; exit 1; }
echo "dnsutils 和 jq 检查/安装完成。" | tee -a "$LOG_FILE"


# ==============================================================================
# 主进程：加载并预处理 DNS 缓存，提取所有域名进行解析
# ==============================================================================

# 尝试从缓存文件加载旧的 DNS 缓存
if [ -f "$DNS_CACHE_FILE" ]; then
    echo "从 $DNS_CACHE_FILE 加载 DNS 缓存并清理过期条目..." | tee -a "$LOG_FILE"
    CURRENT_TIME=$(date +%s) # 获取当前 Unix 时间戳

    mapfile -t CACHE_ENTRIES < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip) \(.[$key].timestamp)"' "$DNS_CACHE_FILE" 2>/dev/null)
    
    LOADED_COUNT=0
    CLEANED_COUNT=0

    for entry in "${CACHE_ENTRIES[@]}"; do
        local key=$(echo "$entry" | cut -d' ' -f1)
        local ip_value=$(echo "$entry" | cut -d' ' -f2)
        local timestamp_value=$(echo "$entry" | cut -d' ' -f3)

        if [[ -n "$key" && -n "$ip_value" && "$timestamp_value" =~ ^[0-9]+$ ]]; then
            if (( CURRENT_TIME - timestamp_value < CACHE_EXPIRATION_SECONDS )); then
                DNS_CACHE["$key"]="$ip_value,$timestamp_value" # 存入主进程缓存
                ((LOADED_COUNT++))
            else
                echo "  - 清理过期缓存: $key (过期于 $(date -d "@$timestamp_value"))" | tee -a "$LOG_FILE"
                ((CLEANED_COUNT++))
            fi
        else
            echo "  - 警告: 缓存文件 $DNS_CACHE_FILE 中发现无效条目: '$entry'，已忽略。" | tee -a "$LOG_FILE"
        fi
    done
    echo "加载了 $LOADED_COUNT 个有效缓存条目，清理了 $CLEANED_COUNT 个过期条目。" | tee -a "$LOG_FILE"
else
    echo "未找到 DNS 缓存文件 $DNS_CACHE_FILE，将创建新缓存。" | tee -a "$LOG_FILE"
fi

echo "开始预解析所有节点链接中的域名..." | tee -a "$LOG_FILE"
PRE_RESOLVED_COUNT=0
SKIPPED_DOMAIN_COUNT=0

# 遍历合并后的所有节点链接，提取域名
while IFS= read -r node_link; do
    if [[ -z "$node_link" ]]; then
        continue # 跳过空行
    fi

    # 尝试解析链接获取 host 和 port
    PARSED_DETAILS=$(parse_node_link_details "$node_link")
    host=$(echo "$PARSED_DETAILS" | cut -d',' -f1)

    if [[ -n "$host" ]] && ! is_ip_address "$host"; then
        # 如果是域名且不在已解析缓存中，或者已过期
        if [[ -z "${DNS_CACHE[$host]}" ]] || (( CURRENT_TIME - $(echo "${DNS_CACHE[$host]}" | cut -d',' -f2) >= CACHE_EXPIRATION_SECONDS )); then
            ALL_DOMAINS_TO_RESOLVE["$host"]=1 # 标记此域名待解析
        fi
    fi
done < "$MERGED_NODES_TEMP_FILE"

# 对所有需要解析的域名进行实际 DNS 查询
for domain in "${!ALL_DOMAINS_TO_RESOLVE[@]}"; do
    if [[ -n "${DNS_CACHE[$domain]}" ]]; then
        # 如果在加载阶段已经存在有效缓存，则跳过 dig
        echo "  - 域名 '$domain' 已存在有效缓存，跳过实时解析。" | tee -a "$LOG_FILE"
        continue
    fi

    echo "  - 预解析域名: $domain" | tee -a "$LOG_FILE"
    resolved_ip=$(dig +short "$domain" A | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | head -n 1) # 只取 IPv4
    if [[ -n "$resolved_ip" ]]; then
        DNS_CACHE["$domain"]="$resolved_ip,$CURRENT_TIME" # 存储 IP 和当前时间戳
        ((PRE_RESOLVED_COUNT++))
        echo "  - 预解析成功: $domain -> $resolved_ip" | tee -a "$LOG_FILE"
    else
        # 记录解析失败的域名，这些将不会被缓存
        echo "  - 警告: 预解析域名失败: $domain" | tee -a "$LOG_FILE"
        ((SKIPPED_DOMAIN_COUNT++))
    fi
done
echo "预解析完成。成功预解析 $PRE_RESOLVED_COUNT 个域名，跳过 $SKIPPED_DOMAIN_COUNT 个无法解析的域名。" | tee -a "$LOG_FILE"

# 在并行测试前，将主进程更新后的 DNS_CACHE 写入文件，供子进程读取
echo "更新主进程 DNS 缓存文件以供并行测试使用..." | tee -a "$LOG_FILE"
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
echo "$json_output" | jq . > "$DNS_CACHE_FILE" 2>/dev/null || { echo "ERROR: 无法写入 DNS 缓存文件 $DNS_CACHE_FILE。" | tee -a "$LOG_FILE"; exit 1; }
echo "主进程 DNS 缓存文件更新完成。" | tee -a "$LOG_FILE"


# ==============================================================================
# 并行执行节点测试
# ==============================================================================

echo "开始并行测试节点连接，并发数: $MAX_CONCURRENT_TESTS..." | tee -a "$LOG_FILE"

if [ -s "$MERGED_NODES_TEMP_FILE" ]; then
    cat "$MERGED_NODES_TEMP_FILE" | xargs -P "$MAX_CONCURRENT_TESTS" -I {} \
        bash -c 'test_node_connectivity_parallel "$@"' _ "{}" "$LOG_FILE" "$OUTPUT_FILE" "$DNS_CACHE_FILE" "$NODE_CONNECT_TIMEOUT"
else
    echo "警告：合并后的节点文件为空，没有节点可供测试。" | tee -a "$LOG_FILE"
fi

# ==============================================================================
# 最终清理和完成
# ==============================================================================

# 清理临时文件，使用 -f 避免文件不存在时报错
rm -f "$MERGED_NODES_TEMP_FILE"

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
echo "成功连接的节点已保存到 $OUTPUT_FILE" | tee -a "$LOG_FILE"
