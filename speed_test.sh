#!/bin/bash

# ==============================================================================
# 脚本配置
# ==============================================================================
# 输出目录
OUTPUT_DIR="data"

# 日志文件和输出文件路径
LOG_FILE="$OUTPUT_DIR/node_connectivity_results.log"
OUTPUT_FILE="$OUTPUT_DIR/sub.txt"
MERGED_NODES_TEMP_FILE="all_merged_nodes_temp.txt"

# DNS 缓存文件路径
DNS_CACHE_FILE="$OUTPUT_DIR/dns_cache.json"
# DNS 缓存有效期（秒），24 小时
CACHE_EXPIRATION_SECONDS=$((24 * 60 * 60))

# 并发测试数量
MAX_CONCURRENT_JOBS=5

# 单节点连接测试超时时间（秒）
NODE_CONNECT_TIMEOUT=2

# 节点来源 URL 数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

# ==============================================================================
# 全局变量
# ==============================================================================
# 主进程 DNS 缓存
declare -A DNS_CACHE
# 待解析域名集合
declare -A ALL_DOMAINS_TO_RESOLVE
# 当前时间戳
CURRENT_TIME=$(date +%s)

# ==============================================================================
# 函数定义
# ==============================================================================

# 检查是否为有效 IPv4 或 IPv6 地址
is_ip_address() {
    local host="$1"
    if echo "$host" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        return 0
    fi
    if echo "$host" | grep -Eq '^\[?[0-9a-fA-F:]+\]?$'; then
        return 0
    fi
    return 1
}

# 解析节点配置，提取协议、主机和端口
parse_node_config() {
    local link="$1"
    local parsed_host=""
    local parsed_port=""
    local type=""
    local debug_log_prefix="DEBUG [parse_node_config]: "

    # 清理换行符和单引号
    link=$(echo "$link" | tr -d '\r\n' | sed "s/'/\\'/g")
    echo "$debug_log_prefix 清理后链接: $link" >&2

    # 提取协议
    if [[ "$link" =~ ^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/ ]]; then
        type="${BASH_REMATCH[1]}"
        echo "$debug_log_prefix 协议: $type" >&2
    else
        echo "警告：无法识别协议: $link" >&2
        echo ",,"
        return
    fi

    # 根据协议解析
    case "$type" in
        vless|vmess|trojan|ss)
            local temp_link="${link#*://}"
            local host_port_part=""
            if [[ "$temp_link" == *"@"* ]]; then
                host_port_part=$(echo "$temp_link" | sed -E 's/^[^@]*@([^/?#]+).*$/\1/')
            else
                host_port_part=$(echo "$temp_link" | sed -E 's/^([^/?#]+).*$/\1/')
            fi
            echo "$debug_log_prefix host_port: $host_port_part" >&2

            if [[ "$host_port_part" =~ ^(\[([0-9a-fA-F:]+)\]|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-zA-Z0-9.-]+):([0-9]+)$ ]]; then
                parsed_host="${BASH_REMATCH[2]:-${BASH_REMATCH[1]}}"
                parsed_port="${BASH_REMATCH[3]}"
            fi
            ;;
        hy2|hysteria2)
            local temp_link="${link#*://}"
            local host_port_part=""
            local auth_part=""
            if [[ "$temp_link" == *"@"* ]]; then
                auth_part="${temp_link%%@*}"
                temp_link="${temp_link#*@}"
                echo "$debug_log_prefix 认证: $auth_part" >&2
            fi
            if [[ "$temp_link" =~ \? ]]; then
                host_port_part="${temp_link%%\?*}"
            elif [[ "$temp_link" =~ \# ]]; then
                host_port_part="${temp_link%%\#*}"
            else
                host_port_part="$temp_link"
            fi
            echo "$debug_log_prefix host_port: $host_port_part" >&2

            if [[ "$host_port_part" =~ ^(\[([0-9a-fA-F:]+)\]|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-zA-Z0-9.-]+):([0-9]+)$ ]]; then
                parsed_host="${BASH_REMATCH[2]:-${BASH_REMATCH[1]}}"
                parsed_port="${BASH_REMATCH[3]}"
            else
                echo "警告：无法解析 hy2 host:port: $host_port_part" >&2
            fi
            ;;
        *)
            echo "错误：未知协议: $type" >&2
            ;;
    esac

    parsed_host=$(echo "$parsed_host" | tr -d '\r\n')
    parsed_port=$(echo "$parsed_port" | tr -d '\r\n')

    if [[ -z "$parsed_host" || -z "$parsed_port" ]]; then
        echo "警告：无法解析 host/port: $link (host='$parsed_host', port='$parsed_port')" >&2
        echo "$type,,"
        return
    fi

    echo "$debug_log_prefix 结果: host='$parsed_host', port='$parsed_port'" >&2
    echo "$type,$parsed_host,$parsed_port"
}

# 并行测试节点连接性
test_node_connectivity() {
    local NODE_LINK="$1"
    local LOG_FILE_PATH="$2"
    local OUTPUT_FILE_PATH="$3"
    local CACHE_FILE_PATH="$4"
    local CONNECT_TIMEOUT="$5"

    local PROTOCOL=""
    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""
    local PARSED_DETAILS=""
    local MAX_RETRIES=2
    local RETRY_COUNT=0
    local SUCCESS=false

    echo "DEBUG [test_node_connectivity]: 处理链接: $NODE_LINK" >> "$LOG_FILE_PATH"

    # 子进程加载 DNS 缓存
    declare -A CHILD_DNS_CACHE
    if [ -f "$CACHE_FILE_PATH" ]; then
        if ! jq . "$CACHE_FILE_PATH" >/dev/null 2>&1; then
            echo "警告：[PID $$] 缓存文件 $CACHE_FILE_PATH 无效" >> "$LOG_FILE_PATH"
        else
            mapfile -t CACHE_ENTRIES_CHILD < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip)"' "$CACHE_FILE_PATH" 2>/dev/null)
            for entry in "${CACHE_ENTRIES_CHILD[@]}"; do
                local key=$(echo "$entry" | cut -d' ' -f1)
                local ip_value=$(echo "$entry" | cut -d' ' -f2)
                if [[ -n "$key" && -n "$ip_value" ]]; then
                    CHILD_DNS_CACHE["$key"]="$ip_value"
                    echo "DEBUG [PID $$]: 缓存加载: $key -> $ip_value" >> "$LOG_FILE_PATH"
                fi
            done
        fi
    fi

    # 解析节点配置
    PARSED_DETAILS=$(parse_node_config "$NODE_LINK")
    PROTOCOL=$(echo "$PARSED_DETAILS" | cut -d',' -f1)
    HOSTNAME_OR_IP=$(echo "$PARSED_DETAILS" | cut -d',' -f2)
    PORT=$(echo "$PARSED_DETAILS" | cut -d',' -f3)

    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ] || [ -z "$PROTOCOL" ]; then
        echo "警告：[PID $$] 无法解析: $NODE_LINK" >> "$LOG_FILE_PATH"
        echo "-------------------------------------" >> "$LOG_FILE_PATH"
        return
    fi

    # 获取 IP
    if is_ip_address "$HOSTNAME_OR_IP"; then
        IP="$HOSTNAME_OR_IP"
        echo "DEBUG [PID $$]: 使用直接 IP: $IP" >> "$LOG_FILE_PATH"
    else
        if [[ -n "${CHILD_DNS_CACHE[$HOSTNAME_OR_IP]}" ]]; then
            IP="${CHILD_DNS_CACHE[$HOSTNAME_OR_IP]}"
            echo "DEBUG [PID $$]: 缓存 IP: $HOSTNAME_OR_IP -> $IP" >> "$LOG_FILE_PATH"
        else
            echo "DEBUG [PID $$]: 实时解析: $HOSTNAME_OR_IP" >> "$LOG_FILE_PATH"
            local RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | head -n 1)
            if [ -n "$RESOLVED_IP" ]; then
                IP="$RESOLVED_IP"
                echo "DEBUG [PID $$]: 解析成功: $HOSTNAME_OR_IP -> $IP" >> "$LOG_FILE_PATH"
            else
                echo "警告：[PID $$] 无法解析: $HOSTNAME_OR_IP" >> "$LOG_FILE_PATH"
            fi
        fi
    fi

    if [ -z "$IP" ]; then
        echo "警告：[PID $$] 无有效 IP: $NODE_LINK" >> "$LOG_FILE_PATH"
        echo "-------------------------------------" >> "$LOG_FILE_PATH"
        return
    fi

    echo "测试: $IP:$PORT (协议: $PROTOCOL)" >> "$LOG_FILE_PATH"

    # 测试连接
    while [ $RETRY_COUNT -le $MAX_RETRIES ] && [ "$SUCCESS" = false ]; do
        if [[ "$PROTOCOL" == "hy2" || "$PROTOCOL" == "hysteria2" ]]; then
            echo "DEBUG [PID $$]: UDP 测试: nc -u -z -w $CONNECT_TIMEOUT $IP $PORT" >> "$LOG_FILE_PATH"
            nc -u -z -w "$CONNECT_TIMEOUT" "$IP" "$PORT" >/dev/null 2>&1
        else
            echo "DEBUG [PID $$]: TCP 测试: nc -z -w $CONNECT_TIMEOUT $IP $PORT" >> "$LOG_FILE_PATH"
            nc -z -w "$CONNECT_TIMEOUT" "$IP" "$PORT" >/dev/null 2>&1
        fi

        if [ $? -eq 0 ]; then
            echo "成功：[PID $$] $IP:$PORT" >> "$LOG_FILE_PATH"
            echo "$NODE_LINK" >> "$OUTPUT_FILE_PATH"
            SUCCESS=true
        else
            echo "失败：[PID $$] $IP:$PORT (尝试 $((RETRY_COUNT + 1))/$((MAX_RETRIES + 1)))" >> "$LOG_FILE_PATH"
            ((RETRY_COUNT++))
            if [ $RETRY_COUNT -le $MAX_RETRIES ]; then
                sleep 1
            fi
        fi
    done

    if [ "$SUCCESS" = false ]; then
        echo "最终失败：[PID $$] $IP:$PORT" >> "$LOG_FILE_PATH"
    fi
    echo "-------------------------------------" >> "$LOG_FILE_PATH"
}

# 加载和清理 DNS 缓存
load_and_clean_dns_cache() {
    local CURRENT_TIME="$1"
    echo "加载缓存: $DNS_CACHE_FILE" | tee -a "$LOG_FILE"
    if [ -f "$DNS_CACHE_FILE" ]; then
        if ! jq . "$DNS_CACHE_FILE" >/dev/null 2>&1; then
            echo "警告：缓存文件无效，清空" | tee -a "$LOG_FILE"
            echo "{}" > "$DNS_CACHE_FILE"
        else
            mapfile -t CACHE_ENTRIES < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip) \(.[$key].timestamp)"' "$DNS_CACHE_FILE" 2>/dev/null)
            local LOADED_COUNT=0
            local CLEANED_COUNT=0

            for entry in "${CACHE_ENTRIES[@]}"; do
                local key=$(echo "$entry" | awk '{print $1}')
                local ip_value=$(echo "$entry" | awk '{print $2}')
                local timestamp_value=$(echo "$entry" | awk '{print $3}')

                echo "DEBUG: 解析缓存: '$entry'" | tee -a "$LOG_FILE"
                if [[ -n "$key" && -n "$ip_value" && "$timestamp_value" =~ ^[0-9]+$ ]]; then
                    if (( CURRENT_TIME - timestamp_value < CACHE_EXPIRATION_SECONDS )); then
                        DNS_CACHE["$key"]="$ip_value,$timestamp_value"
                        ((LOADED_COUNT++))
                    else
                        echo "清理过期: $key (过期于 $(date -d "@$timestamp_value"))" | tee -a "$LOG_FILE"
                        ((CLEANED_COUNT++))
                    fi
                else
                    echo "警告：无效缓存条目: '$entry'" | tee -a "$LOG_FILE"
                fi
            done
            echo "加载 $LOADED_COUNT 个条目，清理 $CLEANED_COUNT 个过期条目" | tee -a "$LOG_FILE"
        fi
    else
        echo "创建新缓存" | tee -a "$LOG_FILE"
        echo "{}" > "$DNS_CACHE_FILE"
    fi
}

# 导出函数和变量
export -f test_node_connectivity parse_node_config is_ip_address load_and_clean_dns_cache
export LOG_FILE OUTPUT_FILE DNS_CACHE_FILE NODE_CONNECT_TIMEOUT

# ==============================================================================
# 核心逻辑
# ==============================================================================

echo "开始测试..." | tee "$LOG_FILE"
echo "时间: $(date '+%Y-%m-%d %H:%M:%S JST')" | tee -a "$LOG_FILE"
echo "-------------------------------------" | tee -a "$LOG_FILE"

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR" || { echo "错误：无法创建目录 $OUTPUT_DIR" | tee -a "$LOG_FILE"; exit 1; }

# 初始化输出文件
echo "# Successful Nodes ($(date '+%Y-%m-%d %H:%M:%S JST'))" > "$OUTPUT_FILE"
echo "-------------------------------------" >> "$OUTPUT_FILE"

# 清空临时文件
> "$MERGED_NODES_TEMP_FILE"

echo "下载节点配置..." | tee -a "$LOG_FILE"
DOWNLOAD_SUCCESS=false
for url in "${NODE_SOURCES[@]}"; do
    echo "下载: $url" | tee -a "$LOG_FILE"
    if curl -sL --fail-with-body "$url" >> "$MERGED_NODES_TEMP_FILE" 2>>"$LOG_FILE"; then
        DOWNLOAD_SUCCESS=true
    else
        echo "警告：无法下载: $url" | tee -a "$LOG_FILE"
    fi
done

if [ ! -f "$MERGED_NODES_TEMP_FILE" ] || [ ! -s "$MERGED_NODES_TEMP_FILE" ] || [ "$DOWNLOAD_SUCCESS" = false ]; then
    echo "错误：无法下载节点配置" | tee -a "$LOG_FILE"
    rm -f "$MERGED_NODES_TEMP_FILE"
    exit 1
fi

echo "下载完成" | tee -a "$LOG_FILE"

# 安装依赖
echo "检查依赖..." | tee -a "$LOG_FILE"
sudo apt-get update >/dev/null 2>>"$LOG_FILE" || { echo "错误：apt-get update 失败" | tee -a "$LOG_FILE"; exit 1; }
sudo apt-get install -y dnsutils jq netcat-traditional >/dev/null 2>>"$LOG_FILE" || { echo "错误：依赖安装失败" | tee -a "$LOG_FILE"; exit 1; }
echo "依赖安装完成" | tee -a "$LOG_FILE"

# 加载 DNS 缓存
load_and_clean_dns_cache "$CURRENT_TIME"

echo "预解析域名..." | tee -a "$LOG_FILE"
PRE_RESOLVED_COUNT=0
SKIPPED_DOMAIN_COUNT=0

while IFS= read -r node_link; do
    if [[ -z "$node_link" ]]; then
        continue
    fi
    echo "DEBUG: 处理节点链接: $node_link" >> "$LOG_FILE"
    PARSED_DETAILS=$(parse_node_config "$node_link")
    host=$(echo "$PARSED_DETAILS" | cut -d',' -f2)

    if [[ -n "$host" ]] && ! is_ip_address "$host"; then
        if [[ -z "${DNS_CACHE[$host]}" ]] || (( CURRENT_TIME - $(echo "${DNS_CACHE[$host]}" | cut -d',' -f2) >= CACHE_EXPIRATION_SECONDS )); then
            ALL_DOMAINS_TO_RESOLVE["$host"]=1
        fi
    fi
done < "$MERGED_NODES_TEMP_FILE"

for domain in "${!ALL_DOMAINS_TO_RESOLVE[@]}"; do
    if [[ -n "${DNS_CACHE[$domain]}" ]]; then
        echo "域名 '$domain' 已缓存" | tee -a "$LOG_FILE"
        continue
    fi

    echo "解析: $domain" | tee -a "$LOG_FILE"
    resolved_ip=$(dig +short "$domain" A | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | head -n 1)
    if [[ -n "$resolved_ip" ]]; then
        DNS_CACHE["$domain"]="$resolved_ip,$CURRENT_TIME"
        ((PRE_RESOLVED_COUNT++))
        echo "成功: $domain -> $resolved_ip" | tee -a "$LOG_FILE"
    else
        echo "失败: $domain" | tee -a "$LOG_FILE"
        ((SKIPPED_DOMAIN_COUNT++))
    fi
done
echo "预解析完成: $PRE_RESOLVED_COUNT 成功，$SKIPPED_DOMAIN_COUNT 失败" | tee -a "$LOG_FILE"

# 更新 DNS 缓存
echo "更新缓存..." | tee -a "$LOG_FILE"
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
echo "$json_output" | jq . > "$DNS_CACHE_FILE" 2>>"$LOG_FILE" || { echo "错误：无法写入缓存文件" | tee -a "$LOG_FILE"; exit 1; }
echo "缓存更新完成" | tee -a "$LOG_FILE"

# 并行测试
echo "开始并行测试: $MAX_CONCURRENT_JOBS" | tee -a "$LOG_FILE"
if [ -s "$MERGED_NODES_TEMP_FILE" ]; then
    cat "$MERGED_NODES_TEMP_FILE" | tr '\n' '\0' | xargs -0 -P "$MAX_CONCURRENT_JOBS" -I {} \
        bash -c 'test_node_connectivity "$@"' _ "{}" "$LOG_FILE" "$OUTPUT_FILE" "$DNS_CACHE_FILE" "$NODE_CONNECT_TIMEOUT"
else
    echo "警告：节点文件为空" | tee -a "$LOG_FILE"
fi

# 清理
rm -f "$MERGED_NODES_TEMP_FILE" || { echo "错误：无法删除临时文件" | tee -a "$LOG_FILE"; exit 1; }

echo "测试完成。结果: $LOG_FILE" | tee -a "$LOG_FILE"
echo "成功节点: $OUTPUT_FILE" | tee -a "$LOG_FILE"
