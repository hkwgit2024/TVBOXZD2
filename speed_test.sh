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

# 定义所有节点来源URL的数组
# 你可以在这里添加/删除/修改你的节点来源网址
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
  #  "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
   # "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
  #  "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

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

# 清空临时合并文件
> "$MERGED_NODES_TEMP_FILE"

echo "下载并合并节点配置文件..."
for url in "${NODE_SOURCES[@]}"; do
    echo "正在下载: $url" | tee -a "$LOG_FILE"
    # 使用 curl -sL 确保跟随重定向，并将内容追加到临时文件
    curl -sL "$url" >> "$MERGED_NODES_TEMP_FILE"
    if [ $? -ne 0 ]; then
        echo "警告：未能从 $url 下载文件。" | tee -a "$LOG_FILE"
    fi
done

# 检查合并后的临时文件是否为空
if [ ! -s "$MERGED_NODES_TEMP_FILE" ]; then
    echo "错误：未能下载任何节点配置文件，或所有文件都为空。" | tee -a "$LOG_FILE"
    exit 1
fi

echo "所有配置文件下载并合并成功。开始解析节点并测试连接性..." | tee -a "$LOG_FILE"

# 确保安装了 dnsutils (用于 dig 命令) 和 jq (用于处理 JSON)
echo "检查并安装 dnsutils 和 jq..." | tee -a "$LOG_FILE"
# 为了避免输出过多信息到日志，将 apt-get 的输出重定向到 /dev/null
sudo apt-get update >/dev/null 2>&1
sudo apt-get install -y dnsutils jq >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "错误：无法安装 dnsutils 或 jq。请手动安装或检查您的apt配置。" | tee -a "$LOG_FILE"
    exit 1
fi
echo "dnsutils 和 jq 检查/安装完成。" | tee -a "$LOG_FILE"

# 声明一个关联数组用于存储 DNS 解析缓存
# 缓存的值是 "IP地址,时间戳" 格式的字符串
declare -A DNS_CACHE

# 尝试从缓存文件加载旧的 DNS 缓存
if [ -f "$DNS_CACHE_FILE" ]; then
    echo "从 $DNS_CACHE_FILE 加载 DNS 缓存并清理过期条目..." | tee -a "$LOG_FILE"
    CURRENT_TIME=$(date +%s) # 获取当前 Unix 时间戳

    # 使用 jq 解析 JSON 文件并填充 Bash 关联数组
    # jq -r 确保输出是原始字符串，没有额外的引号
    # 对于每个键值对，提取域名、IP和时间戳
    mapfile -t CACHE_ENTRIES < <(jq -r 'keys[] as $key | "\($key) \(.[$key].ip) \(.[$key].timestamp)"' "$DNS_CACHE_FILE" 2>/dev/null)
    
    LOADED_COUNT=0
    CLEANED_COUNT=0

    for entry in "${CACHE_ENTRIES[@]}"; do
        # 提取域名、IP和时间戳
        key=$(echo "$entry" | cut -d' ' -f1)
        ip_value=$(echo "$entry" | cut -d' ' -f2)
        timestamp_value=$(echo "$entry" | cut -d' ' -f3)

        # 验证提取的值是否有效
        if [[ -n "$key" && -n "$ip_value" && "$timestamp_value" =~ ^[0-9]+$ ]]; then
            # 检查时间戳是否过期
            if (( CURRENT_TIME - timestamp_value < CACHE_EXPIRATION_SECONDS )); then
                DNS_CACHE["$key"]="$ip_value,$timestamp_value" # 存入缓存
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


while IFS= read -r NODE_LINK; do
    # 跳过空行和注释
    [[ -z "$NODE_LINK" || "$NODE_LINK" =~ ^# ]] && continue

    IP=""
    PORT=""
    HOSTNAME_OR_IP=""

    # 尝试提取 VLESS/VMESS/Trojan/Hysteria2 等协议的 IP/Hostname 和 Port
    if [[ "$NODE_LINK" =~ ^(vless|vmess|trojan|hy2):\/\/(.+@)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)(\/?.*) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" == ss://* ]]; then
        # 修正：处理 ss:// 链接，特别是 base64 编码的
        SS_HOST_PORT=$(echo "$NODE_LINK" | grep -oE '@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)' | head -n 1)
        if [ -n "$SS_HOST_PORT" ]; then
            HOSTNAME_OR_IP=$(echo "$SS_HOST_PORT" | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$SS_HOST_PORT" | cut -d':' -f2)
        else
            # 尝试解码 base64 部分来获取 host:port
            BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_PART" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    if [ -n "$HOSTNAME_OR_IP" ] && [ -n "$PORT" ]; then
        # 检查是否为 IP 地址（IPv4 或 IPv6）
        if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
            IP="$HOSTNAME_OR_IP"
        else
            # 检查 DNS 缓存
            if [[ -n "${DNS_CACHE[$HOSTNAME_OR_IP]}" ]]; then
                # 从缓存中取出 IP 和时间戳
                cached_data="${DNS_CACHE[$HOSTNAME_OR_IP]}"
                cached_ip=$(echo "$cached_data" | cut -d',' -f1)
                cached_timestamp=$(echo "$cached_data" | cut -d',' -f2)

                # 再次检查缓存是否过期 (虽然加载时已清理，但以防万一或缓存期内有再次更新)
                CURRENT_TIME=$(date +%s)
                if (( CURRENT_TIME - cached_timestamp < CACHE_EXPIRATION_SECONDS )); then
                    IP="$cached_ip"
                    echo "  - 从缓存获取解析结果: $HOSTNAME_OR_IP -> $IP" | tee -a "$LOG_FILE"
                else
                    # 缓存过期，需要重新解析
                    echo "  - 缓存过期，重新解析域名: $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
                    RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
                    if [ -n "$RESOLVED_IP" ]; then
                        IP="$RESOLVED_IP"
                        NEW_TIMESTAMP=$(date +%s)
                        DNS_CACHE["$HOSTNAME_OR_IP"]="$IP,$NEW_TIMESTAMP" # 更新缓存
                        echo "  - 重新解析并更新缓存: $HOSTNAME_OR_IP -> $IP" | tee -a "$LOG_FILE"
                    else
                        echo "  - 警告: 无法解析域名 $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
                    fi
                fi
            else
                echo "尝试解析域名: $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
                RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
                if [ -n "$RESOLVED_IP" ]; then
                    IP="$RESOLVED_IP"
                    NEW_TIMESTAMP=$(date +%s)
                    DNS_CACHE["$HOSTNAME_OR_IP"]="$IP,$NEW_TIMESTAMP" # 将解析结果和时间戳存入缓存
                    echo "  - 解析结果并存入缓存: $HOSTNAME_OR_IP -> $IP" | tee -a "$LOG_FILE"
                else
                    echo "  - 警告: 无法解析域名 $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
                fi
            fi
        fi
    fi

    if [ -z "$IP" ] || [ -z "$PORT" ]; then
        echo "警告：无法从链接中解析 IP 或端口 (或域名无法解析): $NODE_LINK" | tee -a "$LOG_FILE"
        echo "-------------------------------------" | tee -a "$LOG_FILE"
        continue
    fi

    echo "正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)" | tee -a "$LOG_FILE"

    # 使用 nc 命令测试连接性，超时时间为 3 秒
    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  - 结果: 成功连接到 $IP:$PORT" | tee -a "$LOG_FILE"
        echo "$NODE_LINK" >> "$OUTPUT_FILE" # 将成功连接的完整节点链接保存到指定的输出文件
    else
        echo "  - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)" | tee -a "$LOG_FILE"
    fi
    echo "-------------------------------------" | tee -a "$LOG_FILE"
done < "$MERGED_NODES_TEMP_FILE" # 从合并后的临时文件读取节点链接

# ==============================================================================
# 脚本清理和结束
# ==============================================================================

# 在脚本结束前，将当前的 DNS 缓存保存到文件
echo "保存 DNS 缓存到 $DNS_CACHE_FILE..." | tee -a "$LOG_FILE"
json_output="{"
first_entry=true
for key in "${!DNS_CACHE[@]}"; do
    if [ "$first_entry" = true ]; then
        first_entry=false
    else
        json_output+=","
    fi
    # 拆分 IP 和时间戳
    cached_data="${DNS_CACHE[$key]}"
    ip_val=$(echo "$cached_data" | cut -d',' -f1)
    timestamp_val=$(echo "$cached_data" | cut -d',' -f2)

    # 格式化为 JSON 对象
    # 这里对 key 和 ip_val 进行 JSON 转义，防止特殊字符导致 JSON 格式错误
    # 但由于通常域名和IP不会包含复杂的JSON特殊字符，直接使用即可。
    # 更严谨的做法是使用 printf %q 或其他方式进行转义。
    json_output+="\"$key\":{\"ip\":\"$ip_val\",\"timestamp\":$timestamp_val}"
done
json_output+="}"
# 使用 jq 格式化并写入文件，2>/dev/null 隐藏可能的 jq 错误信息（例如空对象）
echo "$json_output" | jq . > "$DNS_CACHE_FILE" 2>/dev/null
echo "DNS 缓存保存完成。" | tee -a "$LOG_FILE"


# 清理临时文件
rm "$MERGED_NODES_TEMP_FILE"

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
echo "成功连接的节点已保存到 $OUTPUT_FILE" | tee -a "$LOG_FILE"
