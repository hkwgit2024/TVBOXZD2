#!/bin/bash

# 定义日志文件和成功节点文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data" # 输出目录
OUTPUT_FILE="$OUTPUT_DIR/sub.txt" # 成功节点输出文件
MERGED_NODES_TEMP_FILE="all_merged_nodes_temp.txt" # 临时文件，用于合并所有来源

# 定义所有节点来源URL的数组
# 你可以在这里添加/删除/修改你的节点来源网址
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
  #  "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
  #  "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
  #  "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

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

# 确保安装了 dnsutils (用于 dig 命令)
echo "检查并安装 dnsutils (用于 dig 命令)..." | tee -a "$LOG_FILE"
sudo apt-get update >/dev/null 2>&1
sudo apt-get install -y dnsutils >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "错误：无法安装 dnsutils。请手动安装或检查您的apt配置。" | tee -a "$LOG_FILE"
    exit 1
fi
echo "dnsutils 检查/安装完成。" | tee -a "$LOG_FILE"

# 声明一个关联数组用于存储 DNS 解析缓存
declare -A DNS_CACHE

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

    if [ -n "$HOSTNAME_OR_IP" ] && [ -n "$PORT" ]; then
        # 检查是否为 IP 地址（IPv4 或 IPv6）
        if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
            IP="$HOSTNAME_OR_IP"
        else
            # 检查 DNS 缓存
            if [[ -n "${DNS_CACHE[$HOSTNAME_OR_IP]}" ]]; then
                IP="${DNS_CACHE[$HOSTNAME_OR_IP]}"
                echo "  - 从缓存获取解析结果: $HOSTNAME_OR_IP -> $IP" | tee -a "$LOG_FILE"
            else
                echo "尝试解析域名: $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
                # 使用 dig 解析域名，只取第一个 IPv4 地址
                RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
                if [ -n "$RESOLVED_IP" ]; then
                    IP="$RESOLVED_IP"
                    DNS_CACHE["$HOSTNAME_OR_IP"]="$IP" # 将解析结果存入缓存
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

# 清理临时文件
rm "$MERGED_NODES_TEMP_FILE"

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
echo "成功连接的节点已保存到 $OUTPUT_FILE" | tee -a "$LOG_FILE"
