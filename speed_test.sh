#!/bin/bash

LOG_FILE="node_connectivity_results.log"
echo "开始节点连接性测试..." > "$LOG_FILE"
echo "测试时间: $(date)" >> "$LOG_FILE"
echo "-------------------------------------" >> "$LOG_FILE"

echo "下载节点配置文件..."
curl -s -o config_all_merged_nodes.txt https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt

if [ ! -f "config_all_merged_nodes.txt" ]; then
    echo "错误：未能下载 config_all_merged_nodes.txt 文件。" | tee -a "$LOG_FILE"
    exit 1
fi

echo "文件下载成功。开始解析节点并测试连接性..." | tee -a "$LOG_FILE"

# 确保安装了 dnsutils (用于 dig 命令)
sudo apt-get update >/dev/null 2>&1
sudo apt-get install -y dnsutils >/dev/null 2>&1

while IFS= read -r NODE_LINK; do
    # 跳过空行和注释
    [[ -z "$NODE_LINK" || "$NODE_LINK" =~ ^# ]] && continue

    # 重置 IP 和 PORT
    IP=""
    PORT=""
    HOSTNAME=""

    # 尝试提取 VLESS/VMESS/Trojan/Hysteria2 等协议的 IP/Hostname 和 Port
    # 模式: protocol://[user@]IP_OR_HOST:PORT?...
    # 捕获协议头，然后是用户部分(可选)，然后是 IP/主机名和端口
    if [[ "$NODE_LINK" =~ ^(vless|vmess|trojan|hy2):\/\/(.+@)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)(\/?.*) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" == ss://* ]]; then
        # 对于 Shadowsocks (SS) 链接，提取 @ 符号后面的部分，然后 Base64 解码 (如果需要)
        # 尝试从 @hostname:port 或 @ip:port 格式中直接提取
        SS_HOST_PORT=$(echo "$NODE_LINK" | grep -oE '@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+)' | head -n 1)
        if [ -n "$SS_HOST_PORT" ]; then
            HOSTNAME_OR_IP=$(echo "$SS_HOST_PORT" | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$SS_HOST_PORT" | cut -d':' -f2)
        else
            # 如果直接提取失败，尝试 Base64 解码 SS 链接的用户信息部分
            BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_PART" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?|[a-zA-Z0-9.-]+):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    # 检查是否提取到了 IP 或 Hostname 和 Port
    if [ -n "$HOSTNAME_OR_IP" ] && [ -n "$PORT" ]; then
        # 如果是域名，尝试解析为 IP
        if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
            # 已经是 IP 地址
            IP="$HOSTNAME_OR_IP"
        else
            # 是域名，尝试 DNS 解析
            echo "尝试解析域名: $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
            # dig +short 命令获取IP地址，如果有多条记录只取第一条IPv4
            RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
            if [ -n "$RESOLVED_IP" ]; then
                IP="$RESOLVED_IP"
                echo "  - 解析结果: $HOSTNAME_OR_IP -> $IP" | tee -a "$LOG_FILE"
            else
                echo "  - 警告: 无法解析域名 $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
            fi
        fi
    fi

    if [ -z "$IP" ] || [ -z "$PORT" ]; then
        echo "警告：无法从链接中解析 IP 或端口: $NODE_LINK" | tee -a "$LOG_FILE"
        echo "-------------------------------------" | tee -a "$LOG_FILE"
        continue
    fi

    echo "正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)" | tee -a "$LOG_FILE"

    # 使用 nc 进行端口连通性测试
    # -z: 零I/O模式 (扫描端口)
    # -w 3: 超时3秒
    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  - 结果: 成功连接到 $IP:$PORT" | tee -a "$LOG_FILE"
    else
        echo "  - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)" | tee -a "$LOG_FILE"
    fi
    echo "-------------------------------------" | tee -a "$LOG_FILE"
done < config_all_merged_nodes.txt # 从文件中读取每一行

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
