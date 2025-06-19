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

# 读取文件内容，并尝试提取 IP 地址和端口
# 这个解析逻辑现在更复杂，尝试覆盖 VLESS/VMESS/SS/Trojan 链接中的 IP:Port 部分
# 考虑多种模式: @IP:PORT, IPv6 [::]:PORT, URL编码等
# 使用 awk 来更可靠地提取
while IFS= read -r NODE_LINK; do
    # 跳过空行
    [[ -z "$NODE_LINK" ]] && continue

    # 从链接中提取 IP 和 Port
    # 优先匹配 @IP:PORT 模式
    # 然后匹配协议头后的 IP:PORT (针对那些没有@的)
    # 对于 SS 链接，IP和Port在 @ 后面，并且可能是 Base64 解码后的
    # 这个正则表达式尝试捕获 IPV4, IPV6 和端口
    IP_PORT_MATCH=$(echo "$NODE_LINK" | grep -oE '(@[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|@[0-9a-fA-F:\[\]]+):([0-9]{1,5})' | head -n 1)
    
    # 如果没匹配到 @IP:PORT，尝试匹配协议头后的第一个 IP:PORT
    if [ -z "$IP_PORT_MATCH" ]; then
        IP_PORT_MATCH=$(echo "$NODE_LINK" | grep -oE '(vless|vmess|ss|trojan)://([^/]+)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:\[\]]+):([0-9]{1,5})' | head -n 1)
        # 从这个匹配中再提取IP和端口
        IP=$(echo "$IP_PORT_MATCH" | sed -E 's/.*(vless|vmess|ss|trojan):\/\/([^/]+)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:\[\]]+):([0-9]{1,5}).*/\3/')
        PORT=$(echo "$IP_PORT_MATCH" | sed -E 's/.*(vless|vmess|ss|trojan):\/\/([^/]+)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:\[\]]+):([0-9]{1,5}).*/\4/')
    else
        # 从 @IP:PORT 匹配中提取
        IP=$(echo "$IP_PORT_MATCH" | cut -d'@' -f2 | cut -d':' -f1)
        PORT=$(echo "$IP_PORT_MATCH" | cut -d':' -f2)
    fi

    # 尝试解码 SS 链接，因为有时 IP 和端口在 base64 编码中
    if [[ "$NODE_LINK" == ss://* ]]; then
        BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
        DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then # 如果解码成功
            DECODED_IP=$(echo "$DECODED_PART" | grep -oE '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:\[\]]+)' | head -n 1)
            DECODED_PORT=$(echo "$DECODED_PART" | grep -oE ':([0-9]{1,5})' | tail -n 1 | cut -d':' -f2)
            if [ -n "$DECODED_IP" ] && [ -n "$DECODED_PORT" ]; then
                IP="$DECODED_IP"
                PORT="$DECODED_PORT"
            fi
        fi
        # 再次尝试从原始链接的 @ 后面提取，防止 base64 解析失败
        IP_FROM_RAW=$(echo "$NODE_LINK" | grep -oE '@([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:\[\]]+):([0-9]{1,5})' | head -n 1 | cut -d'@' -f2 | cut -d':' -f1)
        PORT_FROM_RAW=$(echo "$NODE_LINK" | grep -oE '@([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:\[\]]+):([0-9]{1,5})' | head -n 1 | cut -d':' -f2)
        if [ -n "$IP_FROM_RAW" ] && [ -n "$PORT_FROM_RAW" ]; then
            IP="$IP_FROM_RAW"
            PORT="$PORT_FROM_RAW"
        fi
    fi

    if [ -z "$IP" ] || [ -z "$PORT" ]; then
        echo "警告：无法从链接中解析 IP 或端口: $NODE_LINK" | tee -a "$LOG_FILE"
        echo "-------------------------------------" | tee -a "$LOG_FILE"
        continue
    fi

    echo "正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)" | tee -a "$LOG_FILE"

    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  - 结果: 成功连接到 $IP:$PORT" | tee -a "$LOG_FILE"
    else
        echo "  - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)" | tee -a "$LOG_FILE"
    fi
    echo "-------------------------------------" | tee -a "$LOG_FILE"
done < config_all_merged_nodes.txt # 从文件中读取每一行

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
