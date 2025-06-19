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
# 这个解析逻辑非常粗略，仅用于示例，你可能需要根据实际情况精细调整
# 假设格式是 protocol://user@ip:port?... 或 ss://base64encoded@ip:port?...
# 我们尝试匹配 common.
grep -oE "(vless|vmess|ss|trojan)://([^@]+@)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?):([0-9]+)" config_all_merged_nodes.txt | while read -r NODE_LINK; do
    # 提取 IP 和 Port
    IP=$(echo "$NODE_LINK" | grep -oE "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[?[0-9a-fA-F:]+\]?)" | head -n 1)
    PORT=$(echo "$NODE_LINK" | grep -oE ":([0-9]+)" | tail -n 1 | cut -d':' -f2)

    if [ -z "$IP" ] || [ -z "$PORT" ]; then
        echo "警告：无法从链接中解析 IP 或端口: $NODE_LINK" | tee -a "$LOG_FILE"
        continue
    fi

    echo "正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)" | tee -a "$LOG_FILE"

    # 使用 curl 测试连接性 (只连接不传输数据)
    # -v: 详细输出 (可以移除)
    # --connect-timeout: 连接超时
    # --max-time: 最大传输时间
    # -I: 只获取 HTTP 头，对于非 HTTP 服务会报错但仍会尝试连接
    # -s: 静默模式
    # -o /dev/null: 输出到空
    # --retry: 重试
    # --retry-delay: 重试延迟
    # 注意：对于非 HTTP(S) 服务，curl 可能会报错，但连接本身可能成功
    # 更好的方式是使用 nc
    
    # 尝试使用 netcat 进行端口连通性测试
    # -z: 零I/O模式 (扫描端口)
    # -w 3: 超时3秒
    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  - 结果: 成功连接到 $IP:$PORT" | tee -a "$LOG_FILE"
    else
        echo "  - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)" | tee -a "$LOG_FILE"
    fi
    echo "-------------------------------------" | tee -a "$LOG_FILE"
done

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
