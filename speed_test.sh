#!/bin/bash

# 定义日志文件和成功节点文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data" # 输出目录
OUTPUT_FILE="$OUTPUT_DIR/sub.txt" # 成功节点输出文件

echo "开始节点连接性测试..." > "$LOG_FILE"
echo "测试时间: $(date)" >> "$LOG_FILE"
echo "-------------------------------------" >> "$LOG_FILE"

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 清空并初始化成功节点文件
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$OUTPUT_FILE"
echo "-------------------------------------" >> "$OUTPUT_FILE"

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

    IP=""
    PORT=""
    HOSTNAME=""

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
        if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
            IP="$HOSTNAME_OR_IP"
        else
            echo "尝试解析域名: $HOSTNAME_OR_IP" | tee -a "$LOG_FILE"
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

    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  - 结果: 成功连接到 $IP:$PORT" | tee -a "$LOG_FILE"
        echo "$NODE_LINK" >> "$OUTPUT_FILE" # 将成功连接的完整节点链接保存到指定的输出文件
    else
        echo "  - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)" | tee -a "$LOG_FILE"
    fi
    echo "-------------------------------------" | tee -a "$LOG_FILE"
done < config_all_merged_nodes.txt

echo "所有节点连接性测试完成。结果已保存到 $LOG_FILE" | tee -a "$LOG_FILE"
echo "成功连接的节点已保存到 $OUTPUT_FILE" | tee -a "$LOG_FILE"

# --- Git 推送逻辑 ---
echo "开始将成功节点推送到 GitHub 仓库..." | tee -a "$LOG_FILE"

# 配置 Git
git config user.name "GitHub Actions"
git config user.email "actions@github.com"

# 添加文件并提交
# 确保添加的是 data/sub.txt
git add "$OUTPUT_FILE"
# 使用 || true 防止在没有更改时导致 commit 失败
git commit -m "Update successful nodes in data/sub.txt (automated by GitHub Actions)" || true

# 推送更改 (使用 GITHUB_TOKEN)
# GITHUB_TOKEN 是 GitHub Actions 自动提供的，通常具有足够的权限来推送到当前仓库的非保护分支
# 它不需要额外在 Secrets 中创建
git remote set-url origin "https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${GITHUB_REPOSITORY}.git"
git push origin HEAD:${GITHUB_REF##*/} # 推送到当前分支

echo "成功节点已推送到 GitHub 仓库。" | tee -a "$LOG_FILE"
