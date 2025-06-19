#!/bin/bash

# 定义日志文件和输出文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"        # 成功节点输出文件
FAILED_FILE="$OUTPUT_DIR/failed_nodes.log" # 失败节点输出文件
MERGED_NODES_TEMP_FILE="all_merged_nodes_temp.txt" # 临时文件，用于合并所有来源

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
)

# 日志函数
log() {
    local level=$1 # INFO, WARN, ERROR
    shift
    echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# 定义关联数组存储上次失败的节点
declare -A FAILED_NODES
SKIPPED_COUNT=0

# 读取上次失败的节点（如果文件存在）
load_failed_nodes() {
    if [ -f "$FAILED_FILE" ]; then
        log INFO "读取上次失败的节点文件: $FAILED_FILE"
        while IFS= read -r node; do
            # 跳过空行、注释和分隔符
            [[ -z "$node" || "$node" =~ ^# || "$node" =~ ^-*$ ]] && continue
            # 使用节点链接作为键，标记为失败
            FAILED_NODES["$node"]=1
        done < "$FAILED_FILE"
        log INFO "加载了 ${#FAILED_NODES[@]} 个上次失败的节点"
    else
        log INFO "未找到上次失败的节点文件: $FAILED_FILE"
    fi
}

# 初始化
log INFO "开始节点连接性测试..."
mkdir -p "$OUTPUT_DIR"

# 清空并初始化输出文件
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" > "$FAILED_FILE"
echo "-------------------------------------" >> "$FAILED_FILE"

# 清空临时合并文件
> "$MERGED_NODES_TEMP_FILE"

# 检查依赖
command -v dig >/dev/null 2>&1 || {
    log ERROR "dig 命令未找到，请确保安装 dnsutils（例如：sudo apt-get install dnsutils）"
    exit 1
}
command -v nc >/dev/null 2>&1 || {
    log ERROR "nc 命令未找到，请确保安装 netcat（例如：sudo apt-get install netcat）"
    exit 1
}

# 加载上次失败的节点
load_failed_nodes

# 下载并合并节点配置文件
log INFO "下载并合并节点配置文件..."
for url in "${NODE_SOURCES[@]}"; do
    log INFO "  - 正在下载: $url"
    curl -sL --retry 3 --retry-delay 2 "$url" >> "$MERGED_NODES_TEMP_FILE"
    if [ $? -ne 0 ]; then
        log WARN "  - 未能从 $url 下载文件"
    fi
done

# 检查合并后的临时文件是否为空
if [ ! -s "$MERGED_NODES_TEMP_FILE" ]; then
    log ERROR "未能下载任何节点配置文件，或所有文件都为空"
    exit 1
fi

# 去重合并后的节点
sort -u "$MERGED_NODES_TEMP_FILE" -o "$MERGED_NODES_TEMP_FILE"
log INFO "所有配置文件下载并合并成功（去重后），开始解析节点并测试连接性..."

# 读取合并后的临时文件，逐行测试节点
while IFS= read -r NODE_LINK; do
    # 跳过空行和注释
    [[ -z "$NODE_LINK" || "$NODE_LINK" =~ ^# || "$NODE_LINK" =~ ^-*$ ]] && continue

    # 检查是否为上次失败的节点
    if [[ -n "${FAILED_NODES[$NODE_LINK]}" ]]; then
        log INFO "跳过上次失败的节点: $NODE_LINK"
        ((SKIPPED_COUNT++))
        echo "$NODE_LINK" >> "$FAILED_FILE" # 重新写入失败文件以保持记录
        continue
    fi

    IP=""
    PORT=""
    HOSTNAME_OR_IP=""

    # 提取 IP/Hostname 和 Port
    if [[ "$NODE_LINK" =~ ^(vless|vmess|trojan|hy2):\/\/(.+@)?([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" =~ ^ss:// ]]; then
        SS_HOST_PORT=$(echo "$NODE_LINK" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+)' | head -n 1)
        if [ -n "$SS_HOST_PORT" ]; then
            HOSTNAME_OR_IP=$(echo "$SS_HOST_PORT" | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$SS_HOST_PORT" | cut -d':' -f2)
        else
            BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_PART" =~ ([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    if [ -n "$HOSTNAME_OR_IP" ] && [ -n "$PORT" ]; then
        # 如果是 IP 地址（IPv4 或 IPv6），直接使用
        if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
            IP="$HOSTNAME_OR_IP"
        else
            # 否则，解析域名
            log INFO "尝试解析域名: $HOSTNAME_OR_IP"
            RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A "$HOSTNAME_OR_IP" AAAA | head -n 1)
            if [ -n "$RESOLVED_IP" ]; then
                IP="$RESOLVED_IP"
                log INFO "  - 解析结果: $HOSTNAME_OR_IP -> $IP"
            else
                log WARN "  - 无法解析域名: $HOSTNAME_OR_IP"
                echo "$NODE_LINK" >> "$FAILED_FILE"
                continue
            fi
        fi
    else
        log WARN "无法从链接中解析 IP 或端口: $NODE_LINK"
        echo "$NODE_LINK" >> "$FAILED_FILE"
        continue
    fi

    log INFO "正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)"
    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log INFO "  - 结果: 成功连接到 $IP:$PORT"
        echo "$NODE_LINK" >> "$SUCCESS_FILE"
    else
        log WARN "  - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)"
        echo "$NODE_LINK" >> "$FAILED_FILE"
    fi
done < "$MERGED_NODES_TEMP_FILE"

# 清理临时文件
rm -f "$MERGED_NODES_TEMP_FILE"

log INFO "所有节点连接性测试完成。成功节点已保存到 $SUCCESS_FILE"
log INFO "失败节点已保存到 $FAILED_FILE"

# 统计信息
success_nodes_count=$(grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null | wc -l || echo 0)
failed_nodes_count=$(grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null | wc -l || echo 0)

log INFO "测试统计："
log INFO "  - 成功连接节点数: $success_nodes_count"
log INFO "  - 失败节点数: $failed_nodes_count"
log INFO "  - 跳过节点数: $SKIPPED_COUNT"

# --- Git 推送逻辑 ---
log INFO "开始将结果推送到 GitHub 仓库..."

# 配置 Git
git config user.name "GitHub Actions"
git config user.email "actions@github.com"

# 检查是否有更改
if git diff --quiet --exit-code HEAD "$SUCCESS_FILE" "$FAILED_FILE"; then
    log INFO "成功节点和失败节点文件无更改，无需提交"
else
    git add "$SUCCESS_FILE" "$FAILED_FILE"
    git commit -m "Update node connectivity results (automated by GitHub Actions)" || true
    git remote set-url origin "https://x-access-token:${GH_TOKEN_FOR_PUSH}@github.com/${GITHUB_REPOSITORY}.git"
    git push origin HEAD:${GITHUB_REF##*/} || {
        log ERROR "推送失败，请检查 Git 配置或网络"
        exit 1
    }
    log INFO "成功节点和失败节点已推送到 GitHub 仓库"
fi

log INFO "节点连接性测试和推送流程完成。"
