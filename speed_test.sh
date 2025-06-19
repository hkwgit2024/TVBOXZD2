#!/bin/bash

# 定义日志文件和输出文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"        # 成功节点输出文件
FAILED_FILE="$OUTPUT_DIR/failed_nodes.log" # 失败节点输出文件

# 用于并行处理的临时文件
MERGED_NODES_TEMP_FILE="all_merged_nodes_temp.txt"     # 临时合并文件
PREV_FAILED_LOOKUP_FILE="prev_failed_lookup.tmp"     # 存储上次失败节点的查找文件
# Note: CURRENT_RUN_SUCCESS_TEMP and CURRENT_RUN_FAILED_TEMP are now handled by parallel output redirection

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
    # Add more URLs here
)

# 日志函数
log() {
    local level=$1
    shift
    # Using flock for atomic write to log file
    (
        flock 200 || exit 1
        echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
    ) 200> "$LOG_FILE.lock"
}

# 初始化
log INFO "开始节点连接性测试..."
mkdir -p "$OUTPUT_DIR"

# 清空并初始化输出文件（这些文件将在所有测试完成后被 sort -u 重新填充）
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" > "$FAILED_FILE"
echo "-------------------------------------" >> "$FAILED_FILE"

# 清空临时合并文件
> "$MERGED_NODES_TEMP_FILE"

# 检查依赖
command -v dig >/dev/null 2>&1 || { log ERROR "dig 命令未找到，请确保安装 dnsutils"; exit 1; }
command -v nc >/dev/null 2>&1 || { log ERROR "nc 命令未找到，请确保安装 netcat-openbsd"; exit 1; }
command -v parallel >/dev/null 2>&1 || { log WARN "parallel 命令未找到，将使用串行执行（建议在 .github/workflows/connectivity-test.yml 中添加安装步骤：sudo apt-get install -y parallel）"; }

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

log INFO "所有配置文件下载并合并成功，开始解析节点并测试连接性..."

# 加载上一次的失败节点到临时查找文件
log INFO "加载上次运行中失败的节点列表..."
if [ -f "$FAILED_FILE" ]; then
    # Filter out header/comment lines from previous FAILED_FILE
    grep -vE '^(#|--|$)' "$FAILED_FILE" > "$PREV_FAILED_LOOKUP_FILE"
    log INFO "已加载 $(wc -l < "$PREV_FAILED_LOOKUP_FILE") 个历史失败节点用于跳过"
else
    log INFO "未找到上次失败的节点列表 ($FAILED_FILE)，所有节点将被测试。"
    > "$PREV_FAILED_LOOKUP_FILE" # Create an empty file
fi

# 解析和测试节点函数
# This function now prints a prefixed string to stdout based on result
# SUCCESS: NODE_LINK
# FAILED:NODE_LINK
# SKIPPED:NODE_LINK
# LOG:message (for internal logging)
test_node() {
    local NODE_LINK="$1"
    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""

    # Redirect logs from sub-process to the main log file
    # This is important for parallel execution to centralize logs
    exec 1>>"$LOG_FILE" 2>&1

    # Skip empty lines, comments, and separator lines
    [[ -z "$NODE_LINK" || "$NODE_LINK" =~ ^# || "$NODE_LINK" =~ ^-*$ ]] && return

    # Check if this node was previously marked as failed
    # We pass PREV_FAILED_LOOKUP_FILE as an argument or global env for parallel
    if grep -q -F -x "$NODE_LINK" "$PREV_FAILED_LOOKUP_FILE"; then
        echo "SKIPPED:$NODE_LINK" # Indicate it was skipped
        echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - 跳过已知的失败节点: $NODE_LINK"
        return
    fi

    # Extract IP/Hostname and Port
    if [[ "$NODE_LINK" =~ ^(vless|vmess|trojan|hy2):\/\/(.+@)?([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]*\]?):([0-9]+) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" =~ ^ss:// ]]; then
        SS_HOST_PORT=$(echo "$NODE_LINK" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]*\]?):([0-9]+)' | head -n 1)
        if [ -n "$SS_HOST_PORT" ]; then
            HOSTNAME_OR_IP=$(echo "$SS_HOST_PORT" | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$SS_HOST_PORT" | cut -d':' -f2)
        else
            BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
            if [[ "$DECODED_PART" =~ ([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]*\]?):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
        echo "FAILED:$NODE_LINK" # Indicate failure
        echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - 无法从链接中解析 IP 或端口: $NODE_LINK"
        return
    fi

    # Resolve hostname
    if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
        IP="$HOSTNAME_OR_IP"
    else
        echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - 尝试解析域名: $HOSTNAME_OR_IP"
        RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A "$HOSTNAME_OR_IP" AAAA | head -n 1)
        if [ -n "$RESOLVED_IP" ]; then
            IP="$RESOLVED_IP"
            echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') -   - 解析结果: $HOSTNAME_OR_IP -> $IP"
        else
            echo "FAILED:$NODE_LINK" # Indicate failure
            echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') -   - 无法解析域名: $HOSTNAME_OR_IP"
            return
        fi
    fi
    
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - 正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)"
    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$NODE_LINK" # Print successful node link
        echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') -   - 结果: 成功连接到 $IP:$PORT"
    else
        echo "FAILED:$NODE_LINK" # Indicate failure
        echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') -   - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)"
    fi
}

# Export variables and function for parallel
export -f test_node log
export LOG_FILE PREV_FAILED_LOOKUP_FILE

# Test nodes (use parallel if available, otherwise sequentially)
if command -v parallel >/dev/null 2>&1; then
    log INFO "使用 parallel 并行测试节点（并发数：10）"
    # Use --pipe to read from stdin, --colsep '\n' for line-by-line argument
    # --results to redirect stdout/stderr of parallel to specific files
    # We will process stdout for SUCCESS/FAILED/SKIPPED prefixes
    cat "$MERGED_NODES_TEMP_FILE" | \
    parallel -j 10 --pipe \
    'test_node {}' | \
    while IFS= read -r result_line; do
        if [[ "$result_line" == "SKIPPED:"* ]]; then
            echo "${result_line#SKIPPED:}" >> "$FAILED_FILE" # Skipped nodes go to FAILED
        elif [[ "$result_line" == "FAILED:"* ]]; then
            echo "${result_line#FAILED:}" >> "$FAILED_FILE" # Failed nodes go to FAILED
        elif [[ -n "$result_line" ]]; then
            echo "$result_line" >> "$SUCCESS_FILE" # Successful nodes go to SUCCESS
        fi
    done
else
    log INFO "使用串行测试节点"
    while IFS= read -r line; do
        test_node "$line"
    done < "$MERGED_NODES_TEMP_FILE" | \
    while IFS= read -r result_line; do
        if [[ "$result_line" == "SKIPPED:"* ]]; then
            echo "${result_line#SKIPPED:}" >> "$FAILED_FILE"
        elif [[ "$result_line" == "FAILED:"* ]]; then
            echo "${result_line#FAILED:}" >> "$FAILED_FILE"
        elif [[ -n "$result_line" ]]; then
            echo "$result_line" >> "$SUCCESS_FILE"
        fi
    done
fi

# Cleanup temporary files
rm -f "$MERGED_NODES_TEMP_FILE" "$PREV_FAILED_LOOKUP_FILE"

# Final processing of output files to ensure unique entries and proper headers
# Remove initial headers and re-add them after sorting and unique-ing
tail -n +3 "$SUCCESS_FILE" | sort -u > "${SUCCESS_FILE}.tmp"
mv "${SUCCESS_FILE}.tmp" "$SUCCESS_FILE"
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" | cat - "$SUCCESS_FILE" > "${SUCCESS_FILE}.tmp" && mv "${SUCCESS_FILE}.tmp" "$SUCCESS_FILE"
echo "-------------------------------------" | cat - "$SUCCESS_FILE" > "${SUCCESS_FILE}.tmp" && mv "${SUCCESS_FILE}.tmp" "$SUCCESS_FILE"


tail -n +3 "$FAILED_FILE" | sort -u > "${FAILED_FILE}.tmp"
mv "${FAILED_FILE}.tmp" "$FAILED_FILE"
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" | cat - "$FAILED_FILE" > "${FAILED_FILE}.tmp" && mv "${FAILED_FILE}.tmp" "$FAILED_FILE"
echo "-------------------------------------" | cat - "$FAILED_FILE" > "${FAILED_FILE}.tmp" && mv "${FAILED_FILE}.tmp" "$FAILED_FILE"


log INFO "所有节点连接性测试完成。成功节点已保存到 $SUCCESS_FILE"
log INFO "失败节点已保存到 $FAILED_FILE"

# Statistics (count lines in the final files, excluding headers)
total_merged_nodes=$(grep -vE '^(#|--|$)' "$MERGED_NODES_TEMP_FILE" 2>/dev/null | wc -l || echo 0)
success_nodes_count=$(grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null | wc -l || echo 0)
failed_nodes_count=$(grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null | wc -l || echo 0)

log INFO "测试统计："
log INFO "  - 源文件总节点数 (去重后待测试): $(cat "$MERGED_NODES_TEMP_FILE" | grep -vE '^(#|--|$)' | sort -u | wc -l || echo 0)" # More accurate count of unique nodes from source
log INFO "  - 成功连接节点数: $success_nodes_count"
log INFO "  - 失败/跳过节点数: $failed_nodes_count"

# --- Git Push Logic ---
log INFO "开始将结果推送到 GitHub 仓库..."

# Configure Git
git config user.name "GitHub Actions"
git config user.email "actions@github.com"

# Check for changes
if git diff --quiet --exit-code HEAD "$SUCCESS_FILE" "$FAILED_FILE"; then
    log INFO "成功节点和失败节点文件无更改，无需提交"
else
    git add "$SUCCESS_FILE" "$FAILED_FILE"
    git commit -m "Update node connectivity results (automated by GitHub Actions)" || true # || true to prevent script failure if no changes
    git remote set-url origin "https://x-access-token:${GH_TOKEN_FOR_PUSH}@github.com/${GITHUB_REPOSITORY}.git"
    git push origin HEAD:${GITHUB_REF##*/} || {
        log ERROR "推送失败，请检查 Git 配置或网络连接"
        exit 1
    }
    log INFO "成功节点和失败节点已推送到 GitHub 仓库"
fi

log INFO "节点连接性测试和推送流程完成。"
