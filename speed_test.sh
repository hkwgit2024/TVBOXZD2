#!/bin/bash
echo "Script started at $(date)" # 保留这行来确认脚本启动
# 定义日志文件和输出文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"
FAILED_FILE="$OUTPUT_DIR/failed_nodes.log"
MERGED_NODES_TEMP_FILE=$(mktemp)
ALL_TEST_RESULTS_TEMP_FILE=$(mktemp)
CURRENT_RUN_SUCCESS_TEMP_FILE=$(mktemp)
CURRENT_RUN_FAILED_TEMP_FILE=$(mktemp)

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
)

# 配置参数
PARALLEL_JOBS=20
CONNECT_TIMEOUT=5
DEBUG=${DEBUG:-false}

# 日志函数
log() {
    local level=$1
    shift
    echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_FILE"
}

log_debug() {
    if [ "$DEBUG" = "true" ]; then
        log INFO "$@"
    fi
}

# 定义关联数组存储上次失败的节点
declare -A FAILED_NODES
SKIPPED_COUNT=0

# 读取上次失败的节点
load_failed_nodes() {
    if [ -f "$FAILED_FILE" ]; then
        log INFO "读取上次失败的节点文件: $FAILED_FILE"
        while IFS= read -r node; do
            [[ -z "$node" || "$node" =~ ^# || "$node" =~ ^-*$ ]] && continue
            FAILED_NODES["$node"]=1
        done < "$FAILED_FILE"
        log INFO "加载了 ${#FAILED_NODES[@]} 个上次失败的节点"
        if [ ${#FAILED_NODES[@]} -gt 10000 ]; then
            log WARN "失败节点数过多 (${#FAILED_NODES[@]})，清空历史失败节点"
            unset FAILED_NODES
            declare -A FAILED_NODES
        fi
    else
        log INFO "未找到上次失败的节点文件: $FAILED_FILE"
    fi
}

# 检查依赖
check_dependencies() {
    for cmd in dig nc curl sort wc base64 jq; do
        command -v "$cmd" >/dev/null 2>&1 || {
            log ERROR "$cmd 命令未找到，请确保安装（例如：sudo apt-get install $cmd）"
            exit 1
        }
    done
    # 设置 DNS 缓存
    echo "nameserver 8.8.8.8" > /tmp/resolv.conf
    export RESOLV_CONF=/tmp/resolv.conf
}

# 测试单个节点连接性
test_single_node() {
    local NODE_LINK="$1"
    local LOG_PREFIX="[TEST]"
    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""

    if [[ "$NODE_LINK" =~ ^(hysteria2|vless|trojan):\/\/(.+@)?([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" =~ ^ss:// ]]; then
        local PART_AFTER_SS=$(echo "$NODE_LINK" | sed 's/^ss:\/\///')
        if [[ "$PART_AFTER_SS" =~ @([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
            HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
            PORT="${BASH_REMATCH[2]}"
        else
            local BASE64_PART=$(echo "$PART_AFTER_SS" | cut -d'@' -f1)
            local DECODED_AUTH=$(echo "$BASE64_PART" | tr '_-' '+/' | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_AUTH" =~ ([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    elif [[ "$NODE_LINK" =~ ^vmess://(.+)@([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[2]}"
        PORT="${BASH_REMATCH[3]}"
    elif [[ "$NODE_LINK" =~ ^vmess:// ]]; then
        local VMESS_JSON=$(echo "$NODE_LINK" | sed 's/^vmess:\/\///' | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            HOSTNAME_OR_IP=$(echo "$VMESS_JSON" | jq -r '.add // empty' 2>/dev/null)
            PORT=$(echo "$VMESS_JSON" | jq -r '.port // empty' 2>/dev/null)
            if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
                log_debug "$LOG_PREFIX - 无法从 vmess JSON 解析 add 或 port: $NODE_LINK"
                echo "FAILED:$NODE_LINK"
                return
            fi
        else
            log_debug "$LOG_PREFIX - 无法解码 vmess 链接: $NODE_LINK"
            echo "FAILED:$NODE_LINK"
            return
        fi
    fi

    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
        log WARN "$LOG_PREFIX - 无法从链接中解析 IP 或端口: $NODE_LINK"
        echo "FAILED:$NODE_LINK"
        return
    fi

    local TARGET_HOST="$HOSTNAME_OR_IP"
    if [[ "$HOSTNAME_OR_IP" =~ ^\[([0-9a-fA-F:]+)\]$ ]]; then
        IP="${BASH_REMATCH[1]}"
        TARGET_HOST="$HOSTNAME_OR_IP"
    elif [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        IP="$HOSTNAME_OR_IP"
    else
        log_debug "$LOG_PREFIX - 尝试解析域名: $HOSTNAME_OR_IP"
        RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
        if [ -z "$RESOLVED_IP" ]; then
            RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" AAAA | head -n 1)
        fi
        if [ -n "$RESOLVED_IP" ]; then
            IP="$RESOLVED_IP"
            if [[ "$IP" =~ : ]]; then
                TARGET_HOST="[$IP]"
            else
                TARGET_HOST="$IP"
            fi
            log_debug "$LOG_PREFIX - 解析结果: $HOSTNAME_OR_IP -> $IP"
        else
            log WARN "$LOG_PREFIX - 无法解析域名: $HOSTNAME_OR_IP"
            echo "FAILED:$NODE_LINK"
            return
        fi
    fi

    nc -z -w "$CONNECT_TIMEOUT" "$TARGET_HOST" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "SUCCESS:$NODE_LINK"
    else
        log WARN "$LOG_PREFIX - 结果: 无法连接到 $TARGET_HOST:$PORT"
        echo "FAILED:$NODE_LINK"
    fi
}

export -f test_single_node
export -f log
export -f log_debug
export LOG_FILE
export CONNECT_TIMEOUT
export DEBUG

log INFO "开始节点连接性测试..."
mkdir -p "$OUTPUT_DIR"
check_dependencies
load_failed_nodes

log INFO "下载并合并节点配置文件..."
for url in "${NODE_SOURCES[@]}"; do
    log INFO "  - 正在下载: $url"
    curl -sL --retry 3 --retry-delay 2 "$url" >> "$MERGED_NODES_TEMP_FILE" || log WARN "  - 未能从 $url 下载文件"
done

if [ ! -s "$MERGED_NODES_TEMP_FILE" ]; then
    log ERROR "未能下载任何节点配置文件，或所有文件都为空"
    rm -f "$MERGED_NODES_TEMP_FILE" "$ALL_TEST_RESULTS_TEMP_FILE" "$CURRENT_RUN_SUCCESS_TEMP_FILE" "$CURRENT_RUN_FAILED_TEMP_FILE"
    exit 1
fi

sort -u "$MERGED_NODES_TEMP_FILE" -o "$MERGED_NODES_TEMP_FILE"
TOTAL_UNIQUE_NODES=$(grep -vE '^(#|--|$)' "$MERGED_NODES_TEMP_FILE" 2>/dev/null | wc -l || echo 0)
log INFO "所有配置文件下载并合并成功（去重后），共计 ${TOTAL_UNIQUE_NODES} 个节点"

log INFO "开始并行测试 ${PARALLEL_JOBS} 个节点..."
split -l 5000 "$MERGED_NODES_TEMP_FILE" node_batch_
for batch in node_batch_*; do
    log INFO "处理批次 $batch..."
    processed_count=0
    cat "$batch" | grep -vE '^(#|--|$)' | while IFS= read -r NODE_LINK; do
        if [[ -n "${FAILED_NODES[$NODE_LINK]}" ]]; then
            ((SKIPPED_COUNT++))
            echo "FAILED:$NODE_LINK" >> "$ALL_TEST_RESULTS_TEMP_FILE"
        else
            printf "%s\n" "$NODE_LINK"
            ((processed_count++))
            if (( processed_count % 1000 == 0 )); then
                log INFO "批次 $batch 已处理 $processed_count 个节点..."
            fi
        fi
    done | xargs -P "$PARALLEL_JOBS" -d '\n' -I {} bash -c 'test_single_node "$@"' _ {} >> "$ALL_TEST_RESULTS_TEMP_FILE"
    log INFO "批次 $batch 处理完成"
    rm "$batch"
done
rm -f "$MERGED_NODES_TEMP_FILE"

log INFO "处理测试结果并写入文件..."
grep '^SUCCESS:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2- | sort -u > "$CURRENT_RUN_SUCCESS_TEMP_FILE"
grep '^FAILED:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2- | sort -u > "$CURRENT_RUN_FAILED_TEMP_FILE"

if [ -f "$SUCCESS_FILE" ]; then
    grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null >> "$CURRENT_RUN_SUCCESS_TEMP_FILE"
fi
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
sort -u "$CURRENT_RUN_SUCCESS_TEMP_FILE" >> "$SUCCESS_FILE"

if [ -f "$FAILED_FILE" ]; then
    grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null >> "$CURRENT_RUN_FAILED_TEMP_FILE"
fi
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" > "$FAILED_FILE"
echo "-------------------------------------" >> "$FAILED_FILE"
sort -u "$CURRENT_RUN_FAILED_TEMP_FILE" >> "$FAILED_FILE"

rm -f "$ALL_TEST_RESULTS_TEMP_FILE" "$CURRENT_RUN_SUCCESS_TEMP_FILE" "$CURRENT_RUN_FAILED_TEMP_FILE"

success_nodes_count=$(grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null | wc -l || echo 0)
failed_nodes_count=$(grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null | wc -l || echo 0)
total_processed_nodes=$((success_nodes_count + failed_nodes_count + SKIPPED_COUNT))

log INFO "测试统计："
log INFO "  - 总处理节点数: $total_processed_nodes"
log INFO "  - 成功连接节点数: $success_nodes_count"
log INFO "  - 失败节点数: $failed_nodes_count"
log INFO "  - 跳过上次失败的节点数: $SKIPPED_COUNT"

log INFO "开始将结果推送到 GitHub 仓库..."
git config user.name "GitHub Actions"
git config user.email "actions@github.com"

if ! git diff --quiet --exit-code "$SUCCESS_FILE" "$FAILED_FILE"; then
    log INFO "检测到文件内容有实际更改，准备提交。"
    git add "$SUCCESS_FILE" "$FAILED_FILE"
    if ! git commit -m "Update node connectivity results (automated by GitHub Actions)"; then
        log WARN "Git 提交失败，可能没有实际内容更改。"
    else
        git remote set-url origin "https://x-access-token:${GH_TOKEN_FOR_PUSH}@github.com/${GITHUB_REPOSITORY}.git"
        git fetch origin
        if ! git pull --rebase origin "${GITHUB_REF##*/}"; then
            log ERROR "Git pull --rebase 失败，远程分支最新提交: $(git log origin/${GITHUB_REF##*/} -1 --format=%H)"
            exit 1
        fi
        if ! git push origin HEAD:${GITHUB_REF##*/}; then
            log ERROR "推送失败，请检查 Git 配置或网络"
            exit 1
        fi
        log INFO "成功节点和失败节点已推送到 GitHub 仓库"
    fi
else
    log INFO "没有新的节点连接性结果需要提交。"
fi

log INFO "节点连接性测试和推送流程完成。"
