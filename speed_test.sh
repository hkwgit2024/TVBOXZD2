#!/bin/bash

# 定义日志文件和输出文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"        # 成功节点输出文件
FAILED_FILE="$OUTPUT_DIR/failed_nodes.log" # 失败节点输出文件 (注意这里是 .log 后缀，与之前建议一致)
MERGED_NODES_TEMP_FILE="all_merged_nodes_temp.txt" # 临时合并文件

# 用于并行处理的临时文件
PREV_FAILED_LOOKUP_FILE="prev_failed_lookup.tmp" # 存储上次失败节点的查找文件
CURRENT_RUN_SUCCESS_TEMP="current_run_success_tmp.log" # 临时文件，收集本次运行成功的节点
CURRENT_RUN_FAILED_TEMP="current_run_failed_tmp.log"   # 临时文件，收集本次运行失败/跳过的节点

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
    # 添加更多你需要的网址
)

# 日志函数
log() {
    local level=$1
    shift
    # 使用 flock 确保并行写入日志文件时的原子性，避免混乱
    (
        flock 200 || exit 1
        echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
    ) 200> "$LOG_FILE.lock" # 文件锁
}

# 初始化
log INFO "开始节点连接性测试..."
mkdir -p "$OUTPUT_DIR"

# 清空并初始化输出文件，等待 test_node 写入临时文件后合并
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE" # 添加分隔符
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" > "$FAILED_FILE"
echo "-------------------------------------" >> "$FAILED_FILE" # 添加分隔符

# 清空临时合并文件和本次运行结果收集文件
> "$MERGED_NODES_TEMP_FILE"
> "$CURRENT_RUN_SUCCESS_TEMP"
> "$CURRENT_RUN_FAILED_TEMP"

# 检查并安装依赖 (最好在 .yml 中预装，但脚本内部也保留一个检查)
# sudo apt-get update >/dev/null 2>&1
# sudo apt-get install -y dnsutils netcat-openbsd parallel >/dev/null 2>&1

# 检查依赖（仅检查是否安装，不安装）
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
    grep -vE '^(#|--|$)' "$FAILED_FILE" > "$PREV_FAILED_LOOKUP_FILE"
    log INFO "已加载 $(wc -l < "$PREV_FAILED_LOOKUP_FILE") 个历史失败节点用于跳过"
else
    log INFO "未找到上次失败的节点列表 ($FAILED_FILE)，所有节点将被测试。"
    > "$PREV_FAILED_LOOKUP_FILE" # 创建一个空文件
fi

# 解析和测试节点函数
test_node() {
    local NODE_LINK="$1"
    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""

    # 跳过空行和注释行
    [[ -z "$NODE_LINK" || "$NODE_LINK" =~ ^# || "$NODE_LINK" =~ ^-*$ ]] && return

    # 检查是否为已知的失败节点（使用临时查找文件）
    # 使用 flock 确保对查找文件访问的安全性，但在并行中对共享文件频繁 grep 仍是瓶颈
    # 更优是在主进程中处理跳过逻辑，但用户要求在函数内跳过
    if grep -q -F -x "$NODE_LINK" "$PREV_FAILED_LOOKUP_FILE"; then
        log INFO "跳过已知的失败节点: $NODE_LINK"
        echo "$NODE_LINK" >> "$CURRENT_RUN_FAILED_TEMP" # 即使跳过，也记录为本次的失败/跳过节点
        return
    fi

    # 提取 IP/Hostname 和 Port
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
        log WARN "无法从链接中解析 IP 或端口: $NODE_LINK"
        echo "$NODE_LINK" >> "$CURRENT_RUN_FAILED_TEMP" # 记录为失败
        return
    fi

    # 解析域名
    if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
        IP="$HOSTNAME_OR_IP"
    else
        # dig +short to get IP addresses, take the first IPv4 or IPv6
        RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A "$HOSTNAME_OR_IP" AAAA | head -n 1)
        if [ -n "$RESOLVED_IP" ]; then
            IP="$RESOLVED_IP"
            log INFO "  - 解析结果: $HOSTNAME_OR_IP -> $IP"
        else
            log WARN "  - 无法解析域名: $HOSTNAME_OR_IP"
            echo "$NODE_LINK" >> "$CURRENT_RUN_FAILED_TEMP" # 记录为失败
            return
        fi
    fi
    
    log INFO "正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)"
    nc -z -w 3 "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log INFO "  - 结果: 成功连接到 $IP:$PORT"
        echo "$NODE_LINK" >> "$CURRENT_RUN_SUCCESS_TEMP" # 记录为成功
    else
        log WARN "  - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)"
        echo "$NODE_LINK" >> "$CURRENT_RUN_FAILED_TEMP" # 记录为失败
    fi
}

# 导出函数和变量以供 parallel 使用
# export -f test_node 命令会将函数定义复制到子shell中
# 但是关联数组 `failed_nodes` 或通过 `grep` 查找的临时文件 `PREV_FAILED_LOOKUP_FILE`
# 在并行执行时需要特别处理，这里通过环境变量传递文件名
export -f test_node log
export LOG_FILE CURRENT_RUN_SUCCESS_TEMP CURRENT_RUN_FAILED_TEMP PREV_FAILED_LOOKUP_FILE

# 测试节点（优先使用 parallel，若不可用则串行）
if command -v parallel >/dev/null 2>&1; then
    log INFO "使用 parallel 并行测试节点（并发数：10）"
    # 使用 --colsep '\n' 确保每行作为一个参数传递给 test_node
    cat "$MERGED_NODES_TEMP_FILE" | parallel -j 10 --pipe test_node
else
    log INFO "使用串行测试节点"
    while IFS= read -r line; do
        test_node "$line"
    done < "$MERGED_NODES_TEMP_FILE"
fi

# 清理主进程的临时文件
rm -f "$MERGED_NODES_TEMP_FILE" "$PREV_FAILED_LOOKUP_FILE"

# 将临时文件内容合并到最终的输出文件
# 使用 sort -u 去重并排序，确保列表整洁
sort -u "$CURRENT_RUN_SUCCESS_TEMP" >> "$SUCCESS_FILE"
sort -u "$CURRENT_RUN_FAILED_TEMP" >> "$FAILED_FILE"

# 清理并行临时文件
rm -f "$CURRENT_RUN_SUCCESS_TEMP" "$CURRENT_RUN_FAILED_TEMP"

log INFO "所有节点连接性测试完成。成功节点已保存到 $SUCCESS_FILE"
log INFO "失败节点已保存到 $FAILED_FILE"

# 统计信息 (这里统计的是文件中的行数，需要排除注释和分隔符)
# total_nodes 统计的是合并文件中的原始行数，不代表实际测试的节点数 (因为有跳过)
total_merged_nodes=$(grep -vE '^(#|--|$)' "$MERGED_NODES_TEMP_FILE" 2>/dev/null | wc -l || echo 0) # 修正：这里需要从原始合并文件统计
success_nodes_count=$(grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null | wc -l || echo 0)
failed_nodes_count=$(grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null | wc -l || echo 0)

log INFO "测试统计："
log INFO "  - 源文件总节点数 (可能包含重复和跳过的): $total_merged_nodes"
log INFO "  - 成功连接节点数: $success_nodes_count"
log INFO "  - 失败/跳过节点数: $failed_nodes_count" # 这个数字包含了实际测试失败的，以及那些因为在历史失败列表而被直接跳过的


# --- Git 推送逻辑 ---
log INFO "开始将结果推送到 GitHub 仓库..."

# 配置 Git
git config user.name "GitHub Actions"
git config user.email "actions@github.com"

# 检查是否有更改
# git diff --quiet 会检查工作区和索引之间，或索引和HEAD之间是否有差异
# 我们希望检查的是提交后的文件内容与当前 HEAD 上的文件内容是否有差异
if git diff --quiet --exit-code HEAD "$SUCCESS_FILE" "$FAILED_FILE"; then
    log INFO "成功节点和失败节点文件无更改，无需提交"
else
    git add "$SUCCESS_FILE" "$FAILED_FILE"
    git commit -m "Update node connectivity results (automated by GitHub Actions)" || true # || true 避免无更改时报错
    git remote set-url origin "https://x-access-token:${GH_TOKEN_FOR_PUSH}@github.com/${GITHUB_REPOSITORY}.git"
    git push origin HEAD:${GITHUB_REF##*/} || {
        log ERROR "推送失败，请检查 Git 配置或网络连接"
        exit 1
    }
    log INFO "成功节点和失败节点已推送到 GitHub 仓库"
fi

log INFO "节点连接性测试和推送流程完成。"
