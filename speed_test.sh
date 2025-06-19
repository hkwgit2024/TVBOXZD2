#!/bin/bash

# 定义日志文件和输出文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"        # 成功节点输出文件
FAILED_FILE="$OUTPUT_DIR/failed_nodes.log" # 失败节点输出文件
MERGED_NODES_TEMP_FILE=$(mktemp) # 使用 mktemp 创建唯一的临时文件，用于合并所有来源的原始节点列表
ALL_TEST_RESULTS_TEMP_FILE=$(mktemp) # 新增：用于收集所有并行测试结果的临时文件

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    #"https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
)

# 配置参数
PARALLEL_JOBS=10    # 并行测试的节点数量
CONNECT_TIMEOUT=5   # nc 连接超时时间 (秒)

# 日志函数
log() {
    local level=$1 # INFO, WARN, ERROR
    shift
    echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# 定义关联数组存储上次失败的节点
declare -A FAILED_NODES
SKIPPED_COUNT=0 # 用于统计跳过的节点数量

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

# 检查依赖
check_dependencies() {
    command -v dig >/dev/null 2>&1 || {
        log ERROR "dig 命令未找到，请确保安装 dnsutils（例如：sudo apt-get install dnsutils）"
        exit 1
    }
    command -v nc >/dev/null 2>&1 || {
        log ERROR "nc 命令未找到，请确保安装 netcat（例如：sudo apt-get install netcat）"
        exit 1
    }
    command -v curl >/dev/null 2>&1 || {
        log ERROR "curl 命令未找到，请确保安装 curl"
        exit 1
    }
    command -v sort >/dev/null 2>&1 || {
        log ERROR "sort 命令未找到"
        exit 1
    }
    command -v wc >/dev/null 2>&1 || {
        log ERROR "wc 命令未找到"
        exit 1
    }
}

# 核心函数：测试单个节点连接性
# 此函数在子进程中运行，并通过标准输出返回结果
test_single_node() {
    local NODE_LINK="$1"
    local LOG_PREFIX="[TEST]" # 用于在日志中区分，并非实际写入结果文件

    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""

    # 提取 IP/Hostname 和 Port
    if [[ "$NODE_LINK" =~ ^(vless|vmess|trojan|hy2):\/\/(.+@)?([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" =~ ^ss:// ]]; then
        # 尝试直接从URL中匹配 hostname:port
        if echo "$NODE_LINK" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+)' | head -n 1 | grep -qE '.'; then
            HOSTNAME_OR_IP=$(echo "$NODE_LINK" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+)' | head -n 1 | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$NODE_HOST_PORT" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+)' | head -n 1 | cut -d':' -f2)
        else
            # 尝试base64解码
            local BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            local DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_PART" =~ ([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
        log WARN "$LOG_PREFIX - 无法从链接中解析 IP 或端口: $NODE_LINK"
        echo "FAILED:$NODE_LINK" # 输出失败标记和节点链接到 stdout
        return
    fi

    # 如果是 IP 地址（IPv4 或 IPv6），直接使用
    if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
        IP="$HOSTNAME_OR_IP"
    else
        # 否则，解析域名
        # log INFO "$LOG_PREFIX 尝试解析域名: $HOSTNAME_OR_IP" # 并行时日志会非常多，此处可省略
        RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A "$HOSTNAME_OR_IP" AAAA | head -n 1)
        if [ -n "$RESOLVED_IP" ]; then
            IP="$RESOLVED_IP"
            log INFO "$LOG_PREFIX - 解析结果: $HOSTNAME_OR_IP -> $IP"
        else
            log WARN "$LOG_PREFIX - 无法解析域名: $HOSTNAME_OR_IP (原始链接: $NODE_LINK)"
            echo "FAILED:$NODE_LINK" # 输出失败标记和节点链接到 stdout
            return
        fi
    fi

    log INFO "$LOG_PREFIX 正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)"
    nc -z -w "$CONNECT_TIMEOUT" "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log INFO "$LOG_PREFIX - 结果: 成功连接到 $IP:$PORT"
        echo "SUCCESS:$NODE_LINK" # 输出成功标记和节点链接到 stdout
    else
        log WARN "$LOG_PREFIX - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)"
        echo "FAILED:$NODE_LINK" # 输出失败标记和节点链接到 stdout
    fi
}

# 导出函数和变量，以便 xargs 的子进程能够访问它们
export -f test_single_node
export -f log
export LOG_FILE
export CONNECT_TIMEOUT

# --- 主逻辑开始 ---
log INFO "开始节点连接性测试..."
mkdir -p "$OUTPUT_DIR"

# 清空并初始化输出文件 (只保留头部，实际节点数据将在后面追加)
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" > "$FAILED_FILE"
echo "-------------------------------------" >> "$FAILED_FILE"

# 检查依赖
check_dependencies

# 加载上次失败的节点 (主进程加载)
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
    rm -f "$MERGED_NODES_TEMP_FILE"
    rm -f "$ALL_TEST_RESULTS_TEMP_FILE" # 清理新生成的临时文件
    exit 1
fi

# 去重合并后的节点
sort -u "$MERGED_NODES_TEMP_FILE" -o "$MERGED_NODES_TEMP_FILE"
log INFO "所有配置文件下载并合并成功（去重后），开始解析节点并测试连接性..."

# 开始并行测试节点
log INFO "开始并行测试 ${PARALLEL_JOBS} 个节点..."

# 1. 预处理节点：将上次失败的节点直接标记为 FAILED 并写入结果临时文件
# 2. 未跳过的节点通过管道传递给 xargs 进行并行测试
# 3. xargs 将 test_single_node 的所有输出（SUCCESS/FAILED 标记的节点链接）收集到 ALL_TEST_RESULTS_TEMP_FILE
cat "$MERGED_NODES_TEMP_FILE" | grep -vE '^(#|--|$)' | while IFS= read -r NODE_LINK; do
    if [[ -n "${FAILED_NODES[$NODE_LINK]}" ]]; then
        ((SKIPPED_COUNT++))
        echo "FAILED:$NODE_LINK" >> "$ALL_TEST_RESULTS_TEMP_FILE" # 将跳过的节点直接写入结果临时文件
    else
        echo "$NODE_LINK" # 非跳过节点传递给 xargs 进行测试
    fi
done | xargs -P "$PARALLEL_JOBS" -I {} bash -c 'test_single_node "$@"' _ {} >> "$ALL_TEST_RESULTS_TEMP_FILE" # test_single_node 的 stdout 重定向到此文件

# 清理合并后的原始节点列表临时文件
rm -f "$MERGED_NODES_TEMP_FILE"

# 处理所有测试结果，填充 SUCCESS_FILE 和 FAILED_FILE
log INFO "处理所有测试结果并写入最终文件..."

# 从 ALL_TEST_RESULTS_TEMP_FILE 中提取成功和失败的节点
# 使用 cut -d':' -f2- 来获取冒号后面的完整链接，因为链接中可能有冒号
SUCCESS_NODES_RAW=$(grep '^SUCCESS:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2-)
FAILED_NODES_RAW=$(grep '^FAILED:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2-)

# 将去重后的成功节点追加到 SUCCESS_FILE
if [ -n "$SUCCESS_NODES_RAW" ]; then
    echo "$SUCCESS_NODES_RAW" | sort -u >> "$SUCCESS_FILE"
fi

# 将去重后的失败节点追加到 FAILED_FILE
if [ -n "$FAILED_NODES_RAW" ]; then
    echo "$FAILED_NODES_RAW" | sort -u >> "$FAILED_FILE"
fi

# 清理所有测试结果的临时文件
rm -f "$ALL_TEST_RESULTS_TEMP_FILE"

log INFO "所有节点连接性测试完成。成功节点已保存到 $SUCCESS_FILE"
log INFO "失败节点已保存到 $FAILED_FILE"

# 统计信息
# 统计时跳过头部注释和分隔符行
success_nodes_count=$(grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null | wc -l || echo 0)
failed_nodes_count=$(grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null | wc -l || echo 0)
total_processed_nodes=$((success_nodes_count + failed_nodes_count + SKIPPED_COUNT))

log INFO "测试统计："
log INFO "  - 总处理节点数: $total_processed_nodes"
log INFO "  - 成功连接节点数: $success_nodes_count"
log INFO "  - 失败节点数: $failed_nodes_count"
log INFO "  - 跳过上次失败的节点数: $SKIPPED_COUNT"

# --- Git 推送逻辑 ---
log INFO "开始将结果推送到 GitHub 仓库..."

# 配置 Git
git config user.name "GitHub Actions"
git config user.email "actions@github.com"

# 检查是否有更改
# git diff --quiet --exit-code HEAD "$SUCCESS_FILE" "$FAILED_FILE" 比较的是工作区和HEAD的差异
# 如果文件内容只更新了时间戳，这个检查可能会通过，导致不提交
# 为了确保即使只有时间戳也提交，可以简化为直接 add/commit，让 git 自己判断是否有实际内容变化
git add "$SUCCESS_FILE" "$FAILED_FILE"
if ! git commit -m "Update node connectivity results (automated by GitHub Actions)"; then
    log INFO "没有新的节点连接性结果需要提交。"
else
    # 设置远程仓库URL，使用 GitHub Actions 提供的 token 进行认证
    git remote set-url origin "https://x-access-token:${GH_TOKEN_FOR_PUSH}@github.com/${GITHUB_REPOSITORY}.git"
    # 推送当前分支的HEAD到远程同名分支
    git push origin HEAD:${GITHUB_REF##*/} || {
        log ERROR "推送失败，请检查 Git 配置或网络"
        exit 1
    }
    log INFO "成功节点和失败节点已推送到 GitHub 仓库"
fi

log INFO "节点连接性测试和推送流程完成。"
