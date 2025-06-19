#!/bin/bash
echo "Script started at $(date)" # 保留这行来确认脚本启动

# 定义日志文件和输出文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"
FAILED_FILE="$OUTPUT_DIR/failed_nodes.log"

# 创建临时文件，确保它们是唯一的，并在脚本退出时自动删除 (使用trap)
MERGED_NODES_TEMP_FILE=$(mktemp)
ALL_TEST_RESULTS_TEMP_FILE=$(mktemp)
CURRENT_RUN_SUCCESS_TEMP_FILE=$(mktemp)
CURRENT_RUN_FAILED_TEMP_FILE=$(mktemp)

# 在脚本退出时清理临时文件
trap 'rm -f "$MERGED_NODES_TEMP_FILE" "$ALL_TEST_RESULTS_TEMP_FILE" "$CURRENT_RUN_SUCCESS_TEMP_FILE" "$CURRENT_RUN_FAILED_TEMP_FILE" node_batch_*' EXIT

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
)

# 配置参数
PARALLEL_JOBS=${PARALLEL_JOBS:-20} # 允许通过环境变量覆盖
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-5} # 允许通过环境变量覆盖
DEBUG=${DEBUG:-false} # 允许通过环境变量覆盖，默认为false

# 日志函数
log() {
    local level=$1
    shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local message="[$level] $timestamp - $*"

    # 将所有级别的日志写入文件
    echo "$message" >> "$LOG_FILE"

    # 如果是 INFO 或更高级别的日志，也打印到标准输出（控制台）
    # 这样可以在GitHub Actions日志中看到更多进度，而不是完全静默
    case "$level" in
        INFO|WARN|ERROR)
            echo "$message"
            ;;
        DEBUG)
            if [ "$DEBUG" = "true" ]; then
                echo "$message"
            fi
            ;;
    esac
}

# 调试日志函数，只在DEBUG模式下工作
log_debug() {
    if [ "$DEBUG" = "true" ]; then
        log DEBUG "$@" # 调用主log函数，级别为DEBUG
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
            log WARN "失败节点数过多 (${#FAILED_NODES[@]})，清空历史失败节点以避免内存问题。"
            unset FAILED_NODES
            declare -A FAILED_NODES # 重新声明空数组
        fi
    else
        log INFO "未找到上次失败的节点文件: $FAILED_FILE"
    fi
}

# 检查依赖
check_dependencies() {
    log INFO "检查系统依赖..."
    for cmd in dig nc curl sort wc base64 jq; do
        command -v "$cmd" >/dev/null 2>&1 || {
            log ERROR "$cmd 命令未找到，请确保安装（例如：sudo apt-get install -y $cmd）"
            exit 1
        }
    done
    log INFO "所有依赖检查通过。"

    # 设置 DNS 缓存
    # 创建临时的resolv.conf并导出环境变量，确保dig使用指定的DNS服务器
    echo "nameserver 8.8.8.8" > /tmp/resolv.conf
    export RESOLV_CONF=/tmp/resolv.conf
    log_debug "已设置 dig 使用 8.8.8.8 作为 DNS 服务器。"
}

# 测试单个节点连接性
test_single_node() {
    local NODE_LINK_ORIGINAL="$1" # 保留原始链接
    local NODE_LINK="$1"          # 工作副本
    local LOG_PREFIX="[TEST]"
    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""

    # 重要的修复：首先移除 # 及其后面的备注，避免 dig 错误解析
    # 如果原始链接本身以 "-" 开头且不是 IP，仍然可能导致 dig 错误
    # 但对于大多数情况，这个修复是有效的。
    NODE_LINK=$(echo "$NODE_LINK" | cut -d'#' -f1)

    # 尝试解析各种协议的节点链接
    if [[ "$NODE_LINK" =~ ^(hysteria2|vless|trojan):\/\/(.+@)?([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" =~ ^ss:// ]]; then
        local PART_AFTER_SS=$(echo "$NODE_LINK" | sed 's/^ss:\/\///')
        if [[ "$PART_AFTER_SS" =~ @([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
            HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
            PORT="${BASH_REMATCH[2]}"
        else
            # 尝试解码 ss 链接的 base64 部分
            local BASE64_PART=$(echo "$PART_AFTER_SS" | cut -d'@' -f1)
            # 使用 tr 替换字符，然后进行 base64 解码
            local DECODED_AUTH=$(echo "$BASE64_PART" | tr '_-' '+/' | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_AUTH" =~ ([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    elif [[ "$NODE_LINK" =~ ^vmess://(.+)@([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
        # 这种模式的 vmess 链接相对少见，但如果存在，直接提取
        HOSTNAME_OR_IP="${BASH_REMATCH[2]}"
        PORT="${BASH_REMATCH[3]}"
    elif [[ "$NODE_LINK" =~ ^vmess:// ]]; then
        # 解码 vmess JSON 格式的链接
        local VMESS_JSON=$(echo "$NODE_LINK" | sed 's/^vmess:\/\///' | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            # 使用 jq 解析 add 和 port 字段
            HOSTNAME_OR_IP=$(echo "$VMESS_JSON" | jq -r '.add // empty' 2>/dev/null)
            # 修复：确保这里是 /dev/null
            PORT=$(echo "$VMESS_JSON" | jq -r '.port // empty' 2>/dev/null)
            if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
                log_debug "$LOG_PREFIX - 无法从 vmess JSON 解析 add 或 port: $NODE_LINK_ORIGINAL"
                echo "FAILED:$NODE_LINK_ORIGINAL"
                return
            fi
        else
            log_debug "$LOG_PREFIX - 无法解码 vmess 链接: $NODE_LINK_ORIGINAL"
            echo "FAILED:$NODE_LINK_ORIGINAL"
            return
        fi
    fi

    # 如果仍然无法解析出 HOSTNAME_OR_IP 或 PORT，则视为失败
    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
        log WARN "$LOG_PREFIX - 无法从链接中解析 IP 或端口: $NODE_LINK_ORIGINAL"
        echo "FAILED:$NODE_LINK_ORIGINAL"
        return
    fi

    local TARGET_HOST="$HOSTNAME_OR_IP"
    # 判断 HOSTNAME_OR_IP 是 IPv6, IPv4 还是域名
    if [[ "$HOSTNAME_OR_IP" =~ ^\[([0-9a-fA-F:]+)\]$ ]]; then # IPv6 with brackets
        IP="${BASH_REMATCH[1]}"
        TARGET_HOST="$HOSTNAME_OR_IP" # netcat 可以直接处理带括号的IPv6
    elif [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then # IPv4
        IP="$HOSTNAME_OR_IP"
        TARGET_HOST="$IP"
    else # 尝试解析域名
        log_debug "$LOG_PREFIX - 尝试解析域名: $HOSTNAME_OR_IP"
        # 尝试解析 A 记录 (IPv4)
        RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A | head -n 1)
        if [ -z "$RESOLVED_IP" ]; then
            # 如果没有 IPv4，尝试解析 AAAA 记录 (IPv6)
            RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" AAAA | head -n 1)
        fi

        if [ -n "$RESOLVED_IP" ]; then
            IP="$RESOLVED_IP"
            if [[ "$IP" =~ : ]]; then # 解析结果是 IPv6
                TARGET_HOST="[$IP]" # 为 netcat 包裹 IPv6 地址
            else # 解析结果是 IPv4
                TARGET_HOST="$IP"
            fi
            log_debug "$LOG_PREFIX - 解析结果: $HOSTNAME_OR_IP -> $IP"
        else
            log WARN "$LOG_PREFIX - 无法解析域名: $HOSTNAME_OR_IP"
            echo "FAILED:$NODE_LINK_ORIGINAL"
            return
        fi
    fi

    # 使用 netcat 测试连接
    # 连接超时设置为 $CONNECT_TIMEOUT
    nc -z -w "$CONNECT_TIMEOUT" "$TARGET_HOST" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "SUCCESS:$NODE_LINK_ORIGINAL" # 成功，输出原始链接
    else
        log WARN "$LOG_PREFIX - 结果: 无法连接到 $TARGET_HOST:$PORT (原链接: $NODE_LINK_ORIGINAL)"
        echo "FAILED:$NODE_LINK_ORIGINAL" # 失败，输出原始链接
    fi
}

# 导出函数和变量，以便在xargs的子shell中使用
export -f test_single_node
export -f log
export -f log_debug
export LOG_FILE
export CONNECT_TIMEOUT
export DEBUG

# --- 主逻辑开始 ---
log INFO "开始节点连接性测试..."

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 运行依赖检查
check_dependencies

# 加载上次失败的节点列表
load_failed_nodes

log INFO "下载并合并节点配置文件..."
# 清空合并文件，以防上次运行失败残留
> "$MERGED_NODES_TEMP_FILE"
for url in "${NODE_SOURCES[@]}"; do
    log INFO "  - 正在下载: $url"
    # 使用 curl -f 选项，如果HTTP错误，curl会返回非0退出码
    # retry 3 --retry-delay 2 可以增加下载成功率
    curl -sL -f --retry 3 --retry-delay 2 "$url" >> "$MERGED_NODES_TEMP_FILE" || log WARN "  - 未能从 $url 下载文件"
done

# 检查合并后的文件是否为空
if [ ! -s "$MERGED_NODES_TEMP_FILE" ]; then
    log ERROR "未能下载任何节点配置文件，或所有文件都为空"
    exit 1
fi

# 对所有节点进行去重和排序
sort -u "$MERGED_NODES_TEMP_FILE" -o "$MERGED_NODES_TEMP_FILE"
TOTAL_UNIQUE_NODES=$(grep -vE '^(#|--|$)' "$MERGED_NODES_TEMP_FILE" 2>/dev/null | wc -l || echo 0)
log INFO "所有配置文件下载并合并成功（去重后），共计 ${TOTAL_UNIQUE_NODES} 个节点。"

if [ "$TOTAL_UNIQUE_NODES" -eq 0 ]; then
    log WARN "没有可测试的节点，流程结束。"
    exit 0
fi

log INFO "开始并行测试 ${PARALLEL_JOBS} 个节点..."

# 清空所有测试结果文件，准备写入新的结果
> "$ALL_TEST_RESULTS_TEMP_FILE"

# 将合并后的节点文件分割成小批次，以便 xargs 循环处理
# 分割大小根据节点总数和期望的并行度调整
# 注意：这里设定为 5000 行，但如果节点非常多，可能导致文件过多，或者单个批次仍然太大
# 建议根据实际情况调整这个值，或者直接不分割，让xargs处理全部
# 对于非常大的文件，或者需要细粒度进度报告，分割是好的
split -l 5000 "$MERGED_NODES_TEMP_FILE" node_batch_
BATCH_COUNT=0
for batch in node_batch_*; do
    ((BATCH_COUNT++))
    log INFO "处理批次 $batch (第 ${BATCH_COUNT} 批)..."
    current_batch_processed_count=0

    # 过滤掉注释行和空行，然后将每个节点链接通过管道传递给 xargs
    # 注意：这里的 while read 循环用于在处理每个节点前检查是否跳过
    # 如果节点数量非常庞大，这个循环自身可能会消耗一些时间
    # 另一种更高效的方式是让 xargs 在其内部处理 FAILED_NODES 逻辑，但会复杂化子shell的环境
    # 当前实现是将未跳过的节点 printf 给 xargs
    cat "$batch" | grep -vE '^(#|--|$)' | while IFS= read -r NODE_LINK_IN_BATCH; do
        if [[ -n "${FAILED_NODES[$NODE_LINK_IN_BATCH]}" ]]; then
            ((SKIPPED_COUNT++))
            # 跳过的节点也应该写入到结果文件中，标记为 FAILED，这样后续失败文件才能统计到它们
            echo "FAILED:$NODE_LINK_IN_BATCH" >> "$ALL_TEST_RESULTS_TEMP_FILE"
        else
            # 将需要测试的节点通过管道传递给 xargs
            printf "%s\n" "$NODE_LINK_IN_BATCH"
            ((current_batch_processed_count++))
            if (( current_batch_processed_count % 1000 == 0 )); then
                log INFO "批次 $batch 已准备好 $current_batch_processed_count 个节点进行测试..."
            fi
        fi
    done | xargs -P "$PARALLEL_JOBS" -d '\n' -I {} bash -c 'test_single_node "$@"' _ {} >> "$ALL_TEST_RESULTS_TEMP_FILE"

    log INFO "批次 $batch 处理完成。"
    rm "$batch" # 删除处理过的批次文件
done
rm -f "$MERGED_NODES_TEMP_FILE" # 删除最初的合并文件

log INFO "处理测试结果并写入最终文件..."

# 从所有测试结果中提取成功和失败的节点
grep '^SUCCESS:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2- | sort -u > "$CURRENT_RUN_SUCCESS_TEMP_FILE"
grep '^FAILED:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2- | sort -u > "$CURRENT_RUN_FAILED_TEMP_FILE"

# 合并历史成功节点和本次运行成功节点
if [ -f "$SUCCESS_FILE" ]; then
    # 只合并非注释、非空行
    grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null >> "$CURRENT_RUN_SUCCESS_TEMP_FILE"
fi
# 写入新的成功节点文件，包含更新时间戳
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
sort -u "$CURRENT_RUN_SUCCESS_TEMP_FILE" >> "$SUCCESS_FILE" # 确保去重并排序

# 合并历史失败节点和本次运行失败节点
if [ -f "$FAILED_FILE" ]; then
    # 只合并非注释、非空行
    grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null >> "$CURRENT_RUN_FAILED_TEMP_FILE"
fi
# 写入新的失败节点文件，包含更新时间戳
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" > "$FAILED_FILE"
echo "-------------------------------------" >> "$FAILED_FILE"
sort -u "$CURRENT_RUN_FAILED_TEMP_FILE" >> "$FAILED_FILE" # 确保去重并排序

# 清理不再需要的临时文件
rm -f "$ALL_TEST_RESULTS_TEMP_FILE" "$CURRENT_RUN_SUCCESS_TEMP_FILE" "$CURRENT_RUN_FAILED_TEMP_FILE"

# 统计最终结果
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

# 检查是否有实际的文件更改需要提交
# 这里使用 --quiet 避免输出diff内容，--exit-code 在有差异时返回非零
if ! git diff --quiet --exit-code "$SUCCESS_FILE" "$FAILED_FILE"; then
    log INFO "检测到文件内容有实际更改，准备提交。"
    git add "$SUCCESS_FILE" "$FAILED_FILE"
    
    # 尝试提交，如果因为没有实际更改而提交失败（尽管上面已经检查过），则警告
    if ! git commit -m "Update node connectivity results (automated by GitHub Actions)"; then
        log WARN "Git 提交失败，可能没有实际内容更改。这不应发生，但如果出现，则跳过后续推送。"
    else
        log INFO "成功创建提交。开始尝试拉取和推送..."
        # 设置远程URL，使用 GH_TOKEN_FOR_PUSH 进行认证
        git remote set-url origin "https://x-access-token:${GH_TOKEN_FOR_PUSH}@github.com/${GITHUB_REPOSITORY}.git"
        
        # 抓取最新更改，避免rebase冲突（尽管rebase会处理，但先fetch更清晰）
        git fetch origin
        
        # 拉取最新更改并rebase到当前分支，处理潜在的冲突
        # 注意：这里是 Git 冲突最可能发生的地方。如果本地有未跟踪的文件，或者历史记录被意外修改，rebase可能会失败。
        # 确保 .gitignore 包含 node_connectivity_results.log
        if ! git pull --rebase origin "${GITHUB_REF##*/}"; then
            log ERROR "Git pull --rebase 失败。这可能是由于未跟踪的文件、与远程分支的深层冲突，或工作目录不干净。远程分支最新提交: $(git log origin/${GITHUB_REF##*/} -1 --format=%H)。请检查并手动解决。"
            exit 1 # 退出，因为无法安全地推送
        fi
        
        # 推送更改到远程分支
        if ! git push origin HEAD:${GITHUB_REF##*/}; then
            log ERROR "推送失败，请检查 Git 配置、网络连接或远程仓库权限。可能原因是远程分支有新的提交导致需要 rebase 或合并。"
            exit 1 # 退出，因为推送失败
        fi
        log INFO "成功节点和失败节点已推送到 GitHub 仓库。"
    fi
else
    log INFO "没有新的节点连接性结果需要提交。"
fi

log INFO "节点连接性测试和推送流程完成。"
