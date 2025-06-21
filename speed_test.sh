#!/bin/bash

# 节点连接性测试脚本（并行化版本）
# 功能：从多个源下载节点配置文件，并行测试节点连接性，保存成功和失败节点
# 优化：修复统计逻辑，增强 vmess/hysteria 解析，生成失败节点 JSON

# --- 定义常量 ---
LOG_FILE="${LOG_FILE:-node_connectivity_results.log}" # 日志文件路径
OUTPUT_DIR="${OUTPUT_DIR:-data}"                      # 输出目录
SUCCESS_FILE="${SUCCESS_FILE:-$OUTPUT_DIR/sub.txt}"  # 成功节点输出文件
FAILED_FILE="${OUTPUT_DIR}/failed_proxies.json"      # 失败节点输出文件
MERGED_NODES_TEMP_FILE=$(mktemp)                     # 临时文件：存储合并的节点
SUCCESS_TEMP_FILE=$(mktemp)                          # 临时文件：存储成功节点
FAILED_TEMP_FILE=$(mktemp)                           # 临时文件：存储失败节点
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"              # 连接超时时间（秒）
PARALLEL_JOBS="${PARALLEL_JOBS:-10}"                 # 并行任务数

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
)

# --- 函数定义 ---

# 日志函数：输出到控制台和日志文件（线程安全）
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# 检查依赖函数：确保必要的命令存在
check_dependencies() {
    local deps=("dig" "nc" "curl" "base64" "sort" "wc" "parallel" "jq")
    for dep in "${deps[@]}"; do
        command -v "$dep" >/dev/null 2>&1 || {
            log "ERROR: 命令 '$dep' 未找到。请确保已安装（例如：sudo apt install $dep）"
            exit 1
        }
    done
}

# 核心函数：测试单个节点连接性并解析链接
test_node_connectivity() {
    local node_link="$1"
    local node_id="$2" # 用于日志追踪
    local ip=""
    local port=""
    local hostname_or_ip=""
    local failure_reason=""

    # 跳过空行、注释和分隔符
    [[ -z "$node_link" || "$node_link" =~ ^# || "$node_link" =~ ^-*$ ]] && return 1

    # 提取 IP/Hostname 和 Port
    if [[ "$node_link" =~ ^(hysteria2|vless|trojan):\/\/(.+@)?([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
        hostname_or_ip="${BASH_REMATCH[3]}"
        port="${BASH_REMATCH[4]}"
    elif [[ "$node_link" =~ ^hysteria://([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+)(\?sni=.*)?$ ]]; then
        hostname_or_ip="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
    elif [[ "$node_link" =~ ^ss:// ]]; then
        local part_after_ss=$(echo "$node_link" | sed 's/^ss:\/\///')
        if [[ "$part_after_ss" =~ @([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
            hostname_or_ip="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        else # 尝试 base64 解码
            local base64_part=$(echo "$part_after_ss" | cut -d'@' -f1)
            local decoded_auth=$(echo "$base64_part" | tr '_-' '+/' | base64 -d 2>/dev/null)
            if [ $? -ne 0 ]; then
                failure_reason="Base64 decode failed"
                log "WARN: [$node_id] base64 解码失败: $node_link"
                echo "{\"node\": \"$node_link\", \"reason\": \"$failure_reason\"}" >> "$FAILED_TEMP_FILE"
                return 1
            fi
            if [[ "$decoded_auth" =~ ([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+) ]]; then
                hostname_or_ip="${BASH_REMATCH[1]}"
                port="${BASH_REMATCH[2]}"
            fi
        fi
    elif [[ "$node_link" =~ ^vmess://([A-Za-z0-9+/=]+) ]]; then
        local base64_part="${BASH_REMATCH[1]}"
        local decoded_json=$(echo "$base64_part" | tr '_-' '+/' | base64 -d 2>/dev/null)
        if [ $? -ne 0 ]; then
            failure_reason="VMess base64 decode failed"
            log "WARN: [$node_id] base64 解码失败: $node_link"
            echo "{\"node\": \"$node_link\", \"reason\": \"$failure_reason\"}" >> "$FAILED_TEMP_FILE"
            return 1
        fi
        hostname_or_ip=$(echo "$decoded_json" | jq -r '.add' 2>/dev/null)
        port=$(echo "$decoded_json" | jq -r '.port' 2>/dev/null)
        if [ -z "$hostname_or_ip" ] || [ -z "$port" ]; then
            failure_reason="Failed to parse VMess JSON"
            log "WARN: [$node_id] 无法解析 VMess JSON: $node_link"
            echo "{\"node\": \"$node_link\", \"reason\": \"$failure_reason\"}" >> "$FAILED_TEMP_FILE"
            return 1
        fi
    fi

    if [ -z "$hostname_or_ip" ] || [ -z "$port" ]; then
        failure_reason="Unable to parse IP or port"
        log "WARN: [$node_id] 无法从链接中解析 IP 或端口: $node_link"
        echo "{\"node\": \"$node_link\", \"reason\": \"$failure_reason\"}" >> "$FAILED_TEMP_FILE"
        return 1
    fi

    local target_host="$hostname_or_ip"
    if [[ "$hostname_or_ip" =~ ^\[([0-9a-fA-F:]+)\]$ ]]; then # IPv6 with brackets
        ip="${BASH_REMATCH[1]}"
    elif [[ "$hostname_or_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then # IPv4
        ip="$hostname_or_ip"
    else # Domain
        log "INFO: [$node_id] 尝试解析域名: $hostname_or_ip"
        resolved_ips=$(dig +short "$hostname_or_ip" A AAAA 2>/dev/null)
        ip=$(echo "$resolved_ips" | head -n 1)
        if [ -n "$ip" ]; then
            [[ "$ip" =~ : ]] && target_host="[$ip]" # 为 nc 格式化 IPv6
            log "INFO: [$node_id] 解析结果: $hostname_or_ip -> $ip"
        else
            failure_reason="DNS resolution failed"
            log "WARN: [$node_id] 无法解析域名: $hostname_or_ip (原始链接: $node_link)"
            echo "{\"node\": \"$node_link\", \"reason\": \"$failure_reason\"}" >> "$FAILED_TEMP_FILE"
            return 1
        fi
    fi

    log "INFO: [$node_id] 正在测试节点连接: $target_host:$port (超时: ${TIMEOUT_SECONDS}s)"
    nc -z -w "$TIMEOUT_SECONDS" "$target_host" "$port" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log "INFO: [$node_id] 成功连接到 $target_host:$port"
        echo "$node_link" >> "$SUCCESS_TEMP_FILE"
        return 0
    else
        failure_reason="Connection failed"
        log "WARN: [$node_id] 无法连接到 $target_host:$port (可能被防火墙阻止或服务未运行)"
        echo "{\"node\": \"$node_link\", \"reason\": \"$failure_reason\", \"host\": \"$target_host\", \"port\": \"$port\"}" >> "$FAILED_TEMP_FILE"
        return 1
    fi
}

# --- 主逻辑开始 ---

# 1. 初始化
log "INFO: 开始节点连接性测试..."
log "INFO: 测试时间: $(date)"

# 确保临时文件在异常退出时被清理
trap 'rm -f "$MERGED_NODES_TEMP_FILE" "$SUCCESS_TEMP_FILE" "$FAILED_TEMP_FILE"; log "INFO: 清理临时文件并退出"; exit 1' SIGINT SIGTERM EXIT

# 2. 创建输出目录并初始化失败节点文件
mkdir -p "$OUTPUT_DIR"
echo "[]" > "$FAILED_FILE" # 初始化为空 JSON 数组

# 3. 检查依赖
check_dependencies

# 4. 下载并合并节点配置文件
log "INFO: 下载并合并节点配置文件..."
for url in "${NODE_SOURCES[@]}"; do
    log "INFO: 正在下载: $url"
    curl -sL --retry 3 --retry-delay 2 "$url" >> "$MERGED_NODES_TEMP_FILE"
    if [ $? -ne 0 ]; then
        log "WARN: 未能从 $url 下载文件。"
    fi
done

# 检查合并后的临时文件是否为空
if [ ! -s "$MERGED_NODES_TEMP_FILE" ]; then
    log "ERROR: 未能下载任何节点配置文件，或所有文件都为空。"
    rm -f "$MERGED_NODES_TEMP_FILE" "$SUCCESS_TEMP_FILE" "$FAILED_TEMP_FILE"
    exit 1
fi

# 去重合并后的节点
sort -u "$MERGED_NODES_TEMP_FILE" -o "$MERGED_NODES_TEMP_FILE"
TOTAL_UNIQUE_NODES=$(grep -vE '^(#|--|$)' "$MERGED_NODES_TEMP_FILE" 2>/dev/null | wc -l || echo 0)
log "INFO: 所有配置文件下载并合并成功（去重后），共计 ${TOTAL_UNIQUE_NODES} 个节点，开始并行测试连接性..."

# 5. 并行测试节点
log "INFO: 使用 $PARALLEL_JOBS 个并行任务测试节点..."
export -f test_node_connectivity log # 导出函数供 parallel 使用
export LOG_FILE SUCCESS_TEMP_FILE FAILED_TEMP_FILE TIMEOUT_SECONDS # 导出变量
# 使用 seq 和 grep 生成带编号的节点列表
grep -vE '^(#|--|$)' "$MERGED_NODES_TEMP_FILE" | nl -w1 -s' ' | parallel --line-buffer -j "$PARALLEL_JOBS" test_node_connectivity {2} {1}

# 6. 合并和去重成功节点
log "INFO: 合并并去重成功节点..."
# 清空旧的成功节点文件，只保留本次运行结果
: > "$SUCCESS_TEMP_FILE.tmp"
if [ -s "$SUCCESS_TEMP_FILE" ]; then
    sort -u "$SUCCESS_TEMP_FILE" > "$SUCCESS_TEMP_FILE.tmp"
fi
# 写入新头部并保存
echo "# Successful Nodes (Updated by GitHub Actions at $(date '+%Y-%m-%d %H:%M:%S %Z'))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
cat "$SUCCESS_TEMP_FILE.tmp" >> "$SUCCESS_FILE"

# 7. 合并和格式化失败节点
log "INFO: 合并并格式化失败节点..."
if [ -s "$FAILED_TEMP_FILE" ]; then
    # 使用 jq 将临时失败节点格式化为 JSON 数组
    jq -s '.' "$FAILED_TEMP_FILE" > "$FAILED_FILE"
else
    echo "[]" > "$FAILED_FILE"
fi

# 8. 统计结果
SUCCESS_COUNT=$(grep -vE '^(#|--|$)' "$SUCCESS_FILE" | wc -l)
FAILED_COUNT=$(jq length "$FAILED_FILE")
log "INFO: 成功连接节点数: $SUCCESS_COUNT，失败节点数: $FAILED_COUNT"

# 9. 清理临时文件
rm -f "$MERGED_NODES_TEMP_FILE" "$SUCCESS_TEMP_FILE" "$SUCCESS_TEMP_FILE.tmp" "$FAILED_TEMP_FILE"

log "INFO: 节点连接性测试流程完成。"
