#!/bin/bash

# 设置目标文件和输出文件
NODES_URL="https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
SUB_FILE="data/sub.txt"
FAILED_FILE="data/failed_proxies.json"
TEMP_FILE="data/temp_sub.txt"
TIMEOUT=5
MAX_PARALLEL=10

# 确保输出目录存在
mkdir -p data

# 下载节点文件
curl -s -o nodes.txt "$NODES_URL"

# 检查 failed_proxies.json 是否存在，如果不存在则创建空 JSON
if [ ! -f "$FAILED_FILE" ]; then
    echo "[]" > "$FAILED_FILE"
fi

# 测试单个节点的函数
test_node() {
    local node=$1
    local name=$(echo "$node" | cut -d',' -f1)
    local host=$(echo "$node" | cut -d',' -f2)
    local port=$(echo "$node" | cut -d',' -f3)

    # 检查是否在失败列表中
    if jq -e --arg name "$name" '.[] | select(.name == $name)' "$FAILED_FILE" >/dev/null; then
        echo "Skipping $name (already in failed list)"
        return
    fi

    # 测试连通性并测量延迟
    local result=$(timeout $TIMEOUT bash -c "echo -n > /dev/tcp/$host/$port" 2>/dev/null)
    if [ $? -eq 0 ]; then
        # 使用 ping 测量延迟（假设节点支持 ICMP）
        local delay=$(ping -c 1 -W 1 "$host" | grep 'time=' | awk -F'time=' '{print $2}' | awk '{print $1}' | grep -o '[0-9.]*' || echo "1000")
        echo "$name,$delay" >> "$TEMP_FILE"
        echo "Success: $name, Delay: $delay ms"
    else
        # 记录失败节点
        jq --arg name "$name" --arg host "$host" --arg port "$port" '. + [{"name": $name, "host": $host, "port": $port}]' "$FAILED_FILE" > tmp.json && mv tmp.json "$FAILED_FILE"
        echo "Failed: $name"
    fi
}

# 并行测试节点
test_nodes_parallel() {
    local nodes=("$@")
    local i=0
    local pids=()

    for node in "${nodes[@]}"; do
        test_node "$node" &
        pids+=($!)
        ((i++))
        if [ $i -ge $MAX_PARALLEL ]; then
            for pid in "${pids[@]}"; do
                wait $pid
            done
            pids=()
            i=0
        fi
    done

    # 等待剩余进程
    for pid in "${pids[@]}"; do
        wait $pid
    done
}

# 主流程
main() {
    # 读取节点
    mapfile -t nodes < <(grep -v '^$' nodes.txt)

    # 清空临时文件
    : > "$TEMP_FILE"

    # 并行测试
    test_nodes_parallel "${nodes[@]}"

    # 按延迟排序并追加到 sub.txt
    if [ -s "$TEMP_FILE" ]; then
        sort -t',' -k2 -n "$TEMP_FILE" | while IFS=',' read -r name delay; do
            echo "${name}_${delay}ms" >> "$SUB_FILE"
        done
        rm "$TEMP_FILE"
    fi

    # 输出结果
    echo "Results appended to $SUB_FILE"
    echo "Failed nodes saved to $FAILED_FILE"
    cat "$SUB_FILE"
}

main
