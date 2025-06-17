#!/bin/bash
set -e # 遇到错误时退出

# 检查必要文件和目录
if [ ! -f data/520.yaml ]; then
    echo "::error::未找到 data/520.yaml 配置文件，退出。"
    exit 1
fi

if [ ! -x tools/clash ]; then
    echo "::error::未找到可执行的 tools/clash，退出。"
    exit 1
fi

# 清空或创建输出文件
> data/521.yaml

# 启动 Clash 服务
echo "启动 Clash 服务..."
tools/clash -f data/520.yaml -d temp &
CLASH_PID=$!
sleep 5 # 等待 Clash 启动

# 检查 Clash 是否成功启动
if ! ps -p $CLASH_PID > /dev/null; then
    echo "::error::Clash 服务启动失败，退出。"
    exit 1
fi

# 提取代理节点名称（假设 520.yaml 中 proxies 字段包含节点）
# 使用 yq 或 grep 解析 YAML 文件，提取代理名称
if ! command -v yq &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y yq || {
        echo "::error::无法安装 yq，退出。"
        exit 1
    }
fi

# 提取 proxies 字段中的 name
PROXY_NAMES=$(yq e '.proxies[].name' data/520.yaml 2>/dev/null)
if [ -z "$PROXY_NAMES" ]; then
    echo "::error::无法从 520.yaml 提取代理节点名称，退出。"
    kill $CLASH_PID
    exit 1
fi

# 测试每个代理节点
echo "开始测试代理节点..."
while read -r proxy_name; do
    if [ -n "$proxy_name" ]; then
        echo "测试代理节点: $proxy_name"
        # 使用 curl 通过 Clash 代理（默认端口 7890）测试连通性
        http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890 \
        curl -s -m 5 http://www.google.com > /dev/null
        if [ $? -eq 0 ]; then
            echo "- name: $proxy_name" >> data/521.yaml
            echo "  status: 可用" >> data/521.yaml
            echo "$proxy_name: 可用"
        else
            echo "- name: $proxy_name" >> data/521.yaml
            echo "  status: 不可用" >> data/521.yaml
            echo "$proxy_name: 不可用"
        fi
    fi
done <<< "$PROXY_NAMES"

# 关闭 Clash 服务
echo "关闭 Clash 服务..."
kill $CLASH_PID
wait $CLASH_PID 2>/dev/null || true

echo "测试完成，结果已保存至 data/521.yaml"
