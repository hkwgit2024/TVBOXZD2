#!/bin/bash

# 检查 clash-linux 文件是否存在
if [ ! -f "./clash-linux" ]; then
    echo "Error: clash-linux not found in the current directory."
    exit 1
fi

# 赋予 Clash 可执行权限
echo "Granting execute permission to clash-linux..."
chmod +x ./clash-linux

# 下载原始订阅链接
echo "Downloading raw subscription file from qjlxg/VT..."
curl -fsSL -o link.yaml https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml

# 检查订阅文件是否成功下载
if [ ! -f "link.yaml" ]; then
    echo "Error: Failed to download link.yaml."
    exit 1
fi

# 运行 Clash 并测试节点延迟
echo "Running clash to test node latency..."
# -t 100：只测试前100个节点，避免超时。
# --sort：按延迟大小排序。
# -o：输出文件。
./clash-linux -f link.yaml -t 100 --sort -o clash_config.yaml

# 检查输出文件是否成功生成
if [ -f "clash_config.yaml" ]; then
    echo "clash_config.yaml has been generated successfully."
else
    echo "Error: Failed to generate clash_config.yaml."
    exit 1
fi
