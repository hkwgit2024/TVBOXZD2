#!/bin/bash

# 定义 mihomo 可执行文件的路径
MIHOMO_EXE="mihomo/mihomo-linux-amd64-compatible-v1.19.13"

# 检查可执行文件是否存在
if [ ! -f "$MIHOMO_EXE" ]; then
    echo "Error: mihomo executable not found at $MIHOMO_EXE."
    exit 1
fi

# 将 mihomo 可执行文件移动到根目录并重命名
echo "Moving mihomo executable to a simpler name..."
mv "$MIHOMO_EXE" mihomo-linux

# 检查移动是否成功
if [ ! -f "./mihomo-linux" ]; then
    echo "Error: Failed to move mihomo executable."
    exit 1
fi

# 赋予 mihomo 执行权限
echo "Granting execute permission to mihomo..."
chmod +x ./mihomo-linux

# 下载原始的订阅链接
echo "Downloading raw subscription file..."
curl -s -o link.yaml https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml

# 检查订阅文件是否成功下载
if [ ! -f "link.yaml" ]; then
    echo "Error: Failed to download link.yaml."
    exit 1
fi

# 运行 mihomo 并测试节点延迟
echo "Running mihomo to test node latency..."
./mihomo-linux -f link.yaml -t 100 --sort -o clash_config.yaml

# 检查输出文件是否成功生成
if [ -f "clash_config.yaml" ]; then
    echo "clash_config.yaml has been generated successfully."
else
    echo "Error: Failed to generate clash_config.yaml."
    exit 1
fi
