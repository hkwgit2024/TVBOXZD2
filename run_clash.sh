#!/bin/bash

# 定义 mihomo 压缩包的路径
MIHOMO_TAR="mihomo/mihomo-linux-amd64-compatible-v1.19.13"

# 检查压缩包是否存在
if [ ! -f "$MIHOMO_TAR" ]; then
    echo "Error: mihomo archive not found at $MIHOMO_TAR."
    exit 1
fi

# 解压 mihomo
echo "Extracting mihomo binary..."
tar -zxvf "$MIHOMO_TAR" --strip-components=1 mihomo-linux-amd64-compatible -O > mihomo-linux

# 检查解压是否成功
if [ ! -f "./mihomo-linux" ]; then
    echo "Error: Failed to extract mihomo binary."
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
# -t 100：只测试前100个节点
# --sort：按延迟大小排序
# -o：输出文件
./mihomo-linux -f link.yaml -t 100 --sort -o clash_config.yaml

# 检查输出文件是否成功生成
if [ -f "clash_config.yaml" ]; then
    echo "clash_config.yaml has been generated successfully."
else
    echo "Error: Failed to generate clash_config.yaml."
    exit 1
fi
