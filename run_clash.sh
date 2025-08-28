#!/bin/bash

# 下载 Clash 二进制文件
echo "Downloading clash-linux binary..."
# 确保你已经将 clash-linux 放在仓库根目录或者根据实际情况调整路径
chmod +x ./clash-linux

# 下载原始的订阅链接
echo "Downloading raw subscription file..."
curl -s -o link.yaml https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml

# 运行 Clash 并测试节点延迟
echo "Running clash to test node latency..."
# -t 100：测试100个节点，避免测试全部节点耗时过长
# -m 500：只保留延迟小于500ms的节点，可以根据需要调整
# --sort：按延迟排序
# -o：输出文件
./clash-linux -f link.yaml -t 100 --sort --o clash_config.yaml

echo "clash_config.yaml has been generated successfully."
