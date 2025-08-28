#!/bin/bash

# 定义 mihomo 可执行文件的路径
MIHOMO_EXE="mihomo/mihomo-linux-amd64-compatible-v1.19.13"

# 检查可执行文件是否存在
if [ ! -f "$MIHOMO_EXE" ]; then
    echo "错误：在 $MIHOMO_EXE 路径下未找到 mihomo 可执行文件。"
    exit 1
fi

# 移动 mihomo 可执行文件到根目录并重命名
echo "正在将 mihomo 可执行文件移动到更简单的名称..."
mv "$MIHOMO_EXE" mihomo-linux

# 检查移动是否成功
if [ ! -f "./mihomo-linux" ]; then
    echo "错误：无法移动 mihomo 可执行文件。"
    exit 1
fi

# 赋予 mihomo 执行权限
echo "正在授予 mihomo 执行权限..."
chmod +x ./mihomo-linux

# 下载原始的订阅链接
echo "正在下载原始订阅文件..."
curl -s -o link.yaml https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml

# 检查订阅文件是否成功下载
if [ ! -f "link.yaml" ]; then
    echo "错误：无法下载 link.yaml。"
    exit 1
fi

# 使用 yq 过滤掉无效的代理节点
echo "正在过滤无效的代理节点..."
# 使用管道模式，这种语法更加通用和可靠
cat link.yaml | yq '.proxies = [.proxies[] | select(has("port") and (.port | type == "number"))]' > filtered_link.yaml

# 检查过滤后的文件是否生成
if [ ! -f "filtered_link.yaml" ]; then
    echo "错误：无法生成过滤后的文件。"
    exit 1
fi

# 运行 mihomo 并测试节点延迟
echo "正在运行 mihomo 以测试节点延迟..."
./mihomo-linux -f filtered_link.yaml -t 100 --sort -o clash_config.yaml

# 检查输出文件是否成功创建且不为空
if [ -s "clash_config.yaml" ]; then
    echo "clash_config.yaml 已成功生成。"
else
    echo "错误：无法生成 clash_config.yaml。过滤后可能没有有效的节点。"
    # 作为备用方案，创建一个有效的、空的 YAML 文件，以防止 Git 提交错误
    echo "proxies: []" > clash_config.yaml
    echo "已生成一个空的 clash_config.yaml 文件，以防止提交错误。"
fi
