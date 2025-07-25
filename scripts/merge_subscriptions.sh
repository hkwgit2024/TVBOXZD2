#!/bin/bash

# 接收 NODE_LIST_URLS 作为参数
NODE_LIST_URLS="$1"

if [ -z "$NODE_LIST_URLS" ]; then
  echo "错误: 未提供 NODE_LIST_URLS 环境变量"
  exit 1
fi

echo "下载、修复并合并订阅文件..."
mkdir -p temp_subscriptions
ALL_PROXIES="temp_proxies.yaml"
FINAL_CONFIG="clash_subscriptions.yaml"
echo "proxies: []" > "$ALL_PROXIES"

# 将逗号分隔的 URL 转换为数组
IFS=',' read -ra URLS <<< "$NODE_LIST_URLS"
proxy_found=false

for i in "${!URLS[@]}"; do
  url="${URLS[$i]}"
  temp_file="temp_subscriptions/sub_${i}.yaml"
  echo "下载: $url"
  if ! curl -s --fail --connect-timeout 10 "$url" -o "$temp_file"; then
    echo "警告: 无法下载 $url，跳过"
    continue
  fi

  if [ ! -s "$temp_file" ]; then
    echo "警告: $temp_file 为空，跳过"
    continue
  fi

  echo "调试: 显示 $temp_file 前10行内容..."
  head -n 10 "$temp_file"

  echo "修复 $temp_file 中的 TLS 配置..."
  sed -i 's/tls: "true"/tls: true/g; s/tls: "false"/tls: false/g' "$temp_file"

  if yq e '.proxies | length > 0' "$temp_file" &> /dev/null; then
    echo "合并 $temp_file 到 $ALL_PROXIES..."
    yq e '.proxies' "$temp_file" > temp_proxies.yaml
    yq e -o yaml '. as $item ireduce ({}; .proxies += $item)' "$ALL_PROXIES" temp_proxies.yaml > temp.yaml
    mv temp.yaml "$ALL_PROXIES"
    proxy_found=true
  else
    echo "警告: $temp_file 无有效 proxies，跳过"
    echo "调试: 检查 $temp_file 的 proxies 字段..."
    yq e '.proxies' "$temp_file" || echo "调试: 无法解析 proxies 字段"
  fi
done

if [ "$proxy_found" = false ]; then
  echo "错误: 所有订阅均无有效代理，无法生成配置文件"
  exit 1
fi

echo "生成最终 Clash 配置文件..."
cat << EOF > "$FINAL_CONFIG"
# Clash 配置由 GitHub Actions 自动生成
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
proxies:
EOF
yq e -o yaml '.proxies' "$ALL_PROXIES" >> "$FINAL_CONFIG"

if [ ! -s "$FINAL_CONFIG" ]; then
  echo "错误: 生成的 $FINAL_CONFIG 为空"
  exit 1
fi

echo "合并完成，生成文件: $FINAL_CONFIG"
