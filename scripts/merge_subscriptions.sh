#!/bin/bash

# 接收 NODE_LIST_URLS 作为参数
NODE_LIST_URLS="$1"

echo "下载、修复并合并订阅文件..."
mkdir -p temp_subscriptions
ALL_PROXIES="temp_proxies.yaml"
FINAL_CONFIG="clash_subscriptions.yaml"
echo "proxies: []" > "$ALL_PROXIES"

# 将逗号分隔的 URL 转换为数组
IFS=',' read -ra URLS <<< "$NODE_LIST_URLS"
for i in "${!URLS[@]}"; do
  url="${URLS[$i]}"
  temp_file="temp_subscriptions/sub_${i}.yaml"
  echo "下载: $url"
  if ! curl -s --fail --connect-timeout 10 "$url" -o "$temp_file"; then
    echo "警告: 无法下载 $url，跳过"
    continue
  fi

  echo "修复 $temp_file 中的 TLS 配置..."
  sed -i 's/tls: "true"/tls: true/g; s/tls: "false"/tls: false/g' "$temp_file"

  if yq e '.proxies | length > 0' "$temp_file" &> /dev/null; then
    echo "合并 $temp_file 到 $ALL_PROXIES..."
    yq e '.proxies' "$temp_file" > temp_proxies.yaml
    yq e -o yaml '. as $item ireduce ({}; .proxies += $item)' "$ALL_PROXIES" temp_proxies.yaml > temp.yaml
    mv temp.yaml "$ALL_PROXIES"
  else
    echo "警告: $temp_file 无有效 proxies，跳过"
  fi
done

if [ ! -s "$ALL_PROXIES" ]; then
  echo "错误: 未获取到任何有效代理"
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
yq e '.proxies' "$ALL_PROXIES" >> "$FINAL_CONFIG"

echo "合并完成，生成文件: $FINAL_CONFIG"
