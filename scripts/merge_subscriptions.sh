#!/bin/bash

# 接收 NODE_LIST_URLS 作为参数
NODE_LIST_URLS="$1"

if [ -z "$NODE_LIST_URLS" ]; then
  echo "错误: 未提供 NODE_LIST_URLS 环境变量"
  exit 1
fi

# 确保安装 Go 语言版本的 yq
echo "安装 Go 语言版本的 yq..."
YQ_VERSION="v4.44.2"
YQ_BIN="yq_linux_amd64"
curl -sSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BIN}" -o /usr/local/bin/yq
chmod +x /usr/local/bin/yq
if ! command -v yq &> /dev/null; then
  echo "错误: yq 未能成功安装。请检查网络或权限。"
  exit 1
fi
echo "yq 版本:"
yq --version

echo "下载、修复并合并订阅文件..."
mkdir -p temp_subscriptions
ALL_PROXIES_COLLECTED="all_proxies_collected.yaml"
FINAL_CONFIG="clash_subscriptions.yaml"
echo "[]" > "$ALL_PROXIES_COLLECTED"

# 将逗号分隔的 URL 转换为数组
IFS=',' read -ra URLS <<< "$NODE_LIST_URLS"
proxy_found=false

for i in "${!URLS[@]}"; do
  url="${URLS[$i]}"
  temp_raw_file="temp_subscriptions/sub_${i}_raw.yaml"
  temp_cleaned_file="temp_subscriptions/sub_${i}_cleaned.yaml"

  echo "下载: $url"
  if ! curl -s --fail --connect-timeout 15 "$url" -o "$temp_raw_file"; then
    echo "警告: 无法下载 $url，跳过"
    continue
  fi

  if [ ! -s "$temp_raw_file" ]; then
    echo "警告: $temp_raw_file 为空，跳过"
    continue
  fi

  # 清理文件：移除 BOM、回车符、制表符、多余空格
  echo "清理 $temp_raw_file 中的非法字符和 BOM..."
  sed 's/\r$//' "$temp_raw_file" | sed '1s/^\xEF\xBB\xBF//' | sed 's/\t/  /g' | sed 's/[[:space:]]*$//' > "$temp_cleaned_file"

  echo "调试: 显示 $temp_cleaned_file 前10行内容..."
  head -n 10 "$temp_cleaned_file"

  # 验证 YAML 格式
  echo "验证 $temp_cleaned_file 的 YAML 格式..."
  if ! yq eval '.' "$temp_cleaned_file" &> /dev/null; then
    echo "错误: $temp_cleaned_file 包含无效的 YAML 格式，跳过"
    echo "调试: 显示 $temp_cleaned_file 完整内容..."
    cat "$temp_cleaned_file"
    continue
  fi

  # 检查 proxies 字段是否存在且非空
  echo "验证 $temp_cleaned_file 的 proxies 字段..."
  PROXIES_COUNT=$(yq eval '.proxies | length' "$temp_cleaned_file" 2>/dev/null)
  if [ $? -ne 0 ] || [ "$PROXIES_COUNT" -eq 0 ]; then
    echo "警告: $temp_cleaned_file 无有效 proxies，跳过"
    echo "调试: 检查 $temp_cleaned_file 的 proxies 字段..."
    yq eval '.proxies' "$temp_cleaned_file" || echo "调试: 无法解析 proxies 字段，可能为空或格式错误"
    continue
  fi

  # 提取 proxies 字段
  echo "提取 $temp_cleaned_file 的 proxies 字段..."
  yq eval '.proxies' "$temp_cleaned_file" > temp_proxies_for_yq_fix.yaml

  # 修复 TLS 配置
  echo "修复 temp_proxies_for_yq_fix.yaml 中的 TLS 配置..."
  yq eval '
    .[] |= (
      if has("tls") then
        .tls = (
          if .tls == "true" or .tls == "True" then true
          elif .tls == "false" or .tls == "False" or .tls == "" then false
          else false
          end
        )
      else .tls = false
      end
    )
  ' temp_proxies_for_yq_fix.yaml > temp_proxies_fixed.yaml

  # 合并到 ALL_PROXIES_COLLECTED
  echo "合并修复后的代理到 $ALL_PROXIES_COLLECTED..."
  yq eval-all 'select(fileIndex == 0) + select(fileIndex == 1)' "$ALL_PROXIES_COLLECTED" temp_proxies_fixed.yaml > temp_merged.yaml && mv temp_merged.yaml "$ALL_PROXIES_COLLECTED"
  proxy_found=true
done

if [ "$proxy_found" = false ]; then
  echo "错误: 所有订阅均无有效代理，无法生成配置文件"
  exit 1
fi

echo "生成最终 Clash 配置文件: $FINAL_CONFIG..."
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
yq eval '.' "$ALL_PROXIES_COLLECTED" >> "$FINAL_CONFIG"

if [ ! -s "$FINAL_CONFIG" ]; then
  echo "错误: 生成的 $FINAL_CONFIG 为空或无效"
  exit 1
fi

echo "合并完成，生成文件: $FINAL_CONFIG"
echo "final_config_path=$FINAL_CONFIG"
