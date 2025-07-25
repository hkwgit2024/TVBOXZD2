#!/bin/bash

# 接收 NODE_LIST_URLS 作为参数
NODE_LIST_URLS="$1"

if [ -z "$NODE_LIST_URLS" ]; then
  echo "错误: 未提供 NODE_LIST_URLS 环境变量"
  exit 1
fi

# 确保安装 Go 语言版本的 yq
echo "安装 Go 语言版本的 yq..."
YQ_VERSION="v4.44.2" # 您可以根据需要更改为最新版本
YQ_BIN="yq_linux_amd64"
curl -sSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BIN}" -o /usr/local/bin/yq
chmod +x /usr/local/bin/yq
if ! command -v yq &> /dev/null; then
    echo "错误: yq 未能成功安装。请检查安装步骤。"
    exit 1
fi
yq --version

echo "下载、修复并合并订阅文件..."
mkdir -p temp_subscriptions
ALL_PROXIES_COLLECTED="all_proxies_collected.yaml" # 临时文件，只收集所有代理列表
FINAL_CONFIG="clash_subscriptions.yaml"

# 初始化一个空的代理列表文件
echo "[]" > "$ALL_PROXIES_COLLECTED"

# 定义 yq 的 TLS 修复表达式并写入文件
YQ_TLS_FIX_EXPR_FILE="yq_tls_fix_expr.yaml"
cat << 'EOF_YQ_EXPR' > "$YQ_TLS_FIX_EXPR_FILE"
.[] |= (
  select(has("tls")) |= (
    .tls = (
      if .tls | to_string | downcase == "true" then true
      elif .tls | to_string | downcase == "false" or .tls == "" then false
      else false # 默认情况下，如果tls不是标准布尔字符串，则视为 false
      end
    )
  )
)
EOF_YQ_EXPR
# 注意 'EOF_YQ_EXPR' 两边的单引号，防止 Bash 提前解析表达式内容

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

  # 清理文件：移除 BOM、回车符
  echo "清理 $temp_raw_file 中的非法字符和 BOM..."
  sed 's/\r$//' "$temp_raw_file" | sed '1s/^\xEF\xBB\xBF//' > "$temp_cleaned_file"

  echo "调试: 显示 $temp_cleaned_file 前10行内容..."
  head -n 10 "$temp_cleaned_file"

  # 验证 YAML 格式并处理潜在的代理提取
  echo "验证 $temp_cleaned_file 的 YAML 格式并尝试提取代理..."
  # 尝试提取 .proxies 字段，如果失败，说明 YAML 格式有问题或无 proxies
  # 使用一个临时文件来存储提取的代理，而不是直接使用变量，避免变量内容过大问题
  TEMP_EXTRACTED_PROXIES="temp_subscriptions/extracted_proxies_${i}.yaml"
  if ! yq eval '.proxies' "$temp_cleaned_file" > "$TEMP_EXTRACTED_PROXIES" 2>/dev/null; then
    echo "错误: $temp_cleaned_file 无法提取 proxies 字段，可能包含无效 YAML 或无 proxies。"
    echo "调试: 显示 $temp_cleaned_file 完整内容..."
    cat "$temp_cleaned_file"
    continue
  fi

  # 检查提取的代理内容是否为空列表或仅包含空行
  # 检查 temp_extracted_proxies.yaml 是否只包含 "[]" 或为空
  if [ ! -s "$TEMP_EXTRACTED_PROXIES" ] || [ "$(cat "$TEMP_EXTRACTED_PROXIES" | tr -d '[:space:]')" = "[]" ]; then
    echo "警告: $temp_cleaned_file 提取的 proxies 列表为空或无效，跳过。"
    continue
  fi

  # 对提取出的代理进行 TLS 布尔值修复
  echo "修复 temp_extracted_proxies_${i}.yaml 中的 TLS 配置 (使用 yq)..."
  # yq 从文件读取表达式进行修改
  yq eval -f "$YQ_TLS_FIX_EXPR_FILE" "$TEMP_EXTRACTED_PROXIES" > temp_proxies_fixed_for_merge.yaml
  
  # 将修复后的代理列表合并到 ALL_PROXIES_COLLECTED
  echo "合并修复后的代理到 $ALL_PROXIES_COLLECTED..."
  # 使用 yq 的 eval-all 合并两个代理列表（都是 YAML 数组）
  yq eval-all 'select(fileIndex == 0) + select(fileIndex == 1)' "$ALL_PROXIES_COLLECTED" temp_proxies_fixed_for_merge.yaml > temp_merged_proxies.yaml && mv temp_merged_proxies.yaml "$ALL_PROXIES_COLLECTED"
  proxy_found=true
done

if [ "$proxy_found" = false ]; then
  echo "错误: 所有订阅均无有效代理，无法生成配置文件"
  exit 1
fi

echo "生成最终 Clash 配置文件: $FINAL_CONFIG..."
# 将收集到的所有代理列表插入到 Clash 配置模板中
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
# 将代理列表内容追加到 FINAL_CONFIG，确保缩进正确
# 使用 yq eval '.' 来确保输出的是一个格式正确的 YAML 数组
yq eval '.' "$ALL_PROXIES_COLLECTED" >> "$FINAL_CONFIG"

if [ ! -s "$FINAL_CONFIG" ]; then
  echo "错误: 生成的 $FINAL_CONFIG 为空或无效"
  exit 1
fi

echo "合并完成，生成文件: $FINAL_CONFIG"

# 输出最终文件路径，供 GitHub Actions 工作流使用
echo "final_config_path=$FINAL_CONFIG" >> "$GITHUB_OUTPUT" # 确保输出到 $GITHUB_OUTPUT
