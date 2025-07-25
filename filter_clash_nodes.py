import yaml
import sys
import os

try:
    input_file = 'clash_config.yaml'
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    filtered_proxies = []
    if 'proxies' in config and isinstance(config['proxies'], list):
        for proxy in config['proxies']:
            if isinstance(proxy, dict) and 'server' in proxy:
                server_address = proxy['server']
                
                # 定义国家/地区的关键词列表，匹配服务器地址中的标识符
                # 例如：sg001 -> SG, jp001 -> JP, us001 -> US, hk001 -> HK
                keywords_to_match = ['sg', 'jp', 'us', 'hk']
                
                # 检查服务器地址是否包含任何一个关键词
                if any(keyword.lower() in server_address.lower() for keyword in keywords_to_match):
                    # --- 关键修改部分：对 'tls' 字段进行类型转换 ---
                    if 'tls' in proxy:
                        # 获取 tls 的当前值
                        tls_value = proxy['tls']
                        # 如果是字符串类型，则尝试转换为布尔值
                        if isinstance(tls_value, str):
                            # 将字符串 "true" (不区分大小写) 转换为 True，其他字符串都视为 False
                            proxy['tls'] = tls_value.lower() == 'true'
                        # 如果不是布尔类型也不是字符串，可以根据需求处理，这里默认设置为 False
                        elif not isinstance(tls_value, bool):
                            proxy['tls'] = False # 或者可以根据实际情况设置为 True
                    # --- 修改结束 ---
                    filtered_proxies.append(proxy)
            else:
                print(f"Warning: Skipping malformed proxy entry or entry without 'server' key: {proxy}", file=sys.stderr)
    else:
        print("Warning: No 'proxies' key found or it's not a list in the input config.", file=sys.stderr)

    output_config = {'proxies': filtered_proxies}
    
    output_file = 'filtered_nodes.yaml'
    with open(output_file, 'w', encoding='utf-8') as f:
        # 使用 default_flow_style=False 保持块状风格，便于阅读
        # allow_unicode=True 确保正确处理非ASCII字符
        # sort_keys=False 保持原始顺序，不按字母排序
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"Successfully filtered {len(filtered_proxies)} nodes to '{output_file}'")

except yaml.YAMLError as e:
    print(f"Error parsing YAML: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
