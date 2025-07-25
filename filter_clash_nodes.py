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
            # 确保代理是字典且包含 'server' 字段
            if not isinstance(proxy, dict) or 'server' not in proxy:
                print(f"Warning: Skipping malformed proxy entry or entry without 'server' key: {proxy}", file=sys.stderr)
                continue # 跳过当前循环，处理下一个代理

            server_address = proxy['server']
            
            # --- 关键修改：更新为靠近中国的地区关键词 ---
            # 请根据您的节点实际命名规则调整这些关键词
            # 例如，如果香港节点服务器名包含 'hk' 或 'hongkong'，就添加相应的关键词
            keywords_to_match = ['hk', 'tw', 'sg', 'jp', 'kr', 'ru'] 
            
            # 检查服务器地址是否包含任何一个关键词 (不区分大小写)
            if any(keyword.lower() in server_address.lower() for keyword in keywords_to_match):
                
                # 处理 ShadowSocks 的 'unknown method: ss' 错误
                if proxy.get('type') == 'ss':
                    cipher_method = proxy.get('cipher')
                    if cipher_method and cipher_method.lower() == 'ss':
                        print(f"Warning: Skipping SS proxy '{proxy.get('name', 'Unnamed')}' due to unsupported cipher method 'ss'.", file=sys.stderr)
                        continue # 跳过这个节点

                # 处理 'tls' 字段的类型转换
                if 'tls' in proxy:
                    tls_value = proxy['tls']
                    if isinstance(tls_value, str):
                        proxy['tls'] = tls_value.lower() == 'true'
                    elif not isinstance(tls_value, bool):
                        proxy['tls'] = False 
                
                filtered_proxies.append(proxy)
            else:
                # 打印被过滤掉的节点信息，方便调试
                print(f"Info: Skipping proxy '{proxy.get('name', 'Unnamed')}' (server: {server_address}) as it does not match close-to-China regions.", file=sys.stderr)

    else:
        print("Warning: No 'proxies' key found or it's not a list in the input config.", file=sys.stderr)

    output_config = {'proxies': filtered_proxies}
    
    output_file = 'filtered_nodes.yaml'
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"Successfully filtered {len(filtered_proxies)} nodes to '{output_file}'")

except yaml.YAMLError as e:
    print(f"Error parsing YAML: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
