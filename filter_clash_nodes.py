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
            # --- 关键修改：检查 'server' 或 'host' 字段来获取服务器地址 ---
            server_address = proxy.get('server') # 优先尝试 'server'
            if not server_address: # 如果没有 'server'，则尝试 'host'
                server_address = proxy.get('host')
            
            # 如果既没有 'server' 也没有 'host'，则跳过此代理
            if not server_address or not isinstance(proxy, dict):
                print(f"Warning: Skipping malformed proxy entry or entry without 'server' or 'host' key: {proxy}", file=sys.stderr)
                continue # 跳过当前循环，处理下一个代理

            # --- 更新为靠近中国的地区关键词 ---
            # 这些关键词将用于匹配 server_address (可以是域名或IP)
            # 例如 'hk' 可以匹配到 'hk.example.com' 或 '香港节点'
            # 'kr' 可以匹配 'kr.vps.com'
            keywords_to_match = ['hk', 'tw', 'sg', 'jp', 'kr', 'ru'] 
            
            # 检查服务器地址是否包含任何一个关键词 (不区分大小写)
            # 增加对国家代码的精确匹配，以避免IP地址中的数字误判
            matched_region = False
            for keyword in keywords_to_match:
                if keyword.lower() in server_address.lower():
                    matched_region = True
                    break
            
            # 同时，检查节点名称 (remark 或 name) 中是否包含这些关键词
            # 有些订阅可能在名称中标记地区，而不是服务器地址
            proxy_name = proxy.get('remark') or proxy.get('name', '')
            if not matched_region: # 如果服务器地址未匹配，则尝试匹配节点名称
                for keyword in keywords_to_match:
                    if keyword.lower() in proxy_name.lower():
                        matched_region = True
                        break

            if matched_region:
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
                print(f"Info: Skipping proxy '{proxy.get('name', 'Unnamed')}' (server/host: {server_address}) as it does not match close-to-China regions.", file=sys.stderr)

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
