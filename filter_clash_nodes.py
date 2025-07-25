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
            # --- 核心修改点：新增检查确保代理包含 'type' 字段 ---
            if not isinstance(proxy, dict) or 'type' not in proxy:
                print(f"Warning: Skipping malformed proxy entry or entry without 'type' key: {proxy.get('name', 'Unnamed') if isinstance(proxy, dict) else proxy}", file=sys.stderr)
                continue # 跳过这个格式不正确的代理，处理下一个

            # 确保 'server' 或 'host' 字段存在以获取服务器地址
            # VLESS 类型通常使用 'host' 字段作为服务器地址
            server_address = proxy.get('server') # 优先尝试 'server'
            if not server_address: # 如果没有 'server'，则尝试 'host'
                server_address = proxy.get('host')
            
            # 如果既没有 'server' 也没有 'host'，则跳过此代理
            if not server_address:
                print(f"Warning: Skipping proxy '{proxy.get('name', 'Unnamed')}' (type: {proxy.get('type')}) as it has no 'server' or 'host' key.", file=sys.stderr)
                continue 

            # 定义靠近中国的地区关键词，用于匹配服务器地址或节点名称
            # 您可以根据需要调整这些关键词
            keywords_to_match = ['hk', 'tw', 'sg', 'jp', 'kr', 'ru'] 
            
            matched_region = False
            # 检查服务器地址是否包含任何一个关键词 (不区分大小写)
            for keyword in keywords_to_match:
                if keyword.lower() in server_address.lower():
                    matched_region = True
                    break
            
            # 如果服务器地址未匹配，则尝试检查节点名称 (remark 或 name)
            # 有些订阅可能在名称中标记地区信息
            proxy_name = proxy.get('remark') or proxy.get('name', '')
            if not matched_region: 
                for keyword in keywords_to_match:
                    if keyword.lower() in proxy_name.lower():
                        matched_region = True
                        break

            # 如果匹配到指定地区，则进一步处理此代理
            if matched_region:
                # 处理 ShadowSocks 代理的 'unknown method: ss' 错误
                # Clash 工具可能不支持这种特定的加密方法
                if proxy['type'] == 'ss': # 此时 'type' 字段必然存在
                    cipher_method = proxy.get('cipher')
                    if cipher_method and cipher_method.lower() == 'ss':
                        print(f"Warning: Skipping SS proxy '{proxy.get('name', 'Unnamed')}' due to unsupported cipher method 'ss'.", file=sys.stderr)
                        continue # 跳过这个节点

                # 处理 'tls' 字段的类型转换
                # 确保 'tls' 字段是布尔值 (True/False)，而不是字符串
                if 'tls' in proxy:
                    tls_value = proxy['tls']
                    if isinstance(tls_value, str):
                        proxy['tls'] = tls_value.lower() == 'true'
                    elif not isinstance(tls_value, bool):
                        proxy['tls'] = False # 如果不是字符串也不是布尔值，则设为 False
                
                # 将通过所有检查和过滤的代理添加到列表中
                filtered_proxies.append(proxy)
            else:
                # 打印被过滤掉的节点信息，方便调试
                print(f"Info: Skipping proxy '{proxy.get('name', 'Unnamed')}' (server/host: {server_address}) as it does not match close-to-China regions.", file=sys.stderr)

    else:
        print("Warning: No 'proxies' key found or it's not a list in the input config.", file=sys.stderr)

    # 构建输出配置，只包含过滤后的代理
    output_config = {'proxies': filtered_proxies}
    
    output_file = 'filtered_nodes.yaml'
    # 将过滤后的配置写入新文件
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"Successfully filtered {len(filtered_proxies)} nodes to '{output_file}'")

except yaml.YAMLError as e:
    print(f"Error parsing YAML: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
