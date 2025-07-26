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
            # --- 核心修改点：新增检查确保代理包含 'type' 字段且是字典类型 ---
            if not isinstance(proxy, dict) or 'type' not in proxy:
                print(f"Warning: Skipping malformed proxy entry or entry without 'type' key: {proxy.get('name', 'Unnamed') if isinstance(proxy, dict) else str(proxy)[:50]}...", file=sys.stderr)
                continue # 跳过这个格式不正确的代理，处理下一个

            proxy_type = proxy['type'] # 获取代理类型

            # 针对不同类型的代理进行更严格的字段校验
            is_valid_node = True
            missing_fields = []

            # --- 新增：排除 Vmess 不支持的 security type ---
            if proxy_type == 'vmess':
                # Clash 对于 vmess 节点，如果 `tls` 为 true，`network` 为 ws 或 grpc，
                # 但 `cipher` (security) 字段为空，则会报错。
                # 在 Clash 配置中，vmess 的 security 字段通常是其加密方式，
                # 如果是空字符串或不被支持，就会出问题。
                # 我们检查 `tls` 是否为真，以及 `cipher` 是否为空。
                # 注意：这里假设 'cipher' 字段在订阅中可能对应 Clash 的 'security'。
                if proxy.get('tls') is True:
                    if not proxy.get('cipher'): # 如果开启了TLS但cipher字段为空或缺失
                         print(f"Warning: Skipping VMess proxy '{proxy.get('name', 'Unnamed')}' due to empty or missing 'cipher' (security) field when TLS is enabled.", file=sys.stderr)
                         is_valid_node = False
                         # 理论上也可以检查 network 是否为 ws 或 grpc，但更直接的是检查 cipher
                
                # 即使没有 TLS，如果 cipher 是空字符串也可能引发问题，虽然通常不那么致命
                # if not proxy.get('cipher'):
                #     print(f"Warning: Skipping VMess proxy '{proxy.get('name', 'Unnamed')}' due to empty or missing 'cipher' field.", file=sys.stderr)
                #     is_valid_node = False


            if proxy_type == 'vmess':
                required_fields = ['server', 'port', 'uuid', 'alterId']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            elif proxy_type == 'trojan':
                required_fields = ['server', 'port', 'password']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            elif proxy_type == 'ss':
                required_fields = ['server', 'port', 'cipher', 'password']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            elif proxy_type == 'vless':
                required_fields = ['server', 'port', 'uuid']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
                # VLESS 协议的 security 字段通常在 URL 参数中，会被解析到 proxy 字典中
                # 明确处理 security 参数，如果解析出来是空字符串，则 Clash 可能会报错。
                # 在 process_links.py 中已经尝试修复，这里是兜底检查。
                if 'security' in proxy and not proxy['security']:
                    print(f"Warning: Skipping VLESS proxy '{proxy.get('name', 'Unnamed')}' due to empty 'security' field.", file=sys.stderr)
                    is_valid_node = False
            elif proxy_type == 'hysteria2':
                required_fields = ['server', 'port', 'password']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            elif proxy_type == 'ssr':
                required_fields = ['server', 'port', 'cipher', 'password', 'protocol', 'obfs']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            else:
                # 对于不支持的协议类型，直接排除
                print(f"Warning: Skipping unsupported proxy type '{proxy_type}': {proxy.get('name', 'Unnamed')}.", file=sys.stderr)
                continue


            if not is_valid_node:
                # 已经有专门的警告在上面打印了，这里可以省略，或者打印一个更通用的信息
                if missing_fields: # 仅当是缺失字段导致的无效才打印这个信息
                    print(f"Warning: Skipping proxy '{proxy.get('name', 'Unnamed')}' (type: {proxy_type}) due to missing required fields: {', '.join(missing_fields)}.", file=sys.stderr)
                continue # 跳过此代理

            # 确保 'server' 或 'host' 字段存在以获取服务器地址
            server_address = proxy.get('server')
            if not server_address:
                server_address = proxy.get('host')
            
            if not server_address:
                print(f"Warning: Skipping proxy '{proxy.get('name', 'Unnamed')}' (type: {proxy.get('type')}) as it has no 'server' or 'host' key (secondary check).", file=sys.stderr)
                continue

            # 定义靠近中国的地区关键词，用于匹配服务器地址或节点名称
            keywords_to_match = ['hk', 'tw', 'sg', 'jp', 'kr', 'ru']
            
            matched_region = False
            for keyword in keywords_to_match:
                if keyword.lower() in server_address.lower():
                    matched_region = True
                    break
            
            proxy_name = proxy.get('remark') or proxy.get('name', '')
            if not matched_region:
                for keyword in keywords_to_match:
                    if keyword.lower() in proxy_name.lower():
                        matched_region = True
                        break

            if matched_region:
                # 处理 ShadowSocks 代理的 'unknown method: ss' 错误
                if proxy_type == 'ss':
                    cipher_method = proxy.get('cipher')
                    if cipher_method and cipher_method.lower() == 'ss':
                        print(f"Warning: Skipping SS proxy '{proxy.get('name', 'Unnamed')}' due to unsupported cipher method 'ss'.", file=sys.stderr)
                        continue

                # 处理 'tls' 字段的类型转换
                if 'tls' in proxy:
                    tls_value = proxy['tls']
                    if isinstance(tls_value, str):
                        proxy['tls'] = tls_value.lower() == 'true'
                    elif not isinstance(tls_value, bool):
                        proxy['tls'] = False
                
                filtered_proxies.append(proxy)
            else:
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
