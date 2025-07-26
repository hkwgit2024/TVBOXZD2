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
        for i, proxy in enumerate(config['proxies']): # 添加索引 i，方便调试
            # --- 确保代理是字典类型且包含 'type' 字段 (保留) ---
            if not isinstance(proxy, dict) or 'type' not in proxy:
                print(f"Warning: Proxy {i+1}: Skipping malformed proxy entry or entry without 'type' key: {proxy.get('name', 'Unnamed') if isinstance(proxy, dict) else str(proxy)[:50]}...", file=sys.stderr)
                continue # 跳过这个格式不正确的代理，处理下一个

            proxy_type = proxy['type'] # 获取代理类型
            proxy_name = proxy.get('name', f"Unnamed Proxy {i+1}") # 提前获取名称用于日志

            # 针对不同类型的代理进行更严格的字段校验 (保留所有)
            is_valid_node = True
            missing_fields = []

            # --- 增强的 VMess 错误排除：针对 unsupported security type 和 cipher missing ---
            if proxy_type == 'vmess':
                # Clash Vmess 期望的有效 security (加密方式) 列表
                valid_vmess_ciphers = [
                    'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305',
                    'chacha20-ietf-poly1305', # 常见别名
                    'aes-256-gcm' # 某些情况下可能支持
                ]
                
                vmess_cipher = proxy.get('cipher')

                if vmess_cipher is None: # 如果 cipher 字段完全缺失
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy because 'cipher' field is missing. This often causes 'key 'cipher' missing' error.", file=sys.stderr)
                    is_valid_node = False
                elif not isinstance(vmess_cipher, str) or vmess_cipher.strip() == '':
                    # 如果 cipher 是非字符串类型，或者是空字符串（包括只有空格）
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy due to invalid or empty 'cipher' field (received: '{vmess_cipher}'). This often causes 'unsupported security type' error.", file=sys.stderr)
                    is_valid_node = False
                elif vmess_cipher.lower() not in valid_vmess_ciphers:
                    # 如果 cipher 是字符串但不在有效列表内，且不是空字符串
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy due to unsupported 'cipher' type ('{vmess_cipher}'). This often causes 'unsupported security type' error.", file=sys.stderr)
                    is_valid_node = False


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
                # SS 协议的 'cipher' 字段也可能缺失或为 'ss'
                if proxy.get('cipher') is None or proxy.get('cipher').lower() == 'ss':
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SS proxy due to missing or unsupported 'cipher' method ('{proxy.get('cipher', 'missing') if proxy.get('cipher') is not None else 'missing'}').", file=sys.stderr)
                    is_valid_node = False

            elif proxy_type == 'vless':
                required_fields = ['server', 'port', 'uuid']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
                # VLESS 协议的 security 字段通常在 URL 参数中，会被解析到 proxy 字典中。
                # 如果 security 参数存在且不是 'tls' 或 'none'，或者为空，则排除。
                vless_security = proxy.get('security')
                if vless_security is not None: # 如果 security 字段存在
                    # 如果是空字符串或非预期的值，则排除
                    if not isinstance(vless_security, str) or \
                       (isinstance(vless_security, str) and vless_security.strip() == '') or \
                       (vless_security.lower() not in ['tls', 'none']):
                        print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VLESS proxy due to unsupported or empty 'security' field ('{vless_security}').", file=sys.stderr)
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
                # SSR 协议的 'cipher' 字段也可能缺失
                if proxy.get('cipher') is None:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SSR proxy due to missing 'cipher' field.", file=sys.stderr)
                    is_valid_node = False
            else:
                # 对于不支持的协议类型，直接排除 (保留)
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping unsupported proxy type '{proxy_type}'.", file=sys.stderr)
                continue


            if not is_valid_node:
                # 仅当是缺失字段导致的无效才打印这个信息，避免重复
                if missing_fields:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy due to missing required fields: {', '.join(missing_fields)}.", file=sys.stderr)
                continue # 跳过此代理

            # 确保 'server' 或 'host' 字段存在以获取服务器地址 (保留)
            server_address = proxy.get('server')
            if not server_address:
                server_address = proxy.get('host')
            
            if not server_address:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it has no 'server' or 'host' key (secondary check).", file=sys.stderr)
                continue

            # 定义靠近中国的地区关键词，用于匹配服务器地址或节点名称 (保留)
            keywords_to_match = ['hk', 'tw', 'sg', 'jp', 'kr', 'ru']
            
            matched_region = False
            for keyword in keywords_to_match:
                if keyword.lower() in server_address.lower():
                    matched_region = True
                    break
            
            # proxy_name 已经在前面获取
            if not matched_region:
                for keyword in keywords_to_match:
                    if keyword.lower() in proxy_name.lower():
                        matched_region = True
                        break

            if matched_region:
                # 处理 ShadowSocks 代理的 'unknown method: ss' 错误 (保留)
                if proxy_type == 'ss':
                    cipher_method = proxy.get('cipher')
                    # 这里的判断可以和上面 SS 类型校验合并，但为了保留原始逻辑，暂时分开。
                    # 如果上面 SS 校验已经排除了，这里就不会执行。
                    if cipher_method and cipher_method.lower() == 'ss':
                        print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SS proxy due to unsupported cipher method 'ss'.", file=sys.stderr)
                        continue

                # 处理 'tls' 字段的类型转换 (保留)
                if 'tls' in proxy:
                    tls_value = proxy['tls']
                    if isinstance(tls_value, str):
                        proxy['tls'] = tls_value.lower() == 'true'
                    elif not isinstance(tls_value, bool):
                        proxy['tls'] = False
                
                filtered_proxies.append(proxy)
            else:
                print(f"Info: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it does not match close-to-China regions. Server/Host: {server_address}", file=sys.stderr)

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
