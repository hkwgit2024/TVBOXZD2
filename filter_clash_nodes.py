import yaml
import sys
import os
import re

try:
    input_file = 'clash_config.yaml'
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    filtered_proxies = []
    if 'proxies' in config and isinstance(config['proxies'], list):
        for i, proxy in enumerate(config['proxies']):
            # --- 确保代理是字典类型且包含 'type' 字段 ---
            if not isinstance(proxy, dict) or 'type' not in proxy:
                print(f"Warning: Proxy {i+1}: Skipping malformed proxy entry or entry without 'type' key: {proxy.get('name', 'Unnamed') if isinstance(proxy, dict) else str(proxy)[:50]}...", file=sys.stderr)
                continue

            proxy_type = proxy['type']
            proxy_name = proxy.get('name', f"Unnamed Proxy {i+1}")

            is_valid_node = True
            missing_fields = []

            # --- 增强的 VMess 错误排除：针对 unsupported security type 和 cipher missing ---
            if proxy_type == 'vmess':
                valid_vmess_ciphers = [
                    'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305',
                    'chacha20-ietf-poly1305',
                    'aes-256-gcm'
                ]
                
                vmess_cipher = proxy.get('cipher')

                if vmess_cipher is None:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy because 'cipher' field is missing. This often causes 'key 'cipher' missing' error.", file=sys.stderr)
                    is_valid_node = False
                elif not isinstance(vmess_cipher, str) or vmess_cipher.strip() == '':
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy due to invalid or empty 'cipher' field (received: '{vmess_cipher}'). This often causes 'unsupported security type' error.", file=sys.stderr)
                    is_valid_node = False
                elif vmess_cipher.lower() not in valid_vmess_ciphers:
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
                vless_security = proxy.get('security')
                if vless_security is not None:
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
                if proxy.get('cipher') is None:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SSR proxy due to missing 'cipher' field.", file=sys.stderr)
                    is_valid_node = False
            else:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping unsupported proxy type '{proxy_type}'.", file=sys.stderr)
                continue


            if not is_valid_node:
                if missing_fields:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy due to missing required fields: {', '.join(missing_fields)}.", file=sys.stderr)
                continue

            # 确保 'server' 或 'host' 字段存在以获取服务器地址
            server_address = proxy.get('server')
            if not server_address:
                server_address = proxy.get('host')
            
            if not server_address:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it has no 'server' or 'host' key (secondary check).", file=sys.stderr)
                continue

            # --- 新增：排除国内节点的逻辑 ---
            # 定义要排除的国内地区关键词（中文和拼音），以及常见的国内云服务商
            keywords_to_exclude = [
                'cn', 'china', '中国', '大陆', 'tencent', 'aliyun', '华为云', '移动', '联通', '电信', # 省份
                '北京', '上海', '广东', '江苏', '浙江', '四川', '重庆', '湖北', '湖南', '福建', '山东',
                '河南', '河北', '山西', '陕西', '辽宁', '吉林', '黑龙江', '安徽', '江西', '广西', '云南',
                '贵州', '甘肃', '青海', '宁夏', '新疆', '西藏', '内蒙古', '天津', '海南', 'hk', 'tw', 'mo'
            ]
            
            is_domestic_node = False
            # 检查服务器地址
            for keyword in keywords_to_exclude:
                if keyword.lower() in server_address.lower():
                    is_domestic_node = True
                    break
            
            # 检查节点名称 (如果服务器地址没匹配到)
            if not is_domestic_node:
                for keyword in keywords_to_exclude:
                    if keyword.lower() in proxy_name.lower():
                        is_domestic_node = True
                        break

            if is_domestic_node:
                print(f"Info: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it appears to be a domestic Chinese node or a region often considered domestic by VPN users (HK/TW/MO for some policies). Server/Host: {server_address}", file=sys.stderr)
                continue # 跳过此代理


            # 定义靠近中国的地区关键词，用于匹配服务器地址或节点名称 (保留并优化命名)
            # 这些是您希望保留的“靠近中国”的国际节点
            keywords_to_keep_near_china = ['sg', 'jp', 'kr', 'ru'] # 已经把 hk, tw 移到排除列表

            matched_region_to_keep = False
            for keyword in keywords_to_keep_near_china:
                if keyword.lower() in server_address.lower():
                    matched_region_to_keep = True
                    break
            
            if not matched_region_to_keep:
                for keyword in keywords_to_keep_near_china:
                    if keyword.lower() in proxy_name.lower():
                        matched_region_to_keep = True
                        break

            if matched_region_to_keep:
                # 处理 ShadowSocks 代理的 'unknown method: ss' 错误
                if proxy_type == 'ss':
                    cipher_method = proxy.get('cipher')
                    if cipher_method and cipher_method.lower() == 'ss':
                        print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SS proxy due to unsupported cipher method 'ss'.", file=sys.stderr)
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
                print(f"Info: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it does not match close-to-China international regions. Server/Host: {server_address}", file=sys.stderr)

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
