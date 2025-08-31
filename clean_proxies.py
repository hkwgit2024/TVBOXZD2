import yaml
import sys
import re
import urllib.parse
import base64

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    Cleans and deduplicates proxy nodes from a YAML file, ensuring unique names
    and performing strict validation of parameters and their values.
    """
    required_params = {
        'vmess': ['type', 'server', 'port', 'uuid', 'alterId', 'cipher'],
        'ss': ['type', 'server', 'port', 'cipher', 'password'],
        'hy2': ['type', 'server', 'port', 'password', 'auth'],
        'hysteria2': ['type', 'server', 'port', 'password', 'auth'],
        'trojan': ['type', 'server', 'port', 'password'],
        'vless': ['type', 'server', 'port', 'uuid']
    }
    
    # Define valid ciphers, UUID, domain, and IP regex patterns.
    legal_ciphers = ['chacha20-ietf-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'auto', 'none']
    uuid_regex = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    domain_regex = re.compile(r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$')

    def is_valid_server(server):
        return ip_regex.match(server) or domain_regex.match(server)

    def is_valid_uuid(uuid_str):
        try:
            # First, attempt URL decoding
            decoded_uuid = urllib.parse.unquote(uuid_str)
            # Check for standard UUID format
            if uuid_regex.match(decoded_uuid):
                return True
            # If it contains '%' but doesn't match standard UUID, check for a 32-char hex string
            if '%' in uuid_str:
                decoded_chars = ''.join(c for c in decoded_uuid if c.lower() in '0123456789abcdef')
                return len(decoded_chars) == 32
            return False
        except Exception:
            return False

    def is_valid_cipher(cipher):
        return cipher in legal_ciphers
        
    def is_valid_alter_id(alter_id):
        try:
            # Must be an integer within a standard range
            return isinstance(alter_id, int) and 0 <= alter_id <= 65535
        except (ValueError, TypeError):
            return False

    def is_valid_port(port, proxy_type):
        try:
            port = int(port)
            if proxy_type == 'trojan':
                # Common ports for Trojan
                return port in [80, 443, 8443]
            elif proxy_type in ['hy2', 'hysteria2']:
                # Hysteria2 is UDP-based, so specific ports might be preferred.
                # Here we will allow a wider range but a more specific implementation might check for common UDP ports.
                return 1 <= port <= 65535
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False

    def is_valid_password(password, proxy_type):
        if proxy_type == 'trojan':
            try:
                # Ensure the password is a string and encode it to bytes before decoding Base64.
                base64.b64decode(str(password).encode('utf-8'), validate=True)
                return True
            except (base64.binascii.Error, TypeError):
                return False
        
        # For other protocols, require a minimum length of 8 and a mix of letters and numbers.
        if isinstance(password, str) and len(password) >= 8:
            return bool(re.search(r'[a-zA-Z]', password) and re.search(r'[0-9]', password))
        return False

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        proxies = data.get('proxies', [])
        total_nodes_before = len(proxies)
        
        if not proxies:
            print("proxies列表为空，无需处理。")
            return

        cleaned_proxies = []
        seen_keys = set()
        discarded_stats = {
            'unsupported_protocol': 0,
            'missing_params': 0,
            'invalid_params': 0,
            'duplicates': 0
        }
        name_counter = {}

        progress_counter = 0

        for proxy in proxies:
            progress_counter += 1
            if progress_counter % 1000 == 0:
                print(f"处理进度：已处理 {progress_counter} 个节点...")

            proxy_type = proxy.get('type')
            
            # 1. Check for basic parameters and protocol type
            if not proxy_type or proxy_type not in required_params:
                discarded_stats['unsupported_protocol'] += 1
                continue
            
            server = proxy.get('server')
            port = proxy.get('port')

            # 2. Check for existence of server and port
            if not server or not port:
                discarded_stats['missing_params'] += 1
                continue
            
            # 3. Strict value validation for server and port
            if not is_valid_server(str(server)):
                discarded_stats['invalid_params'] += 1
                continue
            
            if not is_valid_port(port, proxy_type):
                discarded_stats['invalid_params'] += 1
                continue
            
            # 4. Check for necessary parameters and their values based on protocol
            is_valid = True
            for param in required_params[proxy_type]:
                value = proxy.get(param)
                if value is None:
                    is_valid = False
                    break
                
                # Specific parameter validation
                if param == 'uuid' and not is_valid_uuid(str(value)):
                    is_valid = False
                    break
                if param == 'cipher' and not is_valid_cipher(str(value)):
                    is_valid = False
                    break
                if param == 'alterId' and not is_valid_alter_id(value):
                    is_valid = False
                    break
                if param == 'password' and not is_valid_password(str(value), proxy_type):
                    is_valid = False
                    break
            
            if not is_valid:
                discarded_stats['invalid_params'] += 1
                continue

            # Extract only the necessary parameters
            cleaned_proxy_data = {}
            for param in required_params[proxy_type]:
                cleaned_proxy_data[param] = proxy[param]
            
            # Handle Hysteria2 password/auth compatibility
            if proxy_type in ['hy2', 'hysteria2']:
                if 'password' not in cleaned_proxy_data and 'auth' in proxy:
                    cleaned_proxy_data['password'] = proxy['auth']
                    
            # 5. Create unique key and check for duplicates
            unique_key = (proxy_type, server, port)
            
            if unique_key in seen_keys:
                discarded_stats['duplicates'] += 1
            else:
                seen_keys.add(unique_key)
                
                # 6. Assign unique names
                base_name = f"[{proxy_type.upper()}] {server}:{port}"
                if base_name not in name_counter:
                    name_counter[base_name] = 1
                    cleaned_proxy_data['name'] = base_name
                else:
                    name_counter[base_name] += 1
                    cleaned_proxy_data['name'] = f"{base_name} ({name_counter[base_name]})"
                
                cleaned_proxies.append(cleaned_proxy_data)

        total_nodes_after = len(cleaned_proxies)
        total_discarded = discarded_stats['unsupported_protocol'] + discarded_stats['missing_params'] + discarded_stats['invalid_params'] + discarded_stats['duplicates']

        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump({'proxies': cleaned_proxies}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

        print("🎉 节点清理报告")
        print("--------------------")
        print(f"📦 清理前节点总数: {total_nodes_before} 个")
        print("🗑️ 丢弃节点详情:")
        print(f"  - 协议不支持: {discarded_stats['unsupported_protocol']} 个")
        print(f"  - 缺少必要参数: {discarded_stats['missing_params']} 个")
        print(f"  - 参数值无效: {discarded_stats['invalid_params']} 个")
        print(f"  - 重复节点: {discarded_stats['duplicates']} 个")
        print(f"  - 丢弃总数: {total_discarded} 个")
        print(f"✅ 清理后节点总数: {total_nodes_after} 个")
        print("--------------------")
        print(f"文件已保存至: {output_file}")

    except FileNotFoundError:
        print(f"错误: 文件 {input_file} 未找到。")
    except yaml.YAMLError as e:
        print(f"错误: YAML解析失败: {e}")

if __name__ == '__main__':
    clean_and_deduplicate_proxies('link.yaml', 'link_cleaned.yaml')
