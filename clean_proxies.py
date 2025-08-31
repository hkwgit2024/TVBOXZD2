import yaml
import sys
import re
import urllib.parse

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    清理并去重代理节点，确保每个节点都有唯一的名称，并进行严格的参数和参数值检查。
    """
    required_params = {
        'vmess': ['type', 'server', 'port', 'uuid', 'alterId', 'cipher'],
        'ss': ['type', 'server', 'port', 'cipher', 'password'],
        'hy2': ['type', 'server', 'port', 'password', 'auth'],
        'hysteria2': ['type', 'server', 'port', 'password', 'auth'],
        'trojan': ['type', 'server', 'port', 'password'],
        'vless': ['type', 'server', 'port', 'uuid']
    }
    
    # 定义合法的加密方法列表和UUID、域名、IP的正则表达式
    legal_ciphers = ['chacha20-ietf-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'auto', 'none']
    uuid_regex = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    domain_regex = re.compile(r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$')

    def is_valid_server(server):
        return ip_regex.match(server) or domain_regex.match(server)

    def is_valid_uuid(uuid_str):
        # 尝试URL解码，然后验证解码后的字符串是否为标准UUID格式
        try:
            decoded_uuid = urllib.parse.unquote(uuid_str)
            return uuid_regex.match(decoded_uuid) is not None
        except Exception:
            return False

    def is_valid_cipher(cipher):
        return cipher in legal_ciphers

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
            
            # 1. 检查基本参数和协议
            if not proxy_type or proxy_type not in required_params:
                discarded_stats['unsupported_protocol'] += 1
                continue
            
            server = proxy.get('server')
            port = proxy.get('port')

            # 2. 检查 server 和 port
            if not server or not port:
                discarded_stats['missing_params'] += 1
                continue
            
            # 3. 严格的参数值验证
            if not is_valid_server(str(server)):
                discarded_stats['invalid_params'] += 1
                continue
            
            try:
                port = int(port)
                if not 1 <= port <= 65535:
                    discarded_stats['invalid_params'] += 1
                    continue
            except (ValueError, TypeError):
                discarded_stats['invalid_params'] += 1
                continue
            
            # 4. 检查特定协议的必要参数及其值
            is_valid = True
            for param in required_params[proxy_type]:
                value = proxy.get(param)
                if value is None:
                    is_valid = False
                    break
                
                # 特定参数的验证
                if param == 'uuid' and not is_valid_uuid(str(value)):
                    is_valid = False
                    break
                if param == 'cipher' and not is_valid_cipher(str(value)):
                    is_valid = False
                    break
            
            if not is_valid:
                discarded_stats['invalid_params'] += 1
                continue

            # 提取必要参数
            cleaned_proxy_data = {}
            for param in required_params[proxy_type]:
                cleaned_proxy_data[param] = proxy[param]
            
            # 特别处理 Hysteria2 的 password/auth 兼容性
            if proxy_type in ['hy2', 'hysteria2']:
                if 'password' not in cleaned_proxy_data and 'auth' in proxy:
                    cleaned_proxy_data['password'] = proxy['auth']
                    
            # 5. 创建唯一的去重键并检查重复
            unique_key = (proxy_type, server, port)
            
            if unique_key in seen_keys:
                discarded_stats['duplicates'] += 1
            else:
                seen_keys.add(unique_key)
                
                # 6. 为自动生成的名称添加唯一标识
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
