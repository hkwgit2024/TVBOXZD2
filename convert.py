import yaml
import sys
import base64
import urllib.parse
from urllib.parse import urlparse, unquote, parse_qs

def decode_vmess(link):
    """
    解码 vmess 链接
    """
    try:
        data = link.replace("vmess://", "")
        # Vmess 链接的格式是 base64 编码的 JSON
        decoded_data = base64.b64decode(data.encode('utf-8')).decode('utf-8')
        vmess_config = yaml.safe_load(decoded_data)
        
        # 提取所需的配置信息
        name = vmess_config.get('ps', 'Unnamed-Vmess')
        server = vmess_config.get('add')
        port = int(vmess_config.get('port'))
        uuid = vmess_config.get('id')
        alterId = int(vmess_config.get('aid', 0))
        network = vmess_config.get('net', 'tcp')
        tls = vmess_config.get('tls', '') == 'tls'
        
        # 根据网络类型构建不同的配置
        config = {
            'name': name,
            'type': 'vmess',
            'server': server,
            'port': port,
            'uuid': uuid,
            'alterId': alterId,
            'cipher': 'auto',
            'network': network,
            'tls': tls,
            'skip-cert-verify': tls
        }

        # 处理 websocket 特殊选项
        if network == 'ws':
            config['ws-opts'] = {
                'path': vmess_config.get('path', '/'),
                'headers': {
                    'Host': vmess_config.get('host', server)
                }
            }
        
        return config
    except Exception as e:
        print(f"Failed to decode vmess link: {link} with error: {e}")
        return None

def decode_ss(link):
    """
    解码 ss 链接
    """
    try:
        parts = urlparse(link)
        name = unquote(parts.fragment) if parts.fragment else 'Unnamed-SS'
        server = parts.hostname
        port = parts.port
        
        # Base64 解码用户信息
        user_info_encoded = parts.netloc.split('@')[0]
        user_info_decoded = base64.b64decode(user_info_encoded.encode('utf-8')).decode('utf-8')
        cipher, password = user_info_decoded.split(':', 1)
        
        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': cipher,
            'password': password
        }
    except Exception as e:
        print(f"Failed to decode ss link: {link} with error: {e}")
        return None

def decode_trojan(link):
    """
    解码 trojan 链接
    """
    try:
        parts = urlparse(link)
        name = unquote(parts.fragment) if parts.fragment else 'Unnamed-Trojan'
        server = parts.hostname
        port = parts.port
        password = parts.username
        
        query_params = parse_qs(parts.query)
        sni = query_params.get('sni', [server])[0]
        
        return {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'sni': sni,
            'skip-cert-verify': query_params.get('allowInsecure', ['0'])[0] == '1'
        }
    except Exception as e:
        print(f"Failed to decode trojan link: {link} with error: {e}")
        return None
        
def main():
    if len(sys.argv) != 2:
        print("用法: python convert.py <订阅文件.txt>")
        print("例如: python convert.py ss.txt")
        sys.exit(1)

    sub_file = sys.argv[1]
    output_proxies = []

    try:
        with open(sub_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # 跳过 YAML 格式的非链接行
                if line.endswith(':'):
                    print(f"Skipping YAML-like line: {line}")
                    continue
                
                node = None
                if line.startswith('ss://'):
                    node = decode_ss(line)
                elif line.startswith('trojan://'):
                    node = decode_trojan(line)
                elif line.startswith('vmess://'):
                    node = decode_vmess(line)
                
                if node:
                    output_proxies.append(node)

    except FileNotFoundError:
        print(f"Error: The file {sub_file} was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    if not output_proxies:
        print("⚠️ Failed to parse any proxies from the subscription file.")
        sys.exit(1)

    output = {
        'proxies': output_proxies,
        'proxy-groups': [
            {
                'name': '自动选择',
                'type': 'url-test',
                'proxies': [p['name'] for p in output_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': '手动选择',
                'type': 'select',
                'proxies': [p['name'] for p in output_proxies]
            }
        ],
        'rules': [
            'MATCH,自动选择'
        ]
    }

    with open('clash-use.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(output, f, allow_unicode=True, sort_keys=False)

    print(f"✅ Successfully generated clash-use.yaml with {len(output_proxies)} proxies.")

if __name__ == '__main__':
    main()
