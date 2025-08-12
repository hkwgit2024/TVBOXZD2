import yaml
import sys
import base64
import urllib.parse

def load_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def decode_vmess(link):
    """
    解码 vmess 链接
    """
    data = link.replace("vmess://", "")
    try:
        decoded_data = base64.b64decode(data).decode('utf-8')
        vmess_config = yaml.safe_load(decoded_data)
        return {
            'name': vmess_config.get('ps', 'Unnamed-Vmess'),
            'type': 'vmess',
            'server': vmess_config.get('add'),
            'port': int(vmess_config.get('port')),
            'uuid': vmess_config.get('id'),
            'alterId': int(vmess_config.get('aid')),
            'cipher': vmess_config.get('scy', 'auto'),
            'network': vmess_config.get('net'),
            'ws-opts': {
                'path': vmess_config.get('path', '/'),
                'headers': {
                    'Host': vmess_config.get('host')
                }
            },
            'tls': vmess_config.get('tls', '') == 'tls',
            'skip-cert-verify': vmess_config.get('tls', '') == 'tls'
        }
    except Exception as e:
        print(f"Failed to decode vmess link: {link} with error: {e}")
        return None

def decode_ss(link):
    """
    解码 ss 链接
    """
    link = link.replace("ss://", "")
    if '#' in link:
        encoded_part, name_encoded = link.split('#', 1)
        name = urllib.parse.unquote(name_encoded)
    else:
        encoded_part = link
        name = 'Unnamed-SS'

    try:
        if '@' in encoded_part:
            # 包含密码和加密信息的格式
            creds_encoded, server_port = encoded_part.split('@', 1)
            creds = base64.b64decode(creds_encoded).decode('utf-8')
            cipher, password = creds.split(':', 1)
            server, port = server_port.split(':', 1)
        else:
            # 不包含密码和加密信息的格式（较少见）
            server_port = base64.b64decode(encoded_part).decode('utf-8')
            server, port = server_port.split(':', 1)
            cipher, password = 'auto', ''

        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': int(port),
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
        parts = urllib.parse.urlparse(link)
        password = parts.username
        server = parts.hostname
        port = parts.port
        name = urllib.parse.unquote(parts.fragment)

        return {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'sni': urllib.parse.parse_qs(parts.query).get('sni', [server])[0],
            'skip-cert-verify': urllib.parse.parse_qs(parts.query).get('allowInsecure', ['0'])[0] == '1'
        }
    except Exception as e:
        print(f"Failed to decode trojan link: {link} with error: {e}")
        return None

def main():
    if len(sys.argv) != 2:
        print("用法: python convert.py <订阅文件.txt>")
        return

    sub_file = sys.argv[1]
    
    output_proxies = []

    with open(sub_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('ss://'):
                node = decode_ss(line)
            elif line.startswith('trojan://'):
                node = decode_trojan(line)
            elif line.startswith('vmess://'):
                node = decode_vmess(line)
            else:
                continue

            if node:
                output_proxies.append(node)

    # 检查是否有节点被成功解析
    if not output_proxies:
        print("⚠️ 未能从文件中解析出任何有效节点。")
        return

    output = {
        'proxies': output_proxies,
        'proxy-groups': [
            {
                'name': '自动选择',
                'type': 'url-test',
                'proxies': [p['name'] for p in output_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            }
        ],
        'rules': [
            'MATCH,自动选择'
        ]
    }

    with open('clash-use.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(output, f, allow_unicode=True, sort_keys=False)

    print("✅ 已生成 clash-use.yaml，包含了来自订阅文件的节点")

if __name__ == '__main__':
    main()
