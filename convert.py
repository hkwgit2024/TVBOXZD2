import yaml
import sys
import base64
from urllib.parse import urlparse, unquote

def decode_ss(link):
    """
    Decodes an ss:// subscription link into a Clash-compatible proxy configuration.
    """
    try:
        parts = urlparse(link)
        name = unquote(parts.fragment) if parts.fragment else 'Unnamed-SS'
        server = parts.hostname
        port = parts.port
        
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
        print(f"Failed to decode ss link: {link}, error: {e}")
        return None

def main():
    # 接受两个参数：输入订阅文件和输出 YAML 文件
    if len(sys.argv) != 3:
        print("Usage: python convert.py <subscription_file.txt> <output_file.yaml>")
        print("Example: python convert.py ss.txt config.yaml")
        sys.exit(1)

    sub_file = sys.argv[1]  # 输入文件：ss.txt
    output_file = sys.argv[2]  # 输出文件：config.yaml
    output_proxies = []

    try:
        with open(sub_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # 只处理 ss:// 链接
                if line.startswith('ss://'):
                    node = decode_ss(line)
                    if node:
                        output_proxies.append(node)
                else:
                    print(f"Skipping unrecognized line: {line}")
                    continue

    except FileNotFoundError:
        print(f"Error: The file {sub_file} was not found in the root directory.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    if not output_proxies:
        print("⚠️ Failed to parse any proxies from the subscription file.")
        sys.exit(1)

    # 构造 Clash 格式的 YAML 输出
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

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(output, f, allow_unicode=True, sort_keys=False)
        print(f"✅ Successfully generated {output_file} with {len(output_proxies)} proxies.")
    except Exception as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
