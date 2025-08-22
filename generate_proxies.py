import requests
import yaml
import base64
import re
from urllib.parse import urlparse, parse_qs

# URLs of the source files
FILE_URLS = {
    'all_unique_nodes': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/all_unique_nodes.txt',
    'merged_configs': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt',
    'ha_link': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml',
    'vt_link': 'https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml'
}

# Output file
OUTPUT_FILE = "main.yaml"

def download_file(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return None

def parse_yaml_content(content):
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError:
        return None

def parse_base64_nodes(content):
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        return decoded.splitlines()
    except Exception:
        return None

def parse_ss_node(line):
    if not line.startswith('ss://'):
        return None
    try:
        parsed = urlparse(line)
        cipher_password = parsed.userinfo
        if '@' not in cipher_password:
            return None
        cipher, password = cipher_password.split('@', 1)
        host_port = parsed.netloc
        host, port = host_port.rsplit(':', 1)
        query = parse_qs(parsed.query)
        node = {
            'type': 'ss',
            'name': f"ss-{host}-{port}",
            'server': host,
            'port': int(port),
            'cipher': cipher,
            'password': password
        }
        if 'obfs' in query:
            node['plugin'] = 'obfs'
            node['plugin-opts'] = {'mode': query['obfs'][0]}
            if 'obfs-password' not in query:
                return None  # Skip if obfs password is missing
            node['plugin-opts']['password'] = query['obfs-password'][0]
        return node
    except Exception:
        return None

def parse_vmess_node(line):
    if not line.startswith('vmess://'):
        return None
    try:
        encoded = line[8:]
        decoded = base64.b64decode(encoded).decode('utf-8')
        config = json.loads(decoded)
        node = {
            'type': 'vmess',
            'name': f"vmess-{config['add']}-{config['port']}",
            'server': config['add'],
            'port': int(config['port']),
            'uuid': config['id'],
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto')
        }
        if config.get('tls'):
            node['tls'] = True
        return node
    except Exception:
        return None

def collect_proxies():
    proxies = []
    
    for key, url in FILE_URLS.items():
        content = download_file(url)
        if content is None:
            print(f"Skipping {key} due to download failure")
            continue

        if 'link' in key:
            # Handle YAML files
            config = parse_yaml_content(content)
            if config and 'proxies' in config:
                for proxy in config['proxies']:
                    # Validate proxy
                    if 'plugin' in proxy and proxy['plugin'] == 'obfs':
                        if 'plugin-opts' not in proxy or 'password' not in proxy['plugin-opts']:
                            continue  # Skip if obfs password is missing
                    proxies.append(proxy)
        else:
            # Handle text files (assume Base64 or plain links)
            lines = parse_base64_nodes(content) or content.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Try parsing as Shadowsocks or VMess
                node = parse_ss_node(line) or parse_vmess_node(line)
                if node:
                    proxies.append(node)

    return proxies

def main():
    proxies = collect_proxies()
    output = {'proxies': proxies}
    
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
            yaml.safe_dump(output, file, allow_unicode=True, sort_keys=False)
            print(f"Successfully created {OUTPUT_FILE} with {len(proxies)} valid proxies")
    except Exception as e:
        print(f"Error writing to {OUTPUT_FILE}: {e}")
        exit(1)

if __name__ == "__main__":
    import json  # Import here to avoid undefined reference
    main()
