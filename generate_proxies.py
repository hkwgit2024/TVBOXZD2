import requests
import yaml
import base64
import re
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# URLs of the source files
FILE_URLS = {
    'all_unique_nodes': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/all_unique_nodes.txt',
    'merged_configs': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt',
    'ha_link': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml',
    'vt_link': 'https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml'
}

# Output file
OUTPUT_FILE = "main.yaml"

# Valid VMess ciphers
VALID_VMESS_CIPHERS = {'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305'}

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
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return None

def parse_base64_nodes(content):
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        return decoded.splitlines()
    except Exception:
        return None

def parse_ss_node(line, name_counts, seen_nodes):
    if not line.startswith('ss://') or line.startswith('ss://ss://'):
        return None
    try:
        parsed = urlparse(line)
        cipher_password = parsed.userinfo
        if not cipher_password or '@' not in cipher_password:
            print(f"Skipping Shadowsocks node {line[:50]}... (invalid userinfo)")
            return None
        cipher, password = cipher_password.split('@', 1)
        host_port = parsed.netloc
        if not host_port or ':' not in host_port:
            print(f"Skipping Shadowsocks node {line[:50]}... (invalid host/port)")
            return None
        host, port = host_port.rsplit(':', 1)
        # Deduplicate based on server, port, password
        node_key = ('ss', host, int(port), password)
        if node_key in seen_nodes:
            print(f"Skipping duplicate Shadowsocks node {line[:50]}...")
            return None
        seen_nodes.add(node_key)
        base_name = f"ss-{host}-{port}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'ss',
            'name': name,
            'server': host,
            'port': int(port),
            'cipher': cipher,
            'password': password
        }
        query = parse_qs(parsed.query)
        if 'obfs' in query:
            node['plugin'] = 'obfs'
            node['plugin-opts'] = {'mode': query['obfs'][0]}
            if 'obfs-password' not in query:
                print(f"Skipping Shadowsocks node {line[:50]}... (missing obfs password)")
                return None
            node['plugin-opts']['password'] = query['obfs-password'][0]
        return node
    except Exception as e:
        print(f"Error parsing Shadowsocks node {line[:50]}...: {e}")
        return None

def parse_vmess_node(line, name_counts, seen_nodes):
    if not line.startswith('vmess://'):
        return None
    try:
        encoded = line[8:]
        decoded = base64.b64decode(encoded).decode('utf-8')
        config = json.loads(decoded)
        # Validate required fields
        if not all(key in config for key in ['add', 'port', 'id']):
            print(f"Skipping VMess node {line[:50]}... (missing required fields)")
            return None
        # Validate cipher
        cipher = config.get('scy', 'auto')
        if cipher not in VALID_VMESS_CIPHERS:
            print(f"Skipping VMess node {line[:50]}... (unsupported cipher: {cipher})")
            return None
        # Deduplicate based on server, port, uuid
        node_key = ('vmess', config['add'], int(config['port']), config['id'])
        if node_key in seen_nodes:
            print(f"Skipping duplicate VMess node {line[:50]}...")
            return None
        seen_nodes.add(node_key)
        base_name = f"vmess-{config['add']}-{config['port']}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'vmess',
            'name': name,
            'server': config['add'],
            'port': int(config['port']),
            'uuid': config['id'],
            'alterId': int(config.get('aid', 0)),
            'cipher': cipher
        }
        if config.get('tls'):
            node['tls'] = True
        return node
    except Exception as e:
        print(f"Error parsing VMess node {line[:50]}...: {e}")
        return None

def generate_unique_name(base_name, name_counts):
    if base_name not in name_counts:
        name_counts[base_name] = 0
        return base_name
    name_counts[base_name] += 1
    return f"{base_name}_{name_counts[base_name]}"

def collect_proxies():
    proxies = []
    name_counts = defaultdict(int)  # Track used names
    seen_nodes = set()  # Track unique nodes for deduplication
    
    for key, url in FILE_URLS.items():
        content = download_file(url)
        if content is None:
            print(f"Skipping {key} due to download failure")
            continue

        if 'link' in key:
            # Handle YAML files
            config = parse_yaml_content(content)
            if config and 'proxies' in config and isinstance(config['proxies'], list):
                for proxy in config['proxies']:
                    # Validate required fields
                    if not all(key in proxy for key in ['type', 'server', 'port']):
                        print(f"Skipping invalid proxy (missing required fields): {proxy}")
                        continue
                    # Skip if obfs password is missing
                    if 'plugin' in proxy and proxy['plugin'] == 'obfs':
                        if 'plugin-opts' not in proxy or 'password' not in proxy['plugin-opts']:
                            print(f"Skipping proxy {proxy.get('name', 'unnamed')} (missing obfs password)")
                            continue
                    # Validate VMess cipher
                    if proxy['type'] == 'vmess':
                        cipher = proxy.get('cipher', 'auto')
                        if cipher not in VALID_VMESS_CIPHERS:
                            print(f"Skipping VMess proxy {proxy.get('name', 'unnamed')} (unsupported cipher: {cipher})")
                            continue
                        # Deduplicate based on server, port, uuid
                        node_key = ('vmess', proxy['server'], proxy['port'], proxy.get('uuid'))
                        if node_key in seen_nodes:
                            print(f"Skipping duplicate VMess proxy {proxy.get('name', 'unnamed')}")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'ss':
                        # Deduplicate based on server, port, password
                        node_key = ('ss', proxy['server'], proxy['port'], proxy.get('password'))
                        if node_key in seen_nodes:
                            print(f"Skipping duplicate Shadowsocks proxy {proxy.get('name', 'unnamed')}")
                            continue
                        seen_nodes.add(node_key)
                    # Ensure unique name
                    base_name = proxy.get('name', f"{proxy['type']}-{proxy['server']}-{proxy['port']}")
                    proxy['name'] = generate_unique_name(base_name, name_counts)
                    proxies.append(proxy)
            else:
                print(f"No valid proxies found in {key}")
        else:
            # Handle text files (assume Base64 or plain links)
            lines = parse_base64_nodes(content) or content.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                node = parse_ss_node(line, name_counts, seen_nodes) or parse_vmess_node(line, name_counts, seen_nodes)
                if node:
                    proxies.append(node)
                else:
                    print(f"Skipping unparsable line in {key}: {line[:50]}...")

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
    import json
    main()
