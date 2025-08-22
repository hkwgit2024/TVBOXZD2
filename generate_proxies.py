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
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return None

def parse_base64_nodes(content):
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        return decoded.splitlines()
    except Exception:
        return None

def parse_ss_node(line, name_counts):
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
        if 'obfs' in parse_qs(parsed.query):
            node['plugin'] = 'obfs'
            node['plugin-opts'] = {'mode': parse_qs(parsed.query)['obfs'][0]}
            if 'obfs-password' not in parse_qs(parsed.query):
                print(f"Skipping Shadowsocks node {line[:50]}... (missing obfs password)")
                return None
            node['plugin-opts']['password'] = parse_qs(parsed.query)['obfs-password'][0]
        return node
    except Exception as e:
        print(f"Error parsing Shadowsocks node {line[:50]}...: {e}")
        return None

def parse_vmess_node(line, name_counts):
    if not line.startswith('vmess://'):
        return None
    try:
        encoded = line[8:]
        decoded = base64.b64decode(encoded).decode('utf-8')
        config = json.loads(decoded)
        base_name = f"vmess-{config['add']}-{config['port']}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'vmess',
            'name': name,
            'server': config['add'],
            'port': int(config['port']),
            'uuid': config['id'],
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto')
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
    name_counts = {}  # Track used names to ensure uniqueness
    
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
                # Try parsing as Shadowsocks or VMess
                node = parse_ss_node(line, name_counts) or parse_vmess_node(line, name_counts)
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
    import json  # Import here to avoid undefined reference
    main()
