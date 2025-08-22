import requests
import yaml
import base64
import re
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
import json

# URLs of the source files
FILE_URLS = {
    'all_unique_nodes': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/all_unique_nodes.txt',
    'merged_configs': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt',
    'ha_link': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml',
    'vt_link': 'https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml'
}

# Output files
OUTPUT_FILE = "main.yaml"
LOG_FILE = "skipped_nodes.log"

# Valid ciphers for protocols
VALID_SS_CIPHERS = {
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
}
VALID_VMESS_CIPHERS = {'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305'}

def download_file(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Error downloading {url}: {e}\n")
        return None

def parse_yaml_content(content):
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Error parsing YAML: {e}\n")
        return None

def parse_base64_nodes(content):
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        return decoded.splitlines()
    except Exception:
        return None

def validate_server_port(server, port):
    if not server or not isinstance(port, int) or port < 1 or port > 65535:
        return False
    # Basic server validation (IP or domain)
    if not re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})$', server):
        return False
    return True

def parse_ss_node(line, name_counts, seen_nodes):
    if not line.startswith('ss://') or line.startswith('ss://ss://'):
        if line.startswith('ss://ss://'):
            line = line[5:]  # Remove outer ss://
        else:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping unparsable line: {line[:50]}...\n")
            return None
    try:
        parsed = urlparse(line)
        cipher_password = parsed.userinfo
        if not cipher_password or '@' not in cipher_password:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Shadowsocks node {line[:50]}... (invalid userinfo)\n")
            return None
        cipher, password = cipher_password.split('@', 1)
        if cipher not in VALID_SS_CIPHERS:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Shadowsocks node {line[:50]}... (unsupported cipher: {cipher})\n")
            return None
        host_port = parsed.netloc
        if not host_port or ':' not in host_port:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Shadowsocks node {line[:50]}... (invalid host/port)\n")
            return None
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        if not validate_server_port(host, port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Shadowsocks node {line[:50]}... (invalid server/port)\n")
            return None
        node_key = ('ss', host, port, password)
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping duplicate Shadowsocks node {line[:50]}...\n")
            return None
        seen_nodes.add(node_key)
        base_name = f"ss-{host}-{port}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'ss',
            'name': name,
            'server': host,
            'port': port,
            'cipher': cipher,
            'password': password
        }
        query = parse_qs(parsed.query)
        if 'obfs' in query:
            node['plugin'] = 'obfs'
            node['plugin-opts'] = {'mode': query['obfs'][0]}
            if 'obfs-password' not in query:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"Skipping Shadowsocks node {line[:50]}... (missing obfs password)\n")
                return None
            node['plugin-opts']['password'] = query['obfs-password'][0]
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Error parsing Shadowsocks node {line[:50]}...: {e}\n")
        return None

def parse_vmess_node(line, name_counts, seen_nodes):
    if not line.startswith('vmess://'):
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Skipping unparsable line: {line[:50]}...\n")
        return None
    try:
        encoded = line[8:]
        decoded = base64.b64decode(encoded).decode('utf-8')
        config = json.loads(decoded)
        if not all(key in config for key in ['add', 'port', 'id']):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping VMess node {line[:50]}... (missing required fields)\n")
            return None
        cipher = config.get('scy')
        if not cipher:  # Explicitly check for None or empty string
            cipher = 'auto'  # Default to 'auto' if missing
        if cipher not in VALID_VMESS_CIPHERS:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping VMess node {line[:50]}... (unsupported cipher: {cipher})\n")
            return None
        port = int(config['port'])
        if not validate_server_port(config['add'], port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping VMess node {line[:50]}... (invalid server/port)\n")
            return None
        node_key = ('vmess', config['add'], port, config['id'])
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping duplicate VMess node {line[:50]}...\n")
            return None
        seen_nodes.add(node_key)
        base_name = f"vmess-{config['add']}-{port}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'vmess',
            'name': name,
            'server': config['add'],
            'port': port,
            'uuid': config['id'],
            'alterId': int(config.get('aid', 0)),
            'cipher': cipher
        }
        if config.get('tls'):
            node['tls'] = True
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Error parsing VMess node {line[:50]}...: {e}\n")
        return None

def parse_trojan_node(line, name_counts, seen_nodes):
    if not line.startswith('trojan://'):
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Skipping unparsable line: {line[:50]}...\n")
        return None
    try:
        parsed = urlparse(line)
        password = parsed.netloc.split('@')[0]
        host_port = parsed.netloc[len(password) + 1:]
        if not host_port or ':' not in host_port:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Trojan node {line[:50]}... (invalid host/port)\n")
            return None
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        if not validate_server_port(host, port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Trojan node {line[:50]}... (invalid server/port)\n")
            return None
        node_key = ('trojan', host, port, password)
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping duplicate Trojan node {line[:50]}...\n")
            return None
        seen_nodes.add(node_key)
        base_name = f"trojan-{host}-{port}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'trojan',
            'name': name,
            'server': host,
            'port': port,
            'password': password
        }
        query = parse_qs(parsed.query)
        if 'sni' in query:
            node['sni'] = query['sni'][0]
        if 'alpn' in query:
            node['alpn'] = query['alpn']
        if 'skip-cert-verify' in query:
            node['skip-cert-verify'] = query['skip-cert-verify'][0].lower() == 'true'
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Error parsing Trojan node {line[:50]}...: {e}\n")
        return None

def parse_hysteria2_node(line, name_counts, seen_nodes):
    if not line.startswith('hysteria2://'):
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Skipping unparsable line: {line[:50]}...\n")
        return None
    try:
        parsed = urlparse(line)
        password = parsed.netloc.split('@')[0]
        host_port = parsed.netloc[len(password) + 1:]
        if not host_port or ':' not in host_port:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Hysteria2 node {line[:50]}... (invalid host/port)\n")
            return None
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        if not validate_server_port(host, port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping Hysteria2 node {line[:50]}... (invalid server/port)\n")
            return None
        node_key = ('hysteria2', host, port, password)
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Skipping duplicate Hysteria2 node {line[:50]}...\n")
            return None
        seen_nodes.add(node_key)
        base_name = f"hysteria2-{host}-{port}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'hysteria2',
            'name': name,
            'server': host,
            'port': port,
            'password': password
        }
        query = parse_qs(parsed.query)
        if 'sni' in query:
            node['sni'] = query['sni'][0]
        if 'obfs' in query:
            node['obfs'] = query['obfs'][0]
            if 'obfs-password' not in query:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"Skipping Hysteria2 node {line[:50]}... (missing obfs-password)\n")
                return None
            node['obfs-password'] = query['obfs-password'][0]
        if 'skip-cert-verify' in query:
            node['skip-cert-verify'] = query['skip-cert-verify'][0].lower() == 'true'
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Error parsing Hysteria2 node {line[:50]}...: {e}\n")
        return None

def generate_unique_name(base_name, name_counts):
    if base_name not in name_counts:
        name_counts[base_name] = 0
        return base_name
    name_counts[base_name] += 1
    return f"{base_name}_{name_counts[base_name]}"

def collect_proxies():
    proxies = []
    name_counts = defaultdict(int)
    seen_nodes = set()
    stats = {'total': 0, 'valid': 0, 'duplicates': 0, 'invalid': 0}

    # Clear log file
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write("Skipped Nodes Log\n================\n")

    for key, url in FILE_URLS.items():
        content = download_file(url)
        if content is None:
            continue

        if 'link' in key:
            config = parse_yaml_content(content)
            if config and 'proxies' in config and isinstance(config['proxies'], list):
                for proxy in config['proxies']:
                    stats['total'] += 1
                    if not all(key in proxy for key in ['type', 'server', 'port']):
                        stats['invalid'] += 1
                        with open(LOG_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"Skipping invalid proxy (missing required fields): {proxy}\n")
                        continue
                    if not validate_server_port(proxy['server'], proxy['port']):
                        stats['invalid'] += 1
                        with open(LOG_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"Skipping proxy {proxy.get('name', 'unnamed')} (invalid server/port)\n")
                        continue
                    if proxy['type'] == 'ss':
                        if proxy.get('cipher') not in VALID_SS_CIPHERS:
                            stats['invalid'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"Skipping Shadowsocks proxy {proxy.get('name', 'unnamed')} (unsupported cipher: {proxy.get('cipher')})\n")
                            continue
                        if 'plugin' in proxy and proxy['plugin'] == 'obfs':
                            if 'plugin-opts' not in proxy or 'password' not in proxy['plugin-opts']:
                                stats['invalid'] += 1
                                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                    f.write(f"Skipping proxy {proxy.get('name', 'unnamed')} (missing obfs password)\n")
                                continue
                        node_key = ('ss', proxy['server'], proxy['port'], proxy.get('password'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"Skipping duplicate Shadowsocks proxy {proxy.get('name', 'unnamed')}\n")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'vmess':
                        cipher = proxy.get('cipher')
                        if not cipher:  # Explicitly check for None or empty string
                            cipher = 'auto'
                            proxy['cipher'] = cipher
                        if cipher not in VALID_VMESS_CIPHERS:
                            stats['invalid'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"Skipping VMess proxy {proxy.get('name', 'unnamed')} (unsupported cipher: {cipher})\n")
                            continue
                        node_key = ('vmess', proxy['server'], proxy['port'], proxy.get('uuid'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"Skipping duplicate VMess proxy {proxy.get('name', 'unnamed')}\n")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'trojan':
                        node_key = ('trojan', proxy['server'], proxy['port'], proxy.get('password'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"Skipping duplicate Trojan proxy {proxy.get('name', 'unnamed')}\n")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'hysteria2':
                        if 'obfs' in proxy and 'obfs-password' not in proxy:
                            stats['invalid'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"Skipping Hysteria2 proxy {proxy.get('name', 'unnamed')} (missing obfs-password)\n")
                            continue
                        node_key = ('hysteria2', proxy['server'], proxy['port'], proxy.get('password'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"Skipping duplicate Hysteria2 proxy {proxy.get('name', 'unnamed')}\n")
                            continue
                        seen_nodes.add(node_key)
                    else:
                        stats['invalid'] += 1
                        with open(LOG_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"Skipping proxy {proxy.get('name', 'unnamed')} (unsupported type: {proxy['type']})\n")
                        continue
                    base_name = proxy.get('name', f"{proxy['type']}-{proxy['server']}-{proxy['port']}")
                    proxy['name'] = generate_unique_name(base_name, name_counts)
                    proxies.append(proxy)
                    stats['valid'] += 1
            else:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"No valid proxies found in {key}\n")
        else:
            lines = parse_base64_nodes(content) or content.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                stats['total'] += 1
                node = (parse_ss_node(line, name_counts, seen_nodes) or
                        parse_vmess_node(line, name_counts, seen_nodes) or
                        parse_trojan_node(line, name_counts, seen_nodes) or
                        parse_hysteria2_node(line, name_counts, seen_nodes))
                if node:
                    proxies.append(node)
                    stats['valid'] += 1
                else:
                    stats['invalid'] += 1
    return proxies, stats

def main():
    proxies, stats = collect_proxies()
    output = {'proxies': proxies}
    
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
            yaml.safe_dump(output, file, allow_unicode=True, sort_keys=False)
        print(f"Successfully created {OUTPUT_FILE} with {len(proxies)} valid proxies")
        print(f"Statistics: Total={stats['total']}, Valid={stats['valid']}, Duplicates={stats['duplicates']}, Invalid={stats['invalid']}")
    except Exception as e:
        print(f"Error writing to {OUTPUT_FILE}: {e}")
        exit(1)

if __name__ == "__main__":
    main()
