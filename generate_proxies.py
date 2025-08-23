import requests
import yaml
import base64
import re
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
import json

# 源文件 URL
FILE_URLS = {
   # 'all_unique_nodes': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/all_unique_nodes.txt',
    'merged_configs': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt',
   # 'ha_link': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml',
   # 'vt_link': 'https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml',
  #  '520_link': 'https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/520.yaml',
  #  'clash_link': 'https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml'
}

# 输出文件
OUTPUT_FILE = "main.yaml"
LOG_FILE = "skipped_nodes.log"

# 有效加密方式
VALID_SS_CIPHERS = {
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
}
VALID_VMESS_CIPHERS = {'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305'}
VALID_VLESS_NETWORKS = {'tcp', 'ws', 'grpc'}

# 验证 Host 字段（域名或 IP）
def validate_host(host):
    if not host or not isinstance(host, str):
        return False
    # 解码 URL 编码字符
    host = unquote(host)
    # 移除空格和非法字符
    host = host.strip()
    if not host:
        return False
    # 验证 IPv4
    if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', host):
        return True
    # 验证域名
    if re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$', host):
        return True
    # 验证 IPv6
    if re.match(r'^[0-9a-fA-F:]+$', host) and ':' in host:
        try:
            parts = host.split(':')
            if len(parts) <= 8 and all(len(part) <= 4 for part in parts if part):
                return True
        except:
            return False
    return False

# 下载文件
def download_file(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"成功下载 {url}\n")
        return response.text
    except requests.RequestException as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"下载 {url} 失败: {e}\n")
        return None

# 解析 YAML 内容
def parse_yaml_content(content):
    try:
        config = yaml.safe_load(content)
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"成功解析 YAML 内容\n")
        return config
    except yaml.YAMLError as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 YAML 失败: {e}\n")
        return None

# 解析 Base64 编码的节点
def parse_base64_nodes(content):
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        return decoded.splitlines()
    except Exception:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 Base64 内容失败\n")
        return None

# 验证服务器地址和端口
def validate_server_port(server, port):
    if not server or not isinstance(port, int) or port < 1 or port > 65535:
        return False
    if not re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})$', server):
        return False
    return True

# 解析 Shadowsocks 节点
def parse_ss_node(line, name_counts, seen_nodes, source):
    if not line.startswith('ss://') or line.startswith('ss://ss://'):
        if line.startswith('ss://ss://'):
            line = line[5:]  # 移除外层 ss://
        else:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过无法解析的行（来源: {source}）: {line[:50]}...\n")
            return None
    try:
        # 尝试解码 Base64 编码的 Shadowsocks 节点
        try:
            # 移除 ss:// 前缀后尝试 Base64 解码
            encoded_part = line[5:].split('#')[0].split('?')[0]
            decoded = base64.b64decode(encoded_part + '==' * (-len(encoded_part) % 4)).decode('utf-8')
            # 重新构建完整的 ss:// URI
            if '?' in line:
                query = line[line.find('?'):]
                line = f"ss://{decoded}{query}"
            else:
                line = f"ss://{decoded}"
        except:
            # 如果解码失败，继续使用原始 line
            pass

        parsed = urlparse(line)
        cipher_password = parsed.netloc
        if not cipher_password or '@' not in cipher_password:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Shadowsocks 节点（来源: {source}）: {line[:50]}... (无效用户信息)\n")
            return None
        cipher, password = cipher_password.split('@', 1)
        if cipher not in VALID_SS_CIPHERS:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Shadowsocks 节点（来源: {source}）: {line[:50]}... (不支持的加密方式: {cipher})\n")
            return None
        host_port = parsed.netloc.split('@')[-1]
        if not host_port or ':' not in host_port:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Shadowsocks 节点（来源: {source}）: {line[:50]}... (无效主机/端口)\n")
            return None
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        if not validate_server_port(host, port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Shadowsocks 节点（来源: {source}）: {line[:50]}... (无效服务器/端口)\n")
            return None
        node_key = ('ss', host, port, password)
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过重复的 Shadowsocks 节点（来源: {source}）: {line[:50]}...\n")
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
            if 'obfs-password' not in query or not query['obfs-password'][0]:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"跳过 Shadowsocks 节点（来源: {source}）: {line[:50]}... (缺少或无效 obfs 密码)\n")
                return None
            node['plugin-opts']['password'] = query['obfs-password'][0]
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 Shadowsocks 节点（来源: {source}）: {line[:50]} 出错: {e}\n")
        return None

# 解析 VMess 节点
def parse_vmess_node(line, name_counts, seen_nodes, source):
    if not line.startswith('vmess://'):
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"跳过无法解析的行（来源: {source}）: {line[:50]}...\n")
        return None
    try:
        encoded = line[8:]
        decoded = base64.b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8')
        config = json.loads(decoded)
        if not all(key in config for key in ['add', 'port', 'id']):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 VMess 节点（来源: {source}）: {line[:50]}... (缺少必要字段)\n")
            return None
        cipher = config.get('scy')
        if not cipher:  # 处理缺失或空的 cipher
            cipher = 'auto'
        if cipher not in VALID_VMESS_CIPHERS:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 VMess 节点（来源: {source}）: {line[:50]}... (不支持的加密方式: {cipher})\n")
            return None
        port = int(config['port'])
        if not validate_server_port(config['add'], port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 VMess 节点（来源: {source}）: {line[:50]}... (无效服务器/端口)\n")
            return None
        node_key = ('vmess', config['add'], port, config['id'])
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过重复的 VMess 节点（来源: {source}）: {line[:50]}...\n")
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
        if config.get('net') in VALID_VLESS_NETWORKS:
            node['network'] = config['net']
            if config['net'] == 'ws':
                host = config.get('host', '')
                if not host or not validate_host(host):  # 确保 host 不为空且有效
                    with open(LOG_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"跳过 VMess 节点（来源: {source}）: {line[:50]}... (无效或缺失 ws-opts.headers[Host]: {host})\n")
                    return None
                node['ws-opts'] = {
                    'path': config.get('path', '/'),
                    'headers': {'Host': host}
                }
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 VMess 节点（来源: {source}）: {line[:50]} 出错: {e}\n")
        return None

# 解析 Trojan 节点
def parse_trojan_node(line, name_counts, seen_nodes, source):
    if not line.startswith('trojan://'):
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"跳过无法解析的行（来源: {source}）: {line[:50]}...\n")
        return None
    try:
        parsed = urlparse(line)
        password = parsed.netloc.split('@')[0]
        host_port = parsed.netloc[len(password) + 1:]
        if not host_port or ':' not in host_port:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Trojan 节点（来源: {source}）: {line[:50]}... (无效主机/端口)\n")
            return None
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        if not validate_server_port(host, port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Trojan 节点（来源: {source}）: {line[:50]}... (无效服务器/端口)\n")
            return None
        node_key = ('trojan', host, port, password)
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过重复的 Trojan 节点（来源: {source}）: {line[:50]}...\n")
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
            f.write(f"解析 Trojan 节点（来源: {source}）: {line[:50]} 出错: {e}\n")
        return None

# 解析 Hysteria2 节点
def parse_hysteria2_node(line, name_counts, seen_nodes, source):
    if not line.startswith('hysteria2://'):
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"跳过无法解析的行（来源: {source}）: {line[:50]}...\n")
        return None
    try:
        parsed = urlparse(line)
        password = parsed.netloc.split('@')[0]
        host_port = parsed.netloc[len(password) + 1:]
        if not host_port or ':' not in host_port:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Hysteria2 节点（来源: {source}）: {line[:50]}... (无效主机/端口)\n")
            return None
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        if not validate_server_port(host, port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Hysteria2 节点（来源: {source}）: {line[:50]}... (无效服务器/端口)\n")
            return None
        node_key = ('hysteria2', host, port, password)
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过重复的 Hysteria2 节点（来源: {source}）: {line[:50]}...\n")
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
            if 'obfs-password' not in query or not query['obfs-password'][0]:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"跳过 Hysteria2 节点（来源: {source}）: {line[:50]}... (缺少或无效 obfs 密码)\n")
                return None
            node['obfs-password'] = query['obfs-password'][0]
        if 'skip-cert-verify' in query:
            node['skip-cert-verify'] = query['skip-cert-verify'][0].lower() == 'true'
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 Hysteria2 节点（来源: {source}）: {line[:50]} 出错: {e}\n")
        return None

# 解析 VLESS 节点
def parse_vless_node(line, name_counts, seen_nodes, source):
    if not line.startswith('vless://'):
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"跳过无法解析的行（来源: {source}）: {line[:50]}...\n")
        return None
    try:
        parsed = urlparse(line)
        uuid = parsed.netloc.split('@')[0]
        host_port = parsed.netloc[len(uuid) + 1:]
        if not host_port or ':' not in host_port:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 VLESS 节点（来源: {source}）: {line[:50]}... (无效主机/端口)\n")
            return None
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        if not validate_server_port(host, port):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 VLESS 节点（来源: {source}）: {line[:50]}... (无效服务器/端口)\n")
            return None
        node_key = ('vless', host, port, uuid)
        if node_key in seen_nodes:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过重复的 VLESS 节点（来源: {source}）: {line[:50]}...\n")
            return None
        seen_nodes.add(node_key)
        base_name = f"vless-{host}-{port}"
        name = generate_unique_name(base_name, name_counts)
        node = {
            'type': 'vless',
            'name': name,
            'server': host,
            'port': port,
            'uuid': uuid
        }
        query = parse_qs(parsed.query)
        if 'security' in query and query['security'][0] == 'tls':
            node['tls'] = True
        if 'sni' in query:
            node['servername'] = query['sni'][0]
        if 'type' in query and query['type'][0] in VALID_VLESS_NETWORKS:
            node['network'] = query['type'][0]
            if query['type'][0] == 'ws':
                host_header = query.get('host', [''])[0]
                if not host_header or not validate_host(host_header):  # 确保 host 不为空且有效
                    with open(LOG_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"跳过 VLESS 节点（来源: {source}）: {line[:50]}... (无效或缺失 ws-opts.headers[Host]: {host_header})\n")
                    return None
                node['ws-opts'] = {
                    'path': query.get('path', ['/'])[0],
                    'headers': {'Host': host_header}
                }
        if 'flow' in query:
            node['flow'] = query['flow'][0]
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 VLESS 节点（来源: {source}）: {line[:50]} 出错: {e}\n")
        return None

# 生成唯一名称
def generate_unique_name(base_name, name_counts):
    if base_name not in name_counts:
        name_counts[base_name] = 0
        return base_name
    name_counts[base_name] += 1
    return f"{base_name}_{name_counts[base_name]}"

# 收集代理节点
def collect_proxies():
    proxies = []
    name_counts = defaultdict(int)
    seen_nodes = set()
    stats = {'total': 0, 'valid': 0, 'duplicates': 0, 'invalid': 0}

    # 清空日志文件
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write("跳过节点日志\n================\n")

    for key, url in FILE_URLS.items():
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"开始处理源文件: {key} ({url})\n")
        content = download_file(url)
        if content is None:
            continue

        if 'link' in key:
            config = parse_yaml_content(content)
            if config and 'proxies' in config and isinstance(config['proxies'], list):
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"找到 {len(config['proxies'])} 个代理节点在 {key}\n")
                for proxy in config['proxies']:
                    stats['total'] += 1
                    if not all(key in proxy for key in ['type', 'server', 'port']):
                        stats['invalid'] += 1
                        with open(LOG_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"跳过无效代理（来源: {key}）: {proxy}\n")
                        continue
                    if not validate_server_port(proxy['server'], proxy['port']):
                        stats['invalid'] += 1
                        with open(LOG_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"跳过代理 {proxy.get('name', '未命名')}（来源: {key}）(无效服务器/端口)\n")
                        continue
                    if proxy['type'] == 'ss':
                        if proxy.get('cipher') not in VALID_SS_CIPHERS:
                            stats['invalid'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过 Shadowsocks 代理 {proxy.get('name', '未命名')}（来源: {key}）(不支持的加密方式: {proxy.get('cipher')})\n")
                            continue
                        if 'plugin' in proxy and proxy['plugin'] == 'obfs':
                            if 'plugin-opts' not in proxy or 'password' not in proxy['plugin-opts'] or not proxy['plugin-opts']['password']:
                                stats['invalid'] += 1
                                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                    f.write(f"跳过 Shadowsocks 代理 {proxy.get('name', '未命名')}（来源: {key}）(缺少或无效 obfs 密码)\n")
                                continue
                        node_key = ('ss', proxy['server'], proxy['port'], proxy.get('password'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过重复的 Shadowsocks 代理 {proxy.get('name', '未命名')}（来源: {key}）\n")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'vmess':
                        cipher = proxy.get('cipher')
                        if not cipher:  # 处理缺失或空的 cipher
                            cipher = 'auto'
                            proxy['cipher'] = cipher
                        if cipher not in VALID_VMESS_CIPHERS:
                            stats['invalid'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过 VMess 代理 {proxy.get('name', '未命名')}（来源: {key}）(不支持的加密方式: {cipher})\n")
                            continue
                        if 'network' in proxy and proxy['network'] == 'ws' and 'ws-opts' in proxy:
                            host = proxy['ws-opts'].get('headers', {}).get('Host', '')
                            if not host or not validate_host(host):  # 确保 host 不为空且有效
                                stats['invalid'] += 1
                                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                    f.write(f"跳过 VMess 代理 {proxy.get('name', '未命名')}（来源: {key}）(无效或缺失 ws-opts.headers[Host]: {host})\n")
                                continue
                        node_key = ('vmess', proxy['server'], proxy['port'], proxy.get('uuid'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过重复的 VMess 代理 {proxy.get('name', '未命名')}（来源: {key}）\n")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'trojan':
                        node_key = ('trojan', proxy['server'], proxy['port'], proxy.get('password'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过重复的 Trojan 代理 {proxy.get('name', '未命名')}（来源: {key}）\n")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'hysteria2':
                        if 'obfs' in proxy and ('obfs-password' not in proxy or not proxy.get('obfs-password')):
                            stats['invalid'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过 Hysteria2 代理 {proxy.get('name', '未命名')}（来源: {key}）(缺少或无效 obfs 密码)\n")
                            continue
                        node_key = ('hysteria2', proxy['server'], proxy['port'], proxy.get('password'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过重复的 Hysteria2 代理 {proxy.get('name', '未命名')}（来源: {key}）\n")
                            continue
                        seen_nodes.add(node_key)
                    elif proxy['type'] == 'vless':
                        if 'network' in proxy and proxy['network'] == 'ws' and 'ws-opts' in proxy:
                            host = proxy['ws-opts'].get('headers', {}).get('Host', '')
                            if not host or not validate_host(host):  # 确保 host 不为空且有效
                                stats['invalid'] += 1
                                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                    f.write(f"跳过 VLESS 代理 {proxy.get('name', '未命名')}（来源: {key}）(无效或缺失 ws-opts.headers[Host]: {host})\n")
                                continue
                        if 'network' in proxy and proxy['network'] not in VALID_VLESS_NETWORKS:
                            stats['invalid'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过 VLESS 代理 {proxy.get('name', '未命名')}（来源: {key}）(不支持的网络类型: {proxy['network']})\n")
                            continue
                        node_key = ('vless', proxy['server'], proxy['port'], proxy.get('uuid'))
                        if node_key in seen_nodes:
                            stats['duplicates'] += 1
                            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"跳过重复的 VLESS 代理 {proxy.get('name', '未命名')}（来源: {key}）\n")
                            continue
                        seen_nodes.add(node_key)
                    else:
                        stats['invalid'] += 1
                        with open(LOG_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"跳过代理 {proxy.get('name', '未命名')}（来源: {key}）(不支持的类型: {proxy['type']})\n")
                        continue
                    base_name = proxy.get('name', f"{proxy['type']}-{proxy['server']}-{proxy['port']}")
                    proxy['name'] = generate_unique_name(base_name, name_counts)
                    proxies.append(proxy)
                    stats['valid'] += 1
            else:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"在 {key} 中未找到有效代理\n")
        else:
            lines = parse_base64_nodes(content) or content.splitlines()
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"找到 {len(lines)} 行节点在 {key}\n")
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                stats['total'] += 1
                node = (parse_ss_node(line, name_counts, seen_nodes, key) or
                        parse_vmess_node(line, name_counts, seen_nodes, key) or
                        parse_trojan_node(line, name_counts, seen_nodes, key) or
                        parse_hysteria2_node(line, name_counts, seen_nodes, key) or
                        parse_vless_node(line, name_counts, seen_nodes, key))
                if node:
                    proxies.append(node)
                    stats['valid'] += 1
                else:
                    stats['invalid'] += 1
    # 确保生成非空的 main.yaml
    if not proxies:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write("警告: 未生成任何有效代理节点，将生成空的 proxies 列表\n")
    return proxies, stats

# 主函数
def main():
    proxies, stats = collect_proxies()
    output = {'proxies': proxies}
    
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
            yaml.safe_dump(output, file, allow_unicode=True, sort_keys=False)
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"成功创建 {OUTPUT_FILE}，包含 {len(proxies)} 个有效代理\n")
        print(f"成功创建 {OUTPUT_FILE}，包含 {len(proxies)} 个有效代理")
        print(f"统计信息: 总计={stats['total']}, 有效={stats['valid']}, 重复={stats['duplicates']}, 无效={stats['invalid']}")
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"写入 {OUTPUT_FILE} 失败: {e}\n")
        print(f"写入 {OUTPUT_FILE} 失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()
