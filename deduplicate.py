
import requests
import base64
import json
import urllib.parse
import hashlib
import yaml
from collections import defaultdict

# 文件 URL
URL1 = "https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml"
URL2 = "https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link%20(1).yaml"

# 有效加密方式
VALID_SS_CIPHERS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'}
VALID_VMESS_CIPHERS = {'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305'}

def validate_server_port(server, port):
    """验证服务器地址和端口"""
    if not server or not isinstance(port, (int, str)) or (isinstance(port, str) and not port.isdigit()) or int(port) < 1 or int(port) > 65535:
        return False
    return True

def parse_vmess_url(url):
    """解析 vmess:// URL"""
    try:
        if not url.startswith('vmess://'):
            return None
        encoded = url[8:].strip()
        decoded = base64.b64decode(encoded).decode('utf-8')
        config = json.loads(decoded)
        node = {
            'type': 'vmess',
            'server': config.get('add'),
            'port': config.get('port'),
            'uuid': config.get('id'),
            'cipher': config.get('scy', 'auto'),
            'name': config.get('ps', 'unnamed')
        }
        required = {'server', 'port', 'uuid', 'cipher'}
        if not all(k in node for k in required) or node['cipher'] not in VALID_VMESS_CIPHERS or not validate_server_port(node['server'], node['port']):
            return None
        return node
    except Exception as e:
        return None

def parse_trojan_url(url):
    """解析 trojan:// URL"""
    try:
        if not url.startswith('trojan://'):
            return None
        parsed = urllib.parse.urlparse(url)
        password = parsed.netloc.split('@')[0]
        server_port = parsed.netloc.split('@')[1].split('?')[0]
        server, port = server_port.split(':') if ':' in server_port else (server_port, None)
        name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else 'unnamed'
        node = {
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'name': name
        }
        required = {'server', 'port', 'password'}
        if not all(k in node for k in required) or not validate_server_port(node['server'], node['port']):
            return None
        return node
    except Exception as e:
        return None

def parse_node_from_url(line):
    """解析单行代理 URL"""
    line = line.strip()
    if line.startswith('vmess://'):
        return parse_vmess_url(line)
    elif line.startswith('trojan://'):
        return parse_trojan_url(line)
    return None

def get_node_key(node):
    """生成节点的哈希键，仅基于官方要求字段，忽略 name"""
    key_dict = {k: node.get(k) for k in node if k != 'name'}
    key_str = json.dumps(key_dict, sort_keys=True)
    return hashlib.sha256(key_str.encode('utf-8')).hexdigest()

def analyze_nodes(url, file_name):
    """逐行下载并分析代理 URL"""
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        proxies = []
        for line in response.iter_lines(decode_unicode=True):
            if line:
                node = parse_node_from_url(line)
                if node:
                    proxies.append(node)
                else:
                    with open(f"compare_{file_name}.log", 'a', encoding='utf-8') as f:
                        f.write(f"无效节点: {line[:50]}... (解析失败或无效格式)\n")
        
        seen_keys = set()
        unique_nodes = []
        name_counts = defaultdict(int)
        invalid_count = 0
        
        for node in proxies:
            if not node:
                invalid_count += 1
                continue
            node_key = get_node_key(node)
            if node_key not in seen_keys:
                seen_keys.add(node_key)
                base_name = f"{node['type']}-{node.get('server')}-{node.get('port')}"
                node['name'] = f"{base_name}_{name_counts[base_name] + 1}"
                name_counts[base_name] += 1
                unique_nodes.append(node)
            else:
                with open(f"compare_{file_name}.log", 'a', encoding='utf-8') as f:
                    f.write(f"重复节点: {node.get('name', '未命名')} ({node_key})\n")
        
        return proxies, unique_nodes, seen_keys, invalid_count
    except Exception as e:
        with open('stats.txt', 'a', encoding='utf-8') as f:
            f.write(f"处理 {url} 失败: {e}\n")
        return [], [], set(), 0

def save_to_yaml(data, filename):
    """保存到 YAML 文件"""
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

if __name__ == "__main__":
    # 初始化 stats.txt
    with open('stats.txt', 'w', encoding='utf-8') as f:
        f.write("分析开始...\n")
    
    # 分析 link.yaml
    proxies1, unique_nodes1, keys1, invalid1 = analyze_nodes(URL1, "link")
    with open('stats.txt', 'a', encoding='utf-8') as f:
        f.write(f"link.yaml: 总节点数 {len(proxies1)}, 独特节点数 {len(unique_nodes1)}, 无效节点数 {invalid1}\n")
    
    # 分析 link (1).yaml
    proxies2, unique_nodes2, keys2, invalid2 = analyze_nodes(URL2, "link1")
    with open('stats.txt', 'a', encoding='utf-8') as f:
        f.write(f"link (1).yaml: 总节点数 {len(proxies2)}, 独特节点数 {len(unique_nodes2)}, 无效节点数 {invalid2}\n")
    
    # 比较重复和差异
    common_keys = keys1.intersection(keys2)
    unique_to_file1 = keys1 - keys2
    unique_to_file2 = keys2 - keys1
    
    with open('stats.txt', 'a', encoding='utf-8') as f:
        f.write("\n比较结果:\n")
        f.write(f"两个文件中共同的独特节点数: {len(common_keys)}\n")
        f.write(f"仅在 link.yaml 中的独特节点数: {len(unique_to_file1)}\n")
        f.write(f"仅在 link (1).yaml 中的独特节点数: {len(unique_to_file2)}\n")
    
    # 保存去重后的节点
    save_to_yaml({'proxies': unique_nodes1}, "unique_link.yaml")
    save_to_yaml({'proxies': unique_nodes2}, "unique_link1.yaml")
    
    with open('stats.txt', 'a', encoding='utf-8') as f:
        f.write("\n去重后的节点已保存到 unique_link.yaml 和 unique_link1.yaml\n")
