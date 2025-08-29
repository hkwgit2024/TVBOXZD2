import requests
import yaml
import hashlib
import json
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

def parse_node_from_dict(node):
    """验证节点是否符合官方要求"""
    if not isinstance(node, dict):
        return None
    node_type = node.get('type')
    if node_type == 'ss':
        required = {'server', 'port', 'cipher', 'password'}
        if not all(k in node for k in required) or node.get('cipher') not in VALID_SS_CIPHERS or not validate_server_port(node.get('server'), node.get('port')):
            return None
        return {k: node[k] for k in required}
    elif node_type == 'vmess':
        required = {'server', 'port', 'uuid', 'cipher'}
        if not all(k in node for k in required) or node.get('cipher') not in VALID_VMESS_CIPHERS or not validate_server_port(node.get('server'), node.get('port')):
            return None
        return {k: node[k] for k in required}
    elif node_type == 'vless':
        required = {'server', 'port', 'uuid'}
        if not all(k in node for k in required) or not validate_server_port(node.get('server'), node.get('port')):
            return None
        return {k: node[k] for k in required}
    elif node_type == 'trojan':
        required = {'server', 'port', 'password'}
        if not all(k in node for k in required) or not validate_server_port(node.get('server'), node.get('port')):
            return None
        return {k: node[k] for k in required}
    elif node_type == 'ssr':
        required = {'server', 'port', 'password', 'cipher', 'protocol', 'obfs'}
        if not all(k in node for k in required) or not validate_server_port(node.get('server'), node.get('port')):
            return None
        return {k: node[k] for k in required}
    elif node_type == 'hysteria2':
        required = {'server', 'port', 'password'}
        if not all(k in node for k in required) or not validate_server_port(node.get('server'), node.get('port')):
            return None
        return {k: node[k] for k in required}
    return None

def get_node_key(node):
    """生成节点的哈希键，仅基于官方要求字段，忽略 name"""
    node_type = node.get('type')
    key_dict = {k: node.get(k) for k in node if k != 'name'}
    key_str = json.dumps(key_dict, sort_keys=True)
    return hashlib.sha256(key_str.encode('utf-8')).hexdigest()

def analyze_nodes(url, file_name):
    """下载并分析 YAML 文件的节点"""
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        # 尝试解析 YAML 文件
        try:
            data = yaml.safe_load(response.text)
        except yaml.YAMLError as e:
            with open(f"compare_{file_name}.log", 'a', encoding='utf-8') as f:
                f.write(f"YAML 解析错误: {e}\n")
            with open('stats.txt', 'a', encoding='utf-8') as f:
                f.write(f"处理 {url} 失败: YAML 解析错误\n")
            return [], [], set(), 0

        # 检查是否为预期的结构
        if not isinstance(data, dict) or 'proxies' not in data or not isinstance(data['proxies'], list):
            with open(f"compare_{file_name}.log", 'a', encoding='utf-8') as f:
                f.write("文件结构不符: 缺少 'proxies' 键或其值不是列表\n")
            with open('stats.txt', 'a', encoding='utf-8') as f:
                f.write(f"处理 {url} 失败: 文件结构不符\n")
            return [], [], set(), 0

        proxies = data['proxies']
        seen_keys = set()
        unique_nodes = []
        name_counts = defaultdict(int)
        invalid_count = 0
        
        for node in proxies:
            if not isinstance(node, dict):
                invalid_count += 1
                with open(f"compare_{file_name}.log", 'a', encoding='utf-8') as f:
                    f.write(f"无效节点: 非字典类型 ({node})\n")
                continue
            
            parsed_node = parse_node_from_dict(node)
            if not parsed_node:
                invalid_count += 1
                with open(f"compare_{file_name}.log", 'a', encoding='utf-8') as f:
                    f.write(f"无效节点: {node.get('name', '未命名')} (缺失必须字段或无效参数)\n")
                continue
            
            node_key = get_node_key(parsed_node)
            if node_key not in seen_keys:
                seen_keys.add(node_key)
                base_name = f"{parsed_node['type']}-{parsed_node.get('server')}-{parsed_node.get('port')}"
                parsed_node['name'] = f"{base_name}_{name_counts[base_name] + 1}"
                name_counts[base_name] += 1
                unique_nodes.append(parsed_node)
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
    # 初始化 stats.txt 和日志文件
    with open('stats.txt', 'w', encoding='utf-8') as f:
        f.write("分析开始...\n")
    with open('compare_link.log', 'w', encoding='utf-8') as f:
        f.write("link.yaml 日志\n")
    with open('compare_link1.log', 'w', encoding='utf-8') as f:
        f.write("link (1).yaml 日志\n")
    
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
