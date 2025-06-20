import requests
import subprocess
import json
import os
import urllib.parse
import time
import base64
from pathlib import Path

# 配置
DATA_DIR = "data"
SUB_FILE = f"{DATA_DIR}/sub.txt"
FAILED_FILE = f"{DATA_DIR}/failed_proxies.json"
TIMEOUT = 5 # nc 连接超时

NODE_URLS = [
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt"
]

# 支持的协议列表
SUPPORTED_PROTOCOLS_PREFIXES = (
    'hysteria2://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'vless://'
)

def setup_files():
    """创建data目录和文件，并确保FAILED_FILE是有效的JSON列表"""
    os.makedirs(DATA_DIR, exist_ok=True)
    Path(SUB_FILE).touch() # 如果文件不存在则创建
    
    # 确保FAILED_FILE存在且是有效的JSON列表，如果不是则重置
    if not os.path.exists(FAILED_FILE):
        with open(FAILED_FILE, 'w') as f:
            json.dump([], f)
    else:
        try:
            with open(FAILED_FILE, 'r') as f:
                content = json.load(f)
                if not isinstance(content, list):
                    raise ValueError("FAILED_FILE content is not a list")
                for item in content:
                    if not isinstance(item, dict) or 'host' not in item or 'port' not in item:
                        if 'reason' not in item: 
                            raise ValueError("Items in FAILED_FILE are not valid dictionaries (missing host/port)")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Warning: {FAILED_FILE} is corrupted or in an unexpected format ({e}). Resetting it.")
            with open(FAILED_FILE, 'w') as f:
                json.dump([], f) # 重置为有效的空列表

def fetch_nodes():
    """获取节点列表并去重"""
    print("Fetching nodes from remote URLs...")
    nodes = set()
    for url in NODE_URLS:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            for line in response.text.splitlines():
                line = line.strip()
                if line.startswith(SUPPORTED_PROTOCOLS_PREFIXES):
                    # 移除URL中可能存在的注释部分，确保只处理原始链接
                    if '#' in line:
                        line = line.split('#')[0]
                    # 移除vmess链接中可能存在的_1000ms后缀
                    if line.startswith('vmess://') and line.endswith('_1000ms'):
                        line = line[:-len('_1000ms')]
                    
                    nodes.add(line)
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
    print(f"Fetched and deduplicated {len(nodes)} nodes.")
    return list(nodes)

def parse_node(node):
    """解析节点信息"""
    try:
        parsed = urllib.parse.urlparse(node)
        scheme = parsed.scheme.lower()

        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            if scheme == 'vmess':
                try:
                    # 确保Base64解码正确处理填充
                    encoded_str = parsed.netloc
                    missing_padding = len(encoded_str) % 4
                    if missing_padding:
                        encoded_str += '=' * (4 - missing_padding)
                    
                    decoded_str = base64.b64decode(encoded_str).decode('utf-8')
                    vmess_config = json.loads(decoded_str)
                    host = vmess_config.get('add')
                    port = vmess_config.get('port')
                    if host and port:
                        port = int(port)
                except Exception:
                    pass

            elif scheme == 'ss':
                try:
                    if '@' in parsed.netloc:
                        parts = parsed.netloc.split('@')[-1].split(':')
                        if len(parts) >= 2:
                            host = parts[0]
                            port = int(parts[1])
                    else: # 尝试base64解码
                        encoded_netloc = parsed.netloc
                        missing_padding = len(encoded_netloc) % 4
                        if missing_padding:
                            encoded_netloc += '=' * (4 - missing_padding)
                        
                        decoded_netloc = base64.b64decode(encoded_netloc).decode('utf-8')
                        if '@' in decoded_netloc:
                            parts = decoded_netloc.split('@')[-1].split(':')
                            if len(parts) >= 2:
                                host = parts[0]
                                port = int(parts[1])
                except Exception:
                    pass

            elif scheme == 'ssr':
                try:
                    if ':' in parsed.netloc: # SSR的netloc可能包含host:port
                        parts = parsed.netloc.split(':')
                        if len(parts) >= 2:
                            host = parts[0]
                            port = int(parts[1])
                    # SSR的path部分也可能包含信息，这里简化处理只取host:port
                except Exception:
                    pass

        if not host or not port:
            print(f"Could not parse host or port for {node}")
            return None

        # 如果端口仍然是None，设置默认值
        if port is None:
            if scheme in ['vmess', 'vless', 'trojan', 'hysteria2']:
                port = 443 # 这些协议常见端口
            elif scheme == 'ss':
                port = 8080 # SS常见端口
            elif scheme == 'ssr':
                port = 443 # SSR也常见443/80

        return {'host': host, 'port': port, 'protocol': scheme, 'original_node': node}
    except Exception as e:
        print(f"Parse error for {node}: {e}")
        return None

def is_failed_node(host, port, failed_nodes):
    """检查节点是否在失败列表中"""
    return any(isinstance(n, dict) and n.get('host') == host and n.get('port') == port for n in failed_nodes)

def test_connectivity(host, port, protocol):
    """使用nc测试端口连通性"""
    try:
        cmd = ['nc', '-z', '-w', str(TIMEOUT), host, str(port)]
        if protocol == 'hysteria2':
            cmd.insert(2, '-u')
        
        print(f"  Testing connectivity for {protocol.upper()} {host}:{port} with command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT + 1)
        
        if result.returncode == 0:
            print(f"  Connectivity successful for {host}:{port}.")
            return True
        else:
            print(f"  Connectivity failed for {host}:{port}. Error: {result.stderr.strip() or result.stdout.strip()}")
            return f"nc failed: {result.returncode}"
    except subprocess.TimeoutExpired:
        print(f"  Connectivity test timed out for {host}:{port}.")
        return "timeout"
    except Exception as e:
        print(f"  Connectivity test error for {host}:{port}: {e}")
        return f"Error: {e}"

# update_node_name 函数现在只用于去除可能存在的旧注释
def clean_node_url(node_url):
    """移除URL中可能存在的注释部分，确保返回纯粹的节点链接"""
    if '#' in node_url:
        node_url = node_url.split('#')[0]
    # 移除vmess链接中可能存在的_1000ms后缀 (再次确保)
    if node_url.startswith('vmess://') and node_url.endswith('_1000ms'):
        node_url = node_url[:-len('_1000ms')]
    return node_url

def main():
    setup_files()
    
    # 读取当前的失败节点列表
    current_failed_nodes = []
    try:
        with open(FAILED_FILE, 'r') as f:
            current_failed_nodes = json.load(f)
            if not isinstance(current_failed_nodes, list) or not all(isinstance(n, dict) and 'host' in n and 'port' in n for n in current_failed_nodes):
                print(f"Warning: {FAILED_FILE} content is malformed. Resetting current failed nodes for this run.")
                current_failed_nodes = []
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Failed to load {FAILED_FILE} ({e}). Starting with an empty failed list for this run.")
        current_failed_nodes = []
        with open(FAILED_FILE, 'w') as f:
            json.dump([], f)

    # 获取所有待测试的节点
    all_nodes_to_test = fetch_nodes()
    
    successful_nodes_this_run = set() # 存储本次运行中连通成功的原始节点链接 (使用set自动去重)
    failed_nodes_this_run = [] # 存储本次运行中失败的节点 (用于追加到文件中)

    for i, node_url in enumerate(all_nodes_to_test, 1):
        # 确保在测试前节点URL是干净的，不带上次可能有的注释
        clean_url = clean_node_url(node_url)

        print(f"\nTesting node {i}/{len(all_nodes_to_test)}: {clean_url}")
        parsed = parse_node(clean_url)
        
        if not parsed:
            print("  Invalid node format or unparsable, skipping.")
            host_temp, port_temp = "unknown", "unknown"
            try:
                temp_parsed = urllib.parse.urlparse(clean_url)
                host_temp = temp_parsed.hostname or "unknown"
                port_temp = temp_parsed.port or "unknown"
            except:
                pass
            
            node_info_failed = {'host': host_temp, 'port': port_temp, 'original_node': clean_url, 'reason': 'Parse Error', 'timestamp': time.time()}
            if not any(n.get('host') == node_info_failed['host'] and n.get('port') == node_info_failed['port'] for n in failed_nodes_this_run):
                failed_nodes_this_run.append(node_info_failed)
            continue
        
        host, port, protocol, original_node = parsed['host'], parsed['port'], parsed['protocol'], parsed['original_node']
        
        # 检查是否为**之前**已失败的节点 (避免重复测试已知失败的)
        if is_failed_node(host, port, current_failed_nodes):
            print(f"  Node {host}:{port} ({protocol.upper()}) already failed in previous runs, skipping.")
            node_info_failed = {'host': host, 'port': port, 'original_node': original_node, 'reason': 'Previously Failed', 'timestamp': time.time()}
            if not any(n.get('host') == node_info_failed['host'] and n.get('port') == node_info_failed['port'] for n in failed_nodes_this_run):
                failed_nodes_this_run.append(node_info_failed)
            continue
        
        # --- 连通性测试 ---
        conn_result = test_connectivity(host, port, protocol)
        if conn_result is True:
            # 连通性成功，添加到成功的集合中 (这里直接使用原始的、纯净的链接)
            successful_nodes_this_run.add(original_node)
        else:
            print(f"  Connectivity test failed for {host}:{port}. Reason: {conn_result}")
            node_info_failed = {'host': host, 'port': port, 'original_node': original_node, 'reason': conn_result, 'timestamp': time.time()}
            if not any(n.get('host') == node_info_failed['host'] and n.get('port') == node_info_failed['port'] for n in failed_nodes_this_run):
                failed_nodes_this_run.append(node_info_failed)

    # --- 保存成功节点到 sub.txt (追加模式) ---
    print(f"\nSaving successful nodes to {SUB_FILE} (appending)...")
    with open(SUB_FILE, 'a') as f: # 'a' for append mode
        for node_url in sorted(list(successful_nodes_this_run)): # 排序后写入，确保顺序一致
            f.write(node_url + '\n')
    print(f"Successfully appended {len(successful_nodes_this_run)} nodes to {SUB_FILE}.")
    
    # --- 保存失败节点到 failed_proxies.json (追加模式，需要先读后写去重) ---
    print(f"\nSaving failed nodes to {FAILED_FILE} (appending)...")
    # 先加载现有失败节点，去除重复（基于host+port），然后添加本次失败节点
    final_failed_nodes = {} # 使用字典去重，键是 'host:port'
    
    # 将旧的失败节点加入，如果存在同host:port的，保留旧的理由，更新时间戳
    for node_data in current_failed_nodes:
        key = f"{node_data.get('host')}:{node_data.get('port')}"
        final_failed_nodes[key] = node_data
        
    # 将本次失败的节点加入，会覆盖旧的（更新时间戳和最新失败原因）
    for node_data in failed_nodes_this_run:
        key = f"{node_data.get('host')}:{node_data.get('port')}"
        final_failed_nodes[key] = node_data

    # 将字典的值转换为列表
    final_failed_list = list(final_failed_nodes.values())

    with open(FAILED_FILE, 'w') as f: # 注意这里仍然是 'w'，因为是写入整个更新后的列表
        json.dump(final_failed_list, f, indent=2)
    print(f"Successfully updated {len(final_failed_list)} failed nodes in {FAILED_FILE}.")
            
    print(f"\nTest completed. Connectivity-tested nodes saved to {SUB_FILE}, failed nodes saved to {FAILED_FILE}.")
    print("\nSummary of newly successful nodes (connectivity OK) added this run:")
    for node_url in sorted(list(successful_nodes_this_run)):
        print(node_url)

if __name__ == "__main__":
    main()
