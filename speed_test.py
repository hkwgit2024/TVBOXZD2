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
# TEST_URL 已不再需要，因为移除了下载测试
TIMEOUT = 5 # nc 连接超时
# DOWNLOAD_TIMEOUT 已不再需要

NODE_URLS = [
   # "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt",
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
                        if 'reason' not in item: # 允许 'reason' 字段存在
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
                    decoded_str = base64.b64decode(parsed.netloc + "==").decode('utf-8')
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
                    else:
                        decoded_netloc = base64.b64decode(parsed.netloc + "==").decode('utf-8')
                        if '@' in decoded_netloc:
                            parts = decoded_netloc.split('@')[-1].split(':')
                            if len(parts) >= 2:
                                host = parts[0]
                                port = int(parts[1])
                except Exception:
                    pass

            elif scheme == 'ssr':
                try:
                    if ':' in parsed.netloc:
                        parts = parsed.netloc.split(':')
                        if len(parts) >= 2:
                            host = parts[0]
                            port = int(parts[1])
                except Exception:
                    pass

        if not host or not port:
            print(f"Could not parse host or port for {node}")
            return None

        if port is None:
            if scheme in ['vmess', 'vless', 'trojan']:
                port = 443
            elif scheme == 'ss':
                port = 8080
            elif scheme == 'hysteria2':
                port = 443

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

# test_download 函数已被移除

# update_node_name 函数也被简化，因为它不再需要处理延迟信息
def update_node_name(node, status_comment=""):
    """在节点名称中添加状态注释（例如连通性OK）"""
    if status_comment:
        # 移除可能已有的旧注释
        if '#' in node:
            node_base = node.split('#')[0]
            return f"{node_base}#{status_comment}"
        else:
            return f"{node}#{status_comment}"
    return node


def main():
    setup_files()
    
    # 读取当前的失败节点列表
    current_failed_nodes = []
    try:
        with open(FAILED_FILE, 'r') as f:
            current_failed_nodes = json.load(f)
            # 再次验证加载的内容，防止外部篡改
            if not isinstance(current_failed_nodes, list) or not all(isinstance(n, dict) and 'host' in n and 'port' in n for n in current_failed_nodes):
                print(f"Warning: {FAILED_FILE} content is malformed. Resetting current failed nodes for this run.")
                current_failed_nodes = []
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Failed to load {FAILED_FILE} ({e}). Starting with an empty failed list for this run.")
        current_failed_nodes = []
        # 确保文件存在且为空列表，以便后续写入
        with open(FAILED_FILE, 'w') as f:
            json.dump([], f) # 确保是一个有效的空JSON列表

    # 获取所有待测试的节点
    all_nodes_to_test = fetch_nodes()
    
    successful_nodes_this_run = set() # 存储本次运行中成功的节点
    failed_nodes_this_run = [] # 存储本次运行中失败的节点 (用于追加到文件中)

    for i, node_url in enumerate(all_nodes_to_test, 1):
        print(f"\nTesting node {i}/{len(all_nodes_to_test)}: {node_url}")
        parsed = parse_node(node_url)
        
        if not parsed:
            print("  Invalid node format or unparsable, skipping.")
            # 添加到本次失败列表，避免重复
            host_temp, port_temp = "unknown", "unknown"
            try:
                temp_parsed = urllib.parse.urlparse(node_url)
                host_temp = temp_parsed.hostname or "unknown"
                port_temp = temp_parsed.port or "unknown"
            except:
                pass
            
            node_info_failed = {'host': host_temp, 'port': port_temp, 'original_node': node_url, 'reason': 'Parse Error', 'timestamp': time.time()}
            # 避免重复添加到本次失败列表中
            if not any(n.get('host') == node_info_failed['host'] and n.get('port') == node_info_failed['port'] for n in failed_nodes_this_run):
                failed_nodes_this_run.append(node_info_failed)
            continue
        
        host, port, protocol, original_node = parsed['host'], parsed['port'], parsed['protocol'], parsed['original_node']
        
        # 检查是否为**之前**已失败的节点 (避免重复测试已知失败的)
        if is_failed_node(host, port, current_failed_nodes):
            print(f"  Node {host}:{port} ({protocol.upper()}) already failed in previous runs, skipping.")
            # 即使跳过，也要记录到本次失败列表，确保最终写入时包含这些旧失败节点，并更新时间戳
            node_info_failed = {'host': host, 'port': port, 'original_node': original_node, 'reason': 'Previously Failed', 'timestamp': time.time()}
            if not any(n.get('host') == node_info_failed['host'] and n.get('port') == node_info_failed['port'] for n in failed_nodes_this_run):
                failed_nodes_this_run.append(node_info_failed)
            continue
        
        # --- 连通性测试 ---
        conn_result = test_connectivity(host, port, protocol)
        if conn_result is True:
            # 连通性成功，添加到成功的集合中
            # 可以在URL末尾添加一个注释，表明连通性通过
            updated_node_url = update_node_name(original_node, "ConnectivityOK")
            # 使用集合避免重复
            successful_nodes_this_run.add(updated_node_url)
        else:
            print(f"  Connectivity test failed for {host}:{port}. Reason: {conn_result}")
            node_info_failed = {'host': host, 'port': port, 'original_node': original_node, 'reason': conn_result, 'timestamp': time.time()}
            # 避免重复添加到本次失败列表中
            if not any(n.get('host') == node_info_failed['host'] and n.get('port') == node_info_failed['port'] for n in failed_nodes_this_run):
                failed_nodes_this_run.append(node_info_failed)

    # --- 保存成功节点到 sub.txt (追加模式) ---
    print(f"\nSaving successful nodes to {SUB_FILE} (appending)...")
    with open(SUB_FILE, 'a') as f: # 'a' for append mode
        for node_url in successful_nodes_this_run:
            f.write(node_url + '\n')
    print(f"Successfully appended {len(successful_nodes_this_run)} nodes to {SUB_FILE}.")
    
    # --- 保存失败节点到 failed_proxies.json (追加模式，需要先读后写) ---
    print(f"\nSaving failed nodes to {FAILED_FILE} (appending)...")
    # 先加载现有失败节点，去除重复（基于host+port），然后添加本次失败节点
    final_failed_nodes = {} # 使用字典去重，键是 'host:port'
    for node_data in current_failed_nodes: # 先加入旧的
        key = f"{node_data.get('host')}:{node_data.get('port')}"
        final_failed_nodes[key] = node_data
        
    for node_data in failed_nodes_this_run: # 再加入本次失败的，会覆盖旧的（更新时间戳）
        key = f"{node_data.get('host')}:{node_data.get('port')}"
        final_failed_nodes[key] = node_data

    # 将字典的值转换为列表
    final_failed_list = list(final_failed_nodes.values())

    with open(FAILED_FILE, 'w') as f: # 注意这里仍然是 'w'，因为是写入整个更新后的列表
        json.dump(final_failed_list, f, indent=2)
    print(f"Successfully updated {len(final_failed_list)} failed nodes in {FAILED_FILE}.")
            
    print(f"\nTest completed. Connectivity-tested nodes saved to {SUB_FILE}, failed nodes saved to {FAILED_FILE}.")
    print("\nSummary of successful nodes (connectivity OK):")
    for node_url in sorted(list(successful_nodes_this_run)): # 排序后打印
        print(node_url)

if __name__ == "__main__":
    main()
