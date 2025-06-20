import requests
import subprocess
import json
import os
import urllib.parse
import time
from pathlib import Path

# 配置
DATA_DIR = "data"
SUB_FILE = f"{DATA_DIR}/sub.txt"
FAILED_FILE = f"{DATA_DIR}/failed_proxies.json"
TEST_URL = "http://speedtest.tele2.net/1MB.zip"
TIMEOUT = 5
DOWNLOAD_TIMEOUT = 10
NODE_URLS = [
   # "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt"
]

def setup_files():
    """创建data目录和文件"""
    os.makedirs(DATA_DIR, exist_ok=True)
    Path(SUB_FILE).touch()
    if not os.path.exists(FAILED_FILE):
        with open(FAILED_FILE, 'w') as f:
            json.dump([], f)

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
                if line.startswith(('hysteria2://', 'vmess://')):
                    nodes.add(line)
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
    print(f"Fetched and deduplicated {len(nodes)} nodes.")
    return list(nodes)

def parse_node(node):
    """解析节点信息"""
    try:
        parsed = urllib.parse.urlparse(node)
        if parsed.scheme not in ['hysteria2', 'vmess']:
            return None
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'vmess' else 8443)
        return {'host': host, 'port': port, 'protocol': parsed.scheme}
    except Exception as e:
        print(f"Parse error for {node}: {e}")
        return None

def is_failed_node(host, port, failed_nodes):
    """检查节点是否在失败列表中"""
    return any(n['host'] == host and n['port'] == port for n in failed_nodes)

def test_connectivity(host, port, protocol):
    """使用nc测试端口连通性"""
    try:
        cmd = ['nc', '-z', '-w', str(TIMEOUT), host, str(port)]
        if protocol == 'hysteria2':
            cmd.insert(2, '-u')  # UDP for hysteria2
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        return f"Error: {e}"

def test_download(host, port):
    """使用curl测试下载速度和延迟"""
    try:
        start_time = time.time()
        cmd = [
            'curl', '-s', '-o', '/dev/null',
            '--connect-timeout', str(DOWNLOAD_TIMEOUT),
            '--write-out', '%{time_connect},%{speed_download}',
            '-x', f'http://{host}:{port}',
            TEST_URL
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            time_connect, speed = map(float, result.stdout.split(','))
            latency = time_connect * 1000  # 转换为毫秒
            speed_mbps = (speed * 8) / 1000000  # 转换为Mbps
            return latency, speed_mbps
        return None, None
    except Exception as e:
        return None, f"Error: {e}"

def update_node_name(node, latency):
    """在节点名称中添加延迟"""
    try:
        parsed = urllib.parse.urlparse(node)
        netloc = parsed.netloc
        path = parsed.path or ''
        query = parsed.query or ''
        new_netloc = f"latency={latency:.2f}ms@{netloc}"
        if query:
            return f"{parsed.scheme}://{new_netloc}{path}?{query}"
        return f"{parsed.scheme}://{new_netloc}{path}"
    except Exception as e:
        print(f"Error updating node name {node}: {e}")
        return node

def main():
    setup_files()
    
    # 读取失败节点
    with open(FAILED_FILE, 'r') as f:
        failed_nodes = json.load(f)
    
    # 获取节点
    nodes = fetch_nodes()
    tested_nodes = []
    new_failed_nodes = failed_nodes.copy()
    
    for i, node in enumerate(nodes, 1):
        print(f"\nTesting node {i}/{len(nodes)}: {node}")
        parsed = parse_node(node)
        if not parsed:
            print("Invalid node format, skipping.")
            continue
        
        host, port, protocol = parsed['host'], parsed['port'], parsed['protocol']
        
        # 检查是否为已失败节点
        if is_failed_node(host, port, failed_nodes):
            print(f"Node {host}:{port} already failed, skipping.")
            continue
        
        # 测试连通性
        conn_result = test_connectivity(host, port, protocol)
        if conn_result is not True:
            print(f"Connectivity test failed: {conn_result}")
            if not any(n['host'] == host and n['port'] == port for n in new_failed_nodes):
                new_failed_nodes.append({'host': host, 'port': port})
            continue
        
        # 测试下载（仅vmess）
        if protocol == 'vmess':
            latency, speed = test_download(host, port)
            if latency is None:
                print(f"Download test failed: {speed}")
                if not any(n['host'] == host and n['port'] == port for n in new_failed_nodes):
                    new_failed_nodes.append({'host': host, 'port': port})
                continue
            print(f"Latency: {latency:.2f}ms, Speed: {speed:.2f}Mbps")
            # 更新节点名称
            new_node = update_node_name(node, latency)
            tested_nodes.append({'node': new_node, 'latency': latency})
        else:
            print("Download test: hysteria2 not supported for direct HTTP testing.")
            continue
    
    # 保存失败节点
    with open(FAILED_FILE, 'w') as f:
        json.dump(new_failed_nodes, f, indent=2)
    
    # 按延迟排序并保存成功节点
    tested_nodes.sort(key=lambda x: x['latency'])
    with open(SUB_FILE, 'a') as f:
        for node_info in tested_nodes:
            f.write(node_info['node'] + '\n')
    
    print(f"\nTest completed. Successful nodes saved to {SUB_FILE}, failed nodes saved to {FAILED_FILE}.")
    print("Sorted nodes by latency:")
    for node_info in tested_nodes:
        print(f"{node_info['node']} (Latency: {node_info['latency']:.2f}ms)")

if __name__ == "__main__":
    main()
