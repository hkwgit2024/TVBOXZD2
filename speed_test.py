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
    """创建data目录和文件，并确保FAILED_FILE是有效的JSON列表"""
    os.makedirs(DATA_DIR, exist_ok=True)
    Path(SUB_FILE).touch()
    if not os.path.exists(FAILED_FILE):
        with open(FAILED_FILE, 'w') as f:
            json.dump([], f)
    else:
        # 尝试加载并验证FAILED_FILE，如果无效则重置
        try:
            with open(FAILED_FILE, 'r') as f:
                content = json.load(f)
                if not isinstance(content, list):
                    raise ValueError("FAILED_FILE content is not a list")
                for item in content:
                    if not isinstance(item, dict) or 'host' not in item or 'port' not in item:
                        raise ValueError("Items in FAILED_FILE are not valid dictionaries")
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
    # 确保 failed_nodes 中的每个元素都是字典
    return any(isinstance(n, dict) and n.get('host') == host and n.get('port') == port for n in failed_nodes)

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
        # 注意：curl -x proxy 只能用于 HTTP/HTTPS 代理。vmess 节点不是标准的 HTTP 代理。
        # 要测试 vmess 节点的下载速度，你需要一个能将 vmess 流量转换为 HTTP 代理的工具。
        # 简单的 curl -x 可能无法直接通过 vmess 协议进行测试。
        # 如果你有一个本地的 vmess 客户端作为 SOCKS5 或 HTTP 代理，你可以这样使用 curl：
        # cmd = [
        #     'curl', '-s', '-o', '/dev/null',
        #     '--connect-timeout', str(DOWNLOAD_TIMEOUT),
        #     '--write-out', '%{time_connect},%{speed_download}',
        #     '-x', f'socks5h://127.0.0.1:YOUR_LOCAL_PROXY_PORT', # 假设你的 vmess 客户端暴露了一个SOCKS5代理
        #     TEST_URL
        # ]
        # 由于当前脚本没有集成v2ray等客户端，直接使用 curl -x host:port 对于 vmess 是不准确的。
        # 这里为了演示，我们假设存在一个可以作为HTTP代理的Vmess转换层。
        # 实际操作中，你需要运行一个本地Vmess客户端，并让curl通过它。

        # 警告：以下 curl 命令可能不会成功，因为 vmess 节点通常不直接作为 HTTP 代理工作。
        # 它需要一个 Vmess 客户端在本地转换流量。
        cmd = [
            'curl', '-s', '-o', '/dev/null',
            '--connect-timeout', str(DOWNLOAD_TIMEOUT),
            '--write-out', '%{time_connect},%{speed_download}',
            '-x', f'http://{host}:{port}', # 这很可能失败，因为这不是标准的HTTP代理
            TEST_URL
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            try:
                time_connect, speed = map(float, result.stdout.split(','))
                latency = time_connect * 1000  # 转换为毫秒
                speed_mbps = (speed * 8) / 1000000  # 转换为Mbps
                return latency, speed_mbps
            except ValueError:
                return None, f"Curl output parse error: {result.stdout}"
        return None, result.stderr.strip() or f"Curl exited with code {result.returncode}"
    except Exception as e:
        return None, f"Error: {e}"

def update_node_name(node, latency):
    """在节点名称中添加延迟"""
    try:
        parsed = urllib.parse.urlparse(node)
        # 从 netloc 中提取现有的用户信息和端口信息，然后插入延迟
        # 示例：vmess://eyJhZ... => vmess://latency=123.45ms@eyJhZ...
        # 假设我们修改的是 Base64 编码的部分
        # 这里需要更复杂的解析来准确地插入延迟信息到Vmess节点的别名中，
        # 如果只是简单地添加到 netloc 会破坏URI结构。
        # 更合理的做法是解析Vmess的JSON数据，修改其中的ps（别名）字段。
        # 但这超出了当前urlparse的范围，需要额外的Base64解码和JSON解析。

        # 作为一个临时的简化方案，我们尝试在路径或查询参数中添加，但这可能不符合Vmess客户端的预期。
        # 假设我们修改原始URL的一部分，并希望它仍然有效。
        # 更好的方法是解码 vmess:// 链接，修改其 'ps' 字段，然后重新编码。
        # 由于当前实现没有解析 vmess:// 内部 JSON 的能力，以下修改可能不会被客户端识别为延迟信息。
        # 为了避免破坏URL，我们暂时将延迟信息作为注释或添加到末尾，或者更推荐的方式是修改其别名 (ps)。

        # 更合适的做法是修改 vmess:// 链接中的 ps (alias) 字段
        # 原始：vmess://BASE64_ENCODED_JSON
        # JSON内部：{"ps": "原始别名"}
        # 目标：{"ps": "原始别名_latency=123ms"}

        # 因为当前代码没有解码 vmess:// 内容，所以直接修改 URL 字符串可能会导致无效链接。
        # 如果要正确添加延迟，需要对 vmess 链接进行 Base64 解码，修改 JSON，再进行 Base64 编码。
        # 对于当前简单的URL操作，我们只能在不太敏感的位置添加。

        # 暂时修改为：在原始URL的末尾添加一个注释
        return f"{node}#latency={latency:.2f}ms"

    except Exception as e:
        print(f"Error updating node name {node}: {e}")
        return node

def main():
    setup_files()
    
    # 读取失败节点
    failed_nodes = []
    try:
        with open(FAILED_FILE, 'r') as f:
            failed_nodes = json.load(f)
            # 再次验证加载的内容，防止外部篡改
            if not isinstance(failed_nodes, list) or not all(isinstance(n, dict) and 'host' in n and 'port' in n for n in failed_nodes):
                print(f"Warning: {FAILED_FILE} content is malformed. Resetting failed nodes.")
                failed_nodes = []
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Failed to load {FAILED_FILE} ({e}). Initializing with empty list.")
        failed_nodes = []
        # 确保文件存在且为空列表，以便后续写入
        with open(FAILED_FILE, 'w') as f:
            json.dump([], f)

    # 获取节点
    nodes = fetch_nodes()
    tested_nodes = []
    new_failed_nodes = failed_nodes.copy() # 使用拷贝以避免在循环中修改原始列表

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
            if not any(n['host'] == host and n['port'] == port for n in new_failed_nodes): # 避免重复添加
                new_failed_nodes.append({'host': host, 'port': port})
            continue
        
        # 测试下载（仅vmess）
        if protocol == 'vmess':
            # 再次强调：这里直接使用 curl -x host:port 对于 vmess 节点是**不准确**的。
            # Vmess 是一种代理协议，需要一个客户端来解密和转发流量。
            # 如果没有本地运行的 Vmess 客户端作为 HTTP 或 SOCKS5 代理，此测试会失败。
            # 如果你有本地 Vmess 客户端（例如 v2ray, xray），并且它在 127.0.0.1:YOUR_LOCAL_PROXY_PORT 上暴露了 HTTP 或 SOCKS5 代理，
            # 你应该将 test_download 函数中的 '-x' 参数修改为指向本地代理，而不是 Vmess 节点本身的 host:port。
            # 例如：'-x', f'http://127.0.0.1:10809' (假设本地 Vmess 客户端在 10809 端口提供 HTTP 代理)
            
            print("Attempting download test for vmess node (Note: requires a local vmess client proxy to work correctly).")
            latency, speed = test_download(host, port) # 这里很可能因为不是标准HTTP代理而失败
            if latency is None:
                print(f"Download test failed: {speed}")
                if not any(n['host'] == host and n['port'] == port for n in new_failed_nodes): # 避免重复添加
                    new_failed_nodes.append({'host': host, 'port': port})
                continue
            print(f"Latency: {latency:.2f}ms, Speed: {speed:.2f}Mbps")
            # 更新节点名称
            new_node = update_node_name(node, latency) # 注意这里更新节点名称的策略
            tested_nodes.append({'node': new_node, 'latency': latency})
        elif protocol == 'hysteria2':
            # Hysteria2 协议是基于 UDP 的，curl 无法直接测试其下载速度。
            # 需要一个支持 Hysteria2 的客户端来做实际的下载测试。
            print("Download test: hysteria2 not supported for direct HTTP testing with curl.")
            # 如果你仍想将通过连通性测试的 hysteria2 节点包含在最终列表中，可以这样做：
            # tested_nodes.append({'node': node, 'latency': float('inf')}) # 可以给一个很大的延迟值或者0
            # 考虑到当前的需求是排序和速度，我们可能需要一个不同的Hysteria2测试方法，否则就跳过下载测试。
            print("Skipping download test for hysteria2 node.")
            # 如果我们决定 Hysteria2 只要连通性通过就加入，可以这样：
            tested_nodes.append({'node': node, 'latency': 9999.99}) # 假设一个较大的默认延迟
        else:
            print(f"Unsupported protocol for download test: {protocol}")
            continue
    
    # 保存失败节点
    with open(FAILED_FILE, 'w') as f:
        json.dump(new_failed_nodes, f, indent=2)
    
    # 按延迟排序并保存成功节点
    # 过滤掉那些没有有效延迟的节点 (例如 hysteria2 如果没有真实测试)
    valid_tested_nodes = [n for n in tested_nodes if n['latency'] != float('inf')]
    valid_tested_nodes.sort(key=lambda x: x['latency'])

    # 将 hysteria2 节点（如果它们被加入且没有真实延迟）放在列表的末尾或单独处理
    hysteria2_nodes = [n for n in tested_nodes if n['latency'] == 9999.99] # 假设这个值代表 hysteria2 节点
    
    with open(SUB_FILE, 'w') as f: # 修改为 'w' 而不是 'a' 来覆盖旧文件
        for node_info in valid_tested_nodes:
            f.write(node_info['node'] + '\n')
        # 如果需要，也写入Hysteria2节点
        for node_info in hysteria2_nodes:
             f.write(node_info['node'] + '\n')
            
    print(f"\nTest completed. Successful nodes saved to {SUB_FILE}, failed nodes saved to {FAILED_FILE}.")
    print("Sorted nodes by latency (vmess only, hysteria2 nodes may be appended with default latency):")
    for node_info in valid_tested_nodes:
        print(f"{node_info['node']} (Latency: {node_info['latency']:.2f}ms)")
    if hysteria2_nodes:
        print("\nHysteria2 nodes (connectivity tested only, appended):")
        for node_info in hysteria2_nodes:
            print(f"{node_info['node']} (Latency: N/A - Connectivity only)")

if __name__ == "__main__":
    main()
