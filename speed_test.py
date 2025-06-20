import requests
import base64
import json
import re
import os
import socket
import struct
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# 确保 data 目录存在
if not os.path.exists('data'):
    os.makedirs('data')

# 配置项
NODES_URL = "https://github.com/qjlxg/aggregator/raw/refs/heads/main/ss.txt"
OUTPUT_FILE = "data/connected_nodes.txt"
CONNECTION_TIMEOUT = 3 # 每个TCP连接的超时时间，适当缩短以提高效率
MAX_WORKERS = 50 # 并发线程数，可以适当调整，对于100个节点，50个已经足够并行

# 新增：限制测试的节点数量
# 设置为 None 或 0 则测试所有节点
# 设置为一个正整数则只测试前 N 个节点
LIMIT_NODES_COUNT = 100 

def decode_base64_urlsafe(data):
    """
    解码 URL Safe Base64 编码，并添加填充。
    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

def parse_node_link(link):
    """
    尝试解析不同协议的节点链接，提取服务器地址和端口。
    这是一个简化的解析，不包含所有高级配置，但足以进行连通性测试。
    """
    try:
        parsed_url = urlparse(link)
        protocol = parsed_url.scheme

        if protocol == "ss":
            try:
                # 尝试解码 netloc 部分 (如果它是 Base64)
                decoded_netloc = base64.b64decode(parsed_url.netloc).decode('utf-8')
                if '@' in decoded_netloc:
                    _, addr_part = decoded_netloc.split('@', 1)
                else:
                    addr_part = decoded_netloc
                
                if ':' in addr_part:
                    server, port_str = addr_part.rsplit(':', 1)
                    return {"protocol": protocol, "server": server, "port": int(port_str), "original_link": link}
            except Exception:
                pass
            
            # 直接解析非 Base64 编码的 SS 链接
            if '@' in parsed_url.netloc:
                _, addr_part = parsed_url.netloc.split('@', 1)
            else:
                addr_part = parsed_url.netloc
            
            if ':' in addr_part:
                server, port_str = addr_part.rsplit(':', 1)
                return {"protocol": protocol, "server": server, "port": int(port_str), "original_link": link}
            return None

        elif protocol == "ssr":
            encoded_part = parsed_url.netloc + parsed_url.path + parsed_url.params + parsed_url.query + parsed_url.fragment
            decoded_part = decode_base64_urlsafe(encoded_part).decode('utf-8')
            parts = decoded_part.split(':')
            if len(parts) >= 2:
                server = parts[0]
                port = int(parts[1])
                return {"protocol": protocol, "server": server, "port": port, "original_link": link}
            return None

        elif protocol == "vmess":
            encoded_json = parsed_url.netloc
            decoded_json = decode_base64_urlsafe(encoded_json).decode('utf-8')
            config = json.loads(decoded_json)
            return {"protocol": protocol, "server": config.get("add"), "port": config.get("port"), "original_link": link}

        elif protocol in ["trojan", "vless", "hysteria2"]:
            if parsed_url.hostname and parsed_url.port:
                return {"protocol": protocol, "server": parsed_url.hostname, "port": parsed_url.port, "original_link": link}
            return None

        else:
            return None

    except Exception as e:
        return None

def test_single_node(node_line):
    """
    测试单个节点的连通性，并返回结果。
    """
    original_line = node_line
    decoded_link = ""

    if node_line.startswith(("ss://", "ssr://", "vmess://", "trojan://", "vless://", "hysteria2://")):
        decoded_link = node_line
    else:
        try:
            decoded_link = base64.b64decode(node_line).decode('utf-8')
        except Exception:
            return original_line, False, "Malformed or non-base64 node line"

    node_info = parse_node_link(decoded_link)
    
    if node_info:
        server = node_info['server']
        port = node_info['port']
        protocol = node_info['protocol']

        if not server or not port:
            return original_line, False, f"Parsed but missing server/port: {decoded_link[:50]}..."

        try:
            sock = socket.create_connection((server, port), timeout=CONNECTION_TIMEOUT)
            sock.close()
            return original_line, True, f"Connected to {protocol}://{server}:{port}"
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e:
            return original_line, False, f"Failed to connect to {protocol}://{server}:{port} ({e})"
    else:
        return original_line, False, f"Unrecognized or unparseable node: {decoded_link[:50]}..."

def main():
    start_time = time.time()
    print("Starting node connectivity test...")

    try:
        response = requests.get(NODES_URL, timeout=15)
        response.raise_for_status()
        nodes_data = response.text.strip().split('\n')
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from {NODES_URL}: {e}")
        return

    nodes_data = [line.strip() for line in nodes_data if line.strip()]
    
    # 核心修改：根据 LIMIT_NODES_COUNT 限制节点数量
    if LIMIT_NODES_COUNT and LIMIT_NODES_COUNT > 0:
        nodes_data = nodes_data[:LIMIT_NODES_COUNT]
        print(f"Limiting test to the first {LIMIT_NODES_COUNT} nodes.")

    total_nodes = len(nodes_data)
    print(f"Total valid nodes to process: {total_nodes}")

    connected_nodes_list = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(test_single_node, node_line): node_line for node_line in nodes_data}
        
        processed_count = 0
        for future in as_completed(future_to_node):
            original_line, is_connected, message = future.result()
            processed_count += 1
            if is_connected:
                connected_nodes_list.append(original_line)
                print(f"[{processed_count}/{total_nodes}] CONNECTED: {message[:100]}")
            else:
                print(f"[{processed_count}/{total_nodes}] FAILED: {message[:100]}")
            
            if processed_count % 10 == 0 or processed_count == total_nodes: # 更频繁地输出进度，因为节点数量少
                print(f"--- Processed {processed_count}/{total_nodes} nodes. Current connected: {len(connected_nodes_list)} ---")

    with open(OUTPUT_FILE, 'w') as f:
        for node in connected_nodes_list:
            f.write(node + '\n')
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Test completed in {elapsed_time:.2f} seconds.")
    print(f"Filtered nodes (connected) saved to {OUTPUT_FILE}. Total connected: {len(connected_nodes_list)}")

if __name__ == "__main__":
    main()
