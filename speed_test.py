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
import dns.resolver # 引入 dnspython 库

# 确保 data 目录存在
if not os.path.exists('data'):
    os.makedirs('data')

# 配置项
NODES_URL = "https://github.com/qjlxg/aggregator/raw/refs/heads/main/ss.txt"
OUTPUT_FILE = "data/connected_nodes.txt"
CONNECTION_TIMEOUT = 3 # 每个TCP连接的超时时间
MAX_WORKERS = 50 # 并发线程数

# 新增：限制测试的节点数量 (为 None 或 0 则测试所有节点)
LIMIT_NODES_COUNT = 100 

# 新增：配置 DNS 服务器 (可以添加多个，会按顺序尝试)
# 例如：Google DNS, Cloudflare DNS, Quad9 DNS, 或您认为在本地网络环境中表现良好的DNS
DNS_SERVERS = ['202.96.128.86', '120.196.165.24', ] # 您已将此设置为您的本地DNS，保持不变

# 初始化 DNS 解析器
resolver = dns.resolver.Resolver(configure=False) # configure=False 禁用系统默认配置
resolver.nameservers = DNS_SERVERS # 使用我们自定义的 DNS 服务器
resolver.timeout = 5 # DNS 查询超时时间
resolver.lifetime = 5 # DNS 查询生命周期

def decode_base64_urlsafe(data):
    """
    解码 URL Safe Base64 编码，并添加填充。
    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

def is_ip_address(address):
    """
    检查字符串是否是有效的 IPv4 或 IPv6 地址。
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False

def resolve_hostname(hostname):
    """
    尝试解析主机名到 IP 地址。
    """
    if is_ip_address(hostname):
        # print(f"Hostname {hostname} is already an IP. Skipping DNS resolution.") # 调试信息
        return hostname

    print(f"Attempting to resolve {hostname} using custom DNS servers: {DNS_SERVERS}...") # 新增日志
    try:
        # 尝试使用配置的 DNS 服务器解析
        answers = resolver.resolve(hostname, 'A') # 优先解析 IPv4
        for rdata in answers:
            resolved_ip = rdata.address
            print(f"Successfully resolved {hostname} to {resolved_ip} with custom DNS.") # 新增日志
            return resolved_ip
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException) as e:
        print(f"DNS resolution failed for {hostname} with custom DNS servers ({DNS_SERVERS}): {type(e).__name__} - {e}") # 新增日志
        # === 核心修改：禁用回退机制，直接返回 None ===
        return None
    # return None # 这行也可以删除，因为前面的except块已经保证了返回

def parse_node_link(link):
    """
    尝试解析不同协议的节点链接，提取服务器地址和端口。
    如果服务器是域名，则尝试解析为 IP 地址。
    """
    try:
        parsed_url = urlparse(link)
        protocol = parsed_url.scheme
        original_server = None
        port = None

        if protocol == "ss":
            try:
                decoded_netloc = base64.b64decode(parsed_url.netloc).decode('utf-8')
                if '@' in decoded_netloc:
                    _, addr_part = decoded_netloc.split('@', 1)
                else:
                    addr_part = decoded_netloc
                
                if ':' in addr_part:
                    original_server, port_str = addr_part.rsplit(':', 1)
                    port = int(port_str)
            except Exception:
                pass
            
            if not original_server and '@' in parsed_url.netloc:
                _, addr_part = parsed_url.netloc.split('@', 1)
            elif not original_server:
                addr_part = parsed_url.netloc
            
            if not original_server and ':' in addr_part:
                original_server, port_str = addr_part.rsplit(':', 1)
                port = int(port_str)
            
            if original_server and port:
                resolved_ip = resolve_hostname(original_server)
                if resolved_ip:
                    return {"protocol": protocol, "server": resolved_ip, "port": port, "original_link": link, "original_hostname": original_server}
            return None

        elif protocol == "ssr":
            encoded_part = parsed_url.netloc + parsed_url.path + parsed_url.params + parsed_url.query + parsed_url.fragment
            decoded_part = decode_base64_urlsafe(encoded_part).decode('utf-8')
            parts = decoded_part.split(':')
            if len(parts) >= 2:
                original_server = parts[0]
                port = int(parts[1])
                resolved_ip = resolve_hostname(original_server)
                if resolved_ip:
                    return {"protocol": protocol, "server": resolved_ip, "port": port, "original_link": link, "original_hostname": original_server}
            return None

        elif protocol == "vmess":
            encoded_json = parsed_url.netloc
            decoded_json = decode_base64_urlsafe(encoded_json).decode('utf-8')
            config = json.loads(decoded_json)
            original_server = config.get("add")
            port = config.get("port")
            if original_server and port:
                resolved_ip = resolve_hostname(original_server)
                if resolved_ip:
                    return {"protocol": protocol, "server": resolved_ip, "port": port, "original_link": link, "original_hostname": original_server}
            return None

        elif protocol in ["trojan", "vless", "hysteria2"]:
            original_server = parsed_url.hostname
            port = parsed_url.port
            if original_server and port:
                resolved_ip = resolve_hostname(original_server)
                if resolved_ip:
                    return {"protocol": protocol, "server": resolved_ip, "port": port, "original_link": link, "original_hostname": original_server}
            return None

        else:
            return None

    except Exception as e:
        # print(f"Error parsing link {link}: {e}")
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
        server_ip = node_info['server'] # 现在这里已经是解析后的 IP
        port = node_info['port']
        protocol = node_info['protocol']
        original_hostname = node_info.get('original_hostname', server_ip) # 如果是IP，original_hostname就是IP

        if not server_ip or not port:
            return original_line, False, f"Parsed but missing server/port or failed DNS resolution: {decoded_link[:50]}..."

        try:
            sock = socket.create_connection((server_ip, port), timeout=CONNECTION_TIMEOUT)
            sock.close()
            return original_line, True, f"Connected to {protocol}://{original_hostname}:{port} ({server_ip})"
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e:
            return original_line, False, f"Failed to connect to {protocol}://{original_hostname}:{port} ({server_ip}) ({e})"
    else:
        return original_line, False, f"Unrecognized or unparseable node: {decoded_link[:50]}..."

def main():
    start_time = time.time()
    print("Starting node connectivity test with DNS pre-resolution...")

    try:
        response = requests.get(NODES_URL, timeout=15)
        response.raise_for_status()
        nodes_data = response.text.strip().split('\n')
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from {NODES_URL}: {e}")
        return

    nodes_data = [line.strip() for line in nodes_data if line.strip()]
    
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
            
            if processed_count % 10 == 0 or processed_count == total_nodes:
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
