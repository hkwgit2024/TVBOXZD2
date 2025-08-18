import os
import requests
import yaml
import csv
import re
import random
import json
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import reduce
from ip_geolocation import GeoLite2Country
from tqdm import tqdm
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus

# 定义文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINKS_FILE = os.path.join(BASE_DIR, 'link.txt')
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# 浏览器User-Agent列表，用于伪装请求头
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
]

# 全局变量用于存储已访问的URL和爬取深度
visited_urls = set()
MAX_DEPTH = 2  # 设置最大爬取深度，防止无限循环
CHUNK_SIZE = 50 # 每次处理的URL批次大小

# 初始化 IP 地理位置解析器
try:
    geolocator = GeoLite2Country(GEOLITE_DB)
    print("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    print(f"错误: 无法找到地理位置数据库文件 {GEOLITE_DB}。请确保文件已上传到仓库根目录。")
    exit(1)

def get_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

def test_connection(link):
    """预测试一个链接的连通性"""
    link = link.replace('http://', '').replace('https://', '')
    
    # 尝试 HTTP
    try:
        requests.head(f"http://{link}", headers=get_headers(), timeout=5)
        return link
    except requests.exceptions.RequestException:
        pass
    
    # 如果 HTTP 失败，尝试 HTTPS
    try:
        requests.head(f"https://{link}", headers=get_headers(), timeout=5)
        return link
    except requests.exceptions.RequestException:
        pass
        
    return None

def pre_test_links(links):
    """并发预测试所有链接，返回可用的链接列表"""
    working_links = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_link = {executor.submit(test_connection, link): link for link in links}
        for future in tqdm(as_completed(future_to_link), total=len(links), desc="预测试链接"):
            result = future.result()
            if result:
                working_links.append(result)
    return working_links

def parse_vmess(node_link):
    try:
        # Base64 解码并解析 JSON
        encoded_json = node_link.replace('vmess://', '')
        decoded_json = base64.b64decode(encoded_json + '=' * (-len(encoded_json) % 4)).decode('utf-8')
        node_data = json.loads(decoded_json)

        # 严格校验必须参数
        required_params = ['add', 'port', 'id', 'aid']
        if not all(p in node_data for p in required_params):
            return None

        # 构造 Clash 兼容格式
        clash_node = {
            'name': node_data.get('ps', 'Vmess Node'),
            'type': 'vmess',
            'server': node_data['add'],
            'port': int(node_data['port']),
            'uuid': node_data['id'],
            'alterId': int(node_data['aid']),
            'cipher': node_data.get('scy', 'auto'),
            'network': node_data.get('net', 'tcp'),
            'tls': node_data.get('tls', '') == 'tls',
        }

        # 更多参数（ws-path, ws-headers, sni等）
        if clash_node['network'] == 'ws':
            clash_node['ws-path'] = node_data.get('path', '/')
            clash_node['ws-headers'] = {'Host': node_data.get('host', node_data['add'])}
            if node_data.get('host'):
                clash_node['ws-headers']['Host'] = node_data['host']
        if clash_node['tls']:
            clash_node['servername'] = node_data.get('sni', node_data['add'])

        return clash_node
    except Exception:
        return None

def parse_trojan(node_link):
    try:
        parsed = urlparse(node_link)
        if not all([parsed.hostname, parsed.port, parsed.username]):
            return None

        clash_node = {
            'name': unquote_plus(parsed.fragment) if parsed.fragment else 'Trojan Node',
            'type': 'trojan',
            'server': parsed.hostname,
            'port': parsed.port,
            'password': parsed.username,
            'network': 'tcp',
            'skip-cert-verify': True
        }

        query = parse_qs(parsed.query)
        if 'security' in query and query['security'][0] == 'tls':
            clash_node['tls'] = True
            if 'sni' in query:
                clash_node['sni'] = query['sni'][0]
            else:
                clash_node['sni'] = parsed.hostname

        return clash_node
    except Exception:
        return None

def parse_ss(node_link):
    try:
        parsed = urlparse(node_link)
        
        # 处理 Base64 编码的 SS
        if parsed.hostname is None:
            decoded_link = base64.b64decode(node_link.replace('ss://', '') + '=' * (-len(node_link) % 4)).decode('utf-8')
            return parse_ss(f'ss://{decoded_link}')

        # 严格校验必须参数
        auth_part = unquote(parsed.username)
        if ':' not in auth_part: return None
        cipher, password = auth_part.split(':', 1)
        if not all([parsed.hostname, parsed.port, cipher, password]):
            return None

        clash_node = {
            'name': unquote_plus(parsed.fragment) if parsed.fragment else 'SS Node',
            'type': 'ss',
            'server': parsed.hostname,
            'port': parsed.port,
            'cipher': cipher,
            'password': password
        }

        return clash_node
    except Exception:
        return None

def parse_vless(node_link):
    try:
        parsed = urlparse(node_link)
        if not all([parsed.hostname, parsed.port, parsed.username]):
            return None
        
        clash_node = {
            'name': unquote_plus(parsed.fragment) if parsed.fragment else 'Vless Node',
            'type': 'vless',
            'server': parsed.hostname,
            'port': parsed.port,
            'uuid': parsed.username,
            'network': 'tcp'
        }
        
        query = parse_qs(parsed.query)
        if 'type' in query:
            clash_node['network'] = query['type'][0]
        
        # TLS 参数
        if query.get('security') == ['tls']:
            clash_node['tls'] = True
            clash_node['skip-cert-verify'] = True
            if 'sni' in query:
                clash_node['sni'] = query['sni'][0]

        # Vmess参数
        if 'flow' in query:
            clash_node['flow'] = query['flow'][0]
        
        return clash_node
    except Exception:
        return None

def parse_hysteria2(node_link):
    try:
        parsed = urlparse(node_link)
        if not all([parsed.hostname, parsed.port, parsed.password]):
            return None

        clash_node = {
            'name': unquote_plus(parsed.fragment) if parsed.fragment else 'Hysteria2 Node',
            'type': 'hysteria2',
            'server': parsed.hostname,
            'port': parsed.port,
            'password': parsed.password,
            'network': 'quic',
        }
        
        query = parse_qs(parsed.query)
        if 'obfs' in query and query['obfs'][0] == 'salamander':
            clash_node['obfs'] = 'salamander'
            if 'obfs-password' in query:
                clash_node['obfs-password'] = query['obfs-password'][0]
        
        if 'tls' in query and query['tls'][0] == '1':
            clash_node['tls'] = True
            if 'sni' in query:
                clash_node['sni'] = query['sni'][0]
                clash_node['skip-cert-verify'] = True
            
        return clash_node
    except Exception:
        return None

def parse_ssr(node_link):
    try:
        base64_part = node_link.replace('ssr://', '')
        decoded_part = base64.b64decode(base64_part + '=' * (-len(base64_part) % 4)).decode('utf-8')
        
        main_parts, params_str = decoded_part.split('/?', 1)
        
        server, port, protocol, method, obfs, password = main_parts.split(':')
        
        query = parse_qs(params_str)
        
        clash_node = {
            'name': unquote_plus(query.get('remarks', ['SSR Node'])[0]),
            'type': 'ssr',
            'server': server,
            'port': int(port),
            'password': base64.b64decode(password).decode('utf-8'),
            'cipher': method,
            'protocol': protocol,
            'obfs': obfs,
            'protocolparam': base64.b64decode(query.get('protoparam', [''])[0]).decode('utf-8'),
            'obfsparam': base64.b64decode(query.get('obfsparam', [''])[0]).decode('utf-8'),
            'group': base64.b64decode(query.get('group', [''])[0]).decode('utf-8')
        }
        
        return clash_node
    except Exception:
        return None

def convert_to_clash_node(node):
    """
    将不同格式的节点统一转换为 Clash 兼容格式
    - 严格校验协议，排除不符合规范的节点
    """
    # 已经是 Clash 格式的节点
    if isinstance(node, dict) and 'type' in node:
        return node
    
    # 尝试解析各种协议
    if isinstance(node, str):
        if node.startswith('vmess://'):
            return parse_vmess(node)
        elif node.startswith('trojan://'):
            return parse_trojan(node)
        elif node.startswith('ss://'):
            return parse_ss(node)
        elif node.startswith('vless://'):
            return parse_vless(node)
        elif node.startswith('hysteria2://'):
            return parse_hysteria2(node)
        elif node.startswith('ssr://'):
            return parse_ssr(node)
    
    return None

def parse_and_fetch(url, depth=0):
    """
    通用解析和获取节点内容
    - 尝试直接下载
    - 尝试解析 HTML 页面，寻找链接并递归
    - 尝试解析不同格式的内容
    """
    if url in visited_urls or depth > MAX_DEPTH:
        return []
    
    visited_urls.add(url)
    all_nodes = []

    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '').lower()
            content = response.text

            # 尝试 Base64 解码
            # 新增: 确保内容是 ASCII 编码，避免 Unicode 错误
            try:
                decoded_content = base64.b64decode(content.encode('utf-8') + b'=' * (-len(content) % 4)).decode('utf-8')
                content = decoded_content
            except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                pass
                
            # 尝试解析 YAML
            try:
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    nodes = data.get('proxies', [])
                    for node in nodes:
                        clash_node = convert_to_clash_node(node)
                        if clash_node: all_nodes.append(clash_node)
                    if all_nodes: return all_nodes
            except yaml.YAMLError:
                pass

            # 尝试解析 JSON
            try:
                data = json.loads(content)
                if isinstance(data, dict) and 'proxies' in data:
                    nodes = data.get('proxies', [])
                    for node in nodes:
                        clash_node = convert_to_clash_node(node)
                        if clash_node: all_nodes.append(clash_node)
                    if all_nodes: return all_nodes
            except json.JSONDecodeError:
                pass
            
            # 尝试从内容中查找各种协议链接
            regexes = [
                r'(vmess|trojan|ss|vless|hysteria2|ssr)://[a-zA-Z0-9+\/=?@.:\-%_&;]+'
            ]
            for pattern in regexes:
                matches = re.findall(pattern, content)
                for match in matches:
                    clash_node = convert_to_clash_node(match)
                    if clash_node: all_nodes.append(clash_node)
            if all_nodes: return all_nodes

            # 如果内容是 HTML 页面，则继续爬取链接
            if 'text/html' in content_type:
                soup = BeautifulSoup(content, 'html.parser')
                links_to_visit = set()
                
                # 从 <a> 标签中查找链接
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href and not href.startswith(('#', 'mailto:', 'tel:')):
                        full_url = requests.compat.urljoin(url, href)
                        links_to_visit.add(full_url)
                
                # 递归访问找到的链接
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = [executor.submit(parse_and_fetch, link, depth + 1) for link in links_to_visit if link not in visited_urls]
                    for future in as_completed(futures):
                        all_nodes.extend(future.result())

    except requests.exceptions.RequestException:
        pass
        
    return all_nodes

def process_links(links):
    """
    第二阶段：处理可用的链接
    - 将URL列表分块处理以提高稳定性
    """
    all_nodes = []
    node_counts = []
    
    urls_to_process = []
    for link in links:
        urls_to_process.append(f"http://{link}/")
        urls_to_process.append(f"https://{link}/")
    
    urls_to_process = list(set(urls_to_process))
    
    # 分块处理URL列表
    url_chunks = [urls_to_process[i:i + CHUNK_SIZE] for i in range(0, len(urls_to_process), CHUNK_SIZE)]

    total_urls = len(urls_to_process)
    processed_count = 0
    
    with tqdm(total=total_urls, desc="获取节点内容") as pbar:
        for chunk in url_chunks:
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_url = {executor.submit(parse_and_fetch, url): url for url in chunk}
                for future in as_completed(future_to_url):
                    nodes = future.result()
                    if nodes:
                        node_counts.append({'url': future_to_url[future], 'count': len(nodes)})
                    all_nodes.extend(nodes)
                    pbar.update(1)

    return all_nodes, node_counts

def main():
    print("脚本开始运行...")
    
    try:
        with open(LINKS_FILE, 'r') as f:
            links_to_test = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"错误: 无法找到链接文件 {LINKS_FILE}。请确保文件已上传到仓库根目录。")
        exit(1)

    print("第一阶段：预测试所有链接...")
    working_links = pre_test_links(links_to_test)
    print(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    
    print("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = process_links(working_links)
    
    # 统计和去重
    unique_nodes = []
    names_count = {}
    for node in all_nodes:
        name = node.get('name')
        if name:
            if name in names_count:
                names_count[name] += 1
                node['name'] = f"{name}_{names_count[name]:02d}"
            else:
                names_count[name] = 1
        
        if node not in unique_nodes:
            unique_nodes.append(node)
    
    # 保存结果
    print("所有链接处理完毕，开始保存文件。")
    final_data = {'proxies': unique_nodes}
    with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(final_data, f, allow_unicode=True)
    print(f"节点已保存到 {OUTPUT_YAML}")
    
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Node Count'])
        for item in node_counts:
            writer.writerow([item['url'], item['count']])
    print(f"统计信息已保存到 {OUTPUT_CSV}")
    print("脚本运行结束。")

if __name__ == "__main__":
    main()
