import os
import requests
import yaml
import csv
import re
import random
import json
import base64
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import reduce
from ip_geolocation import GeoLite2Country
from tqdm.asyncio import tqdm
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
from aiohttp import TCPConnector
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# 定义文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINKS_FILE = os.path.join(BASE_DIR, 'link.txt')
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')
CACHE_FILE = os.path.join(BASE_DIR, 'cache.json')

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
MAX_DEPTH = 1  # 降低爬取深度以提高效率
CHUNK_SIZE = 100 # 增加批次大小

# 初始化 IP 地理位置解析器
try:
    geolocator = GeoLite2Country(GEOLITE_DB)
    print("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    print(f"错误: 无法找到地理位置数据库文件 {GEOLITE_DB}。请确保文件已上传到仓库根目录。")
    exit(1)

def get_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

def get_node_key(node):
    """根据关键字段生成节点唯一标识符"""
    return (node.get('server'), node.get('port'), node.get('uuid'), node.get('password'))

def load_cache():
    """从缓存文件加载已处理的URL和节点"""
    try:
        with open(CACHE_FILE, 'r') as f:
            data = json.load(f)
            return set(data.get('visited_urls', [])), data.get('nodes', [])
    except (FileNotFoundError, json.JSONDecodeError):
        return set(), []

def save_cache(visited_urls, nodes):
    """将已处理的URL和节点保存到缓存文件"""
    with open(CACHE_FILE, 'w') as f:
        json.dump({'visited_urls': list(visited_urls), 'nodes': nodes}, f, indent=4)

def parse_vmess(node_link):
    try:
        encoded_json = node_link.replace('vmess://', '')
        decoded_json = base64.b64decode(encoded_json + '=' * (-len(encoded_json) % 4)).decode('utf-8')
        node_data = json.loads(decoded_json)

        required_params = ['add', 'port', 'id', 'aid']
        if not all(p in node_data for p in required_params):
            return None

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
        
        if parsed.hostname is None:
            decoded_link = base64.b64decode(node_link.replace('ss://', '') + '=' * (-len(node_link) % 4)).decode('utf-8')
            return parse_ss(f'ss://{decoded_link}')

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
        
        if query.get('security') == ['tls']:
            clash_node['tls'] = True
            clash_node['skip-cert-verify'] = True
            if 'sni' in query:
                clash_node['sni'] = query['sni'][0]

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
    if isinstance(node, dict) and 'type' in node:
        return node
    
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

async def test_connection_async(link, session):
    """异步预测试一个链接的连通性，优先尝试HTTPS"""
    link = link.replace('http://', '').replace('https://', '')
    headers = get_headers()
    try:
        async with session.head(f"https://{link}", headers=headers, timeout=3) as resp:
            return link
    except Exception:
        try:
            async with session.head(f"http://{link}", headers=headers, timeout=3) as resp:
                return link
        except Exception:
            return None

async def pre_test_links_async(links):
    """并发预测试所有链接，返回可用的链接列表"""
    working_links = []
    # 使用 aiohttp.TCPConnector 提高连接效率
    conn = TCPConnector(limit=100, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [test_connection_async(link, session) for link in links]
        for future in tqdm(asyncio.as_completed(tasks), total=len(links), desc="预测试链接"):
            result = await future
            if result:
                working_links.append(result)
    return working_links

async def parse_and_fetch_async(url, session, depth=0):
    """异步通用解析和获取节点内容"""
    if url in visited_urls or depth > MAX_DEPTH:
        return []
    
    visited_urls.add(url)
    all_nodes = []
    headers = get_headers()
    start_time = time.time()

    try:
        async with session.get(url, headers=headers, timeout=5, allow_redirects=True) as response:
            if response.status != 200:
                return []
            
            content_type = response.headers.get('content-type', '').lower()
            content = await response.text()

            # 优先尝试 Base64 解码，因为很多节点订阅链接是这种格式
            try:
                decoded_content = base64.b64decode(content.encode('utf-8') + b'=' * (-len(content) % 4)).decode('utf-8')
                content = decoded_content
            except Exception:
                pass
            
            # 根据内容类型快速判断并解析
            if 'application/json' in content_type:
                try:
                    data = json.loads(content)
                    if isinstance(data, dict) and 'proxies' in data:
                        nodes = data.get('proxies', [])
                        for node in nodes:
                            clash_node = convert_to_clash_node(node)
                            if clash_node: all_nodes.append(clash_node)
                        return all_nodes
                except json.JSONDecodeError:
                    pass
            elif 'yaml' in content_type:
                try:
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        nodes = data.get('proxies', [])
                        for node in nodes:
                            clash_node = convert_to_clash_node(node)
                            if clash_node: all_nodes.append(clash_node)
                        return all_nodes
                except yaml.YAMLError:
                    pass
            elif 'text/html' in content_type:
                soup = BeautifulSoup(content, 'html.parser')
                links_to_visit = set()
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href and not href.startswith(('#', 'mailto:', 'tel:')):
                        full_url = requests.compat.urljoin(url, href)
                        # 限制每个页面最多爬取 50 个链接
                        if len(links_to_visit) < 50:
                            links_to_visit.add(full_url)
                        else:
                            break
                
                tasks = [parse_and_fetch_async(link, session, depth + 1) for link in links_to_visit if link not in visited_urls]
                results = await asyncio.gather(*tasks)
                for res in results:
                    all_nodes.extend(res)
            else:
                # Fallback to regex matching for plain text content
                regexes = [
                    r'(vmess|trojan|ss|vless|hysteria2|ssr)://[a-zA-Z0-9+\/=?@.:\-%_&;]+'
                ]
                for pattern in regexes:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        clash_node = convert_to_clash_node(match)
                        if clash_node: all_nodes.append(clash_node)

    except aiohttp.client_exceptions.ClientError:
        pass
    
    elapsed = time.time() - start_time
    if elapsed > 5:
        print(f"慢请求警告: {url} 耗时 {elapsed:.2f} 秒")
        
    return all_nodes

async def process_links_async(links):
    """第二阶段：异步处理可用的链接"""
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
    
    async with aiohttp.ClientSession(connector=TCPConnector(limit=100, ttl_dns_cache=300)) as session:
        for chunk in url_chunks:
            tasks = [parse_and_fetch_async(url, session) for url in chunk]
            for future in tqdm(asyncio.as_completed(tasks), total=len(chunk), desc="获取节点内容"):
                nodes = await future
                if nodes:
                    node_counts.append({'url': '...', 'count': len(nodes)})
                all_nodes.extend(nodes)

    return all_nodes, node_counts

def main():
    print("脚本开始运行...")
    
    # 加载缓存
    global visited_urls
    cache_visited_urls, cache_nodes = load_cache()
    visited_urls.update(cache_visited_urls)
    all_nodes = cache_nodes

    try:
        with open(LINKS_FILE, 'r') as f:
            links_to_test = list(set(line.strip() for line in f if line.strip())) # 提前去重
    except FileNotFoundError:
        print(f"错误: 无法找到链接文件 {LINKS_FILE}。请确保文件已上传到仓库根目录。")
        exit(1)

    print("第一阶段：预测试所有链接...")
    working_links = asyncio.run(pre_test_links_async(links_to_test))
    print(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    
    print("第二阶段：开始处理可用链接...")
    new_nodes, node_counts = asyncio.run(process_links_async(working_links))
    all_nodes.extend(new_nodes)

    # 统计和去重 (优化后的逻辑)
    unique_nodes = []
    seen_keys = set()
    names_count = {}
    for node in all_nodes:
        name = node.get('name')
        if name:
            if name in names_count:
                names_count[name] += 1
                node['name'] = f"{name}_{names_count[name]:02d}"
            else:
                names_count[name] = 1
        
        key = get_node_key(node)
        if key and key not in seen_keys:
            seen_keys.add(key)
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

    # 保存缓存
    save_cache(visited_urls, unique_nodes)
    print("缓存已更新。")
    print("脚本运行结束。")

if __name__ == "__main__":
    main()
