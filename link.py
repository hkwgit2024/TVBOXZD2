import os
import asyncio
import aiohttp
import yaml
import csv
import re
import random
import json
import base64
from ip_geolocation import GeoLite2Country
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
import time

# 文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINKS_FILE = os.path.join(BASE_DIR, 'link.txt')
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')
CACHE_FILE = os.path.join(BASE_DIR, 'cache.json')

# User-Agent
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
]

# 全局变量
visited_urls = set()
MAX_DEPTH = 0
CHUNK_SIZE = 50
SLOW_REQUEST_THRESHOLD = 5
BLACKLIST_DOMAINS = {
    'no-ip.com', 'oracle.com', 'canonical.com', 'openvpn.net', 'aagag.com',
    'docs.tagspaces.org', 'build.openvpn.net', 'documentation.ubuntu.com',
    'fedoraproject.org', 'aws.amazon.com', 'stackoverflow.co', 'discussion.fedoraproject.org',
    'cryptolaw.org', 'github.com', 'reddit.com', 'twitter.com', 'facebook.com', 'google.com',
    'microsoft.com'
}

# 初始化 GeoLite2
try:
    geolocator = GeoLite2Country(GEOLITE_DB)
    print("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    print(f"错误: 无法找到地理位置数据库文件 {GEOLITE_DB}。")
    exit(1)

def get_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

async def test_connection(link, session):
    link = link.replace('http://', '').replace('https://', '')
    if any(domain in link for domain in BLACKLIST_DOMAINS):
        return None
    try:
        async with session.head(f"https://{link}", headers=get_headers(), timeout=2) as resp:
            if resp.status == 200:
                return link
    except:
        try:
            async with session.head(f"http://{link}", headers=get_headers(), timeout=2) as resp:
                if resp.status == 200:
                    return link
        except:
            pass
    return None

async def pre_test_links(links):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=20)) as session:
        tasks = [test_connection(link, session) for link in links]
        working_links = []
        for future in tqdm(asyncio.as_completed(tasks), total=len(links), desc="预测试链接"):
            result = await future
            if result:
                working_links.append(result)
        return working_links

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
        if clash_node['tls']:
            clash_node['servername'] = node_data.get('sni', node_data['add'])
        return clash_node
    except Exception as e:
        print(f"解析 vmess 失败: {e}")
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
            clash_node['sni'] = query.get('sni', [parsed.hostname])[0]
        return clash_node
    except Exception as e:
        print(f"解析 trojan 失败: {e}")
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
    except Exception as e:
        print(f"解析 ss 失败: {e}")
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
    except Exception as e:
        print(f"解析 vless 失败: {e}")
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
    except Exception as e:
        print(f"解析 hysteria2 失败: {e}")
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
    except Exception as e:
        print(f"解析 ssr 失败: {e}")
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

def load_cache():
    try:
        with open(CACHE_FILE, 'r') as f:
            cache = json.load(f)
            visited_urls.update(cache.get('visited_urls', []))
            print(f"加载缓存: {len(cache.get('visited_urls', []))} 个 URL, {len(cache.get('nodes', []))} 个节点")
            return cache.get('nodes', [])
    except FileNotFoundError:
        print("缓存文件不存在，创建新缓存")
        return []

def save_cache(nodes):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump({'visited_urls': list(visited_urls), 'nodes': nodes}, f)
        print(f"保存缓存: {len(visited_urls)} 个 URL, {len(nodes)} 个节点")
    except Exception as e:
        print(f"保存缓存失败: {e}")

async def parse_and_fetch(url, session, depth=0):
    if url in visited_urls or depth > MAX_DEPTH:
        return []
    parsed_url = urlparse(url)
    if any(domain in parsed_url.netloc for domain in BLACKLIST_DOMAINS):
        print(f"跳过黑名单 URL: {url}")
        return []
    visited_urls.add(url)
    all_nodes = []
    start_time = time.time()
    try:
        async with session.get(url, headers=get_headers(), timeout=2) as response:
            if response.status != 200:
                print(f"请求失败: {url}, 状态码: {response.status}")
                return []
            content_type = response.headers.get('content-type', '').lower()
            content = await response.text()
            print(f"请求 {url}, 内容类型: {content_type}, 长度: {len(content)}")
            if 'text/plain' in content_type:
                try:
                    decoded_content = base64.b64decode(content.encode('utf-8') + b'=' * (-len(content) % 4)).decode('utf-8')
                    content = decoded_content
                    print(f"Base64 解码成功: {url}, 长度: {len(content)}")
                except:
                    print(f"Base64 解码失败: {url}")
            if 'application/json' in content_type:
                try:
                    data = json.loads(content)
                    if isinstance(data, dict) and 'proxies' in data:
                        nodes = data.get('proxies', [])
                        for node in nodes:
                            clash_node = convert_to_clash_node(node)
                            if clash_node:
                                all_nodes.append(clash_node)
                        print(f"JSON 解析: {url}, 提取 {len(nodes)} 个节点")
                        return all_nodes
                except json.JSONDecodeError as e:
                    print(f"JSON 解析失败: {url}, 错误: {e}")
            elif 'yaml' in content_type:
                try:
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        nodes = data.get('proxies', [])
                        for node in nodes:
                            clash_node = convert_to_clash_node(node)
                            if clash_node:
                                all_nodes.append(clash_node)
                        print(f"YAML 解析: {url}, 提取 {len(nodes)} 个节点")
                        return all_nodes
                    elif isinstance(data, list):
                        for node in data:
                            clash_node = convert_to_clash_node(node)
                            if clash_node:
                                all_nodes.append(clash_node)
                        print(f"YAML 列表解析: {url}, 提取 {len(data)} 个节点")
                        return all_nodes
                except yaml.YAMLError as e:
                    print(f"YAML 解析失败: {url}, 错误: {e}")
            regexes = [r'(vmess|trojan|ss|vless|hysteria2|ssr)://[a-zA-Z0-9+\/=?@.:\-%_&;]+']
            for pattern in regexes:
                matches = re.findall(pattern, content)
                for match in matches:
                    clash_node = convert_to_clash_node(match)
                    if clash_node:
                        all_nodes.append(clash_node)
                if matches:
                    print(f"正则匹配: {url}, 提取 {len(matches)} 个节点")
            return all_nodes
    except Exception as e:
        print(f"请求错误: {url}, 错误: {e}")
        return []
    finally:
        elapsed = time.time() - start_time
        if elapsed > SLOW_REQUEST_THRESHOLD:
            print(f"慢请求警告: {url} 耗时 {elapsed:.2f} 秒")
    return all_nodes

async def process_links(links):
    all_nodes = load_cache()
    node_counts = []
    urls_to_process = []
    for link in links:
        if not any(domain in link for domain in BLACKLIST_DOMAINS):
            urls_to_process.append(f"http://{link}/")
            urls_to_process.append(f"https://{link}/")
    urls_to_process = list(set(urls_to_process))
    url_chunks = [urls_to_process[i:i + CHUNK_SIZE] for i in range(0, len(urls_to_process), CHUNK_SIZE)]
    total_urls = len(urls_to_process)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=20)) as session:
        with tqdm(total=total_urls, desc="获取节点内容") as pbar:
            for chunk in url_chunks:
                tasks = [parse_and_fetch(url, session) for url in chunk]
                for i, future in enumerate(asyncio.as_completed(tasks)):
                    nodes = await future
                    if nodes:
                        node_counts.append({'url': chunk[i], 'count': len(nodes)})
                    all_nodes.extend(nodes)
                    pbar.update(1)
                save_cache(all_nodes)  # 每块保存一次
    return all_nodes, node_counts

def get_node_key(node):
    return (node.get('server'), node.get('port'), node.get('uuid'), node.get('password'))

def main():
    print("脚本开始运行...")
    try:
        with open(LINKS_FILE, 'r') as f:
            links_to_test = list(set(line.strip() for line in f if line.strip()))
    except FileNotFoundError:
        print(f"错误: 无法找到链接文件 {LINKS_FILE}。")
        exit(1)
    print("第一阶段：预测试所有链接...")
    working_links = asyncio.run(pre_test_links(links_to_test))
    print(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    print("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = asyncio.run(process_links(working_links))
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
        if key not in seen_keys:
            seen_keys.add(key)
            unique_nodes.append(node)
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
    print(f"最终提取 {len(unique_nodes)} 个唯一节点")
    print("脚本运行结束。")

if __name__ == "__main__":
    main()
