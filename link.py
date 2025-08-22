import requests
import yaml
import base64
import io
import os
import csv
import json
import re
import random
import concurrent.futures
import ipaddress
from urllib.parse import urlparse, unquote, urljoin
from collections import OrderedDict
from html.parser import HTMLParser
from tqdm import tqdm
from ip_geolocation import GeoLite2Country
import geoip2.errors

# 多样化的User-Agent列表，涵盖多种设备和浏览器
USER_AGENTS = [
    # Windows 10 Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    # Windows 10 Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    # macOS Big Sur Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    # iPad Pro Safari
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.77 Mobile/15E148 Safari/604.1',
    # iPhone Chrome
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.77 Mobile/15E148 Safari/604.1',
    # Android Chrome
    'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Mobile Safari/537.36',
    # Windows 10 Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
    # Windows 7 Firefox
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0',
    # macOS Monterey Firefox
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.0; rv:95.0) Gecko/20100101 Firefox/95.0',
    # Linux Chrome
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    # Android Firefox
    'Mozilla/5.0 (Android 11; Mobile; rv:95.0) Gecko/95.0 Firefox/95.0',
    # iPhone Safari
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1',
    # iPad Firefox
    'Mozilla/5.0 (iPad; CPU OS 15_1 like Mac OS X; rv:95.0) Gecko/95.0 Firefox/95.0',
    # Googlebot (搜索引擎爬虫，有时可用于绕过某些检测)
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    # Bingbot
    'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    # Baidu Spider
    'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
    # Old IE (仅用于极少数老旧网站)
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)',
    # Opera
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.2

# 全局变量，用于存储和去重所有有效节点
seen_nodes_set = set()
unique_nodes_list = []

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def get_session():
    s = requests.Session()
    s.headers.update({'User-Agent': get_random_user_agent(), 'Accept-Encoding': 'gzip, deflate, br'})
    return s

def save_successful_path(path):
    """将成功的文件路径保存到本地文件，以便下次使用"""
    filename = 'successful_paths.txt'
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(path + '\n')
    except IOError as e:
        print(f"无法保存文件路径 {filename}: {e}")

def load_successful_paths():
    """从本地文件加载之前成功的路径"""
    filename = 'successful_paths.txt'
    paths = set()
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                paths.add(line.strip())
    return list(paths)

# 全局变量，缓存已经加载的成功路径
SUCCESSFUL_PATHS = load_successful_paths()
COMMON_PATHS = ['/sub', '/subscribe', '/clash.yaml', '/config/clash/sub', '/api/v1/client/subscribe']
ALL_PATHS_TO_TRY = list(set(SUCCESSFUL_PATHS + COMMON_PATHS))

def parse_yaml_content(content):
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
            return data['proxies']
    except yaml.YAMLError:
        pass
    return []

def parse_base64_content(content):
    try:
        decoded_content = base64.b64decode(content).decode('utf-8')
        lines = decoded_content.strip().split('\n')
        nodes = []
        for line in lines:
            if line.strip():
                node = parse_single_node_from_link(line.strip())
                if node:
                    nodes.append(node)
        return nodes
    except Exception:
        pass
    return []

def is_ip_address(string):
    """检查字符串是否为有效的IP地址"""
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

def parse_single_node_from_link(link):
    if link.startswith("vmess://"):
        return parse_vmess_link(link)
    elif link.startswith("vless://"):
        return parse_vless_link(link)
    elif link.startswith("trojan://"):
        return parse_trojan_link(link)
    elif link.startswith("ss://"):
        return parse_shadowsocks_link(link)
    elif link.startswith("ssr://"):
        return parse_ssr_link(link)
    return None

def parse_vmess_link(link):
    try:
        encoded_data = link[8:]
        decoded_data = base64.b64decode(encoded_data + "=" * (-len(encoded_data) % 4)).decode('utf-8')
        node = json.loads(decoded_data)
        # Convert to Clash format
        return {
            'name': node.get('ps', 'vmess_node'),
            'type': 'vmess',
            'server': node.get('add'),
            'port': int(node.get('port')),
            'uuid': node.get('id'),
            'alterId': int(node.get('aid', 0)),
            'cipher': 'auto',
            'udp': True,
            'network': node.get('net'),
            'ws-path': node.get('path', '/'),
            'ws-headers': {'Host': node.get('host', '')},
            'tls': node.get('tls', '') == 'tls'
        }
    except Exception:
        return None

def parse_vless_link(link):
    # This is a simplified parser, you might need to handle more parameters
    try:
        match = re.match(r"vless://([^@]+)@([^:]+):(\d+)\??(.*)", link)
        if not match:
            return None
        uuid, server, port, params_str = match.groups()
        params = dict(re.findall(r"([^=]+)=([^&]+)", params_str))
        node = {
            'name': unquote(params.get('flow', f"vless-{server}")),
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'udp': True,
        }
        if 'security' in params and params['security'] == 'tls':
            node['tls'] = True
            node['sni'] = params.get('sni', server)
        if 'encryption' in params:
            node['cipher'] = params['encryption']
        if 'type' in params:
            node['network'] = params['type']
            if params['type'] == 'ws':
                node['ws-path'] = unquote(params.get('path', '/'))
                node['ws-headers'] = {'Host': unquote(params.get('host', ''))}
        return node
    except Exception:
        return None

def parse_trojan_link(link):
    try:
        match = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(.*)", link)
        if not match:
            return None
        password, server, port, params_str = match.groups()
        params = dict(re.findall(r"([^=]+)=([^&]+)", params_str.lstrip('?&')))
        node = {
            'name': unquote(params.get('sni', f"trojan-{server}")),
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': unquote(password),
            'udp': True
        }
        if 'security' in params:
            node['tls'] = True
            node['sni'] = unquote(params.get('security', server))
        if 'alpn' in params:
            node['alpn'] = unquote(params['alpn']).split(',')
        return node
    except Exception:
        return None

def parse_shadowsocks_link(link):
    try:
        link_parts = link.split('#', 1)
        name = unquote(link_parts[1]) if len(link_parts) > 1 else 'ss_node'
        link_no_name = link_parts[0][5:]
        if '@' in link_no_name:
            enc_pass, server_port = link_no_name.split('@', 1)
            enc_pass = unquote(enc_pass)
            server, port = server_port.split(':')
            parts = enc_pass.split(':', 1)
            cipher = parts[0]
            password = parts[1]
        else:
            decoded_link = base64.b64decode(link_no_name.replace('-', '+').replace('_', '/') + "=" * (-len(link_no_name) % 4)).decode('utf-8')
            enc_pass, server_port = decoded_link.split('@', 1)
            cipher, password = enc_pass.split(':')
            server, port = server_port.split(':')

        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': cipher,
            'password': password,
            'udp': True
        }
    except Exception:
        return None

def parse_ssr_link(link):
    try:
        encoded_data = link[6:]
        decoded_data = base64.b64decode(encoded_data + "=" * (-len(encoded_data) % 4)).decode('utf-8')
        parts = decoded_data.split(':')
        server = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password = base64.b64decode(parts[5].replace('-', '+').replace('_', '/') + "=" * (-len(parts[5]) % 4)).decode('utf-8')
        params_str = parts[6]
        params = dict(re.findall(r"([^=]+)=([^&]+)", params_str))
        
        return {
            'name': unquote(base64.b64decode(params.get('remarks', b'')).decode('utf-8')),
            'type': 'ssr',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'protocol': protocol,
            'obfs': obfs,
            'protocol-param': unquote(base64.b64decode(params.get('protoparam', b'')).decode('utf-8')),
            'obfs-param': unquote(base64.b64decode(params.get('obfsparam', b'')).decode('utf-8'))
        }
    except Exception:
        return None
        
def validate_node(node):
    """根据协议类型严格校验节点是否包含必需参数"""
    protocol = node.get('type')
    required_params = {
        'vmess': ['server', 'port', 'uuid', 'alterId', 'cipher', 'network'],
        'vless': ['server', 'port', 'uuid', 'network'],
        'trojan': ['server', 'port', 'password'],
        'ss': ['server', 'port', 'cipher', 'password'],
        'ssr': ['server', 'port', 'password', 'protocol', 'obfs', 'cipher']
    }
    
    if protocol not in required_params:
        return False
        
    for param in required_params[protocol]:
        if param not in node:
            return False
            
    # 特定协议的额外校验
    if protocol == 'vmess' and node.get('network') == 'ws':
        if 'ws-path' not in node or 'ws-headers' not in node:
            return False
            
    if protocol == 'vless' and node.get('network') == 'ws':
        if 'ws-path' not in node or 'ws-headers' not in node:
            return False
    
    return True

def fetch_content(url):
    try:
        session = get_session()
        response = session.get(url, timeout=10, allow_redirects=True)
        response.raise_for_status()
        
        # 检查是否是已知的订阅类型
        content_type = response.headers.get('Content-Type', '')
        if 'yaml' in content_type or 'octet-stream' in content_type:
            return response.text, 'yaml'
        if 'plain' in content_type and 'clash' not in content_type:
            return response.text, 'base64'
        if response.text.startswith('ss://') or response.text.startswith('vmess://'):
            return response.text, 'base64'
        if 'proxies' in response.text or 'proxy-groups' in response.text:
            return response.text, 'yaml'
            
        return response.text, 'html'

    except requests.exceptions.RequestException:
        return None, None

def get_nodes_from_url(link, geocoder):
    nodes = []
    effective_link = None
    
    # Check if the link already has a scheme
    if link.startswith('http://') or link.startswith('https://'):
        url_to_fetch = link
        content, content_type = fetch_content(url_to_fetch)
        if content:
            effective_link = url_to_fetch
        else:
            content, content_type = None, None
    else:
        # 1. Try with https first
        url_to_fetch = f'https://{link}'
        content, content_type = fetch_content(url_to_fetch)
        
        # 2. If https fails, try with http
        if not content:
            url_to_fetch = f'http://{link}'
            content, content_type = fetch_content(url_to_fetch)

        if content:
            effective_link = url_to_fetch

    # 3. If direct fetch fails, try common paths
    if not content and effective_link:
        parsed_url = urlparse(effective_link)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        for path in ALL_PATHS_TO_TRY:
            full_url = urljoin(base_url, path)
            content, content_type = fetch_content(full_url)
            if content:
                effective_link = full_url
                save_successful_path(path) # 保存成功的路径
                break
    
    # 4. If all direct fetches fail, try to scrape HTML
    if not content and effective_link:
        content, content_type = fetch_content(effective_link)
        if content_type == 'html':
            nodes.extend(extract_nodes_from_html(content, effective_link))
    
    # Process fetched content
    if content:
        if content_type == 'yaml':
            nodes.extend(parse_yaml_content(content))
        elif content_type == 'base64':
            nodes.extend(parse_base64_content(content))
        
    # 新增的地理位置查询逻辑
    if nodes and geocoder:
        for node in nodes:
            server = node.get('server')
            if server and is_ip_address(server):
                try:
                    country_code, country_name = geocoder.get_location(server)
                    node['country'] = country_name
                except Exception as e:
                    print(f"查询IP {server} 时发生错误: {e}")

    return nodes, effective_link

class LinkExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.links = []
        self.base_url = base_url

    def handle_starttag(self, tag, attrs):
        if tag in ['a', 'link']:
            for attr, value in attrs:
                if attr in ['href', 'data-clipboard-text'] and value:
                    full_link = urljoin(self.base_url, value)
                    self.links.append(full_link)

    def handle_data(self, data):
        data = data.strip()
        if not data:
            return
        # Simple regex to find base64-like strings or direct links
        # This is a broad catch, so it might grab irrelevant data, but it's a starting point
        # base64 pattern: 24+ alphanumeric chars, ends with '==', '=', or no padding
        base64_pattern = re.compile(r'[a-zA-Z0-9+/]{24,}={0,2}$')
        if base64_pattern.match(data) or data.startswith('vmess://'):
            self.links.append(data)


def extract_nodes_from_html(html_content, base_url):
    parser = LinkExtractor(base_url)
    parser.feed(html_content)
    
    all_nodes = []
    
    for link in parser.links:
        parsed_link = urlparse(link)
        
        if parsed_link.scheme in ['http', 'https']:
            # For links that look like a subscription
            if any(ext in parsed_link.path for ext in ['clash', 'yaml', 'sub', 'subscribe', 'v2ray', 'trojan']):
                try:
                    response = requests.get(link, timeout=5)
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'yaml' in content_type or 'octet-stream' in content_type:
                            nodes = parse_yaml_content(response.text)
                            if nodes: all_nodes.extend(nodes)
                        elif 'plain' in content_type:
                            nodes = parse_base64_content(response.text)
                            if nodes: all_nodes.extend(nodes)
                except requests.exceptions.RequestException:
                    pass
        else:
            node = parse_single_node_from_link(link)
            if node:
                all_nodes.append(node)
                
    return all_nodes

def get_links_from_local_file(filename='link.txt'):
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    return []

def save_to_yaml(data, filename='all_nodes.yaml'):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)
        print(f"成功将所有去重节点保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")

def save_to_csv(data, filename='link.csv'):
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['link', 'node_count']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"成功将节点数量汇总保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")

if __name__ == "__main__":
    geocoder = None
    try:
        # 尝试连接本地 GeoLite2 数据库
        with GeoLite2Country('GeoLite2-Country.mmdb') as geo_db:
            geocoder = geo_db
            print("GeoLite2-Country.mmdb 数据库加载成功，将启用IP地理位置查询功能。")
    except FileNotFoundError:
        print("未找到 GeoLite2-Country.mmdb 数据库文件，将跳过IP地理位置查询。")
    except geoip2.errors.AddressNotFoundError:
        print("GeoLite2-Country.mmdb 文件可能已损坏或格式不正确，将跳过IP地理位置查询。")
    except Exception as e:
        print(f"加载 GeoLite2-Country.mmdb 时发生未知错误: {e}")
        print("将跳过IP地理位置查询。")

    links = get_links_from_local_file()
    all_nodes = []
    nodes_summary = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(get_nodes_from_url, link, geocoder): link for link in links}
        
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(links), desc="处理链接"):
            link = futures[future]
            try:
                nodes, effective_link = future.result()
                if nodes:
                    for node in nodes:
                        if validate_node(node):
                            node_key = str(OrderedDict(sorted(node.items())))
                            if node_key not in seen_nodes_set:
                                seen_nodes_set.add(node_key)
                                unique_nodes_list.append(node)

                    nodes_summary.append({'link': effective_link, 'node_count': len(nodes)})
                    print(f"\n[成功] 从 {effective_link} 找到 {len(nodes)} 个节点。")
                else:
                    nodes_summary.append({'link': link, 'node_count': 0})
            except Exception as e:
                # print(f"\n[错误] 处理 {link} 时发生异常: {e}")
                nodes_summary.append({'link': link, 'node_count': 0})
    
    if unique_nodes_list:
        save_to_yaml({'proxies': unique_nodes_list})
        
    save_to_csv(nodes_summary)
