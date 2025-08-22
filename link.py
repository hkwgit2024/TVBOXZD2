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
import threading
import logging
import argparse
from urllib.parse import urlparse, unquote, urljoin
from collections import OrderedDict
from html.parser import HTMLParser
from tqdm import tqdm
from ip_geolocation import GeoLite2Country
import geoip2.errors
import sys

# 设置日志
def setup_logging(log_level, log_file):
    """设置日志记录器，输出到文件和控制台。"""
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # 文件处理器
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

# 多样化的User-Agent列表，涵盖多种设备和浏览器
USER_AGENTS = [
    # Windows 10 Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    # Windows 10 Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    # macOS Big Sur Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.15 Safari/605.1.15',
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
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.2'
]

def get_random_user_agent():
    """获取一个随机的User-Agent。"""
    return random.choice(USER_AGENTS)

def get_session():
    """创建一个带有随机User-Agent的请求会话。"""
    s = requests.Session()
    s.headers.update({'User-Agent': get_random_user_agent(), 'Accept-Encoding': 'gzip, deflate, br'})
    return s

def save_successful_path(path):
    """将成功的文件路径保存到本地文件，以便下次使用。"""
    filename = 'successful_paths.txt'
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(path + '\n')
    except IOError as e:
        logging.error(f"无法保存文件路径 {filename}: {e}")

def load_successful_paths():
    """从本地文件加载之前成功的路径。"""
    filename = 'successful_paths.txt'
    paths = set()
    if os.path.exists(filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    paths.add(line.strip())
        except IOError as e:
            logging.error(f"无法加载文件 {filename}: {e}")
    return list(paths)

# 全局变量，缓存已经加载的成功路径
SUCCESSFUL_PATHS = load_successful_paths()
COMMON_PATHS = ['/sub', '/subscribe', '/clash.yaml', '/config/clash/sub', '/api/v1/client/subscribe']
ALL_PATHS_TO_TRY = list(set(SUCCESSFUL_PATHS + COMMON_PATHS))

class NodeManager:
    """线程安全的节点管理器，用于去重和存储节点。"""
    def __init__(self):
        self.nodes = []
        self.seen = set()
        self.lock = threading.Lock()

    def add_node(self, node):
        """添加节点，如果节点是唯一的，则进行去重。"""
        node_key = self._create_node_key(node)
        with self.lock:
            if node_key not in self.seen:
                self.seen.add(node_key)
                self.nodes.append(node)
                return True
        return False

    def _create_node_key(self, node):
        """根据节点的关键字段创建哈希键。"""
        # 优化去重逻辑，使用关键字段作为哈希键
        try:
            protocol = node.get('type')
            if protocol == 'vmess':
                return (protocol, node.get('server'), node.get('port'), node.get('uuid'))
            elif protocol == 'vless':
                return (protocol, node.get('server'), node.get('port'), node.get('uuid'))
            elif protocol == 'trojan':
                return (protocol, node.get('server'), node.get('port'), node.get('password'))
            elif protocol == 'ss':
                return (protocol, node.get('server'), node.get('port'), node.get('cipher'), node.get('password'))
            elif protocol == 'ssr':
                return (protocol, node.get('server'), node.get('port'), node.get('cipher'), node.get('password'))
            return str(OrderedDict(sorted(node.items()))) # Fallback for unknown types
        except Exception as e:
            logging.warning(f"无法为节点创建去重键: {e}, 使用默认方法。")
            return str(OrderedDict(sorted(node.items())))

def parse_yaml_content(content):
    """解析 YAML 内容中的节点。"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
            return data['proxies']
    except yaml.YAMLError as e:
        logging.error(f"YAML 解析失败: {e}")
    return []

def parse_base64_content(content):
    """解析 Base64 编码的内容中的节点。"""
    try:
        decoded_content = base64.b64decode(content + "=" * (-len(content) % 4)).decode('utf-8')
        lines = decoded_content.strip().split('\n')
        nodes = []
        for line in lines:
            if line.strip():
                node = parse_single_node_from_link(line.strip())
                if node:
                    nodes.append(node)
        return nodes
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        logging.error(f"Base64 解码失败: {e}")
    except Exception as e:
        logging.error(f"Base64 内容解析失败: {e}")
    return []

def is_ip_address(string):
    """检查字符串是否为有效的IP地址。"""
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

def parse_single_node_from_link(link):
    """根据协议类型解析单个链接。"""
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
    except (json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError) as e:
        logging.error(f"VMess 链接解析失败: {e}, 链接: {link[:50]}...")
        return None

def parse_vless_link(link):
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
    except (KeyError, IndexError, ValueError) as e:
        logging.error(f"VLESS 链接解析失败: {e}, 链接: {link[:50]}...")
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
    except (KeyError, IndexError, ValueError) as e:
        logging.error(f"Trojan 链接解析失败: {e}, 链接: {link[:50]}...")
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
    except (base64.binascii.Error, UnicodeDecodeError, KeyError, IndexError, ValueError) as e:
        logging.error(f"Shadowsocks 链接解析失败: {e}, 链接: {link[:50]}...")
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
    except (base64.binascii.Error, UnicodeDecodeError, KeyError, IndexError, ValueError) as e:
        logging.error(f"SSR 链接解析失败: {e}, 链接: {link[:50]}...")
        return None

def validate_node(node):
    """根据协议类型严格校验节点是否包含必需参数。"""
    protocol = node.get('type')
    required_params = {
        'vmess': ['server', 'port', 'uuid', 'alterId', 'cipher', 'network'],
        'vless': ['server', 'port', 'uuid'],
        'trojan': ['server', 'port', 'password'],
        'ss': ['server', 'port', 'cipher', 'password'],
        'ssr': ['server', 'port', 'password', 'protocol', 'obfs', 'cipher']
    }
    
    if protocol not in required_params:
        return False
        
    for param in required_params[protocol]:
        if param not in node:
            return False
            
    if protocol in ['vmess', 'vless'] and node.get('network') == 'ws':
        if 'ws-path' not in node or 'ws-headers' not in node:
            return False
    
    return True

def fetch_content(url, proxy=None):
    """
    使用requests获取URL内容，并根据Content-Type或内容本身猜测类型。
    """
    try:
        session = get_session()
        response = session.get(url, timeout=10, allow_redirects=True, proxies={'http': proxy, 'https': proxy} if proxy else None)
        response.raise_for_status()
        
        content = response.text
        
        # 增强的内容类型检测
        content_type = response.headers.get('Content-Type', '')
        if 'yaml' in content_type or 'octet-stream' in content_type:
            return content, 'yaml'
        if 'plain' in content_type and 'clash' not in content_type:
            return content, 'base64'
        if 'html' in content_type:
            return content, 'html'
            
        # 根据内容本身进行猜测
        if 'proxies:' in content or 'proxy-groups:' in content:
            return content, 'yaml'
        if 'ss://' in content or 'vmess://' in content or 'vless://' in content:
            return content, 'base64'
        
        # 假设为 Base64，尝试解码
        if len(content) > 100 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in content.strip()):
            return content, 'base64'
            
        return content, 'html'

    except requests.exceptions.RequestException as e:
        logging.warning(f"请求 {url} 失败: {e}")
        return None, None

def check_node_connectivity(node):
    """简单的节点连通性测试。"""
    try:
        server = node.get('server')
        port = node.get('port')
        if not server or not port:
            return False
        
        # 使用ping或简单的socket连接来测试连通性
        # 这里只做简单的请求测试
        test_url = f"http://{server}:{port}"
        requests.get(test_url, timeout=5)
        return True
    except Exception as e:
        logging.debug(f"节点 {node.get('name')} 连通性测试失败: {e}")
        return False

def get_nodes_from_url(link, geocoder, node_manager, args, proxy=None):
    """处理单个链接，提取节点并去重。"""
    nodes = []
    effective_link = None
    error_reason = None
    
    try:
        url_to_fetch = link
        if not (link.startswith('http://') or link.startswith('https://')):
            url_to_fetch = f'https://{link}'
            content, content_type = fetch_content(url_to_fetch, proxy)
            if not content:
                url_to_fetch = f'http://{link}'
                content, content_type = fetch_content(url_to_fetch, proxy)
        else:
            content, content_type = fetch_content(url_to_fetch, proxy)

        if content:
            effective_link = url_to_fetch
        else:
            parsed_url = urlparse(link)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            for path in ALL_PATHS_TO_TRY:
                full_url = urljoin(base_url, path)
                content, content_type = fetch_content(full_url, proxy)
                if content:
                    effective_link = full_url
                    save_successful_path(path)
                    break
        
        if not content and effective_link:
            content, content_type = fetch_content(effective_link, proxy)
            if content_type == 'html':
                nodes.extend(extract_nodes_from_html(content, effective_link, proxy))
        
        if content:
            if content_type == 'yaml':
                nodes.extend(parse_yaml_content(content))
            elif content_type == 'base64':
                nodes.extend(parse_base64_content(content))
            
        if geocoder:
            for node in nodes:
                server = node.get('server')
                if server and is_ip_address(server):
                    try:
                        country_code, country_name = geocoder.get_location(server)
                        node['country'] = country_name
                    except Exception as e:
                        logging.warning(f"IP {server} 地理位置查询失败: {e}")
        
        valid_nodes = [node for node in nodes if validate_node(node)]
        
        for node in valid_nodes:
            if args.check_connectivity and not check_node_connectivity(node):
                logging.debug(f"节点 {node.get('name')} 连通性测试失败，跳过。")
                continue
            node_manager.add_node(node)
            
        return {'link': link, 'effective_link': effective_link, 'status': 'success', 'node_count': len(valid_nodes)}
        
    except Exception as e:
        error_reason = str(e)
        logging.error(f"处理链接 {link} 时发生异常: {e}")
        return {'link': link, 'effective_link': effective_link, 'status': 'fail', 'error': error_reason}

class LinkExtractor(HTMLParser):
    """HTML解析器，用于从HTML中提取链接和Base64字符串。"""
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
        base64_pattern = re.compile(r'^[a-zA-Z0-9+/]{24,}={0,2}$')
        if base64_pattern.match(data) or data.startswith('vmess://') or data.startswith('vless://') or data.startswith('ss://'):
            self.links.append(data)

def extract_nodes_from_html(html_content, base_url, proxy=None):
    """从HTML内容中提取并解析节点。"""
    parser = LinkExtractor(base_url)
    parser.feed(html_content)
    all_nodes = []
    
    for link in parser.links:
        parsed_link = urlparse(link)
        if parsed_link.scheme in ['http', 'https']:
            if any(ext in parsed_link.path for ext in ['clash', 'yaml', 'sub', 'subscribe', 'v2ray', 'trojan', 'proxies']):
                try:
                    response = requests.get(link, timeout=5, proxies={'http': proxy, 'https': proxy} if proxy else None)
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'yaml' in content_type or 'octet-stream' in content_type:
                            nodes = parse_yaml_content(response.text)
                            if nodes: all_nodes.extend(nodes)
                        elif 'plain' in content_type:
                            nodes = parse_base64_content(response.text)
                            if nodes: all_nodes.extend(nodes)
                except requests.exceptions.RequestException as e:
                    logging.warning(f"从HTML中提取链接 {link} 失败: {e}")
        else:
            node = parse_single_node_from_link(link)
            if node:
                all_nodes.append(node)
                
    return all_nodes

def get_links_from_local_file(filename):
    """从本地文件加载链接。"""
    links = []
    try:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                links = [line.strip() for line in f if line.strip()]
    except IOError as e:
        logging.error(f"无法读取输入文件 {filename}: {e}")
    return links

def save_to_yaml(data, filename):
    """将数据保存为 YAML 文件。"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': data}, f, allow_unicode=True, sort_keys=False)
        logging.info(f"成功将所有去重节点保存到 {filename}")
    except IOError as e:
        logging.error(f"无法保存文件 {filename}: {e}")

def save_to_json(data, filename):
    """将数据保存为 JSON 文件。"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({'proxies': data}, f, indent=4, ensure_ascii=False)
        logging.info(f"成功将所有去重节点保存到 {filename}")
    except IOError as e:
        logging.error(f"无法保存文件 {filename}: {e}")

def save_to_csv(data, filename):
    """将汇总报告保存为 CSV 文件。"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['link', 'node_count', 'status', 'error']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        logging.info(f"成功将节点数量汇总保存到 {filename}")
    except IOError as e:
        logging.error(f"无法保存文件 {filename}: {e}")

def main():
    """主函数，处理命令行参数并执行任务。"""
    parser = argparse.ArgumentParser(description="从订阅链接中抓取和处理代理节点。")
    parser.add_argument('-i', '--input', type=str, default='link.txt', help='包含订阅链接的输入文件。')
    parser.add_argument('-o', '--output', type=str, default='all_nodes.yaml', help='保存节点列表的输出文件。')
    parser.add_argument('-s', '--summary', type=str, default='link.csv', help='保存处理摘要的CSV文件。')
    parser.add_argument('-l', '--log-level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='设置日志级别。')
    parser.add_argument('-j', '--json-output', action='store_true', help='启用 JSON 格式输出，而非 YAML。')
    parser.add_argument('-p', '--proxy-pool', type=str, help='指定一个代理池文件以使用HTTP代理。')
    parser.add_argument('-c', '--check-connectivity', action='store_true', help='对提取的节点执行简单的连通性测试。')

    args = parser.parse_args()
    setup_logging(args.log_level.upper(), 'run.log')
    
    logging.info("脚本开始执行...")
    
    # 代理池支持（占位符）
    proxies = []
    if args.proxy_pool:
        try:
            with open(args.proxy_pool, 'r', encoding='utf-8') as f:
                proxies = [line.strip() for line in f if line.strip()]
            logging.info(f"已加载 {len(proxies)} 个代理。")
        except IOError as e:
            logging.error(f"无法加载代理池文件 {args.proxy_pool}: {e}，将不使用代理。")
            proxies = []

    geocoder = None
    try:
        with GeoLite2Country('GeoLite2-Country.mmdb') as geo_db:
            geocoder = geo_db
            logging.info("GeoLite2-Country.mmdb 数据库加载成功，将启用IP地理位置查询功能。")
    except FileNotFoundError:
        logging.warning("未找到 GeoLite2-Country.mmdb 数据库文件，将跳过IP地理位置查询。")
    except Exception as e:
        logging.error(f"加载 GeoLite2-Country.mmdb 时发生未知错误: {e}")
        logging.warning("将跳过IP地理位置查询。")

    links = get_links_from_local_file(args.input)
    if not links:
        logging.warning(f"输入文件 {args.input} 为空或不存在，脚本已终止。")
        return
        
    node_manager = NodeManager()
    summary = []
    
    max_workers = os.cpu_count() * 2 # 动态线程数
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(get_nodes_from_url, link, geocoder, node_manager, args, random.choice(proxies) if proxies else None): link for link in links}
        
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(links), desc="处理链接"):
            link = futures[future]
            try:
                result = future.result()
                summary.append({
                    'link': link,
                    'node_count': result.get('node_count', 0),
                    'status': result.get('status', 'fail'),
                    'error': result.get('error', '')
                })
                if result['status'] == 'success':
                    tqdm.write(f"[成功] 从 {link} 找到 {result['node_count']} 个节点。")
                else:
                    tqdm.write(f"[失败] 处理 {link} 时出错: {result.get('error', '未知错误')}")
            except Exception as e:
                tqdm.write(f"[错误] 意外错误处理链接 {link}: {e}")
                summary.append({'link': link, 'node_count': 0, 'status': 'fail', 'error': str(e)})

    # 保存结果
    if node_manager.nodes:
        if args.json_output:
            save_to_json(node_manager.nodes, args.output)
        else:
            save_to_yaml(node_manager.nodes, args.output)
    else:
        logging.warning("未找到任何有效节点。")
        
    save_to_csv(summary, args.summary)

    # 打印用户友好的总结报告
    success_count = sum(1 for item in summary if item['status'] == 'success')
    fail_count = len(links) - success_count
    total_nodes = len(node_manager.nodes)
    
    print("\n" + "="*50)
    print("                处理结果总结")
    print("="*50)
    print(f"总处理链接数: {len(links)}")
    print(f"成功处理链接数: {success_count}")
    print(f"失败处理链接数: {fail_count}")
    print(f"发现唯一有效节点总数: {total_nodes}")
    print("="*50)
    
    if fail_count > 0:
        print("\n失败链接列表:")
        for item in summary:
            if item['status'] == 'fail':
                print(f"  - {item['link']}: {item['error']}")
    
    logging.info("脚本执行完成。")

if __name__ == "__main__":
    main()
