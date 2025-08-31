# -*- coding: utf-8 -*-

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
import socket
import hashlib
from urllib.parse import urlparse, unquote, urljoin
from collections import OrderedDict, defaultdict
from html.parser import HTMLParser
from tqdm import tqdm
from ip_geolocation import GeoLite2Country
import requests_cache
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
from playwright.async_api import async_playwright
import asyncio
import binascii
import aiohttp

# 全局变量和配置
LOG_FILE = "link_processing.log"
# 缓存网络请求，有效期为1天
requests_cache.install_cache('link_cache', expire_after=86400)

# 多样化的User-Agent列表
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.15 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.80 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'
]

# 忽略 BeautifulSoup 的警告
warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)

# 定义支持的协议和有效的加密方式
SUPPORTED_PROTOCOLS = ['vmess', 'ss', 'ssr', 'vless', 'trojan', 'hysteria2']
VALID_CIPHERS_SS = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305']
VALID_CIPHERS_VMESS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305']

# CSV 文件表头
CSV_HEADERS = ['name', 'type', 'server', 'port', 'password', 'cipher', 'protocol', 'obfs', 'uuid', 'sni', 'country_code']

# 正则表达式用于验证域名和 IP
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# --------------------------------------------------------------------------------
# 增强的辅助函数
# --------------------------------------------------------------------------------

def is_valid_url(url):
    """
    改进的 URL 验证：使用 urllib.parse 进行更健壮的解析。
    
    参数:
        url (str): 待验证的 URL 字符串。
    
    返回:
        bool: 如果是有效 URL 则返回 True，否则返回 False。
    """
    try:
        result = urlparse(url)
        # 检查协议（scheme）和网络位置（netloc）是否存在
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_valid_domain_or_ip(host):
    """验证主机是否为有效域名或IP"""
    return bool(DOMAIN_REGEX.match(host) or IP_REGEX.match(host))

def safe_base64_decode(data):
    """
    更安全的 Base64 解码，处理可能存在的填充问题和非法字符。
    
    参数:
        data (bytes): 待解码的 Base64 字符串（字节）。
    
    返回:
        bytes: 解码后的数据，如果失败则返回 None。
    """
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'=' * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(data)
    except (binascii.Error, TypeError):
        return None

def validate_host(host):
    """验证 Host 字段（域名或 IP）"""
    if not host or not isinstance(host, str):
        return False
    host = host.strip()
    if not host:
        return False
    try:
        # 尝试将域名解析为 IP，如果失败则认为无效
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False

def generate_unique_name(base_name, name_counts):
    """根据基础名称和计数器生成唯一的名称"""
    name_counts[base_name] = name_counts.get(base_name, 0) + 1
    count = name_counts[base_name]
    if count == 1:
        return base_name
    return f"{base_name}_{count}"

def get_node_key(node):
    """
    更健壮的去重逻辑：基于所有关键配置字段生成哈希键。
    
    参数:
        node (dict): 节点信息字典。
    
    返回:
        str: 节点的唯一哈希键。
    """
    node_copy = {k: v for k, v in node.items() if k != 'name'}
    key_str = json.dumps(node_copy, sort_keys=True)
    return hashlib.sha256(key_str.encode('utf-8')).hexdigest()

def process_node_with_geolocation(node, geo_locator):
    """
    处理节点的地理位置信息，并重命名。
    
    参数:
        node (dict): 节点信息字典。
        geo_locator (GeoLite2Country): GeoLite2 数据库实例。
    
    返回:
        tuple: (处理后的节点字典, 是否成功获取地理位置)。
    """
    success = False
    try:
        server = node.get('server')
        if not server:
            raise ValueError("节点缺少服务器地址。")

        try:
            ip_address = socket.gethostbyname(server)
        except socket.gaierror:
            ip_address = server

        location = geo_locator.get_country(ip_address)
        if location and location.get('country_name'):
            country_name = location['country_name']
            node['country_code'] = location['country_code']
            node['name'] = f"{country_name} - {node.get('name', '')}".strip()
            success = True
    except Exception as e:
        node['name'] = f"UNKNOWN - {node.get('name', '')}".strip()
    return node, success

def write_nodes_to_csv(nodes, file_path, write_header=False):
    """将节点列表写入 CSV 文件"""
    with open(file_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        if write_header:
            writer.writeheader()
        
        for node in nodes:
            row = {key: node.get(key, '') for key in CSV_HEADERS}
            writer.writerow(row)

# --------------------------------------------------------------------------------
# 异步网络请求和解析
# --------------------------------------------------------------------------------

def extract_links_from_content(content):
    """
    从文本内容中提取符合协议格式的链接。
    
    参数:
        content (str): 文本内容，可以是网页 HTML 或其他文本。
        
    返回:
        list: 包含所有提取到的链接字符串。
    """
    all_links = []
    regex = r'\b(' + '|'.join(SUPPORTED_PROTOCOLS) + r'://[^\s\'"]+)'
    matches = re.findall(regex, content, re.IGNORECASE)
    
    for link in set(matches):
        link = link.strip()
        if is_valid_url(link):
            all_links.append(link)
            
    return all_links

async def get_content_from_url(session, url):
    """
    使用 aiohttp 异步获取 URL 内容。
    
    参数:
        session (aiohttp.ClientSession): 异步会话。
        url (str): 目标 URL。
    
    返回:
        str: 提取到的文本内容，如果失败则返回 None。
    """
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    try:
        async with session.get(url, headers=headers, timeout=15) as response:
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '').lower()
            content = await response.read()

            if 'text/plain' in content_type or 'application/octet-stream' in content_type:
                decoded_content = safe_base64_decode(content)
                if decoded_content:
                    return decoded_content.decode('utf-8', 'ignore')

            if 'text/html' in content_type:
                soup = BeautifulSoup(content, 'html.parser')
                return soup.get_text()
            
            return content.decode('utf-8', 'ignore')
    except aiohttp.ClientError as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"异步请求 {url} 时发生错误: {e}\n")
        return None

async def get_dynamic_content_with_playwright(page, url):
    """
    使用 Playwright 异步获取动态渲染的页面内容。
    
    参数:
        page (playwright.async_api.Page): Playwright 页面实例。
        url (str): 目标 URL。
        
    返回:
        str: 完整的 HTML 内容，如果失败则返回 None。
    """
    try:
        await page.goto(url, wait_until='networkidle')
        content = await page.content()
        return content
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Playwright 获取 {url} 时发生错误: {e}\n")
        return None

def get_content_from_html(html_content, url):
    """
    从完整的HTML内容中提取链接。
    
    参数:
        html_content (str): 完整的HTML内容。
        url (str): 原始的 URL，用于解析相对路径。
    
    返回:
        list: 提取到的链接列表。
    """
    extracted_links = []
    soup = BeautifulSoup(html_content, 'html.parser')

    for tag in soup.find_all(lambda tag: tag.has_attr('href') or tag.has_attr('src')):
        link = tag.get('href') or tag.get('src')
        if is_valid_url(link):
            extracted_links.append(urljoin(url, link))

    for tag in soup.find_all(['script', 'textarea']):
        extracted_links.extend(extract_links_from_content(tag.get_text()))

    meta_tag = soup.find('meta', {'http-equiv': 'refresh'})
    if meta_tag and 'content' in meta_tag.attrs:
        match = re.search(r'url=(.*)', meta_tag['content'], re.IGNORECASE)
        if match:
            link = urljoin(url, match.group(1))
            if is_valid_url(link):
                extracted_links.append(link)

    extracted_links.extend(extract_links_from_content(soup.get_text()))
    
    return list(set(extracted_links))

# --------------------------------------------------------------------------------
# 核心解析函数 (已增强，严格验证参数)
# --------------------------------------------------------------------------------

def parse_vmess(link, name=None):
    """解析VMess链接"""
    try:
        node_type, encoded_info = link.split('vmess://')
        decoded_info = safe_base64_decode(encoded_info.encode('utf-8'))
        
        if not decoded_info:
            return None
        
        node = json.loads(decoded_info.decode('utf-8'))
        
        # 严格验证关键字段
        if not all(k in node and node[k] for k in ['add', 'port']):
            print(f"VMess解析失败：链接缺少 'add' 或 'port'。")
            return None
        if not validate_host(node.get('add')):
            print(f"VMess解析失败：无效的服务器地址 {node.get('add')}。")
            return None

        node['type'] = 'vmess'
        node['server'] = node.pop('add')
        node['port'] = int(node.pop('port'))
        
        if node.get('scy') and node.get('scy').lower() not in VALID_CIPHERS_VMESS:
            print(f"VMess解析失败：不支持的加密方式 {node.get('scy')}。")
            return None
        node['cipher'] = node.pop('scy', 'auto')
        
        node['name'] = name or unquote(node.pop('ps', f"vmess_{node['server']}"))
        return node
    except (ValueError, json.JSONDecodeError, KeyError) as e:
        print(f"VMess解析失败：{link}，错误：{e}")
        return None

def parse_ss(link, name=None):
    """解析SS链接"""
    try:
        node_type, encoded_info = link.split('ss://')
        parts = unquote(encoded_info).split('#')
        info = parts[0]
        name = name or (unquote(parts[1]) if len(parts) > 1 else "Shadowsocks Node")
        
        decoded_info = safe_base64_decode(info.encode('utf-8'))
        if decoded_info:
            info = decoded_info.decode('utf-8')
        
        cipher, password_server_port = info.split(':', 1)
        password, server_port = password_server_port.split('@', 1)
        server, port = server_port.split(':', 1)
        
        if cipher.lower() not in VALID_CIPHERS_SS:
            print(f"SS解析失败：不支持的加密方式 {cipher}")
            return None
        if not validate_host(server):
            print(f"SS解析失败：无效的服务器地址 {server}")
            return None
        
        return {
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': cipher,
            'password': password,
            'name': name
        }
    except (ValueError, binascii.Error, IndexError) as e:
        print(f"SS解析失败：{link}，错误：{e}")
        return None

def parse_ssr(link, name=None):
    """解析SSR链接"""
    try:
        node_type, encoded_info = link.split('ssr://')
        decoded_info = safe_base64_decode(encoded_info.encode('utf-8'))
        if not decoded_info:
            return None
        info = decoded_info.decode('utf-8')
        
        parts = info.split(':')
        server = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        cipher = parts[3]
        obfs = parts[4]
        password_base64, params_str = parts[5].split('/?', 1)
        password = safe_base64_decode(password_base64.encode('utf-8')).decode('utf-8')
        
        if not validate_host(server):
            return None
        
        node = {
            'type': 'ssr',
            'server': server,
            'port': port,
            'protocol': protocol,
            'cipher': cipher,
            'obfs': obfs,
            'password': password
        }
        
        params = {k: unquote(v) for k, v in [p.split('=', 1) for p in params_str.split('&')] if '=' in p}
        node.update(params)
        
        node['name'] = name or unquote(node.get('remarks', f"ssr_{server}"))
        return node
    except (ValueError, binascii.Error, IndexError) as e:
        print(f"SSR解析失败：{link}，错误：{e}")
        return None

def parse_vless(link, name=None):
    """
    增强的VLESS链接解析，严格验证TLS和UUID。
    """
    try:
        if not link.startswith('vless://'):
            return None
        
        url_parsed = urlparse(link)
        server = url_parsed.hostname
        port = url_parsed.port
        uuid = url_parsed.username
        
        if not validate_host(server) or not port or not uuid:
            print(f"VLESS解析失败：链接缺少有效主机、端口或UUID。")
            return None
        
        node = {
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'name': name or unquote(url_parsed.fragment or f"vless_{server}")
        }

        params = urlparse(link).query
        if params:
            query_params = dict(qp.split('=', 1) for qp in params.split('&') if '=' in qp)
            node.update({k: unquote(v) for k, v in query_params.items()})

        # 严格验证 TLS 参数
        if node.get('security', '').lower() == 'tls' and not is_valid_domain_or_ip(node.get('sni', '')):
            print(f"VLESS解析失败：TLS 安全性启用但SNI无效或缺失。")
            return None
            
        return node
    except (ValueError, IndexError, KeyError) as e:
        print(f"VLESS解析失败：{link}，错误：{e}")
        return None

def parse_trojan(link, name=None):
    """
    增强的Trojan链接解析，严格验证密码和TLS。
    """
    try:
        if not link.startswith('trojan://'):
            return None
        
        url_parsed = urlparse(link)
        password = url_parsed.username
        server = url_parsed.hostname
        port = url_parsed.port
        
        if not validate_host(server) or not port or not password:
            print(f"Trojan解析失败：链接缺少有效主机、端口或密码。")
            return None
            
        node = {
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'name': name or unquote(url_parsed.fragment or f"trojan_{server}")
        }
        
        params = urlparse(link).query
        if params:
            query_params = dict(qp.split('=', 1) for qp in params.split('&') if '=' in qp)
            node.update({k: unquote(v) for k, v in query_params.items()})

        # 严格验证 TLS 参数
        if not is_valid_domain_or_ip(node.get('sni', '')):
            print(f"Trojan解析失败：SNI无效或缺失。")
            return None

        return node
    except (ValueError, IndexError, KeyError) as e:
        print(f"Trojan解析失败：{link}，错误：{e}")
        return None

def parse_hysteria2(link, name=None):
    """
    增强的Hysteria2链接解析，严格验证密码。
    """
    try:
        if not link.startswith('hysteria2://'):
            return None

        url_parsed = urlparse(link)
        server = url_parsed.hostname
        port = url_parsed.port
        password = url_parsed.username

        # Hysteria2链接强制要求有密码
        if not validate_host(server) or not port or not password:
            print(f"Hysteria2解析失败：链接缺少有效主机、端口或密码。")
            return None

        node = {
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'name': name or unquote(url_parsed.fragment or f"hysteria2_{server}")
        }
        
        params = urlparse(link).query
        if params:
            query_params = dict(qp.split('=', 1) for qp in params.split('&') if '=' in qp)
            node.update({k: unquote(v) for k, v in query_params.items()})

        return node
    except (ValueError, IndexError, KeyError) as e:
        print(f"Hysteria2解析失败：{link}，错误：{e}")
        return None

def parse_link(link_str, name=None):
    """根据协议类型解析链接，并返回节点信息字典"""
    link_str = link_str.strip()
    link_str = unquote(link_str)
    
    if not is_valid_url(link_str):
        return None
    
    protocol = link_str.split('://')[0].lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        return None

    if protocol == 'vmess':
        return parse_vmess(link_str, name)
    elif protocol == 'ss':
        return parse_ss(link_str, name)
    elif protocol == 'ssr':
        return parse_ssr(link_str, name)
    elif protocol == 'vless':
        return parse_vless(link_str, name)
    elif protocol == 'trojan':
        return parse_trojan(link_str, name)
    elif protocol == 'hysteria2':
        return parse_hysteria2(link_str, name)
    return None

async def process_url_task(semaphore, session, browser_context, link):
    """
    一个异步工作函数，处理单个 URL 的内容获取和节点解析。
    使用信号量控制 Playwright 页面创建的并发数。
    
    参数:
        semaphore (asyncio.Semaphore): 信号量，用于控制并发数。
        session (aiohttp.ClientSession): 异步会话。
        browser_context (playwright.async_api.BrowserContext): Playwright 浏览器上下文。
        link (str): 目标 URL。
        
    返回:
        list: 从 URL 中解析到的所有节点列表。
    """
    found_nodes = []
    
    # 尝试使用 aiohttp 获取静态内容
    content = await get_content_from_url(session, link)
    
    if content:
        found_links = extract_links_from_content(content)
        if not found_links:
            # 如果没有找到链接，尝试使用 Playwright 获取动态内容
            async with semaphore:
                page = await browser_context.new_page()
                try:
                    html_content = await get_dynamic_content_with_playwright(page, link)
                    if html_content:
                        found_links = get_content_from_html(html_content, link)
                finally:
                    await page.close()
        
        for found_link in found_links:
            node = parse_link(found_link)
            if node:
                found_nodes.append(node)
                
    return found_nodes

# --------------------------------------------------------------------------------
# 主逻辑
# --------------------------------------------------------------------------------

async def main():
    """主函数，负责执行所有任务。"""
    
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    
    print("开始处理代理链接...")

    links_to_process = []
    if os.path.exists("link.txt"):
        with open("link.txt", 'r', encoding='utf-8') as f:
            links_to_process.extend([line.strip() for line in f if line.strip()])
    
    if not links_to_process:
        print("未找到 link.txt 文件或文件中没有链接，请提供链接。")
        return

    seen_keys = set()
    name_counts = defaultdict(int)
    total_unique_nodes = 0

    yaml_file_path = 'link.yaml'
    csv_file_path = 'link.csv'

    with open(yaml_file_path, 'w', encoding='utf-8') as f:
        f.write("proxies:\n")
    if os.path.exists(csv_file_path):
        os.remove(csv_file_path)

    geo_locator = None
    db_path = "GeoLite2-Country.mmdb"
    if os.path.exists(db_path):
        geo_locator = GeoLite2Country(db_path)
    else:
        print(f"警告：未找到 {db_path}，无法进行地理位置重命名。")

    # Playwright 页面并发限制
    concurrency_limit = 5
    semaphore = asyncio.Semaphore(concurrency_limit)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        browser_context = await browser.new_context()
        
        async with aiohttp.ClientSession() as session:
            tasks = [process_url_task(semaphore, session, browser_context, link) for link in links_to_process]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
                for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="处理链接中"):
                    try:
                        nodes_from_url = await coro
                        
                        geolocated_nodes = list(executor.map(
                            lambda node: process_node_with_geolocation(node, geo_locator),
                            nodes_from_url
                        ))

                        new_unique_nodes = []
                        for node, _ in geolocated_nodes:
                            node_key = get_node_key(node)
                            if node_key not in seen_keys:
                                seen_keys.add(node_key)
                                base_name = node.get('name', '')
                                node['name'] = generate_unique_name(base_name, name_counts)
                                new_unique_nodes.append(node)

                        if new_unique_nodes:
                            total_unique_nodes += len(new_unique_nodes)
                            with open(yaml_file_path, 'a', encoding='utf-8') as f:
                                yaml.dump(new_unique_nodes, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
                            
                            write_nodes_to_csv(new_unique_nodes, csv_file_path, write_header=not os.path.exists(csv_file_path) or os.stat(csv_file_path).st_size == 0)
                            
                    except Exception as e:
                        print(f"处理任务时发生意外错误: {e}")
                        
        await browser.close()
    
    if geo_locator:
        geo_locator.close()

    print(f"\n去重后共处理 {total_unique_nodes} 个节点。")
    print(f"已将所有节点信息写入 {yaml_file_path} 和 {csv_file_path}。")
        
    print("处理完成！")

if __name__ == "__main__":
    asyncio.run(main())
