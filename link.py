import requests
import yaml
import base64
import io
import os
import csv
import json
import re
import random
from urllib.parse import urlparse, unquote, urljoin
from collections import OrderedDict
from html.parser import HTMLParser

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
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.80 Mobile/15E148 Safari/604.1',
    # Android Chrome
    'Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
    # HarmonyOS Chrome (模拟)
    'Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36',
    # Linux Firefox
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    # Edge on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'
]

class DirectoryLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.in_pre = False

    def handle_starttag(self, tag, attrs):
        if tag == 'pre':
            self.in_pre = True
        if self.in_pre and tag == 'a':
            for name, value in attrs:
                if name == 'href':
                    self.links.append(value)

    def handle_endtag(self, tag):
        if tag == 'pre':
            self.in_pre = False

def parse_vmess(vmess_url):
    try:
        if not vmess_url.startswith('vmess://'): return None
        base64_content = vmess_url.replace('vmess://', '', 1)
        decoded_json = base64.b64decode(base64_content.encode('utf-8')).decode('utf-8')
        config = json.loads(decoded_json)
        required_fields = ['v', 'ps', 'add', 'port', 'id']
        if not all(field in config for field in required_fields): return None
        return {
            'name': config.get('ps', 'Unnamed VMess'), 'type': 'vmess', 'server': config.get('add'),
            'port': int(config.get('port')), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'), 'network': config.get('net', 'tcp'),
            'ws-opts': {'path': config.get('path', '/'), 'headers': {'Host': config.get('host', config.get('add'))}}
        }
    except Exception as e:
        print(f"解析VMess链接失败: {e}")
        return None

def parse_ss(ss_url):
    try:
        if not ss_url.startswith('ss://'): return None
        base64_content = ss_url.replace('ss://', '', 1)
        if '@' in base64_content:
            part1, part2 = base64_content.split('@', 1)
            decoded_part1 = base64.b64decode(part1.encode('utf-8')).decode('utf-8')
            method, password = decoded_part1.split(':', 1)
        else:
            decoded_content = base64.b64decode(base64_content.encode('utf-8')).decode('utf-8')
            if '@' not in decoded_content: return None
            decoded_part1, part2 = decoded_content.split('@', 1)
            method, password = decoded_part1.split(':', 1)
        server_info, name = part2.split('#', 1) if '#' in part2 else (part2, None)
        server, port = server_info.split(':', 1)
        return {
            'name': unquote(name) if name else 'Unnamed SS', 'type': 'ss', 'server': server,
            'port': int(port), 'cipher': method, 'password': password
        }
    except Exception as e:
        print(f"解析SS链接失败: {e}")
        return None

def parse_vless(vless_url):
    try:
        if not vless_url.startswith('vless://'): return None
        parsed_url = urlparse(vless_url)
        uuid, server, port, name = parsed_url.username, parsed_url.hostname, parsed_url.port, unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed VLESS'
        if not all([uuid, server, port]): return None
        params = dict(re.findall(r'([^=&]+)=([^=&]*)', parsed_url.query))
        return {
            'name': name, 'type': 'vless', 'server': server, 'port': port, 'uuid': uuid,
            'network': params.get('type', 'tcp'), 'tls': params.get('security') == 'tls', 'flow': params.get('flow'),
            'sni': params.get('sni'), 'ws-opts': {'path': params.get('path'), 'headers': {'Host': params.get('host')}}
        }
    except Exception as e:
        print(f"解析VLESS链接失败: {e}")
        return None

def parse_trojan(trojan_url):
    try:
        if not trojan_url.startswith('trojan://'): return None
        parsed_url = urlparse(trojan_url)
        password, server, port, name = parsed_url.username, parsed_url.hostname, parsed_url.port, unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed Trojan'
        if not all([password, server, port]): return None
        params = dict(re.findall(r'([^=&]+)=([^=&]*)', parsed_url.query))
        return {
            'name': name, 'type': 'trojan', 'server': server, 'port': port, 'password': password,
            'sni': params.get('sni'), 'skip-cert-verify': False
        }
    except Exception as e:
        print(f"解析Trojan链接失败: {e}")
        return None

def parse_ssr(ssr_url):
    try:
        if not ssr_url.startswith('ssr://'): return None
        base64_content = ssr_url.replace('ssr://', '', 1)
        decoded = base64.urlsafe_b64decode(base64_content + '==').decode('utf-8')
        parts = decoded.split(':')
        if len(parts) < 6: return None
        server, port, protocol, method, obfs, password_base64 = parts[:6]
        params = dict(re.findall(r'([^=&]+)=([^=&]*)', decoded.split('#', 1)[1])) if '#' in decoded else {}
        return {
            'name': unquote(params.get('remarks', 'Unnamed SSR')), 'type': 'ssr', 'server': server,
            'port': int(port), 'password': base64.urlsafe_b64decode(password_base64 + '==').decode('utf-8'),
            'cipher': method, 'protocol': protocol, 'obfs': obfs,
            'protocol-param': params.get('protoparam'), 'obfs-param': params.get('obfsparam')
        }
    except Exception as e:
        print(f"解析SSR链接失败: {e}")
        return None

def parse_hy2(hy2_url):
    try:
        if not hy2_url.startswith('hy2://'): return None
        parsed_url = urlparse(hy2_url)
        password, server, port, name = parsed_url.username, parsed_url.hostname, parsed_url.port, unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed HY2'
        if not all([password, server, port]): return None
        params = dict(re.findall(r'([^=&]+)=([^=&]*)', parsed_url.query))
        return {
            'name': name, 'type': 'hysteria2', 'server': server, 'port': port, 'password': password,
            'up': params.get('up'), 'down': params.get('down'), 'obfs': params.get('obfs'),
            'obfs-password': params.get('obfs-password'), 'fast-open': True
        }
    except Exception as e:
        print(f"解析HY2链接失败: {e}")
        return None

def parse_node(link):
    if link.startswith('vmess://'): return parse_vmess(link)
    if link.startswith('ss://'): return parse_ss(link)
    if link.startswith('vless://'): return parse_vless(link)
    if link.startswith('trojan://'): return parse_trojan(link)
    if link.startswith('ssr://'): return parse_ssr(link)
    if link.startswith('hy2://'): return parse_hy2(link)
    return None

def extract_links_from_html(html_content):
    links = []
    # 查找所有 class="config" 的 <p> 标签内容
    matches = re.findall(r'<p class="config".*?>(.*?)</p>', html_content, re.DOTALL)
    for match in matches:
        cleaned_link = re.sub(r'<[^>]+>', '', match).strip()
        if cleaned_link:
            links.append(cleaned_link)
    
    # 查找所有 <textarea> 标签内容
    matches = re.findall(r'<textarea[^>]*>(.*?)</textarea>', html_content, re.DOTALL)
    for match in matches:
        links.extend(match.strip().splitlines())
        
    return links

def extract_links_from_script(html_content):
    links = []
    # 查找包含 'const fileData =' 的 <script> 标签内容
    match = re.search(r'const\s+fileData\s*=\s*(\[[^;]+\]);', html_content, re.DOTALL)
    if match:
        json_str = match.group(1)
        try:
            # 尝试用 JSON 解析
            data = json.loads(json_str)
            for item in data:
                if 'url' in item:
                    links.append(item['url'])
        except json.JSONDecodeError:
            # 如果JSON解析失败，尝试用正则表达式解析
            matches = re.findall(r"url\s*:\s*'(.*?)'", json_str)
            for url in matches:
                links.append(url)
    return links

def get_nodes_from_url(url):
    schemes = ['https://', 'http://']
    for scheme in schemes:
        full_url = url
        if not full_url.startswith(('http://', 'https://')):
            full_url = f"{scheme}{url}"
        
        try:
            print(f"正在从 {full_url} 获取数据...")
            headers = {
                'User-Agent': random.choice(USER_AGENTS)
            }
            response = requests.get(full_url, headers=headers, timeout=15)
            response.raise_for_status()
            content = response.text

            nodes = []
            
            # 1. 尝试解析为YAML
            try:
                config = yaml.safe_load(content)
                if isinstance(config, dict) and 'proxies' in config:
                    for node in config['proxies']:
                        if isinstance(node, dict) and 'name' in node and 'type' in node: nodes.append(node)
                    print(f"从 {full_url} 解析了 {len(nodes)} 个YAML节点。")
                    if nodes: return nodes, len(nodes)
            except yaml.YAMLError: pass

            # 2. 尝试解析为纯文本或Base64编码的行
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'): continue
                try:
                    decoded_line = base64.b64decode(line.strip().encode('utf-8')).decode('utf-8')
                    parsed_node = parse_node(decoded_line)
                    if parsed_node: nodes.append(parsed_node)
                except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                    parsed_node = parse_node(line)
                    if parsed_node: nodes.append(parsed_node)
            
            if nodes:
                print(f"从 {full_url} 解析了 {len(nodes)} 个纯文本/Base64行节点。")
                return nodes, len(nodes)
            
            # 3. 尝试从HTML中提取链接
            html_links = extract_links_from_html(content)
            for link in html_links:
                parsed_node = parse_node(link)
                if parsed_node: nodes.append(parsed_node)
            
            # 4. 尝试从JavaScript脚本中提取链接
            script_links = extract_links_from_script(content)
            for link in script_links:
                parsed_node = parse_node(link)
                if parsed_node: nodes.append(parsed_node)
            
            if nodes:
                print(f"从 {full_url} 解析了 {len(nodes)} 个HTML嵌入节点。")
                return nodes, len(nodes)

            # 5. 如果以上都失败，尝试解析为HTML目录页面
            if '<title>Index of /</title>' in content or '<h1>Index of' in content:
                print(f"识别到目录页，正在搜索有效节点文件...")
                parser = DirectoryLinkParser()
                parser.feed(content)
                
                potential_links = [
                    link for link in parser.links 
                    if link.endswith(('.yaml', '.txt', '.m3u')) or 'clash' in link.lower() or 'v2ray' in link.lower() or 'sub' in link.lower() or 'node' in link.lower()
                ]

                total_nodes_found = 0
                for link in potential_links:
                    sub_url = urljoin(full_url, link)
                    sub_nodes, sub_count = get_nodes_from_url(sub_url)
                    nodes.extend(sub_nodes)
                    total_nodes_found += sub_count
                
                if nodes:
                    print(f"从 {full_url} 目录页及其子链接中解析了 {total_nodes_found} 个节点。")
                    return nodes, total_nodes_found
            
            print(f"从 {full_url} 无法解析出任何有效节点。")
            return [], 0

        except requests.exceptions.RequestException as e:
            print(f"无法从 {full_url} 获取数据: {e}")
            continue
    
    print(f"所有协议都无法从 {url} 获取数据。")
    return [], 0

def get_links_from_local_file(filename="link.txt"):
    links = []
    if os.path.exists(filename):
        print(f"正在从本地文件 {filename} 读取链接...")
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        links.append(line)
            print(f"从 {filename} 读取了 {len(links)} 个链接。")
        except IOError as e:
            print(f"无法读取文件 {filename}: {e}")
    else:
        print(f"文件 {filename} 不存在。请创建一个包含链接的 {filename} 文件。")
    return links

def save_to_yaml(data, filename='link.yaml'):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"成功将数据保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")

def save_summary_to_csv(summary_data, filename='link.csv'):
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['link', 'node_count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in summary_data:
                writer.writerow(row)
        print(f"成功将节点数量汇总保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")

if __name__ == "__main__":
    links = get_links_from_local_file()
    all_nodes = []
    nodes_summary = []
    
    processed_urls = set()

    def process_url_recursively(link):
        if link in processed_urls:
            return [], 0
        processed_urls.add(link)
        
        nodes, count = get_nodes_from_url(link)
        return nodes, count

    for link in links:
        nodes, count = process_url_recursively(link)
        all_nodes.extend(nodes)
        nodes_summary.append({'link': link, 'node_count': count})
    
    seen_nodes = set()
    unique_nodes = []
    for node in all_nodes:
        node_key = str(OrderedDict(sorted(node.items())))
        if node_key not in seen_nodes:
            seen_nodes.add(node_key)
            unique_nodes.append(node)

    if unique_nodes:
        save_to_yaml({'proxies': unique_nodes})
    else:
        print("未找到任何有效节点。")

    if nodes_summary:
        save_summary_to_csv(nodes_summary)
