import requests
import yaml
import base64
import io
import os
import csv
import json
from urllib.parse import urlparse, unquote
from collections import OrderedDict

def parse_vmess(vmess_url):
    try:
        if not vmess_url.startswith('vmess://'):
            return None
        
        base64_content = vmess_url.replace('vmess://', '', 1)
        decoded_json = base64.b64decode(base64_content).decode('utf-8')
        config = json.loads(decoded_json)
        
        required_fields = ['v', 'ps', 'add', 'port', 'id']
        if not all(field in config for field in required_fields):
            return None
            
        return {
            'name': config.get('ps', 'Unnamed VMess'),
            'type': 'vmess',
            'server': config.get('add'),
            'port': int(config.get('port')),
            'uuid': config.get('id'),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'network': config.get('net', 'tcp'),
            'ws-opts': {
                'path': config.get('path', '/'),
                'headers': {
                    'Host': config.get('host', config.get('add'))
                }
            }
        }
    except Exception as e:
        print(f"解析VMess链接失败: {e}")
        return None

def parse_ss(ss_url):
    try:
        if not ss_url.startswith('ss://'):
            return None
        
        base64_content = ss_url.replace('ss://', '', 1)
        if '@' in base64_content:
            part1, part2 = base64_content.split('@', 1)
            decoded_part1 = base64.b64decode(part1.encode('utf-8')).decode('utf-8')
            method, password = decoded_part1.split(':', 1)
        else:
            decoded_content = base64.b64decode(base64_content.encode('utf-8')).decode('utf-8')
            if '@' not in decoded_content:
                return None
            decoded_part1, part2 = decoded_content.split('@', 1)
            method, password = decoded_part1.split(':', 1)

        server_info, name = part2.split('#', 1) if '#' in part2 else (part2, None)
        server, port = server_info.split(':', 1)

        return {
            'name': unquote(name) if name else 'Unnamed SS',
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password
        }
    except Exception as e:
        print(f"解析SS链接失败: {e}")
        return None

def parse_vless(vless_url):
    try:
        if not vless_url.startswith('vless://'):
            return None

        parsed_url = urlparse(vless_url)
        uuid = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        params = dict(param.split('=') for param in parsed_url.query.split('&'))
        name = unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed VLESS'
        
        if not all([uuid, server, port, name]):
            return None

        return {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'network': params.get('type', 'tcp'),
            'tls': params.get('security') == 'tls',
            'flow': params.get('flow'),
            'sni': params.get('sni'),
            'ws-opts': {
                'path': params.get('path'),
                'headers': {
                    'Host': params.get('host')
                }
            }
        }
    except Exception as e:
        print(f"解析VLESS链接失败: {e}")
        return None

def parse_trojan(trojan_url):
    try:
        if not trojan_url.startswith('trojan://'):
            return None
        
        parsed_url = urlparse(trojan_url)
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed Trojan'
        
        if not all([password, server, port, name]):
            return None
        
        return {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'sni': parsed_url.query.get('sni'),
            'skip-cert-verify': False
        }
    except Exception as e:
        print(f"解析Trojan链接失败: {e}")
        return None

def parse_ssr(ssr_url):
    try:
        if not ssr_url.startswith('ssr://'):
            return None
        base64_content = ssr_url.replace('ssr://', '', 1)
        decoded = base64.urlsafe_b64decode(base64_content + '==').decode('utf-8')
        
        parts = decoded.split(':')
        if len(parts) < 6: return None
        
        server, port, protocol, method, obfs, password_base64 = parts[:6]
        
        params = {}
        if '#' in decoded:
            password_base64, fragment = decoded.split('#', 1)
            params = dict(p.split('=') for p in fragment.split('&') if '=' in p)
        
        return {
            'name': unquote(params.get('remarks', 'Unnamed SSR')),
            'type': 'ssr',
            'server': server,
            'port': int(port),
            'password': base64.urlsafe_b64decode(password_base64 + '==').decode('utf-8'),
            'cipher': method,
            'protocol': protocol,
            'obfs': obfs,
            'protocol-param': params.get('protoparam'),
            'obfs-param': params.get('obfsparam'),
            'group': unquote(params.get('group', 'Default'))
        }
    except Exception as e:
        print(f"解析SSR链接失败: {e}")
        return None

def parse_hy2(hy2_url):
    try:
        if not hy2_url.startswith('hy2://'):
            return None
        
        # hy2链接的密码在username部分，其他参数在查询字符串
        parsed_url = urlparse(hy2_url)
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed HY2'
        params = dict(param.split('=') for param in parsed_url.query.split('&'))
        
        if not all([password, server, port, name]):
            return None
            
        return {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'up': params.get('up'),
            'down': params.get('down'),
            'obfs': params.get('obfs'),
            'obfs-password': params.get('obfs-password'),
            'fast-open': True
        }
    except Exception as e:
        print(f"解析HY2链接失败: {e}")
        return None

def parse_node(link):
    """
    根据协议类型，调用相应的解析函数。
    """
    if link.startswith('vmess://'):
        return parse_vmess(link)
    elif link.startswith('ss://'):
        return parse_ss(link)
    elif link.startswith('vless://'):
        return parse_vless(link)
    elif link.startswith('trojan://'):
        return parse_trojan(link)
    elif link.startswith('ssr://'):
        return parse_ssr(link)
    elif link.startswith('hy2://'):
        return parse_hy2(link)
    return None

def get_nodes_from_url(url):
    schemes = ['https://', 'http://']
    
    for scheme in schemes:
        full_url = url
        if not full_url.startswith(('http://', 'https://')):
            full_url = f"{scheme}{url}"
        
        try:
            print(f"正在从 {full_url} 获取数据...")
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(full_url, headers=headers, timeout=15)
            response.raise_for_status()

            nodes = []
            content = response.text
            
            # 尝试解析为YAML
            try:
                config = yaml.safe_load(content)
                if isinstance(config, dict) and 'proxies' in config:
                    for node in config['proxies']:
                        if isinstance(node, dict) and 'name' in node and 'type' in node:
                            nodes.append(node)
                    print(f"从 {full_url} 解析了 {len(nodes)} 个YAML节点。")
                    return nodes, len(nodes)
            except yaml.YAMLError:
                pass

            # 尝试解析为纯文本或Base64编码的行
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    decoded_line = base64.b64decode(line).decode('utf-8')
                    parsed_node = parse_node(decoded_line)
                    if parsed_node:
                        nodes.append(parsed_node)
                except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                    parsed_node = parse_node(line)
                    if parsed_node:
                        nodes.append(parsed_node)

            print(f"从 {full_url} 解析了 {len(nodes)} 个纯文本/Base64行节点。")
            return nodes, len(nodes)

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

    for link in links:
        nodes, count = get_nodes_from_url(link)
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
