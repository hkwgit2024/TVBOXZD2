import requests
import os
import base64
import json
import urllib.parse
import yaml

def parse_vmess(url, index):
    """解析 vmess:// 协议，符合 Clash.Meta 要求"""
    try:
        data = base64.b64decode(url.replace('vmess://', '')).decode('utf-8')
        config = json.loads(data)
        node = {
            'type': 'vmess',
            'name': f"vmess-{index}-{config.get('ps', 'node')}",
            'server': config.get('add'),
            'port': int(config.get('port')),
            'uuid': config.get('id'),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'network': config.get('net', 'tcp'),
            'tls': config.get('tls') == 'tls'
        }
        # 验证必填字段
        if not all([node['server'], node['port'], node['uuid']]):
            print(f"Skipping vmess node {url}: missing required fields")
            return None
        return node
    except Exception as e:
        print(f"Error parsing vmess {url}: {e}")
        return None

def parse_trojan(url, index):
    """解析 trojan:// 协议，符合 Clash.Meta 要求"""
    try:
        parsed = urllib.parse.urlparse(url)
        password = parsed.netloc.split('@')[0]
        server_port = parsed.netloc.split('@')[1]
        server, port = server_port.split(':')
        params = urllib.parse.parse_qs(parsed.query)
        node = {
            'type': 'trojan',
            'name': f"trojan-{index}-{server}",
            'server': server,
            'port': int(port),
            'password': password,
            'sni': params.get('sni', [''])[0],
            'skip-cert-verify': params.get('allowInsecure', ['0'])[0] == '1'
        }
        if not all([node['server'], node['port'], node['password']]):
            print(f"Skipping trojan node {url}: missing required fields")
            return None
        return node
    except Exception as e:
        print(f"Error parsing trojan {url}: {e}")
        return None

def parse_ss(url, index):
    """解析 ss:// 协议，符合 Clash.Meta 要求"""
    try:
        parsed = urllib.parse.urlparse(url)
        method_password = parsed.netloc.split('@')[0]
        if method_password.startswith('Y2'):  # Base64 编码
            method_password = base64.b64decode(method_password).decode('utf-8')
        method, password = method_password.split(':')
        server, port = parsed.netloc.split('@')[1].split(':')
        node = {
            'type': 'ss',
            'name': f"ss-{index}-{server}",
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password
        }
        if not all([node['server'], node['port'], node['cipher'], node['password']]):
            print(f"Skipping ss node {url}: missing required fields")
            return None
        return node
    except Exception as e:
        print(f"Error parsing ss {url}: {e}")
        return None

def parse_ssr(url, index):
    """解析 ssr:// 协议，符合 Clash.Meta 要求"""
    try:
        data = base64.b64decode(url.replace('ssr://', '')).decode('utf-8')
        parts = data.split(':')
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, password = parts[:6]
        password = base64.b64decode(password).decode('utf-8')
        params = urllib.parse.parse_qs(data.split('?')[1]) if '?' in data else {}
        node = {
            'type': 'ssr',
            'name': f"ssr-{index}-{server}",
            'server': server,
            'port': int(port),
            'protocol': protocol,
            'cipher': method,
            'obfs': obfs,
            'password': password,
            'obfs-param': params.get('obfsparam', [''])[0],
            'protocol-param': params.get('protoparam', [''])[0]
        }
        if not all([node['server'], node['port'], node['protocol'], node['cipher'], node['obfs'], node['password']]):
            print(f"Skipping ssr node {url}: missing required fields")
            return None
        return node
    except Exception as e:
        print(f"Error parsing ssr {url}: {e}")
        return None

def parse_vless(url, index):
    """解析 vless:// 协议，符合 Clash.Meta 要求"""
    try:
        parsed = urllib.parse.urlparse(url)
        uuid = parsed.netloc.split('@')[0]
        server_port = parsed.netloc.split('@')[1]
        server, port = server_port.split(':')
        params = urllib.parse.parse_qs(parsed.query)
        node = {
            'type': 'vless',
            'name': f"vless-{index}-{server}",
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'encryption': params.get('encryption', ['none'])[0],
            'flow': params.get('flow', [''])[0],
            'tls': params.get('security', [''])[0] == 'tls',
            'servername': params.get('sni', [''])[0]
        }
        if not all([node['server'], node['port'], node['uuid']]):
            print(f"Skipping vless node {url}: missing required fields")
            return None
        return node
    except Exception as e:
        print(f"Error parsing vless {url}: {e}")
        return None

def parse_hysteria2(url, index):
    """解析 hysteria2:// 协议，符合 Clash.Meta 要求"""
    try:
        parsed = urllib.parse.urlparse(url)
        password = parsed.netloc.split('@')[0]
        server_port = parsed.netloc.split('@')[1]
        server, port = server_port.split(':')
        params = urllib.parse.parse_qs(parsed.query)
        node = {
            'type': 'hysteria2',
            'name': f"hysteria2-{index}-{server}",
            'server': server,
            'port': int(port),
            'password': password,
            'sni': params.get('sni', [''])[0],
            'skip-cert-verify': params.get('insecure', ['0'])[0] == '1'
        }
        if not all([node['server'], node['port'], node['password']]):
            print(f"Skipping hysteria2 node {url}: missing required fields")
            return None
        return node
    except Exception as e:
        print(f"Error parsing hysteria2 {url}: {e}")
        return None

def normalize_nodes(url, output_path):
    # 支持的协议及其解析函数
    supported_protocols = {
        'hysteria2://': parse_hysteria2,
        'vmess://': parse_vmess,
        'trojan://': parse_trojan,
        'ss://': parse_ss,
        'ssr://': parse_ssr,
        'vless://': parse_vless
    }
    
    # 获取数据
    try:
        response = requests.get(url)
        response.raise_for_status()
        lines = response.text.splitlines()
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return
    
    # 规范化处理
    proxies = []
    for index, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):  # 忽略空行和注释
            continue
        # 检查协议并解析
        for protocol, parser in supported_protocols.items():
            if line.startswith(protocol):
                node = parser(line, index)
                if node:
                    proxies.append(node)
                break
        else:
            print(f"Skipping unsupported protocol: {line}")
    
    # 去重（基于 name 字段）
    seen_names = set()
    unique_proxies = []
    for proxy in proxies:
        if proxy['name'] not in seen_names:
            seen_names.add(proxy['name'])
            unique_proxies.append(proxy)
    
    # 按协议排序
    unique_proxies.sort(key=lambda x: x['type'])
    
    # 输出 YAML 格式
    output = {'proxies': unique_proxies}
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # 写入输出文件
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(output, f, allow_unicode=True, sort_keys=False)

if __name__ == '__main__':
    input_url = 'https://raw.githubusercontent.com/qjlxg/vt/main/data/sub_2.txt'
    output_path = 'data/sub_3.txt'
    normalize_nodes(input_url, output_path)
