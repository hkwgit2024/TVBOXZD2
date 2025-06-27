import requests
import os
import base64
import json
import urllib.parse

def parse_vmess(url, index):
    """解析 vmess:// 协议，验证必填字段，输出明文"""
    try:
        if '://' not in url:
            print(f"Skipping vmess node {url}: missing protocol separator")
            return None
        data = base64.b64decode(url.replace('vmess://', '')).decode('utf-8')
        config = json.loads(data)
        server = config.get('add')
        port = config.get('port')
        uuid = config.get('id')
        alterId = config.get('aid', '0')
        cipher = config.get('scy', 'auto')
        if not all([server, port, uuid]):
            print(f"Skipping vmess node {url}: missing required fields")
            return None
        return f"vmess {server} {port} uuid={uuid} alterId={alterId} cipher={cipher} name=vmess-{index}-{server}"
    except Exception as e:
        print(f"Error parsing vmess {url}: {e}")
        return None

def parse_trojan(url, index):
    """解析 trojan:// 协议，验证必填字段，输出明文"""
    try:
        if '://' not in url:
            print(f"Skipping trojan node {url}: missing protocol separator")
            return None
        parsed = urllib.parse.urlparse(url)
        password = parsed.netloc.split('@')[0]
        server_port = parsed.netloc.split('@')[1]
        server, port = server_port.split(':')
        params = urllib.parse.parse_qs(parsed.query)
        if not all([server, port, password]):
            print(f"Skipping trojan node {url}: missing required fields")
            return None
        return f"trojan {server} {port} password={password} sni={params.get('sni', [''])[0]} name=trojan-{index}-{server}"
    except Exception as e:
        print(f"Error parsing trojan {url}: {e}")
        return None

def parse_ss(url, index):
    """解析 ss:// 协议，验证必填字段，输出明文"""
    try:
        if '://' not in url:
            print(f"Skipping ss node {url}: missing protocol separator")
            return None
        parsed = urllib.parse.urlparse(url)
        method_password = parsed.netloc.split('@')[0]
        if method_password.startswith('Y2'):  # Base64 编码
            method_password = base64.b64decode(method_password).decode('utf-8')
        method, password = method_password.split(':')
        server, port = parsed.netloc.split('@')[1].split(':')
        if not all([server, port, method, password]):
            print(f"Skipping ss node {url}: missing required fields")
            return None
        return f"ss {server} {port} cipher={method} password={password} name=ss-{index}-{server}"
    except Exception as e:
        print(f"Error parsing ss {url}: {e}")
        return None

def parse_ssr(url, index):
    """解析 ssr:// 协议，验证必填字段，输出明文"""
    try:
        if '://' not in url:
            print(f"Skipping ssr node {url}: missing protocol separator")
            return None
        data = base64.b64decode(url.replace('ssr://', '')).decode('utf-8')
        parts = data.split(':')
        if len(parts) < 6:
            print(f"Skipping ssr node {url}: incomplete format")
            return None
        server, port, protocol, method, obfs, password = parts[:6]
        password = base64.b64decode(password).decode('utf-8')
        if not all([server, port, protocol, method, obfs, password]):
            print(f"Skipping ssr node {url}: missing required fields")
            return None
        return f"ssr {server} {port} protocol={protocol} cipher={method} obfs={obfs} password={password} name=ssr-{index}-{server}"
    except Exception as e:
        print(f"Error parsing ssr {url}: {e}")
        return None

def parse_vless(url, index):
    """解析 vless:// 协议，验证必填字段，输出明文"""
    try:
        if '://' not in url:
            print(f"Skipping vless node {url}: missing protocol separator")
            return None
        parsed = urllib.parse.urlparse(url)
        uuid = parsed.netloc.split('@')[0]
        server_port = parsed.netloc.split('@')[1]
        server, port = server_port.split(':')
        params = urllib.parse.parse_qs(parsed.query)
        if not all([server, port, uuid]):
            print(f"Skipping vless node {url}: missing required fields")
            return None
        return f"vless {server} {port} uuid={uuid} encryption={params.get('encryption', ['none'])[0]} name=vless-{index}-{server}"
    except Exception as e:
        print(f"Error parsing vless {url}: {e}")
        return None

def parse_hysteria2(url, index):
    """解析 hysteria2:// 协议，验证必填字段，输出明文"""
    try:
        if '://' not in url:
            print(f"Skipping hysteria2 node {url}: missing protocol separator")
            return None
        parsed = urllib.parse.urlparse(url)
        password = parsed.netloc.split('@')[0]
        server_port = parsed.netloc.split('@')[1]
        server, port = server_port.split(':')
        params = urllib.parse.parse_qs(parsed.query)
        if not all([server, port, password]):
            print(f"Skipping hysteria2 node {url}: missing required fields")
            return None
        return f"hysteria2 {server} {port} password={password} sni={params.get('sni', [''])[0]} name=hysteria2-{index}-{server}"
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
    normalized = []
    for index, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):  # 忽略空行和注释
            continue
        # 检查协议分隔符
        if '://' not in line:
            print(f"Skipping invalid link {line}: missing protocol separator")
            continue
        # 检查协议并解析
        for protocol, parser in supported_protocols.items():
            if line.startswith(protocol):
                parsed = parser(line, index)
                if parsed:
                    normalized.append(parsed)
                break
        else:
            print(f"Skipping unsupported protocol: {line}")
    
    # 去重（基于 name 参数）
    seen_names = set()
    unique_nodes = []
    for node in normalized:
        name = node.split('name=')[-1]
        if name not in seen_names:
            seen_names.add(name)
            unique_nodes.append(node)
    
    # 按协议排序
    unique_nodes.sort(key=lambda x: x.split()[0])
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # 写入输出文件
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique_nodes) + '\n')

if __name__ == '__main__':
    input_url = 'https://raw.githubusercontent.com/qjlxg/vt/main/data/sub_2.txt'
    output_path = 'data/sub_3.txt'
    normalize_nodes(input_url, output_path)
