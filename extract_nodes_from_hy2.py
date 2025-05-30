import requests
import os
import re
import base64
import yaml
import json
from urllib.parse import quote, urlencode
from datetime import datetime

# GitHub API 基础 URL（用于检查速率限制）
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub Personal Access Token
GITHUB_TOKEN = os.getenv("BOT")

# 输入和输出文件路径
input_file = "data/hy2.txt"
protocol_output_file = "data/protocol_nodes.txt"
yaml_output_file = "data/yaml_nodes.yaml"

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 存储提取的节点
protocol_nodes = []
yaml_nodes = []

# 设置请求头
headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    print("警告：未找到 BOT 环境变量，将使用未认证请求（速率限制较低）")

# 检查速率限制
try:
    response = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=10)
    rate_limit = response.json()
    print(f"速率限制: {rate_limit['rate']['remaining']} 剩余, 重置时间: {rate_limit['rate']['reset']}")
except requests.exceptions.RequestException as e:
    print(f"检查速率限制失败: {e}")

# 正则表达式匹配协议（明文）
protocol_pattern = re.compile(r'^(ss|hysteria2|vless|vmess|trojan)://[^\s]+', re.MULTILINE)
# 正则表达式匹配 Base64 字符串（可能的代理配置）
base64_pattern = re.compile(r'[A-Za-z0-9+/=]{20,}', re.MULTILINE)

# 读取 data/hy2.txt
try:
    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip().split("|")[0] for line in f if line.strip()]
    print(f"从 {input_file} 读取 {len(urls)} 个 URL")
except FileNotFoundError:
    print(f"错误：未找到 {input_file}")
    exit(1)

# 转换 YAML 到协议 URL
def yaml_to_protocol(proxy):
    proxy_type = proxy.get('type')
    server = proxy.get('server', '')
    port = proxy.get('port', 0)
    name = proxy.get('name', '')

    if not server or not port:
        return None

    if proxy_type == 'ss':
        cipher = proxy.get('cipher', 'chacha20-ietf-poly1305')
        password = proxy.get('password', '')
        if password:
            auth_str = f"{cipher}:{password}"
            encoded_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            node = f"ss://{encoded_auth}@{server}:{port}"
            if name:
                node += f"#{quote(name, safe='')}"
            return node
    elif proxy_type == 'hysteria2':
        password = proxy.get('password', '')
        node = f"hysteria2://{password}@{server}:{port}"
        if name:
            node += f"#{quote(name, safe='')}"
        return node
    elif proxy_type == 'trojan':
        password = proxy.get('password', '')
        node = f"trojan://{password}@{server}:{port}"
        if name:
            node += f"#{quote(name, safe='')}"
        return node
    elif proxy_type == 'vmess':
        vmess_config = {
            "v": "2",
            "ps": name,
            "add": server,
            "port": port,
            "id": proxy.get('uuid', ''),
            "aid": proxy.get('alterId', 0),
            "net": proxy.get('network', 'tcp'),
            "type": proxy.get('headerType', 'none'),
            "tls": proxy.get('tls', ''),
            "sni": proxy.get('servername', '')
        }
        encoded_vmess = base64.b64encode(json.dumps(vmess_config).encode('utf-8')).decode('utf-8')
        node = f"vmess://{encoded_vmess}"
        return node
    elif proxy_type == 'vless':
        uuid = proxy.get('uuid', '')
        node = f"vless://{uuid}@{server}:{port}?"
        params = {}
        if proxy.get('tls'):
            params['security'] = 'tls'
        if proxy.get('servername'):
            params['sni'] = proxy.get('servername')
        if proxy.get('network'):
            params['type'] = proxy.get('network')
        if params:
            node += urlencode(params)
        if name:
            node += f"#{quote(name, safe='')}"
        return node
    return None

# 提取节点
def extract_nodes_from_url(url):
    extracted_protocol_nodes = []
    extracted_yaml_nodes = []
    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        content = response.text

        # 提取明文协议
        protocol_matches = protocol_pattern.findall(content)
        for match in protocol_matches:
            node = match.strip()
            extracted_protocol_nodes.append(node)
            print(f"提取明文节点: {node[:50]}... 从 {url}")

        # 提取 Base64 编码协议
        base64_matches = base64_pattern.findall(content)
        for b64_str in base64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8')
                if protocol_pattern.search(decoded):
                    node = decoded.strip()
                    extracted_protocol_nodes.append(node)
                    print(f"提取 Base64 解码节点: {node[:50]}... 从 {url}")
                # 尝试解析为 JSON（vmess:// 常见格式）
                try:
                    json_data = json.loads(decoded)
                    if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                        node = f"vmess://{base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')}"
                        extracted_protocol_nodes.append(node)
                        print(f"提取 Base64 JSON 节点: {node[:50]}... 从 {url}")
                except json.JSONDecodeError:
                    pass
            except (base64.binascii.Error, UnicodeDecodeError):
                continue

        # 提取 YAML 格式节点
        file_extension = os.path.splitext(url)[1].lower()
        if file_extension in ['.yaml', '.yml', '.txt'] or not file_extension:
            try:
                yaml_data = yaml.safe_load(content)
                if isinstance(yaml_data, dict) and 'proxies' in yaml_data:
                    for proxy in yaml_data.get('proxies', []):
                        if isinstance(proxy, dict) and (
                            proxy.get('type') in ['ss', 'hysteria2', 'vless', 'vmess', 'trojan'] or
                            any(key in proxy for key in ['server', 'port', 'cipher', 'password', 'uuid'])
                        ):
                            # 尝试转换为协议 URL
                            protocol_node = yaml_to_protocol(proxy)
                            if protocol_node:
                                extracted_protocol_nodes.append(protocol_node)
                                print(f"提取 YAML 协议节点: {protocol_node[:50]}... 从 {url}")
                            # 保留原始 YAML 结构
                            extracted_yaml_nodes.append(proxy)
                            print(f"提取 YAML 节点: {yaml.dump([proxy], allow_unicode=True, sort_keys=False)[:50]}... 从 {url}")
            except yaml.YAMLError as e:
                print(f"YAML 解析失败: {url} ({e})")

    except requests.exceptions.RequestException as e:
        print(f"获取 {url} 内容失败: {e}")
    
    return extracted_protocol_nodes, extracted_yaml_nodes

# 处理每个 URL
for url in urls:
    print(f"处理 URL: {url}")
    p_nodes, y_nodes = extract_nodes_from_url(url)
    protocol_nodes.extend(p_nodes)
    yaml_nodes.extend(y_nodes)
    time.sleep(1)  # 避免触发速率限制

# 去重节点
protocol_nodes = list(set(protocol_nodes))
yaml_nodes = list({yaml.dump(node, allow_unicode=True, sort_keys=False): node for node in yaml_nodes}.values())

# 保存协议节点到 data/protocol_nodes.txt
with open(protocol_output_file, "w", encoding="utf-8") as f:
    for node in protocol_nodes:
        f.write(node + "\n")

# 保存 YAML 节点到 data/yaml_nodes.yaml
with open(yaml_output_file, "w", encoding="utf-8") as f:
    if yaml_nodes:
        yaml.dump({"proxies": yaml_nodes}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

print(f"提取 {len(protocol_nodes)} 个协议节点，已保存到 {protocol_output_file}")
print(f"提取 {len(yaml_nodes)} 个 YAML 节点，已保存到 {yaml_output_file}")
