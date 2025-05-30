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
debug_log_file = "data/extract_debug.log"

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 存储提取的节点
protocol_nodes = []
yaml_nodes = []
debug_logs = []

# 设置请求头
headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    debug_logs.append("警告：未找到 BOT 环境变量，将使用未认证请求（速率限制较低）")

# 检查速率限制
try:
    response = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=10)
    rate_limit = response.json()
    debug_logs.append(f"速率限制: {rate_limit['rate']['remaining']} 剩余, 重置时间: {rate_limit['rate']['reset']}")
except requests.exceptions.RequestException as e:
    debug_logs.append(f"检查速率限制失败: {e}")

# 正则表达式匹配协议（放宽匹配）
protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s]+', re.MULTILINE | re.IGNORECASE)
# 正则表达式匹配 Base64 字符串（放宽长度）
base64_pattern = re.compile(r'[A-Za-z0-9+/=]{8,}', re.MULTILINE)

# 读取 data/hy2.txt
try:
    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip().split("|")[0] for line in f if line.strip()]
    debug_logs.append(f"从 {input_file} 读取 {len(urls)} 个 URL")
except FileNotFoundError:
    debug_logs.append(f"错误：未找到 {input_file}")
    exit(1)

# 转换 YAML 到协议 URL
def yaml_to_protocol(proxy):
    proxy_type = proxy.get('type', '').lower()
    server = proxy.get('server', '')
    port = proxy.get('port', 0)
    name = proxy.get('name', '')

    if not server or not port:
        return None

    try:
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
    except Exception as e:
        debug_logs.append(f"YAML 转换失败: {proxy.get('name', '未知')} ({e})")
    return None

# 提取节点
def extract_nodes_from_url(url):
    extracted_protocol_nodes = []
    extracted_yaml_nodes = []
    debug_logs.append(f"\n处理 URL: {url}")
    
    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        content = response.text[:1000]  # 限制内容长度，加快处理
        debug_logs.append(f"获取 {url} 内容成功，长度: {len(content)}")

        # 保存内容片段用于调试
        debug_logs.append(f"内容前100字符: {content[:100].replace('\n', ' ')}")

        # 提取明文协议
        protocol_matches = protocol_pattern.finditer(content)
        for match in protocol_matches:
            node = match.group(0).strip()
            extracted_protocol_nodes.append(node)
            debug_logs.append(f"提取明文节点: {node[:50]}...")

        # 提取 Base64 编码协议
        base64_matches = base64_pattern.findall(content)
        debug_logs.append(f"找到 {len(base64_matches)} 个 Base64 字符串")
        for b64_str in base64_matches:
            try:
                decoded = base64.b64decode(b64_str, validate=True).decode('utf-8')
                debug_logs.append(f"Base64 解码: {decoded[:50]}...")
                if protocol_pattern.search(decoded):
                    node = decoded.strip()
                    extracted_protocol_nodes.append(node)
                    debug_logs.append(f"提取 Base64 解码节点: {node[:50]}...")
                # 尝试解析为 JSON（vmess://）
                try:
                    json_data = json.loads(decoded)
                    if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                        node = f"vmess://{base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')}"
                        extracted_protocol_nodes.append(node)
                        debug_logs.append(f"提取 Base64 JSON 节点: {node[:50]}...")
                except json.JSONDecodeError:
                    pass
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                debug_logs.append(f"Base64 解码失败: {b64_str[:20]}... ({e})")

        # 提取 YAML 格式节点
        file_extension = os.path.splitext(url)[1].lower()
        if file_extension in ['.yaml', '.yml', '.txt'] or not file_extension:
            try:
                yaml_data = yaml.safe_load(content)
                if isinstance(yaml_data, dict):
                    # 检查可能的 proxies 字段
                    for key in ['proxies', 'proxy', 'nodes', 'servers']:
                        if key in yaml_data:
                            for proxy in yaml_data.get(key, []):
                                if isinstance(proxy, dict) and any(k in proxy for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                    protocol_node = yaml_to_protocol(proxy)
                                    if protocol_node:
                                        extracted_protocol_nodes.append(protocol_node)
                                        debug_logs.append(f"提取 YAML 协议节点: {protocol_node[:50]}...")
                                    extracted_yaml_nodes.append(proxy)
                                    debug_logs.append(f"提取 YAML 节点: {yaml.dump([proxy], allow_unicode=True, sort_keys=False)[:50]}...")
                else:
                    debug_logs.append(f"YAML 数据不是字典: {type(yaml_data)}")
            except yaml.YAMLError as e:
                debug_logs.append(f"YAML 解析失败: {url} ({e})")

    except requests.exceptions.RequestException as e:
        debug_logs.append(f"获取 {url} 内容失败: {e}")

    return extracted_protocol_nodes, extracted_yaml_nodes

# 处理每个 URL
urls = list(set(urls))  # 去重 URL
for url in urls:
    p_nodes, y_nodes = extract_nodes_from_url(url)
    protocol_nodes.extend(p_nodes)
    yaml_nodes.extend(y_nodes)
    time.sleep(0.5)  # 减小延时，提高效率

# 去重节点
protocol_nodes = list(dict.fromkeys(protocol_nodes))  # 保留顺序去重
yaml_nodes = list({yaml.dump(node, allow_unicode=True, sort_keys=False): node for node in yaml_nodes}.values())
debug_logs.append(f"\n总计提取 {len(protocol_nodes)} 个协议节点")
debug_logs.append(f"总计提取 {len(yaml_nodes)} 个 YAML 节点")

# 保存协议节点
with open(protocol_output_file, "w", encoding="utf-8") as f:
    for node in protocol_nodes:
        f.write(node + "\n")

# 保存 YAML 节点
with open(yaml_output_file, "w", encoding="utf-8") as f:
    if yaml_nodes:
        yaml.dump({"proxies": yaml_nodes}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    else:
        f.write("# No YAML nodes found\n")

# 保存调试日志
with open(debug_log_file, "w", encoding="utf-8") as f:
    f.write("\n".join(debug_logs))

print(f"提取 {len(protocol_nodes)} 个协议节点，已保存到 {protocol_output_file}")
print(f"提取 {len(yaml_nodes)} 个 YAML 节点，已保存到 {yaml_output_file}")
print(f"调试日志已保存到 {debug_log_file}")
