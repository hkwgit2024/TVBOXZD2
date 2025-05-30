import requests
import os
import re
import base64
import yaml
from urllib.parse import quote
from datetime import datetime

# GitHub API 基础 URL（用于检查速率限制）
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub Personal Access Token
GITHUB_TOKEN = os.getenv("BOT")

# 输入和输出文件路径
input_file = "data/hy2.txt"
output_file = "data/nodes.txt"

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 存储提取的节点
nodes = []

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

# 提取节点
def extract_nodes_from_url(url):
    extracted_nodes = []
    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        content = response.text

        # 提取明文协议
        protocol_matches = protocol_pattern.findall(content)
        for match in protocol_matches:
            node = match.strip()
            extracted_nodes.append(node)
            print(f"提取明文节点: {node[:50]}... 从 {url}")

        # 提取 Base64 编码协议
        base64_matches = base64_pattern.findall(content)
        for b64_str in base64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8')
                if protocol_pattern.search(decoded):
                    node = decoded.strip()
                    extracted_nodes.append(node)
                    print(f"提取 Base64 解码节点: {node[:50]}... 从 {url}")
                # 尝试解析为 JSON（vmess:// 常见格式）
                try:
                    json_data = json.loads(decoded)
                    if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                        # 转换为 vmess:// 格式（简化为 JSON 字符串）
                        node = f"vmess://{base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')}"
                        extracted_nodes.append(node)
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
                            # 转换为标准协议格式（如 ss://）
                            if proxy.get('type') == 'ss':
                                cipher = proxy.get('cipher', 'chacha20-ietf-poly1305')
                                password = proxy.get('password', '')
                                server = proxy.get('server', '')
                                port = proxy.get('port', 0)
                                if server and port and password:
                                    # 构造 ss:// 格式
                                    auth_str = f"{cipher}:{password}"
                                    encoded_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
                                    node = f"ss://{encoded_auth}@{server}:{port}"
                                    if proxy.get('name'):
                                        node += f"#{quote(proxy['name'], safe='')}"
                                    extracted_nodes.append(node)
                                    print(f"提取 YAML SS 节点: {node[:50]}... 从 {url}")
                            else:
                                # 其他类型保留原始 YAML 结构
                                node = yaml.dump([proxy], allow_unicode=True, sort_keys=False).strip()
                                extracted_nodes.append(node)
                                print(f"提取 YAML 节点: {node[:50]}... 从 {url}")
            except yaml.YAMLError as e:
                print(f"YAML 解析失败: {url} ({e})")

    except requests.exceptions.RequestException as e:
        print(f"获取 {url} 内容失败: {e}")
    
    return extracted_nodes

# 处理每个 URL
for url in urls:
    print(f"处理 URL: {url}")
    nodes.extend(extract_nodes_from_url(url))
    time.sleep(1)  # 避免触发速率限制

# 去重节点
nodes = list(set(nodes))

# 保存节点到 data/nodes.txt
with open(output_file, "w", encoding="utf-8") as f:
    for node in nodes:
        f.write(node + "\n")

print(f"提取 {len(nodes)} 个唯一节点，已保存到 {output_file}")
