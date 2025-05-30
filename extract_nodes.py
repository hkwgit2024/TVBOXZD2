import requests
import os
import json
import time
import re
import base64
import yaml
from urllib.parse import quote
from datetime import datetime

# GitHub API 基础 URL
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub Personal Access Token
GITHUB_TOKEN = os.getenv("BOT")

# 搜索词
search_terms = ["ss://", "hysteria2://", "vless://", "vmess://", "trojan://"]

# 保存结果的文件路径
output_file = "data/hy2.txt"
invalid_urls_file = "data/invalid_urls.txt"

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 存储有效和无效 URL
found_urls = []
invalid_urls = []

# 加载已知的无效 URL
known_invalid_urls = set()
if os.path.exists(invalid_urls_file):
    with open(invalid_urls_file, "r", encoding="utf-8") as f:
        for line in f:
            url = line.strip().split("|")[0]  # 提取 URL，忽略时间戳
            known_invalid_urls.add(url)

# 设置请求头
headers = {
    "Accept": "application/vnd.github.v3+json"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    print("警告：未找到 BOT 环境

变量，将使用未认证请求（速率限制较低）")

# 检查速率限制
response = requests.get("https://api.github.com/rate_limit", headers=headers)
rate_limit = response.json()
print(f"速率限制: {rate_limit['rate']['remaining']} 剩余, 重置时间: {rate_limit['rate']['reset']}")

# 正则表达式匹配协议（明文）
protocol_pattern = re.compile(r'^(ss|hysteria2|vless|vmess|trojan)://', re.MULTILINE)
# 正则表达式匹配 Base64 字符串（可能的代理配置）
base64_pattern = re.compile(r'[A-Za-z0-9+/=]{20,}', re.MULTILINE)

# 无关扩展名（不太可能包含代理配置）
irrelevant_extensions = [
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',  # 图片
    '.md', '.markdown', '.rst',  # 文档
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',  # 办公文件
    '.zip', '.tar', '.gz', '.rar',  # 压缩文件
    '.exe', '.dll', '.bin',  # 可执行文件
]

# 优先扩展名（可能包含代理配置）
priority_extensions = [
    '.yaml', '.yml',  # Clash 配置
    '.conf',  # 通用配置文件
    '.json',  # JSON 格式配置
    '.txt',  # 文本文件（需进一步检查）
]

# 验证文件内容是否包含目标协议
def verify_content(url):
    if url in known_invalid_urls:
        print(f"跳过已知无效 URL: {url}")
        return False

    # 检查扩展名
    file_extension = os.path.splitext(url)[1].lower()
    if file_extension in irrelevant_extensions:
        print(f"跳过无关扩展名文件: {url} ({file_extension})")
        return False

    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        content = response.text

        # 检查明文协议
        if protocol_pattern.search(content):
            print(f"找到明文协议: {url}")
            return True

        # 检查 Base64 编码
        base64_matches = base64_pattern.findall(content)
        for b64_str in base64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8')
                if protocol_pattern.search(decoded):
                    print(f"找到 Base64 解码协议: {url}")
                    return True
                # 尝试解析为 JSON（vmess:// 常见格式）
                try:
                    json_data = json.loads(decoded)
                    if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                        print(f"找到 Base64 JSON 协议: {url}")
                        return True
                except json.JSONDecodeError:
                    pass
            except (base64.binascii.Error, UnicodeDecodeError):
                continue

        # 检查 YAML 格式（优先扩展名）
        if file_extension in ['.yaml', '.yml']:
            try:
                yaml_data = yaml.safe_load(content)
                if isinstance(yaml_data, dict) and 'proxies' in yaml_data:
                    for proxy in yaml_data.get('proxies', []):
                        if isinstance(proxy, dict) and proxy.get('type') in ['ss', 'hysteria2', 'vless', 'vmess', 'trojan']:
                            print(f"找到 YAML 协议: {url}")
                            return True
            except yaml.YAMLError:
                pass

        return False
    except requests.exceptions.RequestException as e:
        print(f"验证 {url} 失败: {e}")
        return False

# 搜索并重试
def search_with_retry(term, page, max_retries=3):
    for attempt in range(max_retries):
        try:
            print(f"尝试搜索 {term}（第 {page} 页），第 {attempt+1} 次")
            response = requests.get(SEARCH_API_URL, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            print(f"完成搜索 {term}（第 {page} 页），状态码: {response.status_code}")
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(f"搜索 {term}（第 {page} 页）失败，第 {attempt+1} 次重试: {e}")
                time.sleep(5 * (attempt + 1))
            else:
                raise e
        except requests.exceptions.RequestException as e:
            print(f"搜索 {term}（第 {page} 页）失败，第 {attempt+1} 次重试: {e}")
            time.sleep(5 * (attempt + 1))
    print(f"搜索 {term}（第 {page} 页）失败，已达最大重试次数")
    return {"items": []}

# 遍历搜索词
max_pages = 5
max_urls = 100  # 限制最多验证 100 个 URL
for term in search_terms:
    page = 1
    while page <= max_pages:
        params = {
            "q": quote(term, safe=''),
            "per_page": 100,
            "page": page
        }
        print(f"开始搜索 {term}（第 {page} 页）")
        data = search_with_retry(term, page)
        items = data.get("items", [])
        print(f"完成搜索 {term}（第 {page} 页），找到 {len(items)} 条结果")
        if not items:
            break
        for item in items:
            html_url = item["html_url"]
            # 跳过已知无关文件
            if any(ext in html_url.lower() for ext in ['gfwlist', 'proxygfw', 'gfw.txt', 'gfw.pac', 'domain.yml', 'proxy.yaml']):
                print(f"跳过无关文件: {html_url}")
                invalid_urls.append(f"{html_url}|{datetime.now().isoformat()}")
                continue
            # 检查扩展名
            file_extension = os.path.splitext(html_url)[1].lower()
            if file_extension in irrelevant_extensions:
                print(f"跳过无关扩展名文件: {html_url} ({file_extension})")
                invalid_urls.append(f"{html_url}|{datetime.now().isoformat()}")
                continue
            print(f"验证文件: {html_url}")
            if verify_content(html_url):
                found_urls.append(f"{html_url}|{datetime.now().isoformat()}")
                print(f"有效 URL: {html_url}")
            else:
                invalid_urls.append(f"{html_url}|{datetime.now().isoformat()}")
                print(f"无效 URL: {html_url}（不包含目标协议）")
            if len(found_urls) >= max_urls:
                break
        if len(found_urls) >= max_urls:
            break
        page += 1
        time.sleep(5)
    if len(found_urls) >= max_urls:
        break

# 去重 URL
found_urls = list(set(found_urls))
invalid_urls = list(set(invalid_urls))

# 保存有效 URL 到 data/hy2.txt
with open(output_file, "w", encoding="utf-8") as f:
    for url in found_urls:
        f.write(url + "\n")

# 保存无效 URL 到 data/invalid_urls.txt
with open(invalid_urls_file, "a", encoding="utf-8") as f:
    for url in invalid_urls:
        f.write(url + "\n")

print(f"找到 {len(found_urls)} 个包含目标协议的唯一 URL，已保存到 {output_file}")
print(f"找到 {len(invalid_urls)} 个无效 URL，已保存到 {invalid_urls_file}")
