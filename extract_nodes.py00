import aiohttp
import asyncio
import os
import re
import base64
import yaml
import json
import time
from urllib.parse import quote
from datetime import datetime

# GitHub API 基础 URL
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub Personal Access Token
GITHUB_TOKEN = os.getenv("BOT")

# 放宽的搜索词，增加覆盖率
search_terms = [
    "proxies type:",  # 通用 YAML 代理配置
    "server: port:",  # 通用服务器配置
    "vless://", "vmess://", "trojan://", "ss://", "hysteria2://",  # 明文协议
    "filename:*.yaml", "filename:*.yml",  # 匹配所有 YAML 文件
    "proxy:", "nodes:", "servers:",  # 其他代理关键词
]

# 保存结果的文件路径
output_file = "data/hy2.txt"
invalid_urls_file = "data/invalid_urls.txt"
debug_log_file = "data/search_debug.log"

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 存储日志
debug_logs = []

# 加载已知的无效 URL
async def load_known_invalid_urls():
    known_invalid_urls = set()
    try:
        if os.path.exists(invalid_urls_file):
            with open(invalid_urls_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                max_invalid_urls_to_load = 1000
                for line in lines[-max_invalid_urls_to_load:]:
                    url_part = line.strip().split("|")[0]
                    if url_part:
                        known_invalid_urls.add(url_part)
            debug_logs.append(f"加载 {len(known_invalid_urls)} 个已知无效 URL。")
    except Exception as e:
        debug_logs.append(f"加载无效 URL 失败: {e}")
    return known_invalid_urls

# 设置请求头
headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    debug_logs.append("警告：未找到 BOT 环境变量，将使用未认证请求（速率限制较低）")

# 检查 GitHub API 速率限制
async def check_rate_limit(session):
    try:
        async with session.get("https://api.github.com/rate_limit", headers=headers) as response:
            response.raise_for_status()
            rate_limit = await response.json()
            debug_logs.append(f"GitHub API 速率限制: {rate_limit['rate']['remaining']} 剩余，重置时间: {datetime.fromtimestamp(rate_limit['rate']['reset'])}。")
            return rate_limit['rate']['remaining']
    except Exception as e:
        debug_logs.append(f"检查速率限制失败: {e}")
        return 0

# 正则表达式匹配协议（放宽）
protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s<>"\'`]+', re.MULTILINE | re.IGNORECASE)
base64_pattern = re.compile(r'[A-Za-z0-9+/=]{8,}', re.MULTILINE)

# 无关扩展名
irrelevant_extensions = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
    '.md', '.markdown', '.rst',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.exe', '.dll', '.bin', '.so', '.lib',
    '.log', '.gitignore', '.editorconfig', '.gitattributes', '.iml',
    '.svg', '.xml', '.html', '.htm', '.css', '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.c', '.cpp', '.h', '.hpp', '.php', '.go', '.rs', '.swift', '.kt', '.sh', '.bash', '.ps1', '.bat', '.cmd', '.rb', '.pl'
}

# 验证文件内容
async def verify_content(session, url, known_invalid_urls, debug_logs):
    if url in known_invalid_urls:
        debug_logs.append(f"跳过已知无效 URL: {url}")
        return False

    file_extension = os.path.splitext(url)[1].lower()
    if file_extension in irrelevant_extensions and file_extension != '.txt':
        debug_logs.append(f"跳过无关扩展名文件: {url} ({file_extension})")
        return False

    raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        async with session.get(raw_url, headers=headers, timeout=20) as response:
            response.raise_for_status()
            content = await response.text()
            content = content[:1000000]  # 增加到 1MB

            # 1. 明文协议
            if protocol_pattern.search(content):
                debug_logs.append(f"找到明文协议: {url}")
                return True

            # 2. Base64
            base64_matches = base64_pattern.findall(content)
            for b64_str in base64_matches:
                try:
                    decoded = base64.b64decode(b64_str, validate=True).decode('utf-8')
                    if protocol_pattern.search(decoded):
                        debug_logs.append(f"找到 Base64 解码协议: {url}")
                        return True
                    try:
                        json_data = json.loads(decoded)
                        if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                            debug_logs.append(f"找到 Base64 JSON 协议: {url}")
                            return True
                    except json.JSONDecodeError:
                        pass
                except (base64.binascii.Error, UnicodeDecodeError):
                    continue

            # 3. YAML/JSON
            if file_extension in {'.yaml', '.yml', '.conf', '.json', '.txt'} or not file_extension:
                try:
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict):
                        for key in ['proxies', 'proxy', 'nodes', 'servers', 'outbounds']:
                            if key in yaml_data and isinstance(yaml_data[key], (list, dict)):
                                if isinstance(yaml_data[key], list):
                                    for proxy in yaml_data[key]:
                                        if isinstance(proxy, dict) and any(k in proxy for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                            debug_logs.append(f"找到 YAML/JSON 代理配置: {url}")
                                            return True
                                elif isinstance(yaml_data[key], dict):
                                    if any(k in yaml_data[key] for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                        debug_logs.append(f"找到 YAML/JSON 单代理配置: {url}")
                                        return True
                except (yaml.YAMLError, json.JSONDecodeError):
                    pass

            debug_logs.append(f"未在 {url} 中找到目标协议或有效配置。")
            return False

    except aiohttp.ClientError as e:
        debug_logs.append(f"获取 {url} 内容失败 (网络/HTTP 错误): {e}")
        return False
    except asyncio.TimeoutError:
        debug_logs.append(f"获取 {url} 内容超时。")
        return False
    except Exception as e:
        debug_logs.append(f"验证 {url} 发生未知错误: {e}")
        return False

# 搜索并处理
async def search_and_process(session, term, max_pages, max_urls_to_find, known_invalid_urls, found_urls_set):
    page = 1
    current_search_count = 0
    while page <= max_pages:
        if GITHUB_TOKEN:
            remaining = await check_rate_limit(session)
            if remaining < 10:
                reset_time_response = await session.get("https://api.github.com/rate_limit", headers=headers)
                reset_data = await reset_time_response.json()
                reset_timestamp = reset_data['rate']['reset']
                wait_time = max(0, reset_timestamp - int(time.time())) + 5
                debug_logs.append(f"速率限制接近，等待 {wait_time} 秒。")
                await asyncio.sleep(wait_time)

        params = {
            "q": quote(term, safe=''),
            "per_page": 100,
            "page": page
        }
        debug_logs.append(f"搜索 '{term}' (第 {page} 页)...")
        try:
            async with session.get(SEARCH_API_URL, headers=headers, params=params, timeout=20) as response:
                response.raise_for_status()
                data = await response.json()
        except aiohttp.ClientError as e:
            debug_logs.append(f"搜索 '{term}' (第 {page} 页) 失败: {e}")
            break
        except asyncio.TimeoutError:
            debug_logs.append(f"搜索 '{term}' (第 {page} 页) 超时。")
            break
        except Exception as e:
            debug_logs.append(f"搜索 '{term}' (第 {page} 页) 错误: {e}")
            break

        items = data.get("items", [])
        debug_logs.append(f"搜索 '{term}' (第 {page} 页) 找到 {len(items)} 条结果。")

        if not items:
            break

        urls_and_coroutines = []
        for item in items:
            html_url = item["html_url"]
            if any(ext in html_url.lower() for ext in ['gfwlist', 'proxygfw', 'gfw.txt', 'gfw.pac']):
                debug_logs.append(f"跳过无关文件: {html_url}")
                continue
            if html_url in known_invalid_urls:
                debug_logs.append(f"跳过已知无效 URL: {html_url}")
                continue
            if html_url not in found_urls_set:
                urls_and_coroutines.append((html_url, verify_content(session, html_url, known_invalid_urls, debug_logs)))

        coroutines = [coro for _, coro in urls_and_coroutines]
        results = await asyncio.gather(*coroutines, return_exceptions=True)

        for i, result in enumerate(results):
            original_url = urls_and_coroutines[i][0]
            if result is True:
                found_urls_set.add(f"{original_url}|{datetime.now().isoformat()}")
                current_search_count += 1
                debug_logs.append(f"有效 URL: {original_url} (已找到 {current_search_count})")
            elif isinstance(result, Exception):
                debug_logs.append(f"验证 {original_url} 异常: {result}")
            else:
                debug_logs.append(f"URL {original_url} 未通过验证。")

            if current_search_count >= max_urls_to_find:
                debug_logs.append(f"达到 {max_urls_to_find} 个 URL，停止搜索。")
                return

        page += 1
        await asyncio.sleep(2 if GITHUB_TOKEN else 5)

    debug_logs.append(f"搜索 '{term}' 完成。")

async def main():
    async with aiohttp.ClientSession() as session:
        known_invalid_urls = await load_known_invalid_urls()
        found_urls_set = set()

        initial_rate_limit = await check_rate_limit(session)
        if initial_rate_limit == 0 and GITHUB_TOKEN:
            debug_logs.append("初始速率限制为 0，无法搜索。")
            return

        max_urls_to_find = 100  # 目标 100 个 URL
        max_pages_per_term = 5  # 每词搜索 5 页

        for term in search_terms:
            await search_and_process(session, term, max_pages_per_term, max_urls_to_find, known_invalid_urls, found_urls_set)
            if len(found_urls_set) >= max_urls_to_find:
                break

        found_urls_list = sorted(list(found_urls_set))
        with open(output_file, "w", encoding="utf-8") as f:
            for url_entry in found_urls_list:
                f.write(url_entry + "\n")
        debug_logs.append(f"找到 {len(found_urls_list)} 个 URL，已保存到 {output_file}")
        print(f"找到 {len(found_urls_list)} 个 URL，已保存到 {output_file}")

        with open(debug_log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(debug_logs))
        print(f"调试日志已保存到 {debug_log_file}")

if __name__ == "__main__":
    asyncio.run(main())
