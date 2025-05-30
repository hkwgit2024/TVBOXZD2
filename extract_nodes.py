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

# 优化后的搜索词：更侧重于 YAML 代理配置的关键词
search_terms = [
    "filename:config.yaml proxies type:",
    "filename:config.yml proxies type:",
    "path:*.yaml proxies type:",
    "path:*.yml proxies type:",
    "proxies: type:",
    "server: port: password:",
    "server: port: uuid:",
    "trojan://", "vless://", "vmess://", "ss://", "hysteria2://",
    # "dxzx.flyby-world.top", # 示例域名，如果需要可以取消注释
    # "6c29f92a-674e-4e13-93e0-bd965afc9226" # 示例 UUID，如果需要可以取消注释
]

# 保存结果的文件路径
output_file = "data/hy2.txt"
invalid_urls_file = "data/invalid_urls.txt"
debug_log_file = "data/search_debug.log"

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 存储日志
debug_logs = []

# 加载已知的无效 URL (优化，只保留最新的，并去重)
async def load_known_invalid_urls():
    known_invalid_urls = set()
    try:
        if os.path.exists(invalid_urls_file):
            with open(invalid_urls_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                max_invalid_urls_to_load = 1000 # 限制加载的无效 URL 数量
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
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0; +https://github.com/your-repo)" # 建议提供您的项目URL
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
        return 0 # 假定没有剩余，阻止后续请求

# 正则表达式匹配协议（明文）
protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s<>"\'`]+', re.MULTILINE | re.IGNORECASE)
# 正则表达式匹配 Base64 字符串，长度至少为 20
base64_pattern = re.compile(r'[A-Za-z0-9+/=]{20,}', re.MULTILINE)

# 无关扩展名（不太可能包含代理配置）
irrelevant_extensions = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
    '.md', '.markdown', '.rst', # .txt 在验证时会特殊处理
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.exe', '.dll', '.bin', '.so', '.lib',
    '.log', '.gitignore', '.editorconfig', '.gitattributes', '.iml',
    '.svg', '.xml', '.html', '.htm', '.css', '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.c', '.cpp', '.h', '.hpp', '.php', '.go', '.rs', '.swift', '.kt', '.sh', '.bash', '.ps1', '.bat', '.cmd', '.rb', '.pl'
}

# 验证文件内容是否包含目标协议或 YAML 代理配置
async def verify_content(session, url, known_invalid_urls, debug_logs):
    if url in known_invalid_urls:
        debug_logs.append(f"跳过已知无效 URL: {url}")
        return False

    file_extension = os.path.splitext(url).pop().lower() if os.path.splitext(url)[1] else ""

    if file_extension in irrelevant_extensions and file_extension != '.txt':
        debug_logs.append(f"跳过无关扩展名文件: {url} ({file_extension})")
        return False

    raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        async with session.get(raw_url, headers=headers, timeout=15) as response:
            response.raise_for_status()
            content = await response.text()

            content = content[:500000] # 限制为 500KB

            # 1. 检查明文协议
            if protocol_pattern.search(content):
                debug_logs.append(f"找到明文协议: {url}")
                return True

            # 2. 检查 Base64 编码
            base64_matches = base64_pattern.findall(content)
            for b64_str in base64_matches:
                try:
                    decoded_bytes = base64.b64decode(b64_str + '=' * (4 - len(b64_str) % 4), validate=True)
                    decoded = decoded_bytes.decode('utf-8')

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

            # 3. 检查 YAML 格式
            if file_extension in {'.yaml', '.yml', '.conf', '.json'} or not file_extension or file_extension == '.txt':
                try:
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict):
                        if 'proxies' in yaml_data and (isinstance(yaml_data['proxies'], list) or isinstance(yaml_data['proxies'], dict)):
                            if isinstance(yaml_data['proxies'], list):
                                for proxy_entry in yaml_data['proxies']:
                                    if isinstance(proxy_entry, dict) and any(k in proxy_entry for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                        debug_logs.append(f"找到 YAML 代理列表配置: {url}")
                                        return True
                            elif isinstance(yaml_data['proxies'], dict):
                                if any(k in yaml_data['proxies'] for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                    debug_logs.append(f"找到 YAML 单代理配置: {url}")
                                    return True
                        if file_extension == '.json':
                            if isinstance(yaml_data, dict) and any(k in yaml_data for k in ['outbounds', 'inbounds']):
                                debug_logs.append(f"找到 JSON 配置: {url}")
                                return True

                except yaml.YAMLError:
                    pass
                except json.JSONDecodeError:
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

# 搜索并处理结果
async def search_and_process(session, term, max_pages, max_urls_to_find, known_invalid_urls, found_urls_set):
    page = 1
    current_search_count = 0
    while page <= max_pages:
        # 检查并等待速率限制
        if GITHUB_TOKEN:
            remaining = await check_rate_limit(session)
            if remaining < 10:
                reset_time_response = await session.get("https://api.github.com/rate_limit", headers=headers)
                reset_data = await reset_time_response.json()
                reset_timestamp = reset_data['rate']['reset']
                wait_time = max(0, reset_timestamp - int(time.time())) + 5
                debug_logs.append(f"速率限制接近，等待 {wait_time} 秒直到 {datetime.fromtimestamp(reset_timestamp)}。")
                await asyncio.sleep(wait_time)
        else:
            await asyncio.sleep(2)

        params = {
            "q": quote(term, safe=''),
            "per_page": 100,
            "page": page
        }
        debug_logs.append(f"开始搜索 '{term}' (第 {page} 页)...")
        try:
            async with session.get(SEARCH_API_URL, headers=headers, params=params, timeout=20) as response:
                response.raise_for_status()
                data = await response.json()
        except aiohttp.ClientError as e:
            debug_logs.append(f"搜索 '{term}' (第 {page} 页) 失败 (网络/HTTP 错误): {e}")
            break
        except asyncio.TimeoutError:
            debug_logs.append(f"搜索 '{term}' (第 {page} 页) 超时。")
            break
        except Exception as e:
            debug_logs.append(f"搜索 '{term}' (第 {page} 页) 发生未知错误: {e}")
            break

        items = data.get("items", [])
        debug_logs.append(f"搜索 '{term}' (第 {page} 页) 找到 {len(items)} 条结果。")

        if not items:
            break

        # 存储 (URL, 协程) 对，以便后续匹配结果
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

        # 提取协程对象列表用于 asyncio.gather
        coroutines_to_run = [coro for url, coro in urls_and_coroutines]
        # 并行执行验证任务
        verification_results = await asyncio.gather(*coroutines_to_run, return_exceptions=True)

        # 遍历结果，并使用 urls_and_coroutines 列表来获取原始 URL
        for i, result in enumerate(verification_results):
            original_url = urls_and_coroutines[i][0] # 从存储的 (URL, 协程) 对中获取 URL

            if result is True:
                found_urls_set.add(f"{original_url}|{datetime.now().isoformat()}")
                current_search_count += 1
                debug_logs.append(f"成功找到有效 URL: {original_url} (当前已找到 {current_search_count} 个)")
            elif isinstance(result, Exception):
                debug_logs.append(f"验证 URL {original_url} 出现异常: {result}")
            else:
                debug_logs.append(f"URL {original_url} 未通过验证。")

            if current_search_count >= max_urls_to_find:
                debug_logs.append(f"已达到最大目标 URL 数量 {max_urls_to_find}，停止搜索。")
                return

        page += 1
        if GITHUB_TOKEN:
            await asyncio.sleep(1)
        else:
            await asyncio.sleep(5)

    debug_logs.append(f"搜索 '{term}' 已完成所有页或已达到最大目标 URL 数量。")


async def main():
    async with aiohttp.ClientSession() as session:
        known_invalid_urls = await load_known_invalid_urls()
        found_urls_set = set()

        initial_rate_limit = await check_rate_limit(session)
        if initial_rate_limit == 0 and GITHUB_TOKEN:
            debug_logs.append("初始速率限制为 0，无法进行搜索。请稍后再试。")
            return

        max_urls_to_find = 200 # 目标找到的 URL 数量
        max_pages_per_term = 10 # 每个搜索词最多搜索的页数

        for term in search_terms:
            await search_and_process(session, term, max_pages_per_term, max_urls_to_find, known_invalid_urls, found_urls_set)
            if len(found_urls_set) >= max_urls_to_find:
                break

        found_urls_list = sorted(list(found_urls_set))
        with open(output_file, "w", encoding="utf-8") as f:
            for url_entry in found_urls_list:
                f.write(url_entry + "\n")
        debug_logs.append(f"最终找到 {len(found_urls_list)} 个包含目标协议的唯一 URL，已保存到 {output_file}")
        print(f"最终找到 {len(found_urls_list)} 个包含目标协议的唯一 URL，已保存到 {output_file}")

        with open(debug_log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(debug_logs))
        print(f"调试日志已保存到 {debug_log_file}")

if __name__ == "__main__":
    asyncio.run(main())
