import os
import re
import time
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import requests
import aiohttp
import asyncio
import base64
import json
import hashlib
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler('iptv_script.log', maxBytes=10*1024*1024, backupCount=5)
    ]
)
logger = logging.getLogger(__name__)

# 从环境变量获取配置
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH = os.getenv('CONFIG_PATH')
URLS_PATH = os.getenv('URLS_PATH')
URL_STATES_PATH = os.getenv('URL_STATES_PATH')

# 检查环境变量
for var, name in [(GITHUB_TOKEN, 'BOT'), (REPO_OWNER, 'REPO_OWNER'), (REPO_NAME, 'REPO_NAME'),
                  (CONFIG_PATH, 'CONFIG_PATH'), (URLS_PATH, 'URLS_PATH'), (URL_STATES_PATH, 'URL_STATES_PATH')]:
    if not var:
        logger.error(f"错误：环境变量 '{name}' 未设置。")
        exit(1)

# GitHub 相关常量
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# 关键词统计
keyword_stats = {}

# 文件操作类
class FileHandler:
    def __init__(self, is_remote=False, github_token=None):
        self.is_remote = is_remote
        self.github_token = github_token

    def read_txt(self, path):
        if self.is_remote:
            content = fetch_from_github(path)
            return [line.strip() for line in content.split('\n') if line.strip()] if content else []
        try:
            with open(path, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError:
            logger.warning(f"文件 '{path}' 未找到。")
            return []
        except Exception as e:
            logger.error(f"读取文件 '{path}' 发生错误：{e}")
            return []

    def write_txt(self, path, data, commit_message=None, backup=True):
        content = '\n'.join(data)
        if self.is_remote:
            return save_to_github(path, content, commit_message, backup)
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write(content + '\n')
            return True
        except Exception as e:
            logger.error(f"写入文件 '{path}' 发生错误：{e}")
            return False

# GitHub 文件操作
def fetch_from_github(file_path):
    url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP 错误获取 {file_path}: {e.response.status_code}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"请求错误获取 {file_path}: {e}")
        return None

def get_current_sha(file_path):
    url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logger.debug(f"获取 {file_path} 的 SHA 失败（可能不存在）：{e}")
        return None

def save_to_github(file_path, content, commit_message, backup=True):
    url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Content-Type": "application/json"}
    sha = get_current_sha(file_path)
    
    if sha and not check_remote_changes(file_path, sha):
        logger.error(f"远程文件 {file_path} 已更改，取消上传以避免冲突")
        return False

    payload = {
        "message": commit_message,
        "content": base64.b64encode(content.encode('utf-8')).decode('utf-8'),
        "branch": "main"
    }
    if sha:
        payload["sha"] = sha

    if backup and sha:
        backup_path = f"{file_path}.bak"
        old_content = fetch_from_github(file_path)
        if old_content:
            backup_commit = f"备份 {file_path} 于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            if not save_to_github(backup_path, old_content, backup_commit, backup=False):
                logger.error(f"备份 {file_path} 到 {backup_path} 失败，取消上传")
                return False

    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        logger.info(f"成功上传 {file_path} 到 GitHub")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"上传 {file_path} 失败：{e}")
        return False

def check_remote_changes(file_path, local_sha):
    remote_sha = get_current_sha(file_path)
    return remote_sha == local_sha if local_sha else True

# 加载配置
def load_config():
    content = fetch_from_github(CONFIG_PATH)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.error(f"解析 YAML 配置 {CONFIG_PATH} 失败：{e}")
            exit(1)
    logger.error(f"无法加载配置 {CONFIG_PATH}")
    exit(1)

CONFIG = load_config()
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 3)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 30)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 8)
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 100)
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
URL_FILTER_WORDS = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})
CATEGORY_RULES = CONFIG.get('category_rules', [])
STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24)

# 配置 HTTP 会话
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})
retry_strategy = Retry(total=3, backoff_factor=1.5, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# URL 处理和频道提取
def get_url_file_extension(url):
    parsed = urlparse(url)
    return os.path.splitext(parsed.path)[1].lower()

def convert_m3u_to_txt(m3u_content):
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = ""
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTM3U"):
            continue
        if line.startswith("#EXTINF"):
            match = re.search(r'#EXTINF:.*?\,(.*)', line)
            channel_name = match.group(1).strip() if match else "未知频道"
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = ""
    return '\n'.join(txt_lines)

def clean_url_params(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

# URL 状态管理
def load_url_states():
    content = fetch_from_github(URL_STATES_PATH)
    try:
        return json.loads(content) if content else {}
    except json.JSONDecodeError as e:
        logger.error(f"解码 {URL_STATES_PATH} 失败：{e}")
        return {}

def save_url_states(url_states):
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        save_to_github(URL_STATES_PATH, content, "更新 URL 状态", backup=True)
    except Exception as e:
        logger.error(f"保存 URL 状态失败：{e}")

# 异步 URL 内容获取
async def fetch_url_content_async(url, url_states, timeout=CHANNEL_FETCH_TIMEOUT):
    # 初始化 url_states 条目
    if url not in url_states:
        url_states[url] = {}
    
    headers = {}
    current_state = url_states[url]
    if 'etag' in current_state and current_state['etag']:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state and current_state['last_modified']:
        headers['If-Modified-Since'] = current_state['last_modified']

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status == 304:
                    url_states[url]['last_checked'] = datetime.now().isoformat()
                    logger.info(f"URL 未更改：{url}")
                    return None
                content = await response.text()
                content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
                if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
                    url_states[url]['last_checked'] = datetime.now().isoformat()
                    logger.info(f"URL 内容未变：{url}")
                    return None
                url_states[url].update({
                    'etag': response.headers.get('ETag'),
                    'last_modified': response.headers.get('Last-Modified'),
                    'content_hash': content_hash,
                    'last_checked': datetime.now().isoformat()
                })
                logger.info(f"成功获取 URL 内容：{url}")
                return content
        except aiohttp.ClientError as e:
            logger.error(f"获取 URL {url} 失败：{e}")
            return None

def extract_channels_from_url(url, url_states):
    # 验证 URL 文件扩展名
    ext = get_url_file_extension(url)
    if ext not in ['.m3u', '.m3u8', '.txt']:
        logger.warning(f"跳过无效文件扩展名：{url} ({ext})")
        return []
    
    # 创建新事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        content = loop.run_until_complete(fetch_url_content_async(url, url_states))
        if not content:
            return []
        
        if ext in [".m3u", ".m3u8"]:
            content = convert_m3u_to_txt(content)
        
        channels = []
        for line in content.split('\n'):
            line = line.strip()
            if "#genre#" not in line and "," in line and "://" in line:
                name, url = line.split(',', 1)
                name = name.strip()
                url = clean_url_params(url.strip())
                for old, new in CHANNEL_NAME_REPLACEMENTS.items():
                    name = name.replace(old, new)
                if url and not any(word in name.lower() for word in NAME_FILTER_WORDS) and not any(pat in url.lower() for pat in URL_FILTER_WORDS):
                    channels.append((name, url))
        logger.info(f"从 {url} 提取 {len(channels)} 个频道")
        return channels
    finally:
        loop.close()

# 频道验证
async def check_channel_validity_async(name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT):
    if url not in url_states:
        url_states[url] = {}
    
    current_time = datetime.now()
    current_state = url_states[url]
    
    if 'stream_check_failed_at' in current_state:
        last_failed = datetime.fromisoformat(current_state['stream_check_failed_at'])
        if (current_time - last_failed).total_seconds() / 3600 < STREAM_SKIP_FAILED_HOURS:
            return None, False
    
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        try:
            async with session.head(url, timeout=timeout, allow_redirects=True) as response:
                is_valid = 200 <= response.status < 400
            elapsed_time = (time.time() - start_time) * 1000
            
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            if is_valid:
                url_states[url].pop('stream_check_failed_at', None)
                url_states[url].pop('stream_fail_count', None)
                url_states[url]['last_successful_stream_check'] = current_time.isoformat()
                logger.info(f"频道验证成功：{name} ({url})，耗时 {elapsed_time:.2f}ms")
                return elapsed_time, True
            else:
                url_states[url]['stream_check_failed_at'] = current_time.isoformat()
                url_states[url]['stream_fail_count'] = current_state.get('stream_fail_count', 0) + 1
                logger.warning(f"频道验证失败：{name} ({url})，状态码 {response.status}")
                return None, False
        except aiohttp.ClientError as e:
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logger.warning(f"频道验证失败：{name} ({url})，错误：{e}")
            return None, False

async def check_channels_async(channels, url_states):
    tasks = [check_channel_validity_async(name, url, url_states) for name, url in channels]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    valid_channels = [(t, f"{name},{url}") for (t, valid), (name, url) in zip(results, channels) if valid]
    logger.info(f"有效频道数量：{len(valid_channels)}")
    return valid_channels

# 频道分类和文件处理
def categorize_channel(channel_name):
    for rule in CATEGORY_RULES:
        if re.search(rule['pattern'], channel_name, re.IGNORECASE):
            return rule['category']
    return next((rule['default'] for rule in CATEGORY_RULES if 'default' in rule), '其他')

def merge_local_channel_files(channels_dir, output_file="iptv_list.txt"):
    output_lines = [f"更新时间,#genre#\n{datetime.now().strftime('%Y-%m-%d')},url\n{datetime.now().strftime('%H:%M:%S')},url\n"]
    file_handler = FileHandler()
    
    categories = set()
    for file_name in os.listdir(channels_dir):
        if file_name.endswith('_iptv.txt'):
            category = file_name.replace('_iptv.txt', '')
            categories.add(category)
    
    for category in sorted(categories):
        file_path = os.path.join(channels_dir, f"{category}_iptv.txt")
        lines = file_handler.read_txt(file_path)
        if lines:
            output_lines.append(f"{category},#genre#\n")
            output_lines.extend(lines)
    
    file_handler.write_txt(output_file, output_lines, "合并频道文件")
    logger.info(f"合并频道文件到 {output_file}")

# 主逻辑
@retry(stop=stop_after_attempt(3), wait=wait_fixed(30), retry=retry_if_exception_type(requests.exceptions.HTTPError))
def discover_urls():
    global keyword_stats
    file_handler = FileHandler(is_remote=True, github_token=GITHUB_TOKEN)
    existing_urls = set(file_handler.read_txt(URLS_PATH))
    found_urls = set()
    
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3.text-match+json"}
    for keyword in SEARCH_KEYWORDS:
        keyword_stats[keyword] = {"success": 0, "failed": 0, "urls": set()}
        for page in range(1, MAX_SEARCH_PAGES + 1):
            try:
                response = session.get(
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                    headers=headers,
                    params={"q": keyword, "sort": "indexed", "order": "desc", "per_page": PER_PAGE, "page": page},
                    timeout=GITHUB_API_TIMEOUT
                )
                response.raise_for_status()
                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                if rate_limit_remaining < 10:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_seconds = max(0, reset_time - int(time.time())) + 5
                    logger.warning(f"API 速率限制接近，剩余 {rate_limit_remaining} 次，等待 {wait_seconds} 秒")
                    time.sleep(wait_seconds)
                items = response.json().get('items', [])
                keyword_stats[keyword]["success"] += 1
                for item in items:
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', item.get('html_url', ''))
                    if match:
                        raw_url = f"https://raw.githubusercontent.com/{match.group(1)}/{match.group(2)}/{match.group(3)}/{match.group(4)}"
                        if raw_url.endswith(('.m3u', '.m3u8', '.txt')):
                            clean_url = clean_url_params(raw_url)
                            found_urls.add(clean_url)
                            keyword_stats[keyword]["urls"].add(clean_url)
                logger.info(f"关键词 '{keyword}' 第 {page} 页搜索成功，发现 {len(keyword_stats[keyword]['urls'])} 个 URL")
            except requests.exceptions.HTTPError as e:
                logger.error(f"搜索 '{keyword}' 第 {page} 页失败：{e}")
                keyword_stats[keyword]["failed"] += 1
                if e.response.status_code == 403:
                    logger.warning("可能触发 GitHub API 速率限制，重试中...")
                    raise
                continue
            except requests.exceptions.RequestException as e:
                logger.error(f"搜索 '{keyword}' 第 {page} 页失败：{e}")
                keyword_stats[keyword]["failed"] += 1
                continue
    
    new_urls = found_urls - existing_urls
    if new_urls:
        file_handler.write_txt(URLS_PATH, list(found_urls), "更新 URL 列表", backup=True)
        logger.info(f"发现 {len(new_urls)} 个新 URL")
    
    # 打印关键词统计
    logger.info("关键词搜索统计：")
    for keyword, stats in keyword_stats.items():
        logger.info(f"关键词 '{keyword}': 成功 {stats['success']} 次，失败 {stats['failed']} 次，发现 {len(stats['urls'])} 个 URL")

def main():
    file_handler = FileHandler(is_remote=True, github_token=GITHUB_TOKEN)
    local_file_handler = FileHandler()
    
    # 发现 URL
    discover_urls()
    
    # 提取和过滤频道
    urls = file_handler.read_txt(URLS_PATH)
    url_states = load_url_states()
    channels = set()
    for url in urls:
        channels.update(extract_channels_from_url(url, url_states))
    
    # 异步验证频道
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        valid_channels = loop.run_until_complete(check_channels_async(channels, url_states))
    finally:
        loop.close()
    
    # 保存状态
    save_url_states(url_states)
    
    # 分类和保存
    channels_dir = CONFIG.get('paths', {}).get('channels_dir', '地方频道')
    os.makedirs(channels_dir, exist_ok=True)
    
    grouped_channels = {}
    for _, line in valid_channels:
        name = line.split(',', 1)[0]
        category = categorize_channel(name)
        grouped_channels.setdefault(category, []).append(line)
    
    for category, lines in grouped_channels.items():
        local_file_handler.write_txt(os.path.join(channels_dir, f"{category}_iptv.txt"), lines, f"保存 {category} 频道")
    
    # 合并和上传
    merge_local_channel_files(channels_dir)
    final_content = local_file_handler.read_txt("iptv_list.txt")
    file_handler.write_txt("output/iptv_list.txt", final_content, "更新 IPTV 列表", backup=True)

if __name__ == "__main__":
    main()
