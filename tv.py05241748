import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import requests
import aiohttp # tv.py.txt 引入
import asyncio # tv.py.txt 引入
import json # tv.py.txt 引入
from bs4 import BeautifulSoup # 0523.txt 引入
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import sys # tv.py.txt 引入
import traceback # tv.py.txt 引入
import shutil # 用于创建目录

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iptv_crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- 全局配置 ---
# 从 tv.py.txt 引入的配置
CONFIG_DIR = os.path.join(os.getcwd(), 'config')
LAST_MODIFIED_FILE = os.path.join(CONFIG_DIR, "last_modified_urls.txt")
DEFAULT_LAST_MODIFIED = "Thu, 01 Jan 1970 00:00:00 GMT"
URLS_FILE_PATH = os.path.join(CONFIG_DIR, 'urls.txt') # 初始URL列表
SEARCH_CONFIG_FILE = os.path.join(CONFIG_DIR, 'search_keywords.json') # 搜索关键词配置
BLACKLIST_FILE = os.path.join(CONFIG_DIR, 'blacklist.txt') # 黑名单配置

# 从 0523.txt 引入的配置
TEMPLATES_DIR = os.path.join(os.getcwd(), 'config', 'templates')
M3U_TEMPLATE_FILE = os.path.join(CONFIG_DIR, 'template.m3u') # 原始模板文件
TV_SPEED_FILE = os.path.join(CONFIG_DIR, 'tv_speed.txt') # 频道速度测试文件
LOCAL_CHANNELS_DIR = os.path.join(os.getcwd(), 'channels') # 本地频道文件输出目录
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY')
GITHUB_USERNAME = GITHUB_REPO.split('/')[0] if GITHUB_REPO else 'your_github_username' # Fallback if not in GitHub Actions

# --- GitHub API 配置 ---
# 从 tv.py.txt 引入并调整
GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_API_CODE_SEARCH_PATH = "/search/code"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") # 从环境变量获取，用于提高速率限制

# GitHub API 速率限制配置 (从 tv.py.txt 引入)
GITHUB_REQUEST_INTERVAL = 6 # 每6秒一次请求，确保每分钟最多10次请求，用于未认证用户。
GITHUB_KEYWORD_SLEEP = 10 # 关键词之间休眠时间，避免连续的复杂查询触发API限制或422错误。

# GitHub 搜索结果分页数量 (每个关键词搜索的页数) (从 tv.py.txt 引入)
MAX_SEARCH_PAGES = 1 # 默认值，你可以根据需求调整

# 异步 HTTP 请求配置 (从 tv.py.txt 引入)
ASYNC_HTTP_TIMEOUT = 10 # 异步HTTP请求超时时间 (秒)
ASYNC_HTTP_CONNECTIONS = 50 # 异步HTTP并发连接数

# M3U 文件处理配置 (从 tv.py.txt 引入)
M3U_TIMEOUT = 5 # M3U文件下载超时时间 (秒)
M3U_CONCURRENCY = 100 # M3U文件下载并发数

# 域名黑名单 (从 tv.py.txt 引入)
BLACKLIST_DOMAINS = set()

# 结果文件路径 (从 tv.py.txt 引入)
FINAL_LIVE_M3U_FILE = "live.m3u"
FINAL_LIVE_TXT_FILE = "live.txt"

# 缓存上次修改时间 (从 tv.py.txt 引入)
LAST_MODIFIED_CACHE = {}

# --- 辅助函数 (从 tv.py.txt 移植并整合) ---

def is_url_accessible(url):
    """
    检查URL是否可访问且内容不为空。
    考虑到有时HTTP响应会是3xx重定向，使用 HEAD 请求可能无法准确判断最终内容，
    因此这里使用 GET 请求，并设置较短的超时时间。
    """
    try:
        # 使用stream=True和iter_content来避免一次性下载大文件，
        # 并在确认响应头和少量内容后关闭连接。
        with requests.get(url, stream=True, timeout=5) as r:
            r.raise_for_status() # 检查HTTP状态码，如果不是2xx则抛出异常

            # 检查Content-Length，如果为0或不存在，可能内容为空
            content_length = r.headers.get('Content-Length')
            if content_length is not None and int(content_length) == 0:
                return False

            # 尝试读取一小部分内容来判断是否真的有数据
            # 避免下载整个文件，只判断响应是否有效
            # 修改：使用 next(r.iter_content(chunk_size=1)) 更直接
            try:
                first_byte = next(r.iter_content(chunk_size=1))
                if not first_byte:
                    return False
            except StopIteration: # 没有内容
                return False

            return True
    except requests.exceptions.RequestException as e:
        # logging.debug(f"URL {url} 不可访问: {e}") # 访问频繁可开启debug级别
        return False
    except Exception as e:
        # logging.debug(f"检查URL {url} 时发生未知错误: {e}")
        return False

def check_url_and_update_cache(url):
    """检查URL是否可访问，并更新上次修改时间缓存"""
    global LAST_MODIFIED_CACHE

    # 对于已在黑名单中的域名，直接跳过
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain in BLACKLIST_DOMAINS:
        # logging.debug(f"域名 '{domain}' 在黑名单中，跳过URL: {url}")
        return None

    last_modified_str = LAST_MODIFIED_CACHE.get(url, DEFAULT_LAST_MODIFIED)
    headers = {'If-Modified-Since': last_modified_str}
    
    try:
        with requests.head(url, headers=headers, timeout=5) as r:
            r.raise_for_status()

            if r.status_code == 304: # Not Modified
                # logging.debug(f"URL {url} 未修改 (304)")
                return url # 认为可用，因为内容未变
            
            # 检查 Content-Type，确保是文本类型，排除图片、视频等
            content_type = r.headers.get('Content-Type', '').lower()
            if not any(ct_part in content_type for ct_part in ['text', 'application/json', 'application/xml', 'application/x-mpegurl']):
                logging.warning(f"URL {url} 的Content-Type '{content_type}' 不是文本类型，跳过。")
                return None

            # 如果状态码是 200 OK
            new_last_modified = r.headers.get('Last-Modified', datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"))
            LAST_MODIFIED_CACHE[url] = new_last_modified
            # logging.info(f"URL {url} 可访问并已更新缓存。")
            return url
    except requests.exceptions.RequestException as e:
        # logging.debug(f"URL {url} 不可访问或请求错误: {e}")
        return None
    except Exception as e:
        # logging.debug(f"检查URL {url} 时发生未知错误: {e}")
        return None

def extract_m3u_urls(m3u_content, base_url=""):
    """
    从M3U内容中提取所有可能的URL。
    尝试将相对路径解析为绝对路径。
    """
    urls = set()
    # 匹配 #EXTINF 行下方的URL
    matches = re.findall(r'#EXTINF:.*?\n\s*(https?://[^\s]+)', m3u_content, re.IGNORECASE)
    for url in matches:
        urls.add(url.strip())
    
    # 匹配 M3U 文件中直接包含的 URL（不带 #EXTINF）
    # 这种通常是分段列表，也可能是错误的m3u，但仍尝试提取
    # 过滤掉 # 开头的行和空行
    for line in m3u_content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            if line.startswith('http://') or line.startswith('https://'):
                urls.add(line)
            elif base_url: # 尝试解析相对路径
                try:
                    absolute_url = urljoin(base_url, line)
                    if absolute_url.startswith('http'): # 确保是有效的HTTP/HTTPS URL
                        urls.add(absolute_url)
                except ValueError:
                    pass # urljoin可能会因为不规范的base_url或line抛出错误

    return list(urls)

async def fetch_url_content(session, url):
    """异步获取URL内容"""
    try:
        async with session.get(url, timeout=ASYNC_HTTP_TIMEOUT) as response:
            response.raise_for_status() # 检查HTTP状态码
            return await response.text()
    except aiohttp.ClientError as e:
        logging.warning(f"下载M3U URL失败 ({url}): {e}")
        return None
    except asyncio.TimeoutError:
        logging.warning(f"下载M3U URL超时 ({url})")
        return None
    except Exception as e:
        logging.warning(f"下载M3U URL时发生未知错误 ({url}): {e}")
        return None

async def process_m3u_url_content(session, m3u_url):
    """异步处理M3U URL，下载内容并提取内部URL"""
    logging.info(f"正在处理 M3U URL: {m3u_url}")
    content = await fetch_url_content(session, m3u_url)
    if content:
        # 简单检查是否包含M3U文件头
        if "#EXTM3U" not in content:
            logging.warning(f"URL {m3u_url} 内容不包含 #EXTM3U 头，可能不是有效的M3U文件。")
            return [] # 返回空列表

        extracted_urls = extract_m3u_urls(content, base_url=m3u_url)
        # logging.info(f"从 {m3u_url} 提取了 {len(extracted_urls)} 个URL。")
        return extracted_urls
    return []

# --- 数据加载与保存 (从 tv.py.txt 移植并整合) ---

def load_blacklist_domains():
    """加载黑名单域名"""
    global BLACKLIST_DOMAINS
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    BLACKLIST_DOMAINS.add(line)
        logging.info(f"已加载 {len(BLACKLIST_DOMAINS)} 个黑名单域名.")
    else:
        logging.info("黑名单文件不存在，跳过加载。")

def load_last_modified_cache():
    """加载上次修改时间缓存"""
    global LAST_MODIFIED_CACHE
    if os.path.exists(LAST_MODIFIED_FILE):
        with open(LAST_MODIFIED_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',', 1)
                if len(parts) == 2:
                    url, timestamp = parts
                    LAST_MODIFIED_CACHE[url] = timestamp
        logging.info(f"已加载 {len(LAST_MODIFIED_CACHE)} 个URL的上次修改时间缓存.")
    else:
        logging.info("上次修改时间缓存文件不存在，将从头开始。")

def save_last_modified_cache():
    """保存上次修改时间缓存"""
    with open(LAST_MODIFIED_FILE, 'w', encoding='utf-8') as f:
        for url, timestamp in LAST_MODIFIED_CACHE.items():
            f.write(f"{url},{timestamp}\n")
    logging.info("已保存上次修改时间缓存.")

def load_initial_urls():
    """从urls.txt加载初始URL列表"""
    urls = set()
    if os.path.exists(URLS_FILE_PATH):
        with open(URLS_FILE_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and (url.startswith('http://') or url.startswith('https://')):
                    urls.add(url)
        logging.info(f"从 {URLS_FILE_PATH} 加载了 {len(urls)} 个初始 URL.")
    else:
        logging.warning(f"初始URL文件 {URLS_FILE_PATH} 不存在。")
    return list(urls)

def load_search_keywords():
    """
    加载 GitHub 搜索关键词。
    优先从 config/search_keywords.json 加载，如果文件不存在或加载失败，则使用默认关键词。
    """
    default_keywords = [
        # 简化并优化高频使用的关键词
        '"raw.githubusercontent.com" extension:m3u8',
        '"raw.githubusercontent.com" extension:m3u',
        'filename:playlist.m3u8',
        'filename:index.m3u8',
        'filename:channels.m3u',
        'filename:tv.m3u8',
        'filename:tv.m3u',
        'filename:live.m3u8',
        'filename:live.m3u',
        'extension:m3u8',
        'extension:m3u',
        '"#EXTM3U" extension:m3u', # 确保M3U文件中包含头
        '"#EXTM3U" extension:m3u8',
        '"iptv playlist" extension:m3u',
        '"iptv playlist" extension:m3u8',
        '"live tv" extension:m3u',
        '"live tv" extension:m3u8',
        '"tv channels" extension:m3u',
        '"tv channels" extension:m3u8',
        '"直播源" extension:m3u',
        '"直播源" extension:m3u8',
        '"电视直播" extension:m3u',
        '"电视直播" extension:m3u8',
        # 以下是可能触发422但保留作为可选的更复杂查询，建议在有令牌时谨慎使用
        # '"raw.githubusercontent.com" path:.txt "#EXTM3U"', # 这个经常422
        # 'filename:iptv.m3u OR filename:iptv.m3u8 OR filename:iptv.txt "#EXTM3U"', # 这个也容易422
        # '"#EXTM3U" "#EXTINF" "tvg-logo" (extension:m3u OR extension:m3u8)' # 太复杂
    ]
    
    custom_keywords = []
    if os.path.exists(SEARCH_CONFIG_FILE):
        try:
            with open(SEARCH_CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                if 'keywords' in config and isinstance(config['keywords'], list):
                    custom_keywords = config['keywords']
                    logging.info("已加载自定义搜索关键词配置文件.")
                else:
                    logging.warning(f"搜索关键词配置文件 {SEARCH_CONFIG_FILE} 格式不正确，缺少 'keywords' 列表。")
        except json.JSONDecodeError as e:
            logging.error(f"加载搜索关键词配置文件出错: {e}")
            logging.error(f"请检查文件 {SEARCH_CONFIG_FILE} 的JSON格式。")
        except Exception as e:
            logging.error(f"加载搜索关键词配置文件时发生未知错误: {e}")
    else:
        logging.info(f"搜索关键词配置文件 {SEARCH_CONFIG_FILE} 不存在，将使用默认关键词。")
    
    # 优先使用自定义关键词，如果自定义为空，则使用默认关键词
    # 如果自定义不为空，则将默认关键词添加到自定义关键词的后面
    if custom_keywords:
        # 确保没有重复，并保留自定义关键词的顺序
        final_keywords = list(dict.fromkeys(custom_keywords + default_keywords))
    else:
        final_keywords = default_keywords
    
    logging.info(f"最终搜索关键词数量: {len(final_keywords)}")
    return final_keywords

async def github_search_code(session, keyword, page=1):
    """
    使用 GitHub Code Search API 搜索代码。
    """
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json"
    }
    # 避免重复打印 GITHUB_TOKEN 已设置的日志
    if GITHUB_TOKEN and not hasattr(github_search_code, 'token_logged'):
        logging.info("GITHUB_TOKEN 环境变量已设置。")
        github_search_code.token_logged = True # 标记已打印

    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    
    params = {
        "q": keyword,
        "per_page": 100, # 每页最多100个结果
        "page": page
    }
    
    api_url = f"{GITHUB_API_BASE_URL}{GITHUB_API_CODE_SEARCH_PATH}"
    
    async with session.get(api_url, headers=headers, params=params, timeout=ASYNC_HTTP_TIMEOUT) as response:
        # 检查速率限制头
        remaining = response.headers.get('X-RateLimit-Remaining')
        reset_time = response.headers.get('X-RateLimit-Reset')
        if remaining and int(remaining) == 0:
            reset_timestamp = int(reset_time)
            sleep_time = max(0, reset_timestamp - time.time() + 5) # 加5秒缓冲
            logging.warning(f"GitHub API 速率限制已耗尽，将在 {sleep_time:.2f} 秒后重试。")
            await asyncio.sleep(sleep_time)
            # 重新发起请求
            return await github_search_code(session, keyword, page)

        response.raise_for_status() # 抛出HTTP错误，例如403, 404, 422
        return await response.json()

async def search_github_for_m3u_urls():
    """在GitHub上搜索M3U/M3U8 URL"""
    found_urls = set()
    async with aiohttp.ClientSession() as session:
        # 第一次循环时，尝试标记 GITHUB_TOKEN 已设置的日志，避免重复
        if GITHUB_TOKEN and not hasattr(github_search_code, 'token_logged'):
            logging.info("GITHUB_TOKEN 环境变量已设置。")
            github_search_code.token_logged = True # 标记已打印

        for keyword_idx, keyword in enumerate(SEARCH_KEYWORDS):
            logging.info(f"GitHub 搜索 ({keyword_idx + 1}/{len(SEARCH_KEYWORDS)}) 使用关键词: '{keyword}'")
            
            for page in range(1, MAX_SEARCH_PAGES + 1):
                try:
                    results = await github_search_code(session, keyword, page)
                    if not results or not results.get('items'):
                        logging.info(f"关键词 '{keyword}' 页面 {page} 未找到结果。")
                        break # No more results for this keyword or page
                    
                    for item in results['items']:
                        raw_url = item['html_url'].replace('/blob/', '/raw/')
                        found_urls.add(raw_url)
                        # logging.debug(f"找到URL: {raw_url}") # 调试信息
                    
                    logging.info(f"关键词 '{keyword}' 页面 {page} 找到 {len(results['items'])} 个结果。")

                    # 如果当前页结果数小于per_page，说明没有更多页了
                    if len(results['items']) < 100:
                        break

                    # Sleep between pages to respect API limits if needed
                    await asyncio.sleep(GITHUB_REQUEST_INTERVAL) # 页面之间也休眠
                        
                except aiohttp.ClientResponseError as e:
                    if e.status == 403:
                        logging.error(f"GitHub API 速率限制 (403): {e.status} {e.message}. 请等待或设置 GITHUB_TOKEN。")
                        return list(found_urls) # 返回已找到的URL，并停止
                    elif e.status == 422:
                        logging.warning(f"GitHub API 请求处理失败 (422). 关键词 '{keyword}' 可能过于复杂或无效。跳过此关键词。")
                        break # 对于 422 错误，跳过当前关键词的所有页面，尝试下一个关键词
                    else:
                        logging.error(f"GitHub API 请求失败 ({e.status}): {e}")
                        break
                except asyncio.TimeoutError:
                    logging.error(f"GitHub API 请求超时 (关键词: '{keyword}', 页面: {page})")
                    break # Break page loop, try next keyword
                except Exception as e:
                    logging.error(f"GitHub 搜索 '{keyword}' 页面 {page} 时发生未知错误: {e}\n{traceback.format_exc()}")
                    break # Break page loop

            # Sleep between keywords
            if keyword_idx < len(SEARCH_KEYWORDS) - 1: # Don't sleep after the last keyword
                logging.info(f"关键词 '{keyword}' 处理完毕，休眠 {GITHUB_KEYWORD_SLEEP} 秒...")
                await asyncio.sleep(GITHUB_KEYWORD_SLEEP)
            
    return list(found_urls)


# --- 从 0523.txt 移植的核心功能 ---

def get_channel_templates():
    """Reads channel templates from config/templates directory."""
    templates = {}
    if not os.path.exists(TEMPLATES_DIR):
        logging.warning(f"Templates directory not found: {TEMPLATES_DIR}. Creating it...")
        os.makedirs(TEMPLATES_DIR)
        return templates

    for filename in os.listdir(TEMPLATES_DIR):
        if filename.endswith(".txt"):
            template_name = filename[:-4] # Remove .txt extension
            filepath = os.path.join(TEMPLATES_DIR, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                templates[template_name] = [line.strip() for line in f if line.strip()]
            logging.info(f"Loaded template: {template_name} with {len(templates[template_name])} channels.")
    return templates

def sort_cctv_channels(channels):
    """Sorts CCTV channels numerically."""
    def get_cctv_number(channel_name):
        match = re.match(r'CCTV-(\d+)', channel_name, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return float('inf') # Places non-CCTV-X at the end

    return sorted(channels, key=lambda x: get_cctv_number(x.split(',', 1)[0]))

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_m3u_content(url):
    """Fetches M3U content from a URL with retry."""
    logging.info(f"Fetching M3U content from: {url}")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
    }
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    return response.text

def parse_m3u_content(content):
    """Parses M3U content and extracts channel name and URL."""
    channels = []
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("#EXTINF"):
            channel_info = lines[i]
            if i + 1 < len(lines) and (lines[i+1].startswith("http://") or lines[i+1].startswith("https://")):
                channel_url = lines[i+1].strip()
                # Extract channel name, preferring tvg-name or group-title
                match_name = re.search(r'tvg-name="([^"]*)"', channel_info)
                if not match_name:
                    match_name = re.search(r'group-title="([^"]*)"', channel_info)
                
                channel_name = match_name.group(1).strip() if match_name else "Unknown Channel"

                # If the name is still generic, try to extract from the URL or #EXTINF
                if "Unknown Channel" in channel_name or not channel_name:
                    # Fallback to after the last comma in #EXTINF line
                    extinf_parts = channel_info.split(',')
                    if len(extinf_parts) > 1:
                        channel_name = extinf_parts[-1].strip()
                    else: # Fallback to URL if no name found
                         # Basic extraction from URL path, last part before extension
                        path = urlparse(channel_url).path
                        if path:
                            channel_name = os.path.splitext(os.path.basename(path))[0].replace('_', ' ').replace('-', ' ').strip()
                            if not channel_name: # If still empty, use a part of the domain
                                channel_name = urlparse(channel_url).netloc.split('.')[0]
                        else:
                            channel_name = "Unknown Channel" # Final fallback

                channels.append(f"{channel_name},{channel_url}")
                i += 1 # Skip URL line
            else:
                logging.warning(f"Skipping malformed #EXTINF entry: {lines[i]}")
            i += 1
        else:
            i += 1
    return channels

def get_latest_tv_speed_m3u_urls():
    """Fetches the latest M3U content from the configured tv_speed.txt and extracts URLs."""
    all_urls = set()
    if os.path.exists(TV_SPEED_FILE):
        with open(TV_SPEED_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and (line.startswith('http://') or line.startswith('https://')):
                    all_urls.add(line)
        logging.info(f"Loaded {len(all_urls)} URLs from {TV_SPEED_FILE}.")
    else:
        logging.warning(f"{TV_SPEED_FILE} not found. Skipping URL loading from it.")
    return list(all_urls)


def check_stream_speed(channel_url, timeout=5):
    """Checks the speed of an IPTV stream URL by downloading a small part."""
    try:
        start_time = time.time()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
        }
        with requests.get(channel_url, headers=headers, stream=True, timeout=timeout) as r:
            r.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            # Check for M3U content-type, if not, it might not be a stream
            content_type = r.headers.get('Content-Type', '').lower()
            if 'application/x-mpegurl' not in content_type and 'audio/mpegurl' not in content_type and 'video' not in content_type:
                # logging.debug(f"Skipping non-stream URL based on Content-Type: {channel_url} ({content_type})")
                return -1, False # Not a stream, mark as invalid

            # Download a small chunk to measure speed
            chunk_size = 1024 * 5 # 5KB
            downloaded_bytes = 0
            for chunk in r.iter_content(chunk_size=chunk_size):
                downloaded_bytes += len(chunk)
                if downloaded_bytes >= chunk_size:
                    break
            
            if downloaded_bytes == 0: # No content
                return -1, False

            end_time = time.time()
            elapsed_time = end_time - start_time
            if elapsed_time == 0: # Avoid division by zero
                return float('inf'), True # Very fast, or too quick to measure
            
            speed = (downloaded_bytes / 1024) / elapsed_time # KB/s
            logging.debug(f"Checked URL: {channel_url}, Speed: {speed:.2f} KB/s")
            return speed, True
    except (requests.exceptions.Timeout, socket.timeout):
        # logging.debug(f"URL {channel_url} timed out.")
        return -1, False
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
        # logging.debug(f"URL {channel_url} connection error: {e}")
        return -1, False
    except Exception as e:
        # logging.warning(f"Error checking stream speed for {channel_url}: {e}")
        return -1, False

def get_channel_speed_data(channels):
    """Checks speeds for all channels and returns a dictionary with speeds."""
    channel_speeds = {}
    valid_channels_with_speed = []
    
    # Use ThreadPoolExecutor for concurrent speed checks
    # The max_workers is set to M3U_CONCURRENCY from tv.py.txt, which is 100 by default.
    with ThreadPoolExecutor(max_workers=M3U_CONCURRENCY) as executor:
        future_to_channel = {executor.submit(check_stream_speed, channel.split(',', 1)[1]): channel for channel in channels}
        
        for i, future in enumerate(as_completed(future_to_channel)):
            channel_line = future_to_channel[future]
            channel_name, channel_url = channel_line.split(',', 1)
            
            try:
                speed, is_stream = future.result()
                if speed > 0 and is_stream: # Only add if speed is positive and it's recognized as a stream
                    channel_speeds[channel_url] = speed
                    valid_channels_with_speed.append((channel_name, channel_url, speed))
            except Exception as exc:
                logging.warning(f"Channel {channel_name} ({channel_url}) generated an exception: {exc}")
            
            if (i + 1) % 50 == 0 or (i + 1) == len(channels):
                logging.info(f"Speed test progress: {i + 1}/{len(channels)} channels tested.")
    
    # Sort valid channels by speed (descending)
    valid_channels_with_speed.sort(key=lambda x: x[2], reverse=True)
    return valid_channels_with_speed

def merge_iptv_files(directory):
    """Merges all IPTV files in the given directory into a single m3u and txt file."""
    merged_m3u_content = "#EXTM3U\n"
    merged_txt_content = ""
    
    txt_files = [f for f in os.listdir(directory) if f.endswith("_iptv.txt")]
    
    for filename in sorted(txt_files): # Sort for consistent output order
        filepath = os.path.join(directory, filename)
        template_name = filename.replace('_iptv.txt', '')
        
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if lines:
                # First line is usually template name,genre
                merged_txt_content += lines[0] # Add the category line to TXT
                
                # For M3U, add the group-title
                merged_m3u_content += f"#EXTINF:-1 group-title=\"{template_name}\",{template_name}\n"
                # Add a dummy URL for the group title, or simply skip
                # For simplicity, here we add a comment or skip directly to channels
                
                for line_idx, line in enumerate(lines[1:]): # Skip the first line
                    channel_name, channel_url = line.strip().split(',', 1)
                    merged_txt_content += line # Add to TXT content
                    merged_m3u_content += f"#EXTINF:-1 group-title=\"{template_name}\",{channel_name}\n"
                    merged_m3u_content += f"{channel_url}\n"
    
    # Write merged TXT file
    with open(FINAL_LIVE_TXT_FILE, 'w', encoding='utf-8') as f:
        f.write(merged_txt_content)
    logging.info(f"Merged all IPTV channels into {FINAL_LIVE_TXT_FILE}")

    # Write merged M3U file
    with open(FINAL_LIVE_M3U_FILE, 'w', encoding='utf-8') as f:
        f.write(merged_m3u_content)
    logging.info(f"Merged all IPTV channels into {FINAL_LIVE_M3U_FILE}")


def update_repo_files():
    """Commits and pushes changes to the GitHub repository."""
    try:
        subprocess.run(['git', 'config', 'user.name', GITHUB_USERNAME], check=True)
        subprocess.run(['git', 'config', 'user.email', f"{GITHUB_USERNAME}@users.noreply.github.com"], check=True)
        
        # Add generated files
        subprocess.run(['git', 'add', FINAL_LIVE_M3U_FILE], check=True)
        subprocess.run(['git', 'add', FINAL_LIVE_TXT_FILE], check=True)
        subprocess.run(['git', 'add', os.path.join(LOCAL_CHANNELS_DIR, '*_iptv.txt')], check=True)
        subprocess.run(['git', 'add', 'unmatched_channels.txt'], check=True)
        subprocess.run(['git', 'add', LAST_MODIFIED_FILE], check=True) # Add last_modified_urls.txt

        # Check for changes before committing
        result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            commit_message = "Update IPTV channels and cache"
            subprocess.run(['git', 'commit', '-m', commit_message], check=True)
            logging.info("Changes committed.")
            
            subprocess.run(['git', 'push'], check=True)
            logging.info("Changes pushed to repository.")
        else:
            logging.info("No changes to commit.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Git command failed: {e.cmd}\nOutput: {e.stdout}\nError: {e.stderr}")
        raise
    except Exception as e:
        logging.error(f"Error during Git operations: {e}")
        raise

def setup_directories():
    """Ensures necessary directories exist."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    os.makedirs(LOCAL_CHANNELS_DIR, exist_ok=True)
    logging.info("Config and channels directories ensured.")
    
    # Create dummy files if they don't exist, to prevent errors
    for file_path in [URLS_FILE_PATH, TV_SPEED_FILE, BLACKLIST_FILE, M3U_TEMPLATE_FILE]:
        if not os.path.exists(file_path):
            with open(file_path, 'w', encoding='utf-8') as f:
                if file_path == M3U_TEMPLATE_FILE:
                    f.write("#EXTM3U\n#EXTINF:-1,Sample Channel\nhttp://example.com/stream.m3u8\n")
                elif file_path == SEARCH_CONFIG_FILE: # Generate a valid empty template for search_keywords.json
                    f.write('{"keywords": []}\n')
                else:
                    f.write("") # Empty file
            logging.info(f"Created empty dummy file: {file_path}")
    
    # Ensure search_keywords.json exists with valid JSON structure if not there
    if not os.path.exists(SEARCH_CONFIG_FILE):
        with open(SEARCH_CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write('{"keywords": []}\n')
        logging.info(f"Created empty {SEARCH_CONFIG_FILE} for search keywords.")


# --- 主程序逻辑 ---

async def main_integrated_crawler():
    """
    集成了 GitHub 搜索、URL 验证、M3U 内容提取、频道整理和 Git 提交的主函数。
    """
    setup_directories() # 确保所有目录和基础文件存在

    # 1. 加载黑名单、上次修改缓存、初始URL和搜索关键词
    load_blacklist_domains()
    load_last_modified_cache()
    initial_urls = load_initial_urls()
    
    global SEARCH_KEYWORDS
    SEARCH_KEYWORDS = load_search_keywords() # 加载关键词

    all_raw_found_urls = set(initial_urls) # 用于存储所有来源的原始M3U URL

    # 2. 从 GitHub 搜索新的 M3U/M3U8 URL (tv.py.txt 的主要功能)
    logging.info("开始 GitHub 搜索阶段...")
    github_found_urls = await search_github_for_m3u_urls()
    all_raw_found_urls.update(github_found_urls)
    logging.info(f"GitHub 搜索阶段完成，共找到 {len(github_found_urls)} 个新的 URL。")

    # 3. 从 tv_speed.txt 加载 M3U URLs (0523.txt 原有逻辑的一部分，但这里只获取URLs)
    # 假设 tv_speed.txt 存储的是原始 M3U URLs，而不是频道列表
    tv_speed_m3u_urls = get_latest_tv_speed_m3u_urls()
    all_raw_found_urls.update(tv_speed_m3u_urls)
    logging.info(f"从 tv_speed.txt 加载了 {len(tv_speed_m3u_urls)} 个 M3U URL。")

    logging.info(f"所有来源的总 M3U URL 待处理数量: {len(all_raw_found_urls)}")

    # 4. 检查所有原始 M3U URL 的可访问性并过滤 (tv.py.txt 核心功能)
    logging.info(f"开始检查所有 {len(all_raw_found_urls)} 个原始M3U URL的可访问性...")
    
    accessible_m3u_urls = set()
    with ThreadPoolExecutor(max_workers=M3U_CONCURRENCY) as executor:
        future_to_url = {executor.submit(check_url_and_update_cache, url): url for url in all_raw_found_urls}
        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                result_url = future.result()
                if result_url:
                    accessible_m3u_urls.add(result_url)
            except Exception as exc:
                logging.warning(f"URL {url} 检查时产生异常: {exc}")
            
            if (i + 1) % 100 == 0 or (i + 1) == len(all_raw_found_urls):
                logging.info(f"已检查 {i + 1}/{len(all_raw_found_urls)} 个URL。")
    
    logging.info(f"筛选出 {len(accessible_m3u_urls)} 个可访问的 M3U URL。")

    # 5. 异步下载并处理这些 M3U 文件，提取内部的直播频道URL (tv.py.txt 核心功能)
    logging.info(f"开始异步下载并处理 {len(accessible_m3u_urls)} 个 M3U 文件...")
    
    all_extracted_channels = set() # 格式： "频道名,频道URL"
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(ASYNC_HTTP_CONNECTIONS)
        
        async def bounded_process_m3u_url_wrapper(s, url_to_process):
            async with semaphore:
                # process_m3u_url_content 返回的是提取的内部URL列表
                internal_urls = await process_m3u_url_content(s, url_to_process)
                # 对于这些内部URL，我们还需要验证并提取频道信息
                # 这里需要修改 process_m3u_url_content 或新增函数来直接返回 "频道名,URL" 格式
                # 简化处理：这里假设 fetch_m3u_content 已经包含了从M3U内容解析出频道信息的功能
                # 实际这里需要对内部URLs再次进行有效性检查和频道信息提取
                
                # 为了与原 0523.txt 流程兼容，我们现在只提取原始M3U内容，后续再解析和测试速度
                # 重新调整，确保只获取原始M3U内容
                content = await fetch_url_content(session, url_to_process)
                if content:
                    return parse_m3u_content(content) # 返回 [“频道名,URL”, ...]
                return []

        m3u_processing_tasks = [bounded_process_m3u_url_wrapper(session, url) for url in accessible_m3u_urls]
        
        for i, task in enumerate(asyncio.as_completed(m3u_processing_tasks)):
            try:
                extracted_channels_list = await task
                if extracted_channels_list:
                    all_extracted_channels.update(extracted_channels_list)
            except Exception as e:
                logging.warning(f"处理M3U内容任务时发生错误: {e}")
            
            if (i + 1) % 50 == 0 or (i + 1) == len(m3u_processing_tasks):
                logging.info(f"已处理 {i + 1}/{len(m3u_processing_tasks)} 个M3U内容。")

    logging.info(f"从所有M3U文件中提取出 {len(all_extracted_channels)} 个频道。")
    
    # 6. 进行频道速度测试 (0523.txt 核心功能)
    logging.info(f"开始对 {len(all_extracted_channels)} 个频道进行速度测试...")
    # all_extracted_channels 是 set of "name,url" strings
    iptv_speed_channels = get_channel_speed_data(list(all_extracted_channels)) # 转换为列表传入
    logging.info(f"速度测试完成，筛选出 {len(iptv_speed_channels)} 个可用频道。")

    # 7. 根据模板文件匹配和分类频道 (0523.txt 核心功能)
    channel_templates = get_channel_templates()
    
    # Clean up local_channels_directory before writing new files
    if os.path.exists(LOCAL_CHANNELS_DIR):
        shutil.rmtree(LOCAL_CHANNELS_DIR)
    os.makedirs(LOCAL_CHANNELS_DIR)
    
    all_template_channel_names = set() # To track all channel names matched to templates

    for template_name, template_channels in channel_templates.items():
        current_template_matched_channels = []
        template_channel_names_set = set(tc.split(',', 1)[0].strip() for tc in template_channels)
        
        for channel_line in iptv_speed_channels:
            channel_name = channel_line[0].strip() # [0] 是频道名
            if channel_name in template_channel_names_set:
                current_template_matched_channels.append(f"{channel_name},{channel_line[1]}") # 频道名,URL
                all_template_channel_names.add(channel_name) # Add to global set

        # Sort CCTV channels if applicable
        if "CCTV" in template_name or "cctv" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.info(f"Sorted {template_name} channels numerically.")

        output_file_path = os.path.join(LOCAL_CHANNELS_DIR, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.info(f"Channel list written to: {template_name}_iptv.txt, containing {len(current_template_matched_channels)} channels.")

    # 8. 合并所有 IPTV 文件
    merge_iptv_files(LOCAL_CHANNELS_DIR)

    # 9. 查找未匹配的频道
    unmatched_channels = []
    for channel_line in iptv_speed_channels:
        channel_name = channel_line[0].strip() # [0] 是频道名
        if channel_name not in all_template_channel_names:
            unmatched_channels.append(f"{channel_name},{channel_line[1]}") # 频道名,URL

    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels:
            f.write(channel_line + '\n')
    logging.info(f"Unmatched channels written to: unmatched_channels.txt, containing {len(unmatched_channels)} channels.")

    # 10. 保存上次修改时间缓存 (tv.py.txt 的功能)
    save_last_modified_cache()

    # 11. 更新 GitHub 仓库文件 (0523.txt 核心功能)
    logging.info("开始更新 GitHub 仓库文件...")
    update_repo_files()

    logging.info("所有 IPTV 频道整理和更新流程完成。")


if __name__ == "__main__":
    try:
        if sys.platform == "win32" and sys.version_info >= (3, 8):
             asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        asyncio.run(main_integrated_crawler())

    except KeyboardInterrupt:
        logging.info("脚本被用户中断。")
    except Exception as e:
        logging.critical(f"脚本主程序遇到致命错误: {e}")
        logging.critical(traceback.format_exc())
