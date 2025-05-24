import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import requests
import aiohttp
import asyncio
import json
import psutil  # 用于系统资源监控
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import sys
import traceback
import shutil

# --- 配置日志 ---
logging.basicConfig(
    level=logging.INFO,  # 默认INFO级别，可以根据需要调整为DEBUG
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iptv_crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
# 针对 aiohttp 内部日志的调整，减少噪音，只记录 WARNING 及以上
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)


# --- 全局配置 ---
CONFIG_DIR = os.path.join(os.getcwd(), 'config')
LAST_MODIFIED_FILE = os.path.join(CONFIG_DIR, "last_modified_urls.txt")
DEFAULT_LAST_MODIFIED = "Thu, 01 Jan 1970 00:00:00 GMT"
URLS_FILE_PATH = os.path.join(CONFIG_DIR, 'urls.txt')
SEARCH_CONFIG_FILE = os.path.join(CONFIG_DIR, 'search_keywords.json')
BLACKLIST_FILE = os.path.join(CONFIG_DIR, 'blacklist.txt')

TEMPLATES_DIR = os.path.join(os.getcwd(), 'config', 'templates')
M3U_TEMPLATE_FILE = os.path.join(CONFIG_DIR, 'template.m3u')
TV_SPEED_FILE = os.path.join(CONFIG_DIR, 'tv_speed.txt')
LOCAL_CHANNELS_DIR = os.path.join(os.getcwd(), 'channels')
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY')
GITHUB_USERNAME = GITHUB_REPO.split('/')[0] if GITHUB_REPO else 'your_github_username'

# --- GitHub API 配置 ---
GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_API_CODE_SEARCH_PATH = "/search/code"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

GITHUB_REQUEST_INTERVAL = 6
GITHUB_KEYWORD_SLEEP = 10

MAX_SEARCH_PAGES = 1

# --- 异步 HTTP 请求配置 ---
ASYNC_HTTP_TIMEOUT = 15  # 增加超时时间，从10秒增加到15秒
ASYNC_HTTP_CONNECTIONS = 30 # 降低并发连接数，从50降低到30

# M3U 文件处理配置
M3U_TIMEOUT = 10  # 增加M3U内容下载的超时时间
M3U_CONCURRENCY = 50 # 降低M3U并发处理数，从100降低到50

# --- 调试与排查配置（重要！） ---
# 限制处理的M3U URL数量，用于测试。设置为None则不限制。
# 如果你想测试前50个M3U URL，设置为50
# DEBUG_LIMIT_M3U_URLS = 100
DEBUG_LIMIT_M3U_URLS = None

# 限制进行速度测试的频道数量，用于测试。设置为None则不限制。
# 如果你想测试前200个频道，设置为200
# DEBUG_LIMIT_CHANNEL_SPEED_TEST = 200
DEBUG_LIMIT_CHANNEL_SPEED_TEST = None


BLACKLIST_DOMAINS = set()

FINAL_LIVE_M3U_FILE = "live.m3u"
FINAL_LIVE_TXT_FILE = "live.txt"

LAST_MODIFIED_CACHE = {}

# --- 辅助函数 ---

def log_system_metrics(step_name=""):
    """记录当前的系统内存和CPU使用情况"""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cpu_percent = process.cpu_percent(interval=None) # Non-blocking call

    logging.info(f"系统指标 ({step_name}): 内存使用率={mem_info.rss / (1024 * 1024):.2f} MB, CPU利用率={cpu_percent:.2f}%")


def is_url_accessible(url):
    """
    检查URL是否可访问且内容不为空。
    考虑到有时HTTP响应会是3xx重定向，使用 HEAD 请求可能无法准确判断最终内容，
    因此这里使用 GET 请求，并设置较短的超时时间。
    """
    try:
        with requests.get(url, stream=True, timeout=5) as r:
            r.raise_for_status()

            content_length = r.headers.get('Content-Length')
            if content_length is not None and int(content_length) == 0:
                logging.debug(f"URL {url} Content-Length is 0.")
                return False

            try:
                # 尝试读取一小部分内容，判断是否为空
                first_byte = next(r.iter_content(chunk_size=1))
                if not first_byte:
                    logging.debug(f"URL {url} returned no content.")
                    return False
            except StopIteration:
                logging.debug(f"URL {url} stream was empty.")
                return False

            return True
    except requests.exceptions.RequestException as e:
        logging.debug(f"URL {url} 可访问性检查失败: {e}")
        return False
    except Exception as e:
        logging.debug(f"URL {url} 可访问性检查时发生未知错误: {e}")
        return False

def check_url_and_update_cache(url):
    """检查URL是否可访问，并更新上次修改时间缓存"""
    global LAST_MODIFIED_CACHE

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain in BLACKLIST_DOMAINS:
        logging.debug(f"URL {url} 域名在黑名单中，跳过。")
        return None

    last_modified_str = LAST_MODIFIED_CACHE.get(url, DEFAULT_LAST_MODIFIED)
    headers = {'If-Modified-Since': last_modified_str}
    
    try:
        with requests.head(url, headers=headers, timeout=5) as r:
            r.raise_for_status()

            if r.status_code == 304:
                logging.debug(f"URL {url} 未修改 (304)。")
                return url
            
            content_type = r.headers.get('Content-Type', '').lower()
            # 允许更多文本类型，但主要还是M3U/JSON/XML
            if not any(ct_part in content_type for ct_part in ['text', 'json', 'xml', 'mpegurl']):
                logging.warning(f"URL {url} 的Content-Type '{content_type}' 不是预期的文本类型，跳过。")
                return None

            new_last_modified = r.headers.get('Last-Modified', datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"))
            LAST_MODIFIED_CACHE[url] = new_last_modified
            logging.debug(f"URL {url} 已更新或验证，新的Last-Modified: {new_last_modified}")
            return url
    except requests.exceptions.RequestException as e:
        logging.debug(f"URL {url} HEAD请求失败: {e}")
        return None
    except Exception as e:
        logging.debug(f"URL {url} HEAD请求时发生未知错误: {e}")
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
    for line in m3u_content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            # 扩大匹配范围，包括 rtmp, rtsp 等
            if re.match(r'^(https?|rtmp|rtsp)://[^\s]+', line, re.IGNORECASE):
                urls.add(line)
            elif base_url: # 尝试解析相对路径
                try:
                    absolute_url = urljoin(base_url, line)
                    if re.match(r'^(https?|rtmp|rtsp)://', absolute_url, re.IGNORECASE):
                        urls.add(absolute_url)
                except ValueError:
                    pass

    return list(urls)

async def fetch_url_content(session, url):
    """异步获取URL内容"""
    try:
        logging.debug(f"开始下载M3U内容: {url}")
        async with session.get(url, timeout=M3U_TIMEOUT) as response:
            response.raise_for_status()
            content = await response.text()
            logging.debug(f"下载M3U内容完成: {url} (大小: {len(content)} 字符)")
            return content
    except aiohttp.ClientError as e:
        logging.warning(f"下载M3U URL失败 ({url}): {e}")
        return None
    except asyncio.TimeoutError:
        logging.warning(f"下载M3U URL超时 ({url})")
        return None
    except Exception as e:
        logging.warning(f"下载M3U URL时发生未知错误 ({url}): {e}")
        return None

async def process_m3u_url_content(session, m3u_url, url_idx, total_urls):
    """异步处理M3U URL，下载内容并提取内部频道"""
    logging.info(f"正在处理 M3U URL ({url_idx}/{total_urls}): {m3u_url}")
    
    try:
        content = await fetch_url_content(session, m3u_url)
        if content:
            if "#EXTM3U" not in content:
                logging.warning(f"URL {m3u_url} 内容不包含 #EXTM3U 头，可能不是有效的M3U文件。")
                return []

            extracted_channels = parse_m3u_content(content)
            logging.debug(f"从 {m3u_url} 提取了 {len(extracted_channels)} 个频道。")
            return extracted_channels
        return []
    except Exception as e:
        logging.error(f"处理 M3U URL {m3u_url} 时发生未预期错误: {e}\n{traceback.format_exc()}")
        return []


# --- 数据加载与保存 ---

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
        try:
            with open(LAST_MODIFIED_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',', 1)
                    if len(parts) == 2:
                        url, timestamp = parts
                        LAST_MODIFIED_CACHE[url] = timestamp
            logging.info(f"已加载 {len(LAST_MODIFIED_CACHE)} 个URL的上次修改时间缓存.")
        except Exception as e:
            logging.warning(f"加载上次修改时间缓存文件失败: {e}。将从头开始。")
            LAST_MODIFIED_CACHE = {} # 出现错误则清空缓存
    else:
        logging.info("上次修改时间缓存文件不存在，将从头开始。")

def save_last_modified_cache():
    """保存上次修改时间缓存"""
    try:
        with open(LAST_MODIFIED_FILE, 'w', encoding='utf-8') as f:
            for url, timestamp in LAST_MODIFIED_CACHE.items():
                f.write(f"{url},{timestamp}\n")
        logging.info("已保存上次修改时间缓存.")
    except Exception as e:
        logging.error(f"保存上次修改时间缓存失败: {e}")

def load_initial_urls():
    """从urls.txt加载初始URL列表"""
    urls = set()
    if os.path.exists(URLS_FILE_PATH):
        try:
            with open(URLS_FILE_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and re.match(r'^(https?|rtmp|rtsp)://', url, re.IGNORECASE): # 允许更多协议
                        urls.add(url)
            logging.info(f"从 {URLS_FILE_PATH} 加载了 {len(urls)} 个初始 URL.")
        except Exception as e:
            logging.warning(f"加载初始URL文件 {URLS_FILE_PATH} 失败: {e}。跳过加载。")
    else:
        logging.warning(f"初始URL文件 {URLS_FILE_PATH} 不存在。")
    return list(urls)

def load_search_keywords():
    """
    加载 GitHub 搜索关键词。
    优先从 config/search_keywords.json 加载，如果文件不存在或加载失败，则使用默认关键词。
    """
    default_keywords = [
        '"raw.githubusercontent.com" extension:m3u8',
        '"raw.githubusercontent.com" extension:m3u',
      #  'filename:playlist.m3u8',
       # 'filename:index.m3u8',
      #  'filename:channels.m3u',
      #  'filename:tv.m3u8',
     #   'filename:tv.m3u',
      #  'filename:live.m3u8',
     #   'filename:live.m3u',
      #  'extension:m3u8',
     #   'extension:m3u',
      #  '"#EXTM3U" extension:m3u',
     #   '"#EXTM3U" extension:m3u8',
     #   '"iptv playlist" extension:m3u',
     #   '"iptv playlist" extension:m3u8',
     #   '"live tv" extension:m3u',
     #   '"live tv" extension:m3u8',
     #   '"tv channels" extension:m3u',
      #  '"tv channels" extension:m3u8',
        '"直播源" extension:m3u',
        '"直播源" extension:m3u8',
        '"电视直播" extension:m3u',
        '"电视直播" extension:m3u8',
        # 新增对FLV、RTMP、RTSP的搜索关键词
     #   '"raw.githubusercontent.com" extension:flv',
      #  '"raw.githubusercontent.com" rtmp',
     #   '"raw.githubusercontent.com" rtsp'
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
    
    if custom_keywords:
        # 使用 set 消除重复项，并保持顺序
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
    if GITHUB_TOKEN and not hasattr(github_search_code, 'token_logged'):
        logging.info("GITHUB_TOKEN 环境变量已设置。")
        github_search_code.token_logged = True

    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    
    params = {
        "q": keyword,
        "per_page": 100,
        "page": page
    }
    
    api_url = f"{GITHUB_API_BASE_URL}{GITHUB_API_CODE_SEARCH_PATH}"
    
    async with session.get(api_url, headers=headers, params=params, timeout=ASYNC_HTTP_TIMEOUT) as response:
        remaining = response.headers.get('X-RateLimit-Remaining')
        reset_time = response.headers.get('X-RateLimit-Reset')
        if remaining and int(remaining) == 0:
            reset_timestamp = int(reset_time)
            sleep_time = max(0, reset_timestamp - time.time() + 5)
            logging.warning(f"GitHub API 速率限制已耗尽，将在 {sleep_time:.2f} 秒后重试。")
            await asyncio.sleep(sleep_time)
            return await github_search_code(session, keyword, page)

        response.raise_for_status()
        return await response.json()

async def search_github_for_m3u_urls():
    """在GitHub上搜索M3U/M3U8 URL"""
    found_urls = set()
    async with aiohttp.ClientSession() as session:
        if GITHUB_TOKEN and not hasattr(github_search_code, 'token_logged'):
            logging.info("GITHUB_TOKEN 环境变量已设置。")
            github_search_code.token_logged = True

        for keyword_idx, keyword in enumerate(SEARCH_KEYWORDS):
            logging.info(f"GitHub 搜索 ({keyword_idx + 1}/{len(SEARCH_KEYWORDS)}) 使用关键词: '{keyword}'")
            
            for page in range(1, MAX_SEARCH_PAGES + 1):
                try:
                    results = await github_search_code(session, keyword, page)
                    if not results or not results.get('items'):
                        logging.info(f"关键词 '{keyword}' 页面 {page} 未找到结果。")
                        break
                    
                    for item in results['items']:
                        raw_url = item['html_url'].replace('/blob/', '/raw/')
                        found_urls.add(raw_url)
                    
                    logging.info(f"关键词 '{keyword}' 页面 {page} 找到 {len(results['items'])} 个结果。")

                    if len(results['items']) < 100:
                        break # Reach end of results for this keyword

                    await asyncio.sleep(GITHUB_REQUEST_INTERVAL)
                        
                except aiohttp.ClientResponseError as e:
                    if e.status == 403:
                        logging.error(f"GitHub API 速率限制 (403): {e.status} {e.message}. 请等待或设置 GITHUB_TOKEN。")
                        return list(found_urls)
                    elif e.status == 422:
                        logging.warning(f"GitHub API 请求处理失败 (422). 关键词 '{keyword}' 可能过于复杂或无效。跳过此关键词。")
                        break
                    else:
                        logging.error(f"GitHub API 请求失败 ({e.status}): {e}")
                        break
                except asyncio.TimeoutError:
                    logging.error(f"GitHub API 请求超时 (关键词: '{keyword}', 页面: {page})")
                    break
                except Exception as e:
                    logging.error(f"GitHub 搜索 '{keyword}' 页面 {page} 时发生未知错误: {e}\n{traceback.format_exc()}")
                    break

            if keyword_idx < len(SEARCH_KEYWORDS) - 1:
                logging.info(f"关键词 '{keyword}' 处理完毕，休眠 {GITHUB_KEYWORD_SLEEP} 秒...")
                await asyncio.sleep(GITHUB_KEYWORD_SLEEP)
            
    return list(found_urls)


# --- 从 0523.txt 移植的核心功能 (修改部分) ---

def get_channel_templates():
    """Reads channel templates from config/templates directory."""
    templates = {}
    if not os.path.exists(TEMPLATES_DIR):
        logging.warning(f"Templates directory not found: {TEMPLATES_DIR}. Creating it...")
        os.makedirs(TEMPLATES_DIR)
        return templates

    for filename in os.listdir(TEMPLATES_DIR):
        if filename.endswith(".txt"):
            template_name = filename[:-4]
            filepath = os.path.join(TEMPLATES_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    templates[template_name] = [line.strip() for line in f if line.strip()]
                logging.info(f"Loaded template: {template_name} with {len(templates[template_name])} channels.")
            except Exception as e:
                logging.error(f"加载模板文件 {filepath} 失败: {e}")
    return templates

def sort_cctv_channels(channels):
    """Sorts CCTV channels numerically."""
    def get_cctv_number(channel_name):
        match = re.match(r'CCTV-(\d+)', channel_name, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return float('inf')

    return sorted(channels, key=lambda x: get_cctv_number(x.split(',', 1)[0]))

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_m3u_content(url):
    """Fetches M3U content from a URL with retry."""
    logging.debug(f"Fetching M3U content from: {url}")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
    }
    response = requests.get(url, headers=headers, timeout=M3U_TIMEOUT) # Use M3U_TIMEOUT
    response.raise_for_status()
    return response.text

def parse_m3u_content(content):
    """
    Parses M3U content and extracts channel name and URL.
    增加了对多种协议的支持，并尝试更灵活地匹配URL。
    """
    channels = []
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("#EXTINF"):
            channel_info = lines[i]
            
            # 尝试在当前EXTINF行中直接匹配URL (某些M3U格式会将URL放在EXTINF行末尾)
            match_url_in_extinf = re.search(r'(https?|rtmp|rtsp)://[^\s]+', channel_info, re.IGNORECASE)
            
            channel_url = None
            if match_url_in_extinf:
                channel_url = match_url_in_extinf.group(0).strip()
            else:
                # 如果EXTINF行中没有URL，则检查下一行
                j = i + 1
                while j < len(lines):
                    line_to_check = lines[j].strip()
                    # 匹配任何以 http, https, rtmp, rtsp 开头的行
                    if re.match(r'^(https?|rtmp|rtsp)://[^\s]+', line_to_check, re.IGNORECASE):
                        channel_url = line_to_check
                        break
                    # 如果是空行或注释行，则跳过
                    if not line_to_check or line_to_check.startswith('#'):
                        j += 1
                        continue
                    # 如果不是URL也不是空行/注释行，则认为此EXTINF条目有问题
                    break 
                i = j -1 # 调整i以跳过已处理的URL行，或者停在未匹配的行

            if channel_url:
                # 从EXTINF行中提取频道名称
                match_name = re.search(r'tvg-name="([^"]*)"', channel_info)
                if not match_name:
                    match_name = re.search(r'group-title="([^"]*)"', channel_info)
                
                channel_name = match_name.group(1).strip() if match_name else ""

                # 如果名称仍为空或通用，尝试从EXTINF行末尾或URL提取
                if not channel_name or "Unknown Channel" in channel_name: # "Unknown Channel" 是之前的默认值
                    extinf_parts = channel_info.split(',')
                    if len(extinf_parts) > 1 and extinf_parts[-1].strip():
                        # 从 EXTINF 行的最后一个逗号后提取名称
                        name_candidate = extinf_parts[-1].strip()
                        # 确保提取的名称不是一个URL片段
                        if not re.match(r'^(https?|rtmp|rtsp)://', name_candidate, re.IGNORECASE):
                            channel_name = name_candidate
                    
                    if not channel_name and channel_url:
                        # 从URL路径中提取名称
                        path = urlparse(channel_url).path
                        if path:
                            channel_name = os.path.splitext(os.path.basename(path))[0].replace('_', ' ').replace('-', ' ').strip()
                            if not channel_name: # If path basename is empty, try netloc
                                channel_name = urlparse(channel_url).netloc.split('.')[0]
                        else: # If no path, use netloc
                            channel_name = urlparse(channel_url).netloc.split('.')[0] # 最终 fallback
                    
                    if not channel_name: # Final fallback if all else fails
                        channel_name = "Unknown Channel" 
                
                channels.append(f"{channel_name},{channel_url}")
                
            else:
                logging.warning(f"Skipping malformed #EXTINF entry (no URL found): {lines[i]}")
            i += 1
        else:
            i += 1
    return channels

def get_latest_tv_speed_m3u_urls():
    """Fetches the latest M3U content from the configured tv_speed.txt and extracts URLs."""
    all_urls = set()
    if os.path.exists(TV_SPEED_FILE):
        try:
            with open(TV_SPEED_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and re.match(r'^(https?|rtmp|rtsp)://', line, re.IGNORECASE): # 允许更多协议
                        all_urls.add(line)
            logging.info(f"Loaded {len(all_urls)} URLs from {TV_SPEED_FILE}.")
        except Exception as e:
            logging.warning(f"加载 {TV_SPEED_FILE} 失败: {e}。跳过加载。")
    else:
        logging.warning(f"{TV_SPEED_FILE} not found. Skipping URL loading from it.")
    return list(all_urls)


def check_stream_speed(channel_tuple, timeout=5): # 接收元组 (name, url)
    """Checks the speed of an IPTV stream URL by downloading a small part."""
    channel_name, channel_url = channel_tuple
    try:
        start_time = time.time()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
        }
        with requests.get(channel_url, headers=headers, stream=True, timeout=timeout) as r:
            r.raise_for_status()

            content_type = r.headers.get('Content-Type', '').lower()
            # 扩展识别的 Content-Type，包括常见的视频流类型
            if not any(ct_part in content_type for ct_part in [
                'application/x-mpegurl', # M3U/M3U8
                'audio/mpegurl',
                'video/', # 匹配所有 video/* 类型，如 video/mp4, video/x-flv, video/quicktime 等
                'application/octet-stream' # 有些流可能是通用二进制流
            ]):
                logging.debug(f"Skipping non-stream URL based on Content-Type: {channel_url} ({content_type})")
                return -1, False, channel_tuple # 返回原始频道信息

            chunk_size = 1024 * 5
            downloaded_bytes = 0
            for chunk in r.iter_content(chunk_size=chunk_size):
                downloaded_bytes += len(chunk)
                if downloaded_bytes >= chunk_size:
                    break
            
            if downloaded_bytes == 0:
                logging.debug(f"Stream {channel_url} returned 0 bytes.")
                return -1, False, channel_tuple

            end_time = time.time()
            elapsed_time = end_time - start_time
            if elapsed_time == 0:
                speed = float('inf')
            else:
                speed = (downloaded_bytes / 1024) / elapsed_time
            
            logging.debug(f"Checked URL: {channel_url}, Speed: {speed:.2f} KB/s")
            return speed, True, channel_tuple
    except (requests.exceptions.Timeout, socket.timeout) as e:
        logging.debug(f"Stream {channel_url} timeout: {e}")
        return -1, False, channel_tuple
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
        logging.debug(f"Stream {channel_url} connection error: {e}")
        return -1, False, channel_tuple
    except Exception as e:
        logging.warning(f"Error checking stream speed for {channel_url}: {e}\n{traceback.format_exc()}")
        return -1, False, channel_tuple

def get_channel_speed_data(channels):
    """Checks speeds for all channels and returns a dictionary with speeds."""
    valid_channels_with_speed = []
    
    # 将 "频道名,URL" 字符串转换为 (频道名, URL) 元组列表
    channels_tuples = [tuple(c.split(',', 1)) for c in channels]
    
    if DEBUG_LIMIT_CHANNEL_SPEED_TEST:
        logging.info(f"DEBUG模式: 限制速度测试频道数量为 {DEBUG_LIMIT_CHANNEL_SPEED_TEST} 个。")
        channels_tuples = channels_tuples[:DEBUG_LIMIT_CHANNEL_SPEED_TEST]

    total_channels_to_test = len(channels_tuples)
    
    with ThreadPoolExecutor(max_workers=M3U_CONCURRENCY) as executor: # 复用M3U_CONCURRENCY，或者可以定义新的并发数
        future_to_channel_tuple = {executor.submit(check_stream_speed, channel_tuple): channel_tuple for channel_tuple in channels_tuples}
        
        for i, future in enumerate(as_completed(future_to_channel_tuple)):
            original_channel_tuple = future_to_channel_tuple[future]
            channel_name, channel_url = original_channel_tuple
            
            try:
                speed, is_stream, _ = future.result() # 接收返回的原始频道信息
                if speed > 0 and is_stream:
                    valid_channels_with_speed.append((channel_name, channel_url, speed))
                else:
                    logging.debug(f"Channel {channel_name} ({channel_url}) 被标记为无效或速度为 -1。")
            except Exception as exc:
                logging.warning(f"Channel {channel_name} ({channel_url}) 速度测试时发生异常: {exc}\n{traceback.format_exc()}")
            
            if (i + 1) % 50 == 0 or (i + 1) == total_channels_to_test:
                logging.info(f"速度测试进度: {i + 1}/{total_channels_to_test} 频道已测试。")
                log_system_metrics(f"速度测试进行中 - {i + 1}/{total_channels_to_test}")
    
    valid_channels_with_speed.sort(key=lambda x: x[2], reverse=True)
    return valid_channels_with_speed

def merge_iptv_files(directory):
    """Merges all IPTV files in the given directory into a single m3u and txt file."""
    merged_m3u_content = "#EXTM3U\n"
    merged_txt_content = ""
    
    txt_files = [f for f in os.listdir(directory) if f.endswith("_iptv.txt")]
    
    for filename in sorted(txt_files):
        filepath = os.path.join(directory, filename)
        template_name = filename.replace('_iptv.txt', '')
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if lines:
                    merged_txt_content += lines[0] # Add genre header
                    
                    merged_m3u_content += f"#EXTINF:-1 group-title=\"{template_name}\",{template_name}\n" # Genre header for M3U
                    
                    for line_idx, line in enumerate(lines[1:]): # Skip the first line (genre header)
                        channel_name, channel_url = line.strip().split(',', 1)
                        merged_txt_content += line
                        merged_m3u_content += f"#EXTINF:-1 group-title=\"{template_name}\",{channel_name}\n"
                        merged_m3u_content += f"{channel_url}\n"
        except Exception as e:
            logging.error(f"合并文件 {filepath} 失败: {e}")
            continue # Skip this file and continue with others
            
    try:
        with open(FINAL_LIVE_TXT_FILE, 'w', encoding='utf-8') as f:
            f.write(merged_txt_content)
        logging.info(f"Merged all IPTV channels into {FINAL_LIVE_TXT_FILE}")

        with open(FINAL_LIVE_M3U_FILE, 'w', encoding='utf-8') as f:
            f.write(merged_m3u_content)
        logging.info(f"Merged all IPTV channels into {FINAL_LIVE_M3U_FILE}")
    except Exception as e:
        logging.error(f"写入合并文件失败: {e}")


def update_repo_files():
    """Commits and pushes changes to the GitHub repository."""
    try:
        subprocess.run(['git', 'config', 'user.name', GITHUB_USERNAME], check=True)
        subprocess.run(['git', 'config', 'user.email', f"{GITHUB_USERNAME}@users.noreply.github.com"], check=True)
        
        # Add files to be staged
        subprocess.run(['git', 'add', FINAL_LIVE_M3U_FILE], check=True)
        subprocess.run(['git', 'add', FINAL_LIVE_TXT_FILE], check=True)
        subprocess.run(['git', 'add', os.path.join(LOCAL_CHANNELS_DIR, '*_iptv.txt')], check=True)
        subprocess.run(['git', 'add', 'unmatched_channels.txt'], check=True)
        subprocess.run(['git', 'add', LAST_MODIFIED_FILE], check=True)

        # Check if there are any changes to commit
        result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            commit_message = "Update IPTV channels and cache"
            subprocess.run(['git', 'commit', '-m', commit_message], check=True)
            logging.info("Changes committed.")
            
            # Push changes to the repository
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
    
    # Create empty dummy files if they don't exist
    for file_path in [URLS_FILE_PATH, TV_SPEED_FILE, BLACKLIST_FILE]:
        if not os.path.exists(file_path):
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("")
            logging.info(f"Created empty dummy file: {file_path}")
    
    if not os.path.exists(M3U_TEMPLATE_FILE):
        with open(M3U_TEMPLATE_FILE, 'w', encoding='utf-8') as f:
            f.write("#EXTM3U\n#EXTINF:-1,Sample Channel\nhttp://example.com/stream.m3u8\n")
        logging.info(f"Created sample {M3U_TEMPLATE_FILE}.")

    if not os.path.exists(SEARCH_CONFIG_FILE):
        with open(SEARCH_CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write('{"keywords": []}\n')
        logging.info(f"Created empty {SEARCH_CONFIG_FILE} for search keywords.")


# --- 主程序逻辑 ---

async def main_integrated_crawler():
    """
    集成了 GitHub 搜索、URL 验证、M3U 内容提取、频道整理和 Git 提交的主函数。
    """
    logging.info("===== 脚本开始执行 =====")
    log_system_metrics("启动")

    setup_directories()

    load_blacklist_domains()
    load_last_modified_cache()
    initial_urls = load_initial_urls()
    
    global SEARCH_KEYWORDS
    SEARCH_KEYWORDS = load_search_keywords()

    all_raw_found_urls = set(initial_urls)

    logging.info("开始 GitHub 搜索阶段...")
    log_system_metrics("GitHub搜索开始")
    github_found_urls = await search_github_for_m3u_urls()
    all_raw_found_urls.update(github_found_urls)
    logging.info(f"GitHub 搜索阶段完成，共找到 {len(github_found_urls)} 个新的 URL。")
    log_system_metrics("GitHub搜索结束")

    tv_speed_m3u_urls = get_latest_tv_speed_m3u_urls()
    all_raw_found_urls.update(tv_speed_m3u_urls)
    logging.info(f"从 tv_speed.txt 加载了 {len(tv_speed_m3u_urls)} 个 M3U URL。")

    all_raw_found_urls_list = list(all_raw_found_urls)

    if DEBUG_LIMIT_M3U_URLS:
        logging.info(f"DEBUG模式: 限制M3U URL数量为 {DEBUG_LIMIT_M3U_URLS} 个。")
        all_raw_found_urls_list = all_raw_found_urls_list[:DEBUG_LIMIT_M3U_URLS]

    logging.info(f"所有来源的总 M3U URL 待处理数量: {len(all_raw_found_urls_list)}")

    logging.info(f"开始检查所有 {len(all_raw_found_urls_list)} 个原始M3U URL的可访问性...")
    log_system_metrics("URL可访问性检查开始")
    
    accessible_m3u_urls = set()
    with ThreadPoolExecutor(max_workers=M3U_CONCURRENCY) as executor: # 复用 M3U_CONCURRENCY
        future_to_url = {executor.submit(check_url_and_update_cache, url): url for url in all_raw_found_urls_list}
        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                result_url = future.result()
                if result_url:
                    accessible_m3u_urls.add(result_url)
            except Exception as exc:
                logging.warning(f"URL {url} 可访问性检查时产生异常: {exc}\n{traceback.format_exc()}")
            
            if (i + 1) % 100 == 0 or (i + 1) == len(all_raw_found_urls_list):
                logging.info(f"已检查 {i + 1}/{len(all_raw_found_urls_list)} 个URL。")
                log_system_metrics(f"URL可访问性检查进行中 - {i + 1}/{len(all_raw_found_urls_list)}")
    
    logging.info(f"筛选出 {len(accessible_m3u_urls)} 个可访问的 M3U URL。")
    log_system_metrics("URL可访问性检查结束")

    logging.info(f"开始异步下载并处理 {len(accessible_m3u_urls)} 个 M3U 文件...")
    log_system_metrics("M3U文件处理开始")
    
    all_extracted_channels = set()
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(ASYNC_HTTP_CONNECTIONS)
        
        async def bounded_process_m3u_url_wrapper(s, url_to_process, url_idx, total_urls):
            async with semaphore:
                return await process_m3u_url_content(s, url_to_process, url_idx, total_urls)

        m3u_urls_to_process = list(accessible_m3u_urls)
        total_m3u_urls_to_process = len(m3u_urls_to_process)
        m3u_processing_tasks = [
            bounded_process_m3u_url_wrapper(session, url, i + 1, total_m3u_urls_to_process)
            for i, url in enumerate(m3u_urls_to_process)
        ]
        
        for i, task in enumerate(asyncio.as_completed(m3u_processing_tasks)):
            try:
                extracted_channels_list = await task
                if extracted_channels_list:
                    all_extracted_channels.update(extracted_channels_list)
            except Exception as e:
                logging.warning(f"处理M3U内容任务时发生意外错误: {e}\n{traceback.format_exc()}")
            
            if (i + 1) % 50 == 0 or (i + 1) == total_m3u_urls_to_process:
                logging.info(f"已处理 {i + 1}/{total_m3u_urls_to_process} 个M3U内容。")
                log_system_metrics(f"M3U内容处理进行中 - {i + 1}/{total_m3u_urls_to_process}")

    logging.info(f"从所有M3U文件中提取出 {len(all_extracted_channels)} 个频道。")
    log_system_metrics("M3U文件处理结束")
    
    logging.info(f"开始对 {len(all_extracted_channels)} 个频道进行速度测试...")
    log_system_metrics("速度测试开始")
    iptv_speed_channels = get_channel_speed_data(list(all_extracted_channels))
    logging.info(f"速度测试完成，筛选出 {len(iptv_speed_channels)} 个可用频道。")
    log_system_metrics("速度测试结束")

    channel_templates = get_channel_templates()
    
    if os.path.exists(LOCAL_CHANNELS_DIR):
        logging.info(f"清空现有 {LOCAL_CHANNELS_DIR} 目录。")
        shutil.rmtree(LOCAL_CHANNELS_DIR)
    os.makedirs(LOCAL_CHANNELS_DIR)
    
    all_template_channel_names = set()

    for template_name, template_channels in channel_templates.items():
        current_template_matched_channels = []
        template_channel_names_set = set(tc.split(',', 1)[0].strip() for tc in template_channels)
        
        for channel_line in iptv_speed_channels:
            channel_name = channel_line[0].strip()
            if channel_name in template_channel_names_set:
                current_template_matched_channels.append(f"{channel_name},{channel_line[1]}")
                all_template_channel_names.add(channel_name)

        if "CCTV" in template_name or "cctv" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.info(f"Sorted {template_name} channels numerically.")

        output_file_path = os.path.join(LOCAL_CHANNELS_DIR, f"{template_name}_iptv.txt")
        try:
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(f"{template_name},#genre#\n")
                for channel in current_template_matched_channels:
                    f.write(channel + '\n')
            logging.info(f"Channel list written to: {template_name}_iptv.txt, containing {len(current_template_matched_channels)} channels.")
        except Exception as e:
            logging.error(f"写入模板文件 {output_file_path} 失败: {e}")

    logging.info("开始合并IPTV文件...")
    log_system_metrics("文件合并开始")
    merge_iptv_files(LOCAL_CHANNELS_DIR)
    log_system_metrics("文件合并结束")

    unmatched_channels = []
    for channel_line in iptv_speed_channels:
        channel_name = channel_line[0].strip()
        if channel_name not in all_template_channel_names:
            unmatched_channels.append(f"{channel_name},{channel_line[1]}")

    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    try:
        with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
            for channel_line in unmatched_channels:
                f.write(channel_line + '\n')
        logging.info(f"Unmatched channels written to: unmatched_channels.txt, containing {len(unmatched_channels)} channels.")
    except Exception as e:
        logging.error(f"写入未匹配频道文件失败: {e}")

    save_last_modified_cache()

    logging.info("开始更新 GitHub 仓库文件...")
    log_system_metrics("Git操作开始")
    try:
        update_repo_files()
    except Exception as e:
        logging.critical(f"Git 操作失败，可能需要手动处理: {e}\n{traceback.format_exc()}")
    log_system_metrics("Git操作结束")

    logging.info("===== 所有 IPTV 频道整理和更新流程完成。=====")


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
