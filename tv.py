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
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import sys
import traceback
import shutil

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

# 异步 HTTP 请求配置
ASYNC_HTTP_TIMEOUT = 10
ASYNC_HTTP_CONNECTIONS = 50

# M3U 文件处理配置
M3U_TIMEOUT = 5
M3U_CONCURRENCY = 100

BLACKLIST_DOMAINS = set()

FINAL_LIVE_M3U_FILE = "live.m3u"
FINAL_LIVE_TXT_FILE = "live.txt"

LAST_MODIFIED_CACHE = {}

# --- 辅助函数 ---

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
                return False

            try:
                first_byte = next(r.iter_content(chunk_size=1))
                if not first_byte:
                    return False
            except StopIteration:
                return False

            return True
    except requests.exceptions.RequestException:
        return False
    except Exception:
        return False

def check_url_and_update_cache(url):
    """检查URL是否可访问，并更新上次修改时间缓存"""
    global LAST_MODIFIED_CACHE

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain in BLACKLIST_DOMAINS:
        return None

    last_modified_str = LAST_MODIFIED_CACHE.get(url, DEFAULT_LAST_MODIFIED)
    headers = {'If-Modified-Since': last_modified_str}
    
    try:
        with requests.head(url, headers=headers, timeout=5) as r:
            r.raise_for_status()

            if r.status_code == 304:
                return url
            
            content_type = r.headers.get('Content-Type', '').lower()
            # 允许更多文本类型，但主要还是M3U/JSON/XML
            if not any(ct_part in content_type for ct_part in ['text', 'json', 'xml', 'mpegurl']):
                logging.warning(f"URL {url} 的Content-Type '{content_type}' 不是文本类型，跳过。")
                return None

            new_last_modified = r.headers.get('Last-Modified', datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"))
            LAST_MODIFIED_CACHE[url] = new_last_modified
            return url
    except requests.exceptions.RequestException:
        return None
    except Exception:
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
        async with session.get(url, timeout=ASYNC_HTTP_TIMEOUT) as response:
            response.raise_for_status()
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
        if "#EXTM3U" not in content:
            logging.warning(f"URL {m3u_url} 内容不包含 #EXTM3U 头，可能不是有效的M3U文件。")
            return []

        # 直接返回解析后的 "频道名,URL" 格式列表
        return parse_m3u_content(content)
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
                if url and re.match(r'^(https?|rtmp|rtsp)://', url, re.IGNORECASE): # 允许更多协议
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
        '"#EXTM3U" extension:m3u',
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
        # 新增对FLV、RTMP、RTSP的搜索关键词
        '"raw.githubusercontent.com" extension:flv',
        '"raw.githubusercontent.com" rtmp',
        '"raw.githubusercontent.com" rtsp'
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
                        break

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
        return float('inf')

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
                match_name = re.search(r'tvg-name="([^"]*)"', channel_info)
                if not match_name:
                    match_name = re.search(r'group-title="([^"]*)"', channel_info)
                
                channel_name = match_name.group(1).strip() if match_name else ""

                # 如果名称仍为空或通用，尝试从EXTINF行末尾或URL提取
                if not channel_name or "Unknown Channel" in channel_name: # "Unknown Channel" 是之前的默认值
                    extinf_parts = channel_info.split(',')
                    if len(extinf_parts) > 1 and extinf_parts[-1].strip():
                        channel_name = extinf_parts[-1].strip()
                    elif channel_url:
                        path = urlparse(channel_url).path
                        if path:
                            channel_name = os.path.splitext(os.path.basename(path))[0].replace('_', ' ').replace('-', ' ').strip()
                            if not channel_name:
                                channel_name = urlparse(channel_url).netloc.split('.')[0]
                        else:
                            channel_name = urlparse(channel_url).netloc.split('.')[0] # 最终 fallback
                    else:
                        channel_name = "Unknown Channel" # 最终 fallback
                
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
        with open(TV_SPEED_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and re.match(r'^(https?|rtmp|rtsp)://', line, re.IGNORECASE): # 允许更多协议
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
                return -1, False

            chunk_size = 1024 * 5
            downloaded_bytes = 0
            for chunk in r.iter_content(chunk_size=chunk_size):
                downloaded_bytes += len(chunk)
                if downloaded_bytes >= chunk_size:
                    break
            
            if downloaded_bytes == 0:
                return -1, False

            end_time = time.time()
            elapsed_time = end_time - start_time
            if elapsed_time == 0:
                return float('inf'), True
            
            speed = (downloaded_bytes / 1024) / elapsed_time
            logging.debug(f"Checked URL: {channel_url}, Speed: {speed:.2f} KB/s")
            return speed, True
    except (requests.exceptions.Timeout, socket.timeout):
        return -1, False
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
        return -1, False
    except Exception as e:
        logging.warning(f"Error checking stream speed for {channel_url}: {e}")
        return -1, False

def get_channel_speed_data(channels):
    """Checks speeds for all channels and returns a dictionary with speeds."""
    channel_speeds = {}
    valid_channels_with_speed = []
    
    with ThreadPoolExecutor(max_workers=M3U_CONCURRENCY) as executor:
        future_to_channel = {executor.submit(check_stream_speed, channel.split(',', 1)[1]): channel for channel in channels}
        
        for i, future in enumerate(as_completed(future_to_channel)):
            channel_line = future_to_channel[future]
            channel_name, channel_url = channel_line.split(',', 1)
            
            try:
                speed, is_stream = future.result()
                if speed > 0 and is_stream:
                    channel_speeds[channel_url] = speed
                    valid_channels_with_speed.append((channel_name, channel_url, speed))
            except Exception as exc:
                logging.warning(f"Channel {channel_name} ({channel_url}) generated an exception: {exc}")
            
            if (i + 1) % 50 == 0 or (i + 1) == len(channels):
                logging.info(f"Speed test progress: {i + 1}/{len(channels)} channels tested.")
    
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
        
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if lines:
                merged_txt_content += lines[0]
                
                merged_m3u_content += f"#EXTINF:-1 group-title=\"{template_name}\",{template_name}\n"
                
                for line_idx, line in enumerate(lines[1:]):
                    channel_name, channel_url = line.strip().split(',', 1)
                    merged_txt_content += line
                    merged_m3u_content += f"#EXTINF:-1 group-title=\"{template_name}\",{channel_name}\n"
                    merged_m3u_content += f"{channel_url}\n"
    
    with open(FINAL_LIVE_TXT_FILE, 'w', encoding='utf-8') as f:
        f.write(merged_txt_content)
    logging.info(f"Merged all IPTV channels into {FINAL_LIVE_TXT_FILE}")

    with open(FINAL_LIVE_M3U_FILE, 'w', encoding='utf-8') as f:
        f.write(merged_m3u_content)
    logging.info(f"Merged all IPTV channels into {FINAL_LIVE_M3U_FILE}")


def update_repo_files():
    """Commits and pushes changes to the GitHub repository."""
    try:
        subprocess.run(['git', 'config', 'user.name', GITHUB_USERNAME], check=True)
        subprocess.run(['git', 'config', 'user.email', f"{GITHUB_USERNAME}@users.noreply.github.com"], check=True)
        
        subprocess.run(['git', 'add', FINAL_LIVE_M3U_FILE], check=True)
        subprocess.run(['git', 'add', FINAL_LIVE_TXT_FILE], check=True)
        subprocess.run(['git', 'add', os.path.join(LOCAL_CHANNELS_DIR, '*_iptv.txt')], check=True)
        subprocess.run(['git', 'add', 'unmatched_channels.txt'], check=True)
        subprocess.run(['git', 'add', LAST_MODIFIED_FILE], check=True)

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
    
    for file_path in [URLS_FILE_PATH, TV_SPEED_FILE, BLACKLIST_FILE, M3U_TEMPLATE_FILE]:
        if not os.path.exists(file_path):
            with open(file_path, 'w', encoding='utf-8') as f:
                if file_path == M3U_TEMPLATE_FILE:
                    f.write("#EXTM3U\n#EXTINF:-1,Sample Channel\nhttp://example.com/stream.m3u8\n")
                elif file_path == SEARCH_CONFIG_FILE:
                    f.write('{"keywords": []}\n')
                else:
                    f.write("")
            logging.info(f"Created empty dummy file: {file_path}")
    
    if not os.path.exists(SEARCH_CONFIG_FILE):
        with open(SEARCH_CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write('{"keywords": []}\n')
        logging.info(f"Created empty {SEARCH_CONFIG_FILE} for search keywords.")


# --- 主程序逻辑 ---

async def main_integrated_crawler():
    """
    集成了 GitHub 搜索、URL 验证、M3U 内容提取、频道整理和 Git 提交的主函数。
    """
    setup_directories()

    load_blacklist_domains()
    load_last_modified_cache()
    initial_urls = load_initial_urls()
    
    global SEARCH_KEYWORDS
    SEARCH_KEYWORDS = load_search_keywords()

    all_raw_found_urls = set(initial_urls)

    logging.info("开始 GitHub 搜索阶段...")
    github_found_urls = await search_github_for_m3u_urls()
    all_raw_found_urls.update(github_found_urls)
    logging.info(f"GitHub 搜索阶段完成，共找到 {len(github_found_urls)} 个新的 URL。")

    tv_speed_m3u_urls = get_latest_tv_speed_m3u_urls()
    all_raw_found_urls.update(tv_speed_m3u_urls)
    logging.info(f"从 tv_speed.txt 加载了 {len(tv_speed_m3u_urls)} 个 M3U URL。")

    logging.info(f"所有来源的总 M3U URL 待处理数量: {len(all_raw_found_urls)}")

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

    logging.info(f"开始异步下载并处理 {len(accessible_m3u_urls)} 个 M3U 文件...")
    
    all_extracted_channels = set()
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(ASYNC_HTTP_CONNECTIONS)
        
        async def bounded_process_m3u_url_wrapper(s, url_to_process):
            async with semaphore:
                return await process_m3u_url_content(s, url_to_process)

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
    
    logging.info(f"开始对 {len(all_extracted_channels)} 个频道进行速度测试...")
    iptv_speed_channels = get_channel_speed_data(list(all_extracted_channels))
    logging.info(f"速度测试完成，筛选出 {len(iptv_speed_channels)} 个可用频道。")

    channel_templates = get_channel_templates()
    
    if os.path.exists(LOCAL_CHANNELS_DIR):
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
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.info(f"Channel list written to: {template_name}_iptv.txt, containing {len(current_template_matched_channels)} channels.")

    merge_iptv_files(LOCAL_CHANNELS_DIR)

    unmatched_channels = []
    for channel_line in iptv_speed_channels:
        channel_name = channel_line[0].strip()
        if channel_name not in all_template_channel_names:
            unmatched_channels.append(f"{channel_name},{channel_line[1]}")

    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels:
            f.write(channel_line + '\n')
    logging.info(f"Unmatched channels written to: unmatched_channels.txt, containing {len(unmatched_channels)} channels.")

    save_last_modified_cache()

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
