import os
import re
import subprocess
import socket
import time
from datetime import datetime, timedelta
import logging
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
import psutil
import asyncio
import aiohttp
from collections import defaultdict

# 配置日志
def setup_logging():
    log_level = getattr(logging, CONFIG.get('log_level', 'ERROR').upper(), logging.ERROR)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')

# 验证环境变量
for var, name in [
    (GITHUB_TOKEN, 'BOT'),
    (REPO_OWNER, 'REPO_OWNER'),
    (REPO_NAME, 'REPO_NAME'),
    (CONFIG_PATH_IN_REPO, 'CONFIG_PATH'),
    (URLS_PATH_IN_REPO, 'URLS_PATH'),
    (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH')
]:
    if not var:
        logging.error(f"错误：环境变量 '{name}' 未设置。")
        exit(1)

GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

def fetch_from_github(file_path_in_repo):
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"从 GitHub 获取 {file_path_in_repo} 发生错误：{e}")
        return None

def get_current_sha(file_path_in_repo):
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"获取 {file_path_in_repo} 的 SHA 发生错误：{e}")
        return None

def save_to_github(file_path_in_repo, content, commit_message):
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    sha = get_current_sha(file_path_in_repo)
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }
    import base64
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": "main"
    }
    if sha:
        payload["sha"] = sha
    try:
        response = requests.put(api_url, headers=headers, json=payload)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"将 {file_path_in_repo} 保存到 GitHub 发生错误：{e}")
        return False

def load_config():
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"错误：远程配置文件 '{CONFIG_PATH_IN_REPO}' 中的 YAML 无效：{e}")
            exit(1)
    logging.error(f"无法从 GitHub 的 '{CONFIG_PATH_IN_REPO}' 加载配置。")
    exit(1)

CONFIG = load_config()
setup_logging()

# 配置参数
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
SEARCH_KEYWORDS_PRIORITY = CONFIG.get('search_keywords_priority', {'high': SEARCH_KEYWORDS})
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 3)
MAX_URLS = CONFIG.get('max_urls', 1000)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20)
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 30)
RATE_LIMIT_THRESHOLD = CONFIG.get('rate_limit_threshold', 5)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 5)
CHANNEL_CHECK_TIMEOUT_HTTP = CONFIG.get('channel_check_timeout_http', 3)
CHANNEL_CHECK_WORKERS = CONFIG.get('channel_check_workers', 100)
CHANNEL_CHECK_BATCH_SIZE = CONFIG.get('channel_check_batch_size', 1000)
CHANNEL_EXTRACT_WORKERS = CONFIG.get('channel_extract_workers', 10)
SEARCH_CACHE_TTL = CONFIG.get('search_cache_ttl', 3600)
CHANNEL_CACHE_TTL = CONFIG.get('channel_cache_ttl', 86400)
URL_STATES_TTL = CONFIG.get('url_states_ttl', 604800)
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 100)
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})
ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])
ALLOWED_PROTOCOLS = set(CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []))
STREAM_EXTENSIONS = set(CONFIG.get('url_pre_screening', {}).get('stream_extensions', []))
INVALID_URL_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])]
PROTOCOL_TIMEOUTS = CONFIG.get('protocol_timeouts', {})
PROTOCOL_PRIORITY = CONFIG.get('protocol_priority', ['http', 'https', 'rtmp', 'rtsp', 'rtp', 'udp', 'p3p'])
OUTPUT_FORMAT = CONFIG.get('output_format', 'm3u')
EPG_ENABLED = CONFIG.get('epg_enabled', False)
EPG_SEARCH_KEYWORDS = CONFIG.get('epg_search_keywords', [])
EPG_MAX_URLS = CONFIG.get('epg_max_urls', 10)
CHANNEL_CACHE_PATH = CONFIG.get('channel_cache_path', 'config/channel_cache.json')
KEYWORD_STATS_PATH = CONFIG.get('keyword_stats_path', 'config/keyword_stats.json')

# 配置 HTTP 会话
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"})
pool_size = CONFIG.get('requests_pool_size', 100)
retry_strategy = Retry(
    total=CONFIG.get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1.5),
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

def read_txt_to_array_local(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到。")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 发生错误：{e}")
        return []

def write_array_to_txt_local(file_name, data_array):
    try:
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 发生错误：{e}")

def get_url_file_extension(url):
    parsed_url = urlparse(url)
    return os.path.splitext(parsed_url.path)[1].lower()

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
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

def load_url_states_remote():
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    if content:
        try:
            url_states = json.loads(content)
            ttl = URL_STATES_TTL
            cutoff = datetime.now() - timedelta(seconds=ttl)
            return {
                k: v for k, v in url_states.items()
                if not k.startswith('search:') or
                datetime.fromisoformat(v.get('last_checked', '1970-01-01T00:00:00')) > cutoff
            }
        except json.JSONDecodeError as e:
            logging.error(f"解码远程 '{URL_STATES_PATH_IN_REPO}' 中的 JSON 发生错误：{e}")
            return {}
    return {}

def save_url_states_remote(url_states):
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态")
    except Exception as e:
        logging.error(f"将 URL 状态保存到远程 '{URL_STATES_PATH_IN_REPO}' 发生错误：{e}")

def load_channel_cache():
    content = fetch_from_github(CHANNEL_CACHE_PATH)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"解码频道缓存失败：{e}")
            return {}
    return {}

def save_channel_cache(channel_cache):
    try:
        content = json.dumps(channel_cache, indent=4, ensure_ascii=False)
        save_to_github(CHANNEL_CACHE_PATH, content, "更新频道缓存")
    except Exception as e:
        logging.error(f"保存频道缓存失败：{e}")

def load_keyword_stats():
    content = fetch_from_github(KEYWORD_STATS_PATH)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {}
    return {}

def save_keyword_stats(keyword_stats):
    try:
        content = json.dumps(keyword_stats, indent=4, ensure_ascii=False)
        save_to_github(KEYWORD_STATS_PATH, content, "更新关键词统计")
    except Exception as e:
        logging.error(f"保存关键词统计失败：{e}")

async def fetch_url_content_async(url, url_states, timeout):
    headers = {}
    current_state = url_states.get(url, {})
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status == 304:
                    return None
                response.raise_for_status()
                content = await response.text()
                content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
                if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
                    return None
                url_states[url] = {
                    'etag': response.headers.get('ETag'),
                    'last_modified': response.headers.get('Last-Modified'),
                    'content_hash': content_hash,
                    'last_checked': datetime.now().isoformat()
                }
                return content
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"异步获取 URL {url} 失败：{e}")
            return None

def extract_channels_from_content(content, url):
    extracted_channels = []
    if get_url_file_extension(url) in STREAM_EXTENSIONS:
        content = convert_m3u_to_txt(content)
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if "#genre#" not in line and "," in line and "://" in line:
            parts = line.split(',', 1)
            channel_name = parts[0].strip()
            channel_address_raw = parts[1].strip()
            if '#' in channel_address_raw:
                url_list = channel_address_raw.split('#')
                for channel_url in url_list:
                    channel_url = clean_url_params(channel_url.strip())
                    if channel_url:
                        extracted_channels.append((channel_name, channel_url))
            else:
                channel_url = clean_url_params(channel_address_raw)
                if channel_url:
                    extracted_channels.append((channel_name, channel_url))
    return extracted_channels

async def extract_channels_from_url(url, url_states):
    try:
        content = await fetch_url_content_async(url, url_states, CHANNEL_FETCH_TIMEOUT)
        if content is None:
            return []
        return extract_channels_from_content(content, url)
    except Exception as e:
        logging.error(f"从 {url} 提取频道时发生错误：{e}")
        return []

def extract_channels_parallel(urls, url_states):
    extracted_channels = []
    max_workers = CHANNEL_EXTRACT_WORKERS
    loop = asyncio.get_event_loop()
    if loop.is_running():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    tasks = [extract_channels_from_url(url, url_states) for url in urls]
    results = loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
    for result in results:
        if isinstance(result, list):
            extracted_channels.extend(result)
    save_url_states_remote(url_states)
    return extracted_channels

def pre_screen_url(url):
    if not isinstance(url, str) or not url or len(url) < 15:
        return False
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ALLOWED_PROTOCOLS or not parsed_url.netloc:
        return False
    if not any(parsed_url.path.lower().endswith(ext) for ext in STREAM_EXTENSIONS):
        return False
    for pattern in INVALID_URL_PATTERNS:
        if pattern.search(url):
            logging.debug(f"预筛选过滤（无效模式）：{url}")
            return False
    return True

def filter_and_modify_channels(channels):
    filtered_channels = []
    for name, url in channels:
        if not pre_screen_url(url):
            continue
        if any(word.lower() in name.lower() for word in NAME_FILTER_WORDS):
            continue
        for old_str, new_str in CHANNEL_NAME_REPLACEMENTS.items():
            name = re.sub(re.escape(old_str), new_str, name, flags=re.IGNORECASE)
        filtered_channels.append((name, url))
    return filtered_channels

async def check_http_url_async(url, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.head(url, timeout=timeout, allow_redirects=True) as response:
                return 200 <= response.status < 400
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.debug(f"HTTP URL {url} 检查失败：{e}")
            return False

def check_http_url(url, timeout):
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} 检查失败：{e}")
        return False

def check_rtmp_url(url, timeout):
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("未找到 ffprobe 或其无法工作。RTMP 流检查已跳过。")
        return False
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} 检查超时")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} 检查错误：{e}")
        return False

def check_rtp_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL {url} 检查失败：{e}")
        return False

def check_p3p_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'
        if not host:
            return False
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} 检查失败：{e}")
        return False

def check_rtsp_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 554
        path = parsed_url.path if parsed_url.path else '/'
        if not host:
            return False
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return response.startswith("RTSP/1.0 200 OK")
    except Exception as e:
        logging.debug(f"RTSP URL {url} 检查失败：{e}")
        return False

def check_udp_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'', (host, port))
            s.recv(1024)
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"UDP URL {url} 检查失败：{e}")
        return False

def check_channel_validity_and_speed(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    start_time = time.time()
    is_valid = False
    scheme = urlparse(url).scheme
    timeout = PROTOCOL_TIMEOUTS.get(scheme, CHANNEL_CHECK_TIMEOUT_HTTP if scheme in ['http', 'https'] else CHANNEL_CHECK_TIMEOUT)
    try:
        if scheme in ['http', 'https']:
            is_valid = check_http_url(url, timeout)
        elif scheme == 'p3p':
            is_valid = check_p3p_url(url, timeout)
        elif scheme == 'rtmp':
            is_valid = check_rtmp_url(url, timeout)
        elif scheme == 'rtp':
            is_valid = check_rtp_url(url, timeout)
        elif scheme == 'rtsp':
            is_valid = check_rtsp_url(url, timeout)
        elif scheme == 'udp':
            is_valid = check_udp_url(url, timeout)
        else:
            logging.debug(f"频道 {channel_name} 的协议不受支持：{url}")
            return None, False
        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            return elapsed_time, True
        return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 时发生错误：{e}")
        return None, False

async def check_channel_validity_and_speed_async(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    start_time = time.time()
    scheme = urlparse(url).scheme
    timeout = PROTOCOL_TIMEOUTS.get(scheme, CHANNEL_CHECK_TIMEOUT_HTTP if scheme in ['http', 'https'] else CHANNEL_CHECK_TIMEOUT)
    try:
        if scheme in ['http', 'https']:
            is_valid = await check_http_url_async(url, timeout)
        else:
            elapsed_time, is_valid = check_channel_validity_and_speed(channel_name, url, timeout)
            return elapsed_time, is_valid
        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            return elapsed_time, True
        return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 时发生错误：{e}")
        return None, False

async def check_channels_async(channel_lines, max_concurrent=100):
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    async def process_channel(line):
        async with semaphore:
            if "://" not in line:
                return None, None
            parts = line.split(',', 1)
            if len(parts) == 2:
                name, url = parts
                url = url.strip()
                elapsed_time, is_valid = await check_channel_validity_and_speed_async(name, url)
                if is_valid:
                    return elapsed_time, f"{name},{url}"
            return None, None
    tasks = [process_channel(line) for line in channel_lines]
    for future in asyncio.as_completed(tasks):
        elapsed_time, result_line = await future
        if elapsed_time is not None and result_line is not None:
            results.append((elapsed_time, result_line))
    return results

def check_channels_multithreaded(channel_lines, max_workers=None):
    if max_workers is None:
        max_workers = min(CHANNEL_CHECK_WORKERS, psutil.cpu_count() * 10)
    results = []
    channel_cache = load_channel_cache()
    ttl = CHANNEL_CACHE_TTL
    cutoff = datetime.now() - timedelta(seconds=ttl)
    channels_to_check = []
    cache_hits = 0

    for line in channel_lines:
        if "://" not in line:
            continue
        name, url = line.split(',', 1)
        cache_key = f"{name}:{url}"
        cached = channel_cache.get(cache_key)
        if cached and datetime.fromisoformat(cached.get('last_validated', '1970-01-01T00:00:00')) > cutoff:
            results.append((cached['response_time'], line))
            cache_hits += 1
            continue
        channels_to_check.append(line)

    logging.info(f"频道缓存命中 {cache_hits}/{len(channel_lines)}，剩余 {len(channels_to_check)} 个频道需检测...")

    checked_count = 0
    total_channels = len(channels_to_check)
    logging.info(f"开始多线程频道有效性和速度检测，总计 {total_channels} 个频道...")
    start_time = time.time()
    for i in range(0, len(channels_to_check), CHANNEL_CHECK_BATCH_SIZE):
        batch = channels_to_check[i:i + CHANNEL_CHECK_BATCH_SIZE]
        logging.info(f"处理批次 {i//CHANNEL_CHECK_BATCH_SIZE + 1}，包含 {len(batch)} 个频道...")
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            batch_results = loop.run_until_complete(check_channels_async(batch, max_concurrent=max_workers))
            for elapsed_time, result_line in batch_results:
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
                    name, url = result_line.split(',', 1)
                    cache_key = f"{name}:{url}"
                    channel_cache[cache_key] = {
                        'last_validated': datetime.now().isoformat(),
                        'response_time': elapsed_time
                    }
            checked_count += len(batch)
            elapsed = time.time() - start_time
            logging.info(f"已检查 {checked_count}/{total_channels} 个频道，耗时 {elapsed:.2f} 秒...")
        except Exception as e:
            logging.error(f"批次处理错误：{e}")
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(check_channel_validity_and_speed, *line.split(',', 1)): line for line in batch}
                for future in as_completed(futures):
                    checked_count += 1
                    if checked_count % 100 == 0:
                        elapsed = time.time() - start_time
                        logging.info(f"已检查 {checked_count}/{total_channels} 个频道，耗时 {elapsed:.2f} 秒...")
                    try:
                        elapsed_time, is_valid = future.result()
                        if is_valid:
                            result_line = futures[future]
                            results.append((elapsed_time, result_line))
                            name, url = result_line.split(',', 1)
                            cache_key = f"{name}:{url}"
                            channel_cache[cache_key] = {
                                'last_validated': datetime.now().isoformat(),
                                'response_time': elapsed_time
                            }
                    except Exception as exc:
                        logging.warning(f"频道行处理期间发生异常：{exc}")
    save_channel_cache(channel_cache)
    logging.info(f"频道检测完成，总耗时 {(time.time() - start_time):.2f} 秒。")
    return results

def write_sorted_channels_to_file(file_path, data_list):
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        return int(match.group()) if match else float('inf')
    return sorted(channels, key=channel_key)

def generate_update_time_header():
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    grouped_channels = defaultdict(list)
    for line_content in lines:
        line_content = line_content.strip()
        if line_content:
            channel_name = line_content.split(',', 1)[0].strip()
            grouped_channels[channel_name].append(line_content)
    final_grouped_lines = []
    for channel_name in grouped_channels:
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            final_grouped_lines.append(ch_line + '\n')
    return final_grouped_lines

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt"):
    output_format = OUTPUT_FORMAT
    if output_format == 'json':
        channels_data = []
        all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
        for category in ORDERED_CATEGORIES:
            file_name = f"{category}_iptv.txt"
            if file_name in all_iptv_files_in_dir:
                with open(os.path.join(local_channels_directory, file_name), "r", encoding="utf-8") as file:
                    lines = file.readlines()
                    if not lines or '#genre#' not in lines[0]:
                        continue
                    category_channels = []
                    for line in lines[1:]:
                        if line.strip() and ',' in line:
                            name, url = line.strip().split(',', 1)
                            category_channels.append({"name": name, "url": url})
                    channels_data.append({"category": category, "channels": category_channels})
        with open(output_file_name, 'w', encoding='utf-8') as f:
            json.dump(channels_data, f, indent=2, ensure_ascii=False)
    else:  # m3u
        final_output_lines = generate_update_time_header()
        all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
        files_to_merge_paths = []
        processed_files = set()
        for category in ORDERED_CATEGORIES:
            file_name = f"{category}_iptv.txt"
            if file_name in all_iptv_files_in_dir and file_name not in processed_files:
                files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
                processed_files.add(file_name)
        for file_name in sorted(all_iptv_files_in_dir):
            if file_name not in processed_files:
                files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
                processed_files.add(file_name)
        for file_path in files_to_merge_paths:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
                if not lines:
                    continue
                header = lines[0].strip()
                if '#genre#' in header:
                    final_output_lines.append(header + '\n')
                    final_output_lines.extend(group_and_limit_channels(lines[1:]))
                else:
                    logging.warning(f"文件 {file_path} 未以类别标题开头。跳过。")
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(final_output_lines)
    logging.info(f"所有区域频道列表文件已合并。输出已保存到：{output_file_name}")

def read_txt_to_array_remote(file_path_in_repo):
    content = fetch_from_github(file_path_in_repo)
    if content:
        return [line.strip() for line in content.split('\n') if line.strip()]
    return []

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message):
    content = '\n'.join(data_array)
    if save_to_github(file_path_in_repo, content, commit_message):
        pass
    else:
        logging.error(f"将数据写入远程 '{file_path_in_repo}' 失败。")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def search_keyword(keyword, headers):
    found_urls = set()
    page = 1
    while page <= MAX_SEARCH_PAGES:
        params = {
            "q": keyword,
            "sort": "indexed",
            "order": "desc",
            "per_page": PER_PAGE,
            "page": page
        }
        try:
            response = session.get(
                f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                headers=headers,
                params=params,
                timeout=GITHUB_API_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            if rate_limit_remaining <= RATE_LIMIT_THRESHOLD:
                wait_seconds = max(0, int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()) + 1
                logging.warning(f"接近 GitHub API 速率限制！剩余请求：{rate_limit_remaining}。等待 {wait_seconds:.0f} 秒...")
                time.sleep(wait_seconds)
                continue
            if not data.get('items'):
                break
            for item in data['items']:
                html_url = item.get('html_url', '')
                match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                if match:
                    user, repo, branch, path = match.groups()
                    raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
                    cleaned_url = clean_url_params(raw_url)
                    if (cleaned_url.startswith("https://raw.githubusercontent.com/") and
                        any(cleaned_url.lower().endswith(ext) for ext in STREAM_EXTENSIONS) and
                        pre_screen_url(cleaned_url)):
                        found_urls.add(cleaned_url)
            page += 1
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            logging.error(f"关键词 '{keyword}' 搜索失败：{e}")
            break
    return keyword, found_urls

def auto_discover_github_urls(urls_file_path_remote, github_token):
    if not github_token:
        logging.warning("环境变量 'BOT' 未设置。跳过 GitHub URL 自动发现。")
        return
    url_states = load_url_states_remote()
    keyword_stats = load_keyword_stats()
    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }
    logging.info("开始从 GitHub 自动发现新的 IPTV 源 URL...")
    for priority in ['high', 'medium', 'low']:
        if priority not in SEARCH_KEYWORDS_PRIORITY:
            continue
        keywords = SEARCH_KEYWORDS_PRIORITY[priority]
        sorted_keywords = sorted(
            keywords,
            key=lambda k: keyword_stats.get(k, {}).get('hit_rate', 0),
            reverse=True
        )
        for keyword in sorted_keywords:
            if len(found_urls) >= MAX_URLS:
                logging.info(f"已达到最大 URL 数量 {MAX_URLS}，停止搜索。")
                break
            keyword_state = url_states.get(f"search:{keyword}", {})
            last_searched = keyword_state.get('last_searched')
            if last_searched:
                last_time = datetime.fromisoformat(last_searched)
                if (datetime.now() - last_time).total_seconds() < SEARCH_CACHE_TTL:
                    found_urls.update(keyword_state.get('urls', []))
                    logging.info(f"关键词 '{keyword}' 的搜索结果已缓存，跳过...")
                    continue
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {executor.submit(search_keyword, keyword, headers): keyword}
                for future in as_completed(futures):
                    keyword, urls = future.result()
                    new_urls = urls - found_urls
                    found_urls.update(urls)
                    url_states[f"search:{keyword}"] = {
                        'last_searched': datetime.now().isoformat(),
                        'urls': list(urls)
                    }
                    keyword_stats[keyword] = {
                        'hit_rate': len(new_urls) / max(1, len(urls)),
                        'last_updated': datetime.now().isoformat()
                    }
                    logging.info(f"关键词 '{keyword}' 搜索完成，发现 {len(new_urls)} 个新 URL。")
            save_url_states_remote(url_states)
            save_keyword_stats(keyword_stats)
            time.sleep(0.5)
        if len(found_urls) >= MAX_URLS:
            break
    new_urls_count = len(found_urls - existing_urls)
    if new_urls_count > 0:
        updated_urls = list(existing_urls | found_urls)
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "通过 GitHub 发现的新 URL 更新 urls.txt")
        logging.info(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URL。总 URL 数：{len(updated_urls)}")
    else:
        logging.info("未发现新的 GitHub IPTV 源 URL。")

def clear_directory_txt_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
            except Exception as e:
                logging.error(f"删除文件 {file_path} 发生错误：{e}")

def main():
    auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)
    urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
    if not urls:
        logging.warning(f"在远程 '{URLS_PATH_IN_REPO}' 中未找到 URL，脚本将提前退出。")
        return
    url_states = load_url_states_remote()
    logging.info(f"已加载 {len(url_states)} 个历史 URL 状态。")
    all_extracted_channels = set(extract_channels_parallel(urls, url_states))
    logging.info(f"从所有源提取了 {len(all_extracted_channels)} 个原始频道。")
    filtered_channels = filter_and_modify_channels(list(all_extracted_channels))
    unique_filtered_channels = list(set(filtered_channels))
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]
    logging.info(f"过滤和清理后，剩余 {len(unique_filtered_channels_str)} 个唯一频道。")
    valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
    logging.info(f"有效且响应的频道数量：{len(valid_channels_with_speed)}")
    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_sorted_channels_to_file(iptv_speed_file_path, valid_channels_with_speed)
    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    os.makedirs(local_channels_directory, exist_ok=True)
    clear_directory_txt_files(local_channels_directory)
    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True)
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]
    channels_for_matching = read_txt_to_array_local(iptv_speed_file_path)
    all_template_channel_names = set()
    for template_file in template_files:
        names_from_current_template = read_txt_to_array_local(os.path.join(template_directory, template_file))
        all_template_channel_names.update(names_from_current_template)
    for template_file in template_files:
        template_channels_names = set(read_txt_to_array_local(os.path.join(template_directory, template_file)))
        template_name = os.path.splitext(template_file)[0]
        current_template_matched_channels = []
        for channel_line in channels_for_matching:
            channel_name = channel_line.split(',', 1)[0].strip()
            if channel_name in template_channels_names:
                current_template_matched_channels.append(channel_line)
        if "央视" in template_name or "CCTV" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.info(f"已按数字对 '{template_name}' 频道进行排序。")
        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.info(f"频道列表已写入：'{template_name}_iptv.txt'，包含 {len(current_template_matched_channels)} 个频道。")
    final_iptv_list_output_file = "iptv_list.txt"
    merge_local_channel_files(local_channels_directory, final_iptv_list_output_file)
    try:
        with open(final_iptv_list_output_file, "r", encoding="utf-8") as f:
            final_iptv_content = f.read()
        save_to_github(f"output/{final_iptv_list_output_file}", final_iptv_content, "更新最终 IPTV 列表")
        logging.info(f"已将 {final_iptv_list_output_file} 推送到远程仓库。")
    except Exception as e:
        logging.error(f"无法将 {final_iptv_list_output_file} 推送到 GitHub：{e}")
    unmatched_channels_list = []
    for channel_line in channels_for_matching:
        channel_name = channel_line.split(',', 1)[0].strip()
        if channel_name not in all_template_channel_names:
            unmatched_channels_list.append(channel_line)
    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels_list:
            f.write(channel_line.split(',')[0].strip() + '\n')
    logging.info(f"已保存不匹配但已检测到的频道列表到：'{unmatched_output_file_path}'，总共 {len(unmatched_channels_list)} 个频道。")
    try:
        for temp_file in ['iptv.txt', 'iptv_speed.txt']:
            if os.path.exists(temp_file):
                os.remove(temp_file)
    except OSError as e:
        logging.warning(f"删除临时文件时发生错误：{e}")

if __name__ == "__main__":
    main()

