import os
import re
import subprocess
import socket
import time
from datetime import datetime, timedelta
import logging
import logging.handlers
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
import base64
import psutil
from cachetools import TTLCache
import threading
from tqdm import tqdm
import aiohttp
import asyncio

# 预编译正则表达式以优化性能
URL_PROTOCOL_RE = re.compile(r'^[a-zA-Z0-9+.-]+://')
M3U_HEADER_RE = re.compile(r'#EXTM3U', re.IGNORECASE)
EXTINF_RE = re.compile(r'#EXTINF:.*?\,(.*)', re.IGNORECASE)
GITHUB_URL_RE = re.compile(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)')
FILE_EXT_RE = re.compile(r'\.(m3u8|m3u|txt|csv|ts|flv|mp4|hls|dash)$', re.IGNORECASE)
INVALID_CHAR_RE = re.compile(r'[^\x00-\x7F]')

# 配置日志系统
def setup_logging(config):
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=1
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 配置文件路径
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 检查环境变量 GITHUB_TOKEN
GITHUB_TOKEN = os.getenv('BOT')
if not GITHUB_TOKEN:
    logging.error("错误：未设置环境变量 'BOT'")
    exit(1)

# 从配置中获取文件路径
URLS_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'urls.txt')
URL_STATES_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'url_states.json')
IPTV_LIST_PATH = CONFIG['output']['paths']['final_iptv_file']

# GitHub API 基础 URL
GITHUB_RAW_CONTENT_BASE_URL = "https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = "https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# 初始化缓存
if CONFIG['url_state']['cache_enabled']:
    os.makedirs(CONFIG['url_state']['cache_dir'], exist_ok=True)
    content_cache = TTLCache(maxsize=5000, ttl=CONFIG['url_state'].get('cache_ttl', 86400))

# 配置 requests 会话
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
pool_size = CONFIG['network']['requests_pool_size']
retry_strategy = Retry(
    total=3,
    backoff_factor=CONFIG['network']['requests_retry_backoff_factor'],
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(
    pool_connections=pool_size,
    pool_maxsize=pool_size,
    max_retries=retry_strategy
)
session.mount("http://", adapter)
session.mount("https://", adapter)

# 性能监控装饰器
def performance_monitor(func):
    if not CONFIG['performance_monitor']['enabled']:
        return func
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        logging.info(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒")
        return result
    return wrapper

# --- GitHub 文件操作函数 ---
@performance_monitor
def fetch_from_github(file_path_in_repo):
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = session.get(raw_url, headers=headers, timeout=8)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"错误：从 GitHub 获取 {file_path_in_repo} 失败: {e}")
        return None

@performance_monitor
def get_current_sha(file_path_in_repo):
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = session.get(api_url, headers=headers, timeout=8)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.info(f"获取 {file_path_in_repo} 的 SHA 值失败（可能不存在）: {e}")
        return None

@performance_monitor
def save_to_github(file_path_in_repo, content, commit_message):
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    sha = get_current_sha(file_path_in_repo)
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": "main"
    }
    if sha:
        payload["sha"] = sha
    try:
        response = session.put(api_url, headers=headers, json=payload)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"错误：保存 {file_path_in_repo} 到 GitHub 失败: {e}")
        return False

# --- 本地文件操作函数 ---
@performance_monitor
def read_txt_to_array_local(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return []

@performance_monitor
def read_existing_channels(file_path):
    existing_channels = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ',' in line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        existing_channels.add((parts[0].strip(), parts[1].strip()))
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.error(f"读取文件 '{file_path}' 进行去重失败: {e}")
    return existing_channels

@performance_monitor
def write_sorted_channels_to_file(file_path, data_list):
    existing_channels = read_existing_channels(file_path)
    new_channels = set()
    for _, line in data_list:
        if ',' in line:
            name, url = line.split(',', 1)
            new_channels.add((name.strip(), url.strip()))
    all_channels = existing_channels | new_channels
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            for name, url in sorted(all_channels, key=lambda x: x[0]):
                file.write(f"{name},{url}\n")
        logging.info(f"写入 {len(all_channels)} 个频道到 {file_path}")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

# --- URL 处理和频道提取函数 ---
@performance_monitor
def get_url_file_extension(url):
    try:
        parsed_url = urlparse(url)
        return os.path.splitext(parsed_url.path)[1].lower()
    except ValueError as e:
        logging.info(f"获取 URL 扩展名失败: {url} - {e}")
        return ""

@performance_monitor
def convert_m3u_to_txt(m3u_content):
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = "未知频道"
    for line in lines:
        line = line.strip()
        if not line or M3U_HEADER_RE.match(line):
            continue
        if line.startswith('#EXTINF'):
            match = EXTINF_RE.search(line)
            channel_name = match.group(1).strip() or "未知频道" if match else "未知频道"
        elif URL_PROTOCOL_RE.match(line) and not line.startswith('#'):
            txt_lines.append(f"{channel_name},{line}")
        channel_name = "未知频道"
    return '\n'.join(txt_lines)

@performance_monitor
def clean_url_params(url):
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.info(f"清理 URL 参数失败: {url} - {e}")
        return url

@performance_monitor
async def fetch_url_content_async(url, url_states, session):
    if CONFIG['url_state']['cache_enabled']:
        cache_file = os.path.join(CONFIG['url_state']['cache_dir'], f"{hashlib.md5(url.encode()).hexdigest()}.txt")
        if url in content_cache:
            logging.info(f"从内存缓存读取 URL 内容: {url}")
            return content_cache[url]
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as f:
                content = f.read()
                content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
                if url_states.get(url, {}).get('content_hash') == content_hash:
                    logging.info(f"从文件缓存读取 URL 内容: {url}")
                    content_cache[url] = content
                    return content
    headers = {}
    current_state = url_states.get(url, {})
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']
    try:
        async with session.get(url, headers=headers, timeout=5) as response:
            if response.status == 304:
                logging.info(f"URL 内容未变更 (304): {url}")
                url_states[url]['last_checked'] = datetime.now().isoformat()
                return None
            response.raise_for_status()
            content = await response.text()
            content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
            if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
                logging.info(f"URL 内容未变更（哈希相同）: {url}")
                url_states[url]['last_checked'] = datetime.now().isoformat()
                return None
            url_states[url] = {
                'etag': response.headers.get('ETag'),
                'last_modified': response.headers.get('Last-Modified'),
                'content_hash': content_hash,
                'last_checked': datetime.now().isoformat()
            }
            if CONFIG['url_state']['cache_enabled']:
                content_cache[url] = content
                cache_file = os.path.join(CONFIG['url_state']['cache_dir'], f"{hashlib.md5(url.encode()).hexdigest()}.txt")
                with open(cache_file, 'w', encoding='utf-8') as f:
                    f.write(content)
            logging.info(f"成功获取新内容: {url}")
            return content
    except aiohttp.ClientError as e:
        logging.error(f"异步请求 URL 失败: {url} - {e}")
        return None

@performance_monitor
def extract_channels_from_url(url, url_states, source_tracker):
    extracted_channels = []
    try:
        start_time = time.time()
        loop = asyncio.get_event_loop()
        async with aiohttp.ClientSession() as session:
            text = loop.run_until_complete(fetch_url_content_async(url, url_states, session))
        if text is None:
            logging.info(f"URL {url} 无新内容或获取失败，跳过")
            return []

        extension = get_url_file_extension(url).lower()
        if extension in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)
        elif extension in [".ts", ".flv", ".mp4", ".hls", ".dash"]:
            channel_name = f"Stream_{os.path.basename(urlparse(url).path)}"
            if pre_screen_url(channel_name, url):
                extracted_channels.append((channel_name, url))
                source_tracker[(channel_name, url)] = url
                logging.info(f"提取单一流: {channel_name},{url}")
            return extracted_channels
        elif extension not in [".txt", ".csv"]:
            logging.info(f"不支持的文件扩展名: {url}")
            return []

        lines = text.split('\n')
        channel_count = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if "," in line and "://" in line:
                parts = line.split(',', 1)
                if len(parts) != 2:
                    logging.info(f"跳过无效频道行（格式错误）: {line}")
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip() or "未知频道"
                channel_address_raw = channel_address_raw.strip()

                if not URL_PROTOCOL_RE.match(channel_address_raw):
                    logging.info(f"跳过无效频道 URL（无有效协议）: {line}")
                    continue

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_name, channel_url):
                            extracted_channels.append((channel_name, channel_url))
                            source_tracker[(channel_name, channel_url)] = url
                            channel_count += 1
                        else:
                            logging.info(f"跳过无效或预筛选失败的频道 URL: {channel_url}")
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_name, channel_url):
                        extracted_channels.append((channel_name, channel_url))
                        source_tracker[(channel_name, channel_url)] = url
                        channel_count += 1
                    else:
                        logging.info(f"跳过无效或预筛选失败的频道 URL: {channel_url}")
            elif URL_PROTOCOL_RE.match(line):
                channel_name = f"Stream_{channel_count + 1}"
                channel_url = clean_url_params(line)
                if channel_url and pre_screen_url(channel_name, channel_url):
                    extracted_channels.append((channel_name, channel_url))
                    source_tracker[(channel_name, channel_url)] = url
                    channel_count += 1
                else:
                    logging.info(f"跳过无效或预筛选失败的单一 URL: {line}")
        logging.info(f"成功从 {url} 提取 {channel_count} 个频道，耗时 {time.time() - start_time:.2f} 秒")
        return extracted_channels
    except Exception as e:
        logging.error(f"从 {url} 提取频道失败: {e}")
        return []

# --- URL 状态管理函数 ---
@performance_monitor
def load_url_states_local():
    url_states = {}
    try:
        with open(URL_STATES_PATH, 'r', encoding='utf-8') as file:
            url_states = json.load(file)
    except FileNotFoundError:
        logging.warning(f"URL 状态文件 '{URL_STATES_PATH}' 未找到，使用空状态")
    except json.JSONDecodeError as e:
        logging.error(f"解析 '{URL_STATES_PATH}' 的 JSON 失败: {e}")
        return {}
    
    current_time = datetime.now()
    updated_url_states = {}
    for url, state in tqdm(url_states.items(), desc="清理 URL 状态", leave=False):
        if 'last_checked' in state:
            try:
                last_checked_datetime = datetime.fromisoformat(state['last_checked'])
                if (current_time - last_checked_datetime).days < CONFIG['url_state']['expiration_days']:
                    updated_url_states[url] = state
                else:
                    logging.info(f"移除过期 URL 状态: {url}（最后检查于 {state['last_checked']}）")
            except ValueError:
                logging.warning(f"无法解析 URL {url} 的 last_checked 时间戳: {state['last_checked']}")
                updated_url_states[url] = state
        else:
            updated_url_states[url] = state
    return updated_url_states

@performance_monitor
def save_url_states_local(url_states):
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}")

@performance_monitor
def pre_screen_url(channel_name, url):
    if not isinstance(url, str) or not url:
        logging.info(f"预筛选过滤（无效类型或空）: {url}")
        return False
    if not URL_PROTOCOL_RE.match(url):
        logging.info(f"预筛选过滤（无有效协议）: {url}")
        return False
    if INVALID_CHAR_RE.search(url) or ' ' in url:
        logging.info(f"预筛选过滤（包含非法字符或空格）: {url}")
        return False
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in CONFIG['url_pre_screening']['allowed_protocols']:
            logging.info(f"预筛选过滤（不支持的协议）: {url}")
            return False
        if not parsed_url.netloc:
            logging.info(f"预筛选过滤（无网络位置）: {url}")
            return False
        invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns']
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                logging.info(f"预筛选过滤（无效模式）: {url}")
                return False
        if len(url) < 15:
            logging.info(f"预筛选过滤（URL 过短）: {url}")
            return False
        return True
    except ValueError as e:
        logging.info(f"预筛选过滤（URL 解析错误）: {url} - {e}")
        return False

@performance_monitor
def filter_and_modify_channels(channels):
    filtered_channels = []
    pre_screened_count = 0
    for name, url in tqdm(channels, desc="过滤和修改频道", leave=False):
        if not pre_screen_url(name, url):
            logging.info(f"过滤频道（预筛选失败）: {name},{url}")
            continue
        pre_screened_count += 1
        new_name = name
        for old_str, new_str in CONFIG['channel_name_replacements'].items():
            new_name = re.sub(old_str, new_str, new_name, flags=re.IGNORECASE)
        new_name = new_name.strip()
        if any(word.lower() in new_name.lower() for word in CONFIG['name_filter_words']):
            logging.info(f"过滤频道（名称匹配黑名单）: {name},{url}")
            continue
        filtered_channels.append((new_name, url))
    logging.info(f"URL 预筛选后剩余 {pre_screened_count} 个频道进行进一步过滤")
    return filtered_channels

# --- 频道有效性检查函数 ---
@performance_monitor
async def check_http_url_async(url, session, timeout):
    try:
        async with session.head(url, timeout=timeout, allow_redirects=True) as response:
            return 200 <= response.status_code < 400
    except aiohttp.ClientError:
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("ffprobe 未找到或不可用，跳过 RTMP 检查")
        return False
    try:
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.info(f"RTMP URL 检查超时: {url}")
        return False
    except Exception as e:
        logging.info(f"RTMP URL 检查错误: {url} - {e}")
        return False

@performance_monitor
def check_rtp_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.info(f"RTP URL 解析失败（缺少主机或端口）: {url}")
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error) as e:
        logging.info(f"RTP URL 检查失败: {url} - {e}")
        return False
    except Exception as e:
        logging.info(f"RTP URL 检查错误: {url} - {e}")
        return False

@performance_monitor
def check_p3p_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'
        if not host:
            logging.info(f"P3P URL 解析失败（缺少主机）: {url}")
            return False
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.info(f"P3P URL 检查失败: {url} - {e}")
        return False

@performance_monitor
def check_webrtc_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme == 'webrtc':
            return False
        return True
    except Exception as e:
        logging.info(f"WebRTC URL 检查失败: {url} - {e}")
        return False

@performance_monitor
async def check_channel_validity_and_speed_async(channel_name, url, url_states, timeout=CONFIG['network']['check_timeout']):
    current_time = datetime.now()
    current_url_state = url_states.get(url, {})
    if 'stream_check_failed_at' in current_url_state:
        try:
            last_failed_datetime = datetime.fromisoformat(current_url_state['stream_check_failed_at'])
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
            if time_since_failed_hours < CONFIG['channel_retention']['stream_retention_hours']:
                logging.info(f"跳过频道 {channel_name} ({url})，因其在冷却期内（{CONFIG['channel_retention']['stream_retention_hours']}h）")
                return None, False
        except ValueError:
            logging.warning(f"无法解析 URL {url} 的失败时间戳: {current_url_state['stream_check_failed_at']}")
    start_time = time.time()
    is_valid = False
    async with aiohttp.ClientSession() as session:
        if url.startswith("http"):
            is_valid = await check_http_url_async(url, session, timeout)
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, timeout)
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, timeout)
        elif url.startswith("webrtc"):
            is_valid = check_webrtc_url(url, timeout)
        else:
            logging.info(f"频道 {channel_name} 的协议不支持: {url}")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat()
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            return None, False
        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            if url not in url_states:
                url_states[url] = {}
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_successful_stream_check'] = current_time.isoformat()
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.info(f"频道 {channel_name} ({url}) 检查成功，耗时 {elapsed_time:.0f} ms")
            return elapsed_time, True
        else:
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.info(f"频道 {channel_name} ({url}) 检查失败")
            return None, False

@performance_monitor
async def process_single_channel_line_async(channel_line, url_states):
    if "://" not in channel_line:
        logging.info(f"跳过无效频道行（无协议）: {channel_line}")
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = await check_channel_validity_and_speed_async(name, url, url_states)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

@performance_monitor
async def check_channels_async(channel_lines, url_states, max_concurrent=CONFIG['network']['channel_check_workers']):
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"开始异步检查 {total_channels} 个频道的有效性和速度")
    semaphore = asyncio.Semaphore(max_concurrent)
    async def sem_process(channel_line):
        async with semaphore:
            return await process_single_channel_line_async(channel_line, url_states)
    tasks = [sem_process(line) for line in channel_lines]
    for future in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="检查频道有效性", leave=False):
        checked_count += 1
        if checked_count % CONFIG['performance_monitor']['log_interval'] == 0:
            logging.warning(f"已检查 {checked_count}/{total_channels} 个频道")
        try:
            elapsed_time, result_line = await future
            if elapsed_time is not None and result_line is not None:
                results.append((elapsed_time, result_line))
        except Exception as exc:
            logging.warning(f"处理频道行时发生异常: {exc}")
    return results

# --- 文件合并和排序函数 ---
@performance_monitor
def generate_update_time_header():
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d %H:%M:%S')},url\n"
    ]

@performance_monitor
def group_and_limit_channels(lines):
    grouped_channels = {}
    for line_content in lines:
        line_content = line_content.strip()
        if line_content:
            channel_name = line_content.split(',', 1)[0].strip()
            if channel_name not in grouped_channels:
                grouped_channels[channel_name] = []
            grouped_channels[channel_name].append(line_content)
    
    final_grouped_lines = []
    for channel_name in tqdm(grouped_channels, desc="分组和限制频道", leave=False):
        for ch_line in grouped_channels[channel_name][:CONFIG.get('max_channel_urls_per_group', 100)]:
            final_grouped_lines.append(ch_line + '\n')
    return final_grouped_lines

@performance_monitor
def merge_local_channel_files(local_channels_directory, output_file_name, url_states):
    os.makedirs(local_channels_directory, exist_ok=True)
    existing_channels_data = read_existing_channels(output_file_name)
    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    
    uncategorized_file_in_root = CONFIG['output']['paths']['uncategorized_channels_file']
    if os.path.isfile(uncategorized_file_in_root):
        all_iptv_files_in_dir.append(os.path.basename(uncategorized_file_in_root))
    else:
        logging.info(f"未分类文件 '{uncategorized_file_in_root}' 不存在，跳过添加")

    files_to_merge_paths = []
    processed_files = set()

    all_possible_categories = list(CONFIG.get('ordered_categories', []))
    for alias_target in set(CONFIG.get('category_aliases', {}).values()):
        if alias_target not in all_possible_categories:
            all_possible_categories.append(alias_target)

    for category in all_possible_categories:
        file_name = f"{category}_iptv.txt"
        temp_path = os.path.join(local_channels_directory, file_name)
        
        if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files:
            files_to_merge_paths.append(temp_path)
            processed_files.add(os.path.basename(temp_path))

    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
            full_path = os.path.join(local_channels_directory, file_name) if file_name != os.path.basename(uncategorized_file_in_root) else uncategorized_file_in_root
            if os.path.isfile(full_path):
                files_to_merge_paths.append(full_path)
                processed_files.add(file_name)
            else:
                logging.info(f"文件 '{full_path}' 不存在，跳过添加")

    new_channels_from_merged_files = set()
    for file_path in tqdm(files_to_merge_paths, desc="合并频道文件", leave=False):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
                if not lines:
                    continue
                for line in lines:
                    line = line.strip()
                    if line and ',' in line and '#genre#' not in line:
                        name, url = line.split(',', 1)
                        new_channels_from_merged_files.add((name.strip(), url.strip()))
        except FileNotFoundError:
            logging.warning(f"无法打开文件 '{file_path}'，可能已被删除或路径错误")
            continue
        except Exception as e:
            logging.error(f"读取文件 '{file_path}' 失败: {e}")
            continue

    combined_channels = existing_channels_data | new_channels_from_merged_files
    channels_for_checking_lines = [f"{name},{url}" for name, url in combined_channels]
    logging.warning(f"总计 {len(channels_for_checking_lines)} 个唯一频道待检查和过滤")

    loop = asyncio.get_event_loop()
    valid_channels_from_check = loop.run_until_complete(check_channels_async(channels_for_checking_lines, url_states))

    categorized_channels_checked, uncategorized_channels_checked, final_ordered_categories_checked = categorize_channels(
        [(name, url) for _, line in valid_channels_from_check for name, url in [line.split(',', 1)]]
    )

    try:
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(generate_update_time_header())
            for category in final_ordered_categories_checked:
                if category in categorized_channels_checked and categorized_channels_checked[category]:
                    iptv_list_file.write(f"{category},#genre#\n")
                    for name, url in sorted(categorized_channels_checked[category], key=lambda x: x[0]):
                        iptv_list_file.write(f"{name},{url}\n")
        logging.warning(f"所有频道列表文件合并、去重、分类完成，输出保存到: {output_file_name}")
    except Exception as e:
        logging.error(f"写入文件 '{output_file_name}' 失败: {e}")

    try:
        os.makedirs(os.path.dirname(uncategorized_file_in_root), exist_ok=True)
        with open(uncategorized_file_in_root, "w", encoding='utf-8') as uncat_file:
            for name, url in sorted(uncategorized_channels_checked, key=lambda x: x[0]):
                uncat_file.write(f"{name},{url}\n")
        logging.warning(f"未分类频道保存到: {uncategorized_file_in_root}")
    except Exception as e:
        logging.error(f"写入未分类文件 '{uncategorized_file_in_root}' 失败: {e}")

# --- 远程 TXT 文件操作函数 ---
@performance_monitor
def write_array_to_txt_local(file_path, data_array, commit_message=None):
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write('\n'.join(data_array))
        logging.info(f"写入 {len(data_array)} 行到 '{file_path}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

# --- GitHub URL 自动发现函数 ---
@performance_monitor
def auto_discover_github_urls(urls_file_path_local, github_token):
    if not github_token:
        logging.warning("未提供 GitHub token，跳过 URL 自动发现")
        return
    existing_urls = set(read_txt_to_array_local(urls_file_path_local))
    for backup_url in tqdm(CONFIG.get('backup_urls', []), desc="处理备用 URL", leave=False):
        try:
            response = session.get(backup_url, timeout=8)
            response.raise_for_status()
            existing_urls.update([line.strip() for line in response.text.split('\n') if line.strip()])
        except Exception as e:
            logging.warning(f"从备用 URL {backup_url} 获取失败: {e}")
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }
    logging.warning("开始从 GitHub 自动发现新的 IPTV 源 URL")
    keyword_url_counts = {keyword: 0 for keyword in CONFIG.get('search_keywords', [])}
    for i, keyword in enumerate(tqdm(CONFIG.get('search_keywords', []), desc="搜索 GitHub 关键词", leave=False)):
        keyword_found_urls = set()
        if i > 0:
            logging.warning(f"切换到下一个关键词: '{keyword}'，等待 {CONFIG['github']['retry_wait']} 秒以避免速率限制")
            time.sleep(CONFIG['github']['retry_wait'])
        page = 1
        while page <= CONFIG['github']['max_search_pages']:
            params = {
                "q": keyword,
                "sort": "indexed",
                "order": "desc",
                "per_page": CONFIG['github']['per_page'],
                "page": page
            }
            try:
                response = session.get(
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                    headers=headers,
                    params=params,
                    timeout=CONFIG['github']['api_timeout']
                )
                response.raise_for_status()
                data = response.json()
                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
                if rate_limit_remaining == 0:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制达到，剩余请求: 0，等待 {wait_seconds:.0f} 秒")
                    time.sleep(wait_seconds)
                    continue
                if not data.get('items'):
                    logging.info(f"关键词 '{keyword}' 在第 {page} 页无结果")
                    break
                for item in tqdm(data['items'], desc=f"处理关键词 '{keyword}' 第 {page} 页", leave=False):
                    html_url = item.get('html_url', '')
                    raw_url = None
                    match = GITHUB_URL_RE.search(html_url)
                    if match:
                        user, repo, branch, file_path = match.groups()
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}"
                    else:
                        logging.info(f"无法解析 raw URL: {html_url}")
                        continue
                    if raw_url and raw_url not in existing_urls and raw_url not in found_urls:
                        try:
                            content_response = session.get(raw_url, timeout=5)
                            content_response.raise_for_status()
                            content = content_response.text
                            if M3U_HEADER_RE.search(content) or FILE_EXT_RE.search(raw_url):
                                found_urls.add(raw_url)
                                keyword_found_urls.add(raw_url)
                                logging.info(f"发现新的 IPTV 源 URL: {raw_url}")
                            else:
                                logging.info(f"URL {raw_url} 不包含 M3U 内容或不支持的文件扩展名，跳过")
                        except requests.exceptions.RequestException as req_e:
                            logging.info(f"获取 {raw_url} 内容失败: {req_e}")
                        except Exception as exc:
                            logging.info(f"检查 {raw_url} 内容时发生意外错误: {exc}")
                logging.info(f"完成关键词 '{keyword}' 第 {page} 页，发现 {len(keyword_found_urls)} 个新 URL")
                page += 1
            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                    logging.error(f"GitHub API 速率限制或访问被拒绝，关键词 '{keyword}': {e}")
                    if rate_limit_remaining == 0:
                        wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                        logging.warning(f"关键词 '{keyword}' 速率限制，等待 {wait_seconds:.0f} 秒")
                        time.sleep(wait_seconds)
                        continue
                else:
                    logging.error(f"搜索 GitHub 关键词 '{keyword}' 失败: {e}")
                break
            except Exception as e:
                logging.error(f"搜索 GitHub 关键词 '{keyword}' 时发生意外错误: {e}")
                break
        keyword_url_counts[keyword] = len(keyword_found_urls)
    if found_urls:
        updated_urls = sorted(list(existing_urls | found_urls))
        logging.warning(f"发现 {len(found_urls)} 个新唯一 URL，总计保存 {len(updated_urls)} 个 URL")
        write_array_to_txt_local(urls_file_path_local, updated_urls)
    else:
        logging.warning("未发现新的 IPTV 源 URL")
    for keyword, count in keyword_url_counts.items():
        logging.warning(f"关键词 '{keyword}' 发现 {count} 个新 URL")

# --- URL 清理函数 ---
@performance_monitor
def cleanup_urls_local(urls_file_path_local, url_states):
    all_urls = read_txt_to_array_local(urls_file_path_local)
    current_time = datetime.now()
    urls_to_keep = []
    removed_count = 0
    for url in tqdm(all_urls, desc="清理无效 URL", leave=False):
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        last_failed_time_str = state.get('stream_check_failed_at')
        remove_url = False
        if fail_count > CONFIG['channel_retention']['url_fail_threshold']:
            if last_failed_time_str:
                try:
                    last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
                    if (current_time - last_failed_datetime).total_seconds() / 3600 > CONFIG['channel_retention']['url_retention_hours']:
                        remove_url = True
                        logging.info(f"移除 URL '{url}'，因失败次数过多 ({fail_count}) 且超出保留时间 ({CONFIG['channel_retention']['url_retention_hours']}h)")
                except ValueError:
                    logging.warning(f"无法解析 URL {url} 的最后失败时间戳: {last_failed_time_str}")
            else:
                remove_url = True
                logging.info(f"移除 URL '{url}'，因失败次数过多 ({fail_count}) 且无最后失败时间戳")
        if not remove_url:
            urls_to_keep.append(url)
        else:
            removed_count += 1
            url_states.pop(url, None)
    if removed_count > 0:
        logging.warning(f"从 {urls_file_path_local} 清理 {removed_count} 个 URL")
        write_array_to_txt_local(urls_file_path_local, urls_to_keep)
    else:
        logging.warning("无需清理 urls.txt 中的 URL")

# --- 分类和文件保存函数 ---
@performance_monitor
def categorize_channels(channels):
    categorized_data = {category: [] for category in CONFIG.get('ordered_categories', [])}
    uncategorized_data = []
    category_aliases = CONFIG.get('category_aliases', {})
    for name, url in tqdm(channels, desc="分类频道", leave=False):
        found_category = False
        for category in CONFIG.get('ordered_categories', []):
            category_keywords = CONFIG['category_keywords'].get(category, [])
            if any(keyword.lower() in name.lower() for keyword in category_keywords):
                final_category = category_aliases.get(category, category)
                if final_category not in categorized_data:
                    categorized_data[final_category] = []
                categorized_data[final_category].append((name, url))
                found_category = True
                break
        if not found_category:
            uncategorized_data.append((name, url))
    categorized_data_cleaned = {
        k: v for k, v in categorized_data.items() if v
    }
    all_final_categories = list(categorized_data_cleaned.keys())
    for alias_target in set(category_aliases.values()):
        if alias_target not in all_final_categories:
            all_final_categories.append(alias_target)
    final_ordered_categories = [cat for cat in CONFIG.get('ordered_categories', []) if cat in all_final_categories]
    for cat in sorted(all_final_categories):
        if cat not in final_ordered_categories:
            final_ordered_categories.append(cat)
    return categorized_data_cleaned, uncategorized_data, final_ordered_categories

@performance_monitor
def process_and_save_channels_by_category(all_channels, url_states, source_tracker):
    categorized_channels, uncategorized_channels, final_ordered_categories = categorize_channels(all_channels)
    categorized_dir = CONFIG['output']['paths']['channels_dir']
    os.makedirs(categorized_dir, exist_ok=True)
    for category in tqdm(final_ordered_categories, desc="保存分类频道", leave=False):
        channels = categorized_channels.get(category)
        if channels:
            output_file = os.path.join(categorized_dir, f"{category}_iptv.txt")
            logging.warning(f"处理分类: {category}，包含 {len(channels)} 个频道")
            sorted_channels = sorted(channels, key=lambda x: x[0])
            channels_to_write = [(0, f"{name},{url}") for name, url in sorted_channels]
            write_sorted_channels_to_file(output_file, channels_to_write)
    output_uncategorized_file = CONFIG['output']['paths']['uncategorized_channels_file']
    logging.warning(f"处理未分类频道: {len(uncategorized_channels)} 个频道")
    sorted_uncategorized = sorted(uncategorized_channels, key=lambda x: x[0])
    uncategorized_to_write = [(0, f"{name},{url}") for name, url in sorted_uncategorized]
    write_sorted_channels_to_file(output_uncategorized_file, uncategorized_to_write)
    logging.warning(f"未分类频道保存到: {output_uncategorized_file}")

# --- 主逻辑 ---
@performance_monitor
def main():
    logging.warning("开始执行 IPTV 处理脚本")
    total_start_time = time.time()
    url_states = load_url_states_local()
    logging.warning(f"加载 {len(url_states)} 个 URL 状态")
    auto_discover_github_urls(URLS_PATH, GITHUB_TOKEN)
    cleanup_urls_local(URLS_PATH, url_states)
    urls = read_txt_to_array_local(URLS_PATH)
    if not urls:
        logging.error("未在 urls.txt 中找到 URL，退出")
        exit(1)
    logging.warning(f"从 '{URLS_PATH}' 加载 {len(urls)} 个 URL")
    all_extracted_channels = []
    source_tracker = {}
    logging.warning(f"开始从 {len(urls)} 个 URL 提取频道")
    batch_size = 5000
    for i in range(0, len(urls), batch_size):
        batch_urls = urls[i:i+batch_size]
        max_workers = min(CONFIG['network']['url_fetch_workers'], max(2, psutil.cpu_count() - 1))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(extract_channels_from_url, url, url_states, source_tracker): url for url in batch_urls}
            for j, future in enumerate(tqdm(as_completed(futures), total=len(futures), desc=f"提取频道（批次 {i//batch_size+1}）", leave=False)):
                url = futures[future]
                if (j + 1) % CONFIG['performance_monitor']['log_interval'] == 0:
                    logging.warning(f"已处理 {j + 1}/{len(batch_urls)} 个 URL（批次 {i//batch_size+1}）")
                try:
                    channels = future.result()
                    if channels:
                        all_extracted_channels.extend(channels)
                    logging.info(f"完成 URL {url} 的频道提取，获取 {len(channels)} 个频道")
                except Exception as exc:
                    logging.error(f"URL {url} 提取异常: {exc}")
    logging.warning(f"完成频道提取，过滤前总计提取 {len(all_extracted_channels)} 个频道")
    filtered_and_modified_channels = []
    channel_batch_size = 100000
    for i in range(0, len(all_extracted_channels), channel_batch_size):
        batch_channels = all_extracted_channels[i:i+channel_batch_size]
        filtered_and_modified_channels.extend(filter_and_modify_channels(batch_channels))
        logging.warning(f"过滤和修改批次 {i//channel_batch_size+1} 后累计 {len(filtered_and_modified_channels)} 个频道")
    logging.warning(f"过滤和修改后剩余 {len(filtered_and_modified_channels)} 个频道")
    process_and_save_channels_by_category(filtered_and_modified_channels, url_states, source_tracker)
    merge_local_channel_files(CONFIG['output']['paths']['channels_dir'], IPTV_LIST_PATH, url_states)
    save_url_states_local(url_states)
    logging.warning("最终频道检查状态已保存")
    try:
        temp_files = ['iptv.txt', 'iptv_speed.txt']
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                os.remove(temp_file)
                logging.info(f"移除临时文件 '{temp_file}'")
        temp_dir = CONFIG['output']['paths']['channels_dir']
        if os.path.exists(temp_dir):
            for f_name in os.listdir(temp_dir):
                if f_name.endswith('_iptv.txt'):
                    os.remove(os.path.join(temp_dir, f_name))
                    logging.info(f"移除临时频道文件 '{f_name}'")
            if not os.listdir(temp_dir):
                os.rmdir(temp_dir)
                logging.info(f"移除空目录 '{temp_dir}'")
        logging.warning(f"保留未分类文件 '{CONFIG['output']['paths']['uncategorized_channels_file']}'")
    except Exception as e:
        logging.error(f"清理临时文件失败: {e}")
    total_elapsed_time = time.time() - total_start_time
    logging.warning(f"IPTV 处理脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
