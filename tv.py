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
import base64

# 配置日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH', 'config/url_states.json')
KEYWORD_STATS_PATH_IN_REPO = os.getenv('KEYWORD_STATS_PATH', 'config/keyword_stats.json')
CHANNEL_CACHE_PATH_IN_REPO = os.getenv('CHANNEL_CACHE_PATH', 'config/channel_cache.json')

# 验证环境变量
for var, name in [(GITHUB_TOKEN, 'BOT'), (REPO_OWNER, 'REPO_OWNER'), (REPO_NAME, 'REPO_NAME'),
                  (CONFIG_PATH_IN_REPO, 'CONFIG_PATH'), (URLS_PATH_IN_REPO, 'URLS_PATH'),
                  (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH'),
                  (KEYWORD_STATS_PATH_IN_REPO, 'KEYWORD_STATS_PATH'),
                  (CHANNEL_CACHE_PATH_IN_REPO, 'CHANNEL_CACHE_PATH')]:
    if not var:
        logging.error(f"[{datetime.now()}] 错误：环境变量 '{name}' 未设置")
        exit(1)

# GitHub 基础 URL
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# --- GitHub 文件操作 ---
def fetch_from_github(file_path_in_repo):
    """从 GitHub 获取文件内容"""
    logging.debug(f"[{datetime.now()}] 获取文件：{file_path_in_repo}")
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        logging.debug(f"[{datetime.now()}] 成功获取 {file_path_in_repo}")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"[{datetime.now()}] 获取 {file_path_in_repo} 失败：{e}")
        return None

def get_current_sha(file_path_in_repo):
    """获取文件 SHA 值"""
    logging.debug(f"[{datetime.now()}] 获取 {file_path_in_repo} SHA")
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        sha = response.json().get('sha')
        logging.debug(f"[{datetime.now()}] SHA：{sha}")
        return sha
    except requests.exceptions.RequestException as e:
        logging.debug(f"[{datetime.now()}] 获取 SHA 失败：{e}")
        return None

def save_to_github(file_path_in_repo, content, commit_message):
    """保存内容到 GitHub"""
    logging.debug(f"[{datetime.now()}] 保存到 {file_path_in_repo}")
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
        response = requests.put(api_url, headers=headers, json=payload)
        response.raise_for_status()
        logging.debug(f"[{datetime.now()}] 保存 {file_path_in_repo} 成功")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"[{datetime.now()}] 保存 {file_path_in_repo} 失败：{e}")
        return False

def check_file_size(content, file_path_in_repo, max_size_mb=50):
    """检查文件大小"""
    size_bytes = len(content.encode('utf-8'))
    if size_bytes > max_size_mb * 1024 * 1024:
        logging.error(f"[{datetime.now()}] {file_path_in_repo} 大小 {size_bytes / (1024 * 1024):.2f}MB 超限")
        return False
    logging.debug(f"[{datetime.now()}] {file_path_in_repo} 大小：{size_bytes / (1024 * 1024):.2f}MB")
    return True

# --- JSON 文件管理 ---
def save_url_states_remote(url_states, retention_days=7, max_size_mb=50):
    """保存 URL 状态"""
    file_path_in_repo = URL_STATES_PATH_IN_REPO
    logging.debug(f"[{datetime.now()}] 保存 URL 状态到 {file_path_in_repo}")
    try:
        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
        cleaned_states = {}
        max_fail_count = 10
        for url, state in url_states.items():
            last_checked = state.get('last_checked') or state.get('last_stream_checked')
            fail_count = state.get('stream_fail_count', 0)
            if last_checked and last_checked > cutoff_date and fail_count < max_fail_count:
                cleaned_states[url] = state

        content = json.dumps(cleaned_states, ensure_ascii=False)
        if not check_file_size(content, file_path_in_repo, max_size_mb):
            archive_path = f"archive/url_states_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            save_to_github(archive_path, content, "归档 URL 状态")
            cleaned_states = dict(sorted(cleaned_states.items(), key=lambda x: x[1].get('last_checked', ''), reverse=True)[:500])
            content = json.dumps(cleaned_states, ensure_ascii=False)

        if check_file_size(content, file_path_in_repo):
            success = save_to_github(file_path_in_repo, content, "更新 URL 状态")
            if success:
                logging.info(f"[{datetime.now()}] 保存 {file_path_in_repo}，记录：{len(cleaned_states)}")
    except Exception as e:
        logging.error(f"[{datetime.now()}] 保存 {file_path_in_repo} 失败：{e}")

def save_keyword_stats(keyword_stats, retention_days=7, max_size_mb=50):
    """保存关键词统计"""
    file_path_in_repo = KEYWORD_STATS_PATH_IN_REPO
    logging.debug(f"[{datetime.now()}] 保存关键词统计到 {file_path_in_repo}")
    try:
        existing_stats = {}
        content = fetch_from_github(file_path_in_repo)
        if content:
            try:
                existing_stats = json.loads(content)
            except json.JSONDecodeError:
                logging.warning(f"[{datetime.now()}] {file_path_in_repo} 解码失败")

        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
        existing_stats = {k: v for k, v in existing_stats.items() if v.get('timestamp', '') > cutoff_date}

        current_time = datetime.now().isoformat()
        for keyword, count in keyword_stats.items():
            existing_stats[keyword] = {'count': count, 'timestamp': current_time}

        content = json.dumps(existing_stats, ensure_ascii=False)
        if not check_file_size(content, file_path_in_repo, max_size_mb):
            archive_path = f"archive/keyword_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            save_to_github(archive_path, content, "归档关键词统计")
            existing_stats = dict(list(existing_stats.items())[-500:])
            content = json.dumps(existing_stats, ensure_ascii=False)

        if check_file_size(content, file_path_in_repo):
            success = save_to_github(file_path_in_repo, content, "更新关键词统计")
            if success:
                logging.info(f"[{datetime.now()}] 保存 {file_path_in_repo}，记录：{len(existing_stats)}")
    except Exception as e:
        logging.error(f"[{datetime.now()}] 保存 {file_path_in_repo} 失败：{e}")

def save_channel_cache(channel_cache, retention_days=7, max_size_mb=50):
    """保存频道缓存"""
    file_path_in_repo = CHANNEL_CACHE_PATH_IN_REPO
    logging.debug(f"[{datetime.now()}] 保存频道缓存到 {file_path_in_repo}")
    try:
        existing_cache = {}
        content = fetch_from_github(file_path_in_repo)
        if content:
            try:
                existing_cache = json.loads(content)
            except json.JSONDecodeError:
                logging.warning(f"[{datetime.now()}] {file_path_in_repo} 解码失败")

        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
        existing_cache = {k: v for k, v in existing_cache.items() if v.get('last_checked', '') > cutoff_date}

        current_time = datetime.now().isoformat()
        for channel_id, data in channel_cache.items():
            existing_cache[channel_id] = {
                'name': data.get('name'),
                'url': data.get('url'),
                'last_checked': current_time,
                'is_valid': data.get('is_valid', False)
            }

        content = json.dumps(existing_cache, ensure_ascii=False)
        if not check_file_size(content, file_path_in_repo, max_size_mb):
            archive_path = f"archive/channel_cache_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            save_to_github(archive_path, content, "归档频道缓存")
            existing_cache = dict(list(existing_cache.items())[-500:])
            content = json.dumps(existing_cache, ensure_ascii=False)

        if check_file_size(content, file_path_in_repo):
            success = save_to_github(file_path_in_repo, content, "更新频道缓存")
            if success:
                logging.info(f"[{datetime.now()}] 保存 {file_path_in_repo}，记录：{len(existing_cache)}")
    except Exception as e:
        logging.error(f"[{datetime.now()}] 保存 {file_path_in_repo} 失败：{e}")

def load_config():
    """加载 YAML 配置"""
    logging.debug(f"[{datetime.now()}] 加载配置：{CONFIG_PATH_IN_REPO}")
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            config = yaml.safe_load(content)
            logging.debug(f"[{datetime.now()}] 配置加载成功")
            return config
        except yaml.YAMLError as e:
            logging.error(f"[{datetime.now()}] 配置 {CONFIG_PATH_IN_REPO} 无效：{e}")
            exit(1)
    logging.error(f"[{datetime.now()}] 无法加载 {CONFIG_PATH_IN_REPO}")
    exit(1)

# 加载配置
CONFIG = load_config()

# 配置参数
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 3)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20)
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 20)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 5)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 3)
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200)
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
URL_FILTER_WORDS = CONFIG.get('url_filter_words', [])
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})
ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])
STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24)

# 配置 requests
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})
pool_size = CONFIG.get('requests_pool_size', 50)
retry_strategy = Retry(
    total=CONFIG.get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1),
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# --- 本地文件操作 ---
def read_txt_to_array_local(file_name):
    """读取本地 TXT 文件"""
    logging.debug(f"[{datetime.now()}] 读取本地：{file_name}")
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]
            logging.debug(f"[{datetime.now()}] 读取 {len(lines)} 行")
            return lines
    except FileNotFoundError:
        logging.warning(f"[{datetime.now()}] {file_name} 未找到")
        return []
    except Exception as e:
        logging.error(f"[{datetime.now()}] 读取 {file_name} 失败：{e}")
        return []

def read_existing_channels(file_path):
    """读取现有频道"""
    logging.debug(f"[{datetime.now()}] 读取频道：{file_path}")
    existing_channels = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ',' in line and not line.startswith('#'):
                    name, url = line.split(',', 1)
                    existing_channels.add((name.strip(), url.strip()))
        logging.debug(f"[{datetime.now()}] 读取 {len(existing_channels)} 个频道")
        return existing_channels
    except FileNotFoundError:
        return set()
    except Exception as e:
        logging.error(f"[{datetime.now()}] 读取 {file_path} 失败：{e}")
        return set()

def write_sorted_channels_to_file(file_path, data_list):
    """写入排序后的频道"""
    logging.debug(f"[{datetime.now()}] 写入：{file_path}")
    existing_channels = read_existing_channels(file_path)
    new_channels = set()
    
    for _, line in data_list:
        if ',' in line:
            name, url = line.split(',', 1)
            new_channels.add((name.strip(), url.strip()))
    
    all_channels = existing_channels | new_channels
    
    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            for name, url in all_channels:
                if (name, url) not in existing_channels:
                    file.write(f"{name},{url}\n")
        logging.debug(f"[{datetime.now()}] 追加 {len(all_channels - existing_channels)} 个频道到 {file_path}")
    except Exception as e:
        logging.error(f"[{datetime.now()}] 写入 {file_path} 失败：{e}")

# --- URL 处理 ---
def get_url_file_extension(url):
    """获取 URL 扩展名"""
    try:
        parsed_url = urlparse(url)
        return os.path.splitext(parsed_url.path)[1].lower()
    except ValueError as e:
        logging.debug(f"[{datetime.now()}] 获取 {url} 扩展名失败：{e}")
        return ""

def convert_m3u_to_txt(m3u_content):
    """转换 M3U 到 TXT"""
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
    """清理 URL 参数"""
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.debug(f"[{datetime.now()}] 清理 {url} 失败：{e}")
        return url

# --- URL 状态管理 ---
def load_url_states():
    """加载 URL 状态"""
    logging.debug(f"[{datetime.now()}] 加载 URL 状态：{URL_STATES_PATH_IN_REPO}")
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    if content:
        try:
            states = json.loads(content)
            logging.debug(f"[{datetime.now()}] 加载 {len(states)} 个 URL 状态")
            return states
        except json.JSONDecodeError as e:
            logging.error(f"[{datetime.now()}] 解码 {URL_STATES_PATH_IN_REPO} 失败：{e}")
            return {}
    return {}

def load_channel_cache():
    """加载频道缓存"""
    logging.debug(f"[{datetime.now()}] 加载频道缓存：{CHANNEL_CACHE_PATH_IN_REPO}")
    content = fetch_from_github(CHANNEL_CACHE_PATH_IN_REPO)
    if content:
        try:
            cache = json.loads(content)
            logging.debug(f"[{datetime.now()}] 加载 {len(cache)} 个频道缓存")
            return cache
        except json.JSONDecodeError as e:
            logging.error(f"[{datetime.now()}] 解码 {CHANNEL_CACHE_PATH_IN_REPO} 失败：{e}")
            return {}
    return {}

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
    """获取 URL 内容"""
    logging.debug(f"[{datetime.now()}] 获取 {url}")
    headers = {}
    current_state = url_states.get(url, {})

    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']

    try:
        response = session.get(url, headers=headers, timeout=CHANNEL_FETCH_TIMEOUT)
        response.raise_for_status()

        if response.status_code == 304:
            logging.debug(f"[{datetime.now()}] {url} 未修改 (304)")
            url_states[url] = url_states.get(url, {})
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"[{datetime.now()}] {url} 哈希相同")
            url_states[url] = url_states.get(url, {})
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }

        logging.debug(f"[{datetime.now()}] 获取 {url} 成功")
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"[{datetime.now()}] 获取 {url} 失败：{e}")
        return None
    except Exception as e:
        logging.error(f"[{datetime.now()}] 获取 {url} 错误：{e}")
        return None

def extract_channels_from_url(url, url_states, channel_cache):
    """从 URL 提取频道"""
    logging.debug(f"[{datetime.now()}] 提取频道：{url}")
    extracted_channels = []
    try:
        content = fetch_url_content_with_retry(url, url_states)
        if content is None:
            return []

        if get_url_file_extension(url) in [".m3u", ".m3u8"]:
            content = convert_m3u_to_txt(content)

        lines = content.split('\n')
        channel_count = 0
        for line in lines:
            line = line.strip()
            if "#genre#" not in line and "," in line and "://" in line:
                parts = line.split(',', 1)
                if len(parts) != 2:
                    logging.debug(f"[{datetime.now()}] 跳过无效行：{line}")
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip()
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    logging.debug(f"[{datetime.now()}] 跳过无效 URL：{line}")
                    continue

                channel_id = hashlib.md5(f"{channel_name}:{channel_address_raw}".encode()).hexdigest()
                channel_cache[channel_id] = {
                    'name': channel_name,
                    'url': channel_address_raw,
                    'last_checked': datetime.now().isoformat(),
                    'is_valid': False
                }

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                            channel_count += 1
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
                        channel_count += 1
        logging.debug(f"[{datetime.now()}] 从 {url} 提取 {channel_count} 个频道")
        return extracted_channels
    except Exception as e:
        logging.error(f"[{datetime.now()}] 提取 {url} 失败：{e}")
        return []

def pre_screen_url(url):
    """预筛选 URL"""
    if not isinstance(url, str) or not url:
        return False
    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        return False
    try:
        parsed_url = urlparse(url)
        allowed_protocols = CONFIG.get('url_pre_screening', {}).get('allowed_protocols', ['http', 'https', 'rtmp', 'rtp', 'p3p'])
        if parsed_url.scheme not in allowed_protocols or not parsed_url.netloc:
            return False
        invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
        for pattern in [re.compile(p, re.IGNORECASE) for p in invalid_url_patterns]:
            if pattern.search(url):
                return False
        return len(url) >= 15
    except ValueError:
        return False

def filter_and_modify_channels(channels):
    """过滤和修改频道"""
    filtered_channels = []
    for name, url in channels:
        if not pre_screen_url(url):
            continue
        if any(word in url for word in URL_FILTER_WORDS) or any(word.lower() in name.lower() for word in NAME_FILTER_WORDS):
            continue
        for old_str, new_str in CHANNEL_NAME_REPLACEMENTS.items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    logging.debug(f"[{datetime.now()}] 过滤后 {len(filtered_channels)} 个频道")
    return filtered_channels

# --- 频道有效性检查 ---
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException:
        return False

def check_rtmp_url(url, timeout):
    """检查 RTMP URL"""
    logging.debug(f"[{datetime.now()}] 检查 RTMP：{url}")
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-timeout', '3000000', '-i', url],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
        return result.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False

def check_rtp_url(url, timeout):
    """检查 RTP URL"""
    try:
        parsed_url = urlparse(url)
        host, port = parsed_url.hostname, parsed_url.port
        if not host or not port:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error):
        return False

def check_p3p_url(url, timeout):
    """检查 P3P URL"""
    try:
        parsed_url = urlparse(url)
        host, port = parsed_url.hostname, parsed_url.port or 80
        path = parsed_url.path or '/'
        if not host:
            return False
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/")
    except Exception:
        return False

def check_channel_validity_and_speed(channel_name, url, url_states, channel_cache, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查频道有效性"""
    logging.debug(f"[{datetime.now()}] 检查 {channel_name} ({url})")
    current_time = datetime.now()
    current_url_state = url_states.get(url, {})
    channel_id = hashlib.md5(f"{channel_name}:{url}".encode()).hexdigest()

    if 'stream_check_failed_at' in current_url_state:
        try:
            last_failed = datetime.fromisoformat(current_url_state['stream_check_failed_at'])
            if (current_time - last_failed).total_seconds() / 3600 < STREAM_SKIP_FAILED_HOURS:
                logging.debug(f"[{datetime.now()}] 跳过 {channel_name} ({url})，冷却中")
                return None, False
        except ValueError:
            logging.warning(f"[{datetime.now()}] 无效时间戳：{current_url_state['stream_check_failed_at']}")

    start_time = time.time()
    is_valid = False

    try:
        if url.startswith("http"):
            is_valid = check_http_url(url, timeout)
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, timeout)
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, timeout)
        else:
            url_states[url] = url_states.get(url, {})
            url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat()
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            return None, False

        elapsed_time = (time.time() - start_time) * 1000

        url_states[url] = url_states.get(url, {})
        channel_cache[channel_id] = channel_cache.get(channel_id, {})
        channel_cache[channel_id].update({'name': channel_name, 'url': url, 'last_checked': current_time.isoformat()})

        if is_valid:
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_successful_stream_check'] = current_time.isoformat()
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            channel_cache[channel_id]['is_valid'] = True
            logging.debug(f"[{datetime.now()}] {channel_name} ({url}) 有效，耗时 {elapsed_time:.0f}ms")
            return elapsed_time, True
        else:
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            channel_cache[channel_id]['is_valid'] = False
            logging.debug(f"[{datetime.now()}] {channel_name} ({url}) 无效")
            return None, False
    except Exception as e:
        url_states[url] = url_states.get(url, {})
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
        url_states[url]['last_stream_checked'] = current_time.isoformat()
        channel_cache[channel_id] = channel_cache.get(channel_id, {})
        channel_cache[channel_id].update({'name': channel_name, 'url': url, 'last_checked': current_time.isoformat(), 'is_valid': False})
        logging.error(f"[{datetime.now()}] 检查 {channel_name} ({url}) 失败：{e}")
        return None, False

def process_single_channel_line(channel_line, url_states, channel_cache):
    """处理单行频道"""
    if "://" not in channel_line:
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states, channel_cache)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

def check_channels_multithreaded(channel_lines, url_states, channel_cache, max_workers=50):
    """多线程检查频道"""
    logging.warning(f"[{datetime.now()}] 检查 {len(channel_lines)} 个频道，线程：{max_workers}")
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line, url_states, channel_cache): line for line in channel_lines}
        for future in as_completed(futures):
            checked_count += 1
            if checked_count % 100 == 0:
                logging.warning(f"[{datetime.now()}] 已检查 {checked_count}/{total_channels} 个")
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line:
                    results.append((elapsed_time, result_line))
            except Exception as e:
                logging.error(f"[{datetime.now()}] 处理行失败：{e}")
    logging.warning(f"[{datetime.now()}] 检查完成，{len(results)} 个有效频道")
    return results

# --- 文件合并和排序 ---
def generate_update_time_header():
    """生成时间头"""
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    """分组并限制频道"""
    grouped_channels = {}
    for line in lines:
        line = line.strip()
        if line:
            channel_name = line.split(',', 1)[0].strip()
            grouped_channels.setdefault(channel_name, []).append(line)
    final_lines = []
    for channel_name in grouped_channels:
        final_lines.extend(line + '\n' for line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP])
    return final_lines

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt"):
    """合并本地频道"""
    existing_channels = read_existing_channels(output_file_name)
    if not existing_channels:
        final_output_lines = generate_update_time_header()
    else:
        final_output_lines = []

    all_files = []
    try:
        all_files = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    except FileNotFoundError:
        logging.warning(f"[{datetime.now()}] 目录 {local_channels_directory} 不存在")
        return

    files_to_process = []
    processed_files = set()

    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        if file_name in all_files and file_name not in processed_files:
            files_to_process.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    for file_name in sorted(all_files):
        if file_name in processed_files:
            files_to_process.append(os.path.join(file_name, local_channels_directory))
        else:
            files_to_process.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    new_channels = set()
    for file_path in files_to_process):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
                if not lines:
                    continue
                header = lines[0].strip()
                if '#genre#' in header:
                    final_output_lines.append(header + '\n')
                    for line in lines[1:]:
                        line = line.strip()
                        if line and ',' in line:
                            name, url = line.split(',', 1)
                            new_channels.add((name.strip(), url.strip()))
                except Exception as e:
                    logging.error(f"[{datetime.now()}] 读取 {file_path} 失败：{e}")

            all_channels = existing_channels | new_channels
            for name, url in all_channels:
                if (name, url) not in existing_channels:
                    final_output_lines.append(f"{name},{url}\n")

            try:
                with open(output_file_name, "a", encoding='utf-8') as file:
                    file.writelines(final_output_lines)
                logging.warning(f"[{datetime.now()}] {合并完成，输出到 {output_file_name}}")
            except Exception as e:
                logging.error(f"[{datetime.now()}] 写入 {output_file_name} 失败：{e}")

# --- 远程 TXT 操作 ---
def read_txt_to_array_remote(file_path_in_repo):
    """读取远程 TXT"""
    logging.debug(f"[{datetime.now()}] 读取 {file_path_in_repo}")
    content = fetch_from_github(file_path_in_repo)
    if not content:
        return []
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    logging.info(f"[{datetime.now()}] 读取 {len(lines)} 行")
    return lines

def write_array_to_txt_remote(file_path_in_repo, lines, commit_message):
    """写入远程 GitHub"""
    logging.debug(f"[{datetime.now()}] 写入 {file_path_in_repo}")
    content = '\n'
    join(content, lines)
    if check_file_size(content, file_path_in_repo):
        success = save_to_github(content, file_path_in_repo, commit_message)
        logging.info(f"[{datetime.now()}] 写入 {file_path_in_repo} {成功} if success else '失败'}')

# --- GitHub URL 发现 ---
def auto_discover_github_urls():
    file_path_in_repo, github_token, keyword_stats = (urls_file_path_remote, github_token, keyword_stats)
    """发现 GitHub：{urls_file_path_in_repo}"""
    logging.debug(f"[{datetime.now()}] 开始发现 GitHub URL")
    if not github_token:
        logging.error(f"[{datetime.now()}] 缺少 GitHub token")
        return False

    existing_urls = set(read_txt_to_array_remote(file_path_in_repo))
    found_urls = set()
    try:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {github_token}"}
        }

        keyword_url_counts = {}
        for keyword in SEARCH_KEYWORDS:
            keyword_url_counts[keyword.lower()] = 0

        for i, (keyword in enumerate(SEARCH_KEYWORDS)):
            logging.debug(f"[{datetime.now()}] 处理 '{keyword}'，第 {i + 1}/{len(SEARCH_KEYWORDS)}")
            keyword_found_urls = set()
            if i > 0:
                logging.warning(f"[{datetime.now()}] 切换到 '{keyword}'，等待 {GITHUB_API_RETRY_WAIT} 秒")
                time.sleep(GITHUB_API_RETRY_WAIT)

            page = 1
            while page <= MAX_SEARCH_PAGES:
                params = {'q': keyword, 'page': page, 'per_page': PER_PAGE}
                try:
                    response = session.get(
                        f"{GITHUB_API_BASE_URL}/{SEARCH_CODE_ENDPOINT}",
                        headers=headers,
                        params=params,
                        timeout=GITHUB_API_TIMEOUT
                    )
                    response.raise_for_status()

                    rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                    rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
                    logging.debug(f"[{datetime.now()}] API 剩余：{rate_limit_remaining}， logging重置：{rate_limit_reset}})

                    if rate_limit.remaining == 0:
                        wait_seconds = max(int(0), rate_limit_reset - int(time.time())) + 5
                        logging.warning(f"[{datetime.now()}] API 限制，等待 {wait_seconds} 秒")
                        time.sleep(wait_seconds)
                        continue

                    data = response.json()
                    if not data.get('['items']):
                        logging.warning(f"[{datetime.now()}] '{keyword}' 无结果 第 {page} 页")
                        logging.debug(f"[{datetime.now()}] 跳出")
                    break

                    for item in data['items']:
                        html_url = item.get('html_url', '')
                        match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/(.+)/(.*)', html_url)
                        if match:
                            user, repo, _, path = match.groups()
                            raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{path}/{raw_url}"
                            cleaned_url = clean_url_params(raw_url)
                            if cleaned_url.startswith(cleaned_url.lower().endswith(("https://raw.githubusercontent.com") and raw_url in ('.m3u', '.m3u8', '.txt')) and pre_screen_url(cleaned_url'):
                                found_urls.add(cleaned_url)
                                keyword_found_urls.add(cleaned_url)
                                logging.debug(f"[{datetime.now()}] 发现：{cleaned_url}")

                    if len(data['items']) < PER_PAGE:
                        logging.warning(f"[{datetime.now()}] 页面数据不足，跳出")
                        break

                    page += 1
                    time.sleep(1)

                except requests.exceptions.RequestException as e:
                    logging.error(f"[{datetime.now()}] API 请求失败（{keyword}，页 {page}）：{e}")
                    if e.response.status_code == 403:
                        wait_seconds = int(response.headers.get('X-RateLimit-Reset', 0)) - int(time.time()) + 1
                        logging.warning(f"[{datetime.now()}] API 限制，等待 {wait_seconds} 秒")
                        time.sleep(wait_seconds)
                        continue
                    logging.warning(f"[{datetime.now()}] {e}")
                    break
                except json.JSONDecodeError as e):
                    logging.error(f"[{datetime.now()}] API 无效 JSON：{e}")
                    break
                except Exception as e:
                    logging.error(f"[{datetime.now()}] 错误：{e}")
                    break

            keyword_url_counts[keyword.lower()] = len(keyword_found_urls)
            logging.warning(f"[{datetime.now()}] '{keyword}' 找到 {len(keyword_found_urls)} 个 URL")

        save_keyword_stats(keyword_url_counts)

        logging.warning(f"\n[{datetime.now()}] === 关键词总结 ===")
        low_result_threshold = 3
        for keyword, count in keyword_url_counts.items():
            logging.warning(f"[关键词 '{keyword}'：{count} 个 URL")
            if count <= low_result_threshold:
                logging.warning(f"  - '{keyword}' ({count})")

        new_urls_count = sum(1 for url in found_urls if not url not in existing_urls)
        if new_urls_count:
            existing_urls.update(found_urls)
            updated_urls = sorted(existing_urls)
            write_array_to_txt_remote(file_path_in_repo, updated_urls, "更新 urls.txt")
            logging.warning(f"[{datetime.now()}] 添加 {new_urls_count} 个新 URL 到 {file_path_in_repo}")
        else:
            logging.warning(f"[{datetime.now()}] 无新 URL")

        logging.info(f"[{datetime.now()}] 发现完成，找到 {len(found_urls)} 个 URL")
        return True
    except Exception as e:
        logging.error(f"[{datetime.now()}] 发现失败：{e}")
        return False

# --- 主函数 ---
def main():
    """主逻辑"""
    try:
        logging.info(f"[{datetime.now()}] 初始化")
        url_states = load_url_states()
        channel_cache = load_channel_cache()
        keyword_stats = {}

        # 步骤 1: 发现 URL
        logging.info(f"[{datetime.now()}] 步骤 1：发现 URL")
        if not auto_discover_github(URLS_PATH_IN_REPO, GITHUB_TOKEN, keyword_stats):
            logging.error(f"[{datetime.now()}] URL 发现失败")
            return False

        # 步骤 2：读取 URL
        logging.info(f"[{datetime.now()}] 步骤 2：读取 URL")
        urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
        if not urls:
            logging.error(f"[{datetime.now()}] 无 URL：{URLS_PATH_IN_REPO}")
            return False
        logging.info(f"[{datetime.now()}] 找到 {len(urls)} 个 URL")

        # 步骤 3: 提取频道
        logging.info(f"[{datetime.now()}] 步骤 3：提取频道")
        all_extracted_channels = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(extract_channels_from_url, url, url_states, channel_cache): url for url in urls}
            for future in as_completed(futures):
                try:
                    all_extracted_channels.extend(future.result())
                except Exception as e:
                    logging.error(f"[{datetime.now()}] 提取 {futures[future]} 失败：{e}")

        logging.warning(f"[{datetime.now()}] 提取 {len(all_extracted_channels)} 个频道")

        # 保存状态
        save_url_states_remote(url_states)
        save_channel_cache(channel_cache)
        logging.info(f"[{datetime.now()}] 保存状态")

        # 步骤 4: 过滤频道
        logging.info(f"[{datetime.now()}] 步骤 4：过滤频道")
        filtered_channels = filter_and_modify_channels(all_extracted_channels)
        unique_channels = list(set(filtered_channels))
        unique_str_channels = [f"{name},{url}" for name, url in unique_channels]
        logging.debug(f"[{datetime.now()}] 过滤后 {len(unique_channels)} 个频道")

        # 步骤 5: 检查有效性
        logging.info(f"[{datetime.now()}] 步骤 5：检查有效性")
        valid_channels = check_channels_multithreaded(unique_str_channels, url_states, channel_cache)
        logging.warning(f"[{datetime.now()}] {len(valid_channels)} 个有效频道")

        # 保存状态
        save_url_states_remote(url_states)
        logging.info(f"[{datetime.now()}] 保存状态")

        # 步骤 6: 保存有效频道
        logging.info(f"[{datetime.now()}] 步骤 6：保存有效频道")
        iptv_temp_file = 'iptv_speed.txt'
        with open(iptv_temp_file,'w', encoding='utf-8') as f:
            for _, line in sorted(valid_channels):
                f.write(f"{line}\n")
        logging.info(f"[{datetime.now()}] 保存到 {iptv_temp_file}")

        # 步骤 7: 创建目录
        logging.info(f"[{datetime.now()}] 步骤 7：创建目录")
        os.makedirs('local_channels', exist_ok=True)
        os.makedirs('templates', exist_ok=True)
        template_files = [f for f in os.listdir('templates') if f.endswith('.txt')]
        channels_to_process = read_txt_to_array_local(iptv_temp_file)

        # 收集模板频道
        all_template_channel_names = set()
        for template_file in template_files:
            all_template_channel_names.update(read_txt_to_array_local(os.path.join('templates', template_file)))

        # 步骤 8: 处理模板分类
        logging.info(f"[{datetime.now()}] 步骤 8：分类频道")
        for template_file in template_files:
            template_channel_names = set(read_txt_to_array_local(os.path.join('templates', template_file)))
            template_name = os.path.splitext(template_file)[0]
            matched_channels = [ch for ch in channels_to_process if ch.split(',')[1].strip()[0] in template_channel_names]
            
            if "CCTV" in template_name.upper():
                matched_channels = sort_cctv_channels(matched_channels)
                logging.warning(f"[{datetime.now()}] {template_name} 已排序")

            output_file = os.path.join('local_channels', f"{template_name}_iptv.txt')
            existing_channels = read_existing_channels(output_file)
            new_channels = set()
            for channel in matched_channels:
                name, url = channel.split(',', 1)
                new_channels.add((name.strip(), url.strip()))

            all_channels = existing_channels | existing_channels
            with open(output_file, 'a', encoding='utf-8') as f:
                if not new_channels:
                    f.write(f"{template_name},#ttv_channels\n")
                for name, url in all_channels:
                    if (name.strip(), url.strip()) not in existing_channels:
                        f.write(f"{name},{url}\n")
            logging.warning(f"{[{datetime.now()}] 添加 {len(new_channels)} 个频道到 {output_file}")

        # 步骤 9: 合并频道
        logging.info(f"{[{datetime.now()}] 步骤 9：合并频道")
        final_iptv_list_file = "iptv_list.txt"
        merge_local_channel_files('local_channels', final_iptv_list_file)

        # 步骤 10：上传结果
        logging.info(f"[{datetime.now()}] 步骤 10：上传 {final_iptv_list_file}")
        with open(final_iptv_list_file, 'r', encoding='utf-8') as f:
            final_content = f.read()]
        if check_file_size(final_content, f"output/{final_iptv_list_file}"):
            save_to_github(f"output/{final_iptv_list_file}", final_content, "更新 IPTV")
            logging.info(f"[{datetime.now()}] 上传 {final_iptv_list_file}")
        # 步骤 11: 保存未匹配频道
        logging.info(f"[{datetime.now()}] 步骤 11：保存未匹配频道")
        unmatched_channels = []
        if channels_to_process:
            unmatched_channels = [ch for ch in channels_to_process if ch.split(',')[1].strip() not in all_template_channel_names]
        unmatched_output_file = os.path.join('output', 'unmatched_channels.txt')
        existing_unmatched = read_existing_channels(unmatched_output_file)
        new_unmatched = set()
        for channel in unmatched_channels:
            name, url = channel.split(',', 1)
            new_unmatched.add((name.strip(), url.strip())))

        all_unmatched = existing_unmatched | new_unmatched
        with open(unmatched_output_file, 'a', encoding='utf-8') as f:
            for name, url in all_unmatched:
                if (name.strip(), url.strip()) not in existing_unmatched:
                    f.write(f"{name},{url}"\n")
        logging.warning(f"[{datetime.now()}] 保存 {len(all_unmatched)} 个未匹配到 {unmatched_output_file}")

        # 清理临时文件
        logging.info(f"[{datetime.now()}] 清理临时文件")
        for temp_file in ['iptv_speed.txt']:
            if os.path.exists(temp_file):
                os.remove(temp_file)
                logging.debug(f"[{datetime.now()}] 删除 {temp_file}")

        logging.info(f"[{datetime.now()}] 完成")
        return True

    except Exception as e:
        logging.error(f"[{datetime.now()}] 主程序失败：{e}")
        return False

def sort_cctv_channels(channels):
    """排序 CCTV """
    def sort_key(ch):
        channel_name = ch.split(',', 1)[0].strip()
        match = re.search(r'\d+', channel_name)
        return int(match.group()) if match else float('inf')
    return sorted(channels, key=sort_key)

if __name__ == "__main__":
