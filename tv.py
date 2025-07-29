
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
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 固定配置文件路径
CONFIG_PATH = "config/config.yaml"
URLS_PATH = "config/urls.txt"
URL_STATES_PATH = "config/url_states.json"
IPTV_LIST_PATH = "iptv_list.txt"  # 输出到根目录
GITHUB_TOKEN = os.getenv('BOT')  # 从环境变量获取 BOT secret
GITHUB_RAW_CONTENT_BASE_URL = "https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = "https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# 检查 GITHUB_TOKEN 是否设置
if not GITHUB_TOKEN:
    logging.error("Error: Environment variable 'BOT' not set.")
    exit(1)

# --- GitHub 文件操作函数 ---
def fetch_from_github(file_path_in_repo):
    """从 GitHub 仓库获取文件内容。"""
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {file_path_in_repo} from GitHub: {e}")
        return None

def get_current_sha(file_path_in_repo):
    """获取 GitHub 仓库中文件的当前 SHA 值。"""
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error getting SHA for {file_path_in_repo} (might not exist): {e}")
        return None

def save_to_github(file_path_in_repo, content, commit_message):
    """保存（创建或更新）内容到 GitHub 仓库。"""
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
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error saving {file_path_in_repo} to GitHub: {e}")
        logging.error(f"GitHub API response: {response.text if 'response' in locals() else 'N/A'}")
        return False

def load_config():
    """从本地 config/config.yaml 加载并解析 YAML 配置文件。"""
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"Error: Config file '{CONFIG_PATH}' not found.")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Error: Invalid YAML in config file '{CONFIG_PATH}': {e}")
        exit(1)
    except Exception as e:
        logging.error(f"Error loading config file '{CONFIG_PATH}': {e}")
        exit(1)

# 加载配置
CONFIG = load_config()

# 从配置中获取参数
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20)
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 10)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 6)
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200)
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
URL_FILTER_WORDS = CONFIG.get('url_filter_words', [])
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})
ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])
STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24)
URL_STATE_EXPIRATION_DAYS = CONFIG.get('url_state_expiration_days', 90)
CHANNEL_FAIL_THRESHOLD = CONFIG.get('channel_fail_threshold', 5)
URL_FAIL_THRESHOLD = CONFIG.get('url_fail_threshold', 5)
URL_RETENTION_HOURS = CONFIG.get('url_retention_hours', 72)

# 配置 requests 会话
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"})
pool_size = CONFIG.get('requests_pool_size', 200)
retry_strategy = Retry(
    total=CONFIG.get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1),
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# --- 本地文件操作函数 ---
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组。"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        lines = [line.strip() for line in lines if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"File '{file_name}' not found.")
        return []
    except Exception as e:
        logging.error(f"Error reading file '{file_name}': {e}")
        return []

def read_existing_channels(file_path):
    """从文件中读取现有的频道（名称，URL）组合以进行去重。"""
    existing_channels = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ',' in line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        name, url = parts
                        existing_channels.add((name.strip(), url.strip()))
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.error(f"Error reading file '{file_path}' for deduplication: {e}")
    return existing_channels

def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道数据追加到文件，去重。"""
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
        logging.debug(f"Appended {len(all_channels - existing_channels)} new channels to {file_path}")
    except Exception as e:
        logging.error(f"Error appending to file '{file_path}': {e}")

# --- URL 处理和频道提取函数 ---
def get_url_file_extension(url):
    """从 URL 获取文件扩展名。"""
    try:
        parsed_url = urlparse(url)
        extension = os.path.splitext(parsed_url.path)[1].lower()
        return extension
    except ValueError as e:
        logging.debug(f"Failed to get URL extension: {url} - {e}")
        return ""

def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式内容转换为 TXT 格式（频道名称，URL）。"""
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = ""
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTM3U"):
            continue
        if line.startswith("#EXTINF"):
            match = re.search(r'#EXTINF:.*?\,(.*)', line)
            if match:
                channel_name = match.group(1).strip()
            else:
                channel_name = "未知频道"
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = ""
    return '\n'.join(txt_lines)

def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径。"""
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.debug(f"Failed to clean URL parameters: {url} - {e}")
        return url

# --- URL 状态管理函数 ---
def load_url_states_local():
    """从本地 config/url_states.json 加载 URL 状态，并清理过期状态。"""
    url_states = {}
    try:
        with open(URL_STATES_PATH, 'r', encoding='utf-8') as file:
            url_states = json.load(file)
    except FileNotFoundError:
        logging.warning(f"URL states file '{URL_STATES_PATH}' not found. Starting with empty state.")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from '{URL_STATES_PATH}': {e}. Starting with empty state.")
        return {}
    
    # 清理过期状态
    current_time = datetime.now()
    updated_url_states = {}
    for url, state in url_states.items():
        if 'last_checked' in state:
            try:
                last_checked_datetime = datetime.fromisoformat(state['last_checked'])
                if (current_time - last_checked_datetime).days < URL_STATE_EXPIRATION_DAYS:
                    updated_url_states[url] = state
                else:
                    logging.debug(f"Removing expired URL state: {url} (last checked on {state['last_checked']})")
            except ValueError:
                logging.warning(f"Could not parse last_checked timestamp for URL {url}: {state['last_checked']}, keeping its state.")
                updated_url_states[url] = state
        else:
            updated_url_states[url] = state
            
    return updated_url_states

def save_url_states_local(url_states):
    """将 URL 状态保存到本地 config/url_states.json。"""
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Error saving URL states to '{URL_STATES_PATH}': {e}")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
    """尝试带重试机制获取 URL 内容，并使用 ETag/Last-Modified/Content-Hash 避免重复下载。"""
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
            logging.debug(f"URL content {url} not modified (304). Skipping download.")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL content {url} is same based on hash. Skipping download.")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }

        logging.debug(f"Successfully fetched new content for URL: {url}. Content updated.")
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error fetching URL (after retries): {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"Unknown error fetching URL: {url} - {e}")
        return None

def extract_channels_from_url(url, url_states):
    """从给定 URL 提取频道。"""
    extracted_channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states)
        if text is None:
            return []

        if get_url_file_extension(url) in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)

        lines = text.split('\n')
        channel_count = 0
        for line in lines:
            line = line.strip()
            if "#genre#" not in line and "," in line and "://" in line:
                parts = line.split(',', 1)
                if len(parts) != 2:
                    logging.debug(f"Skipping invalid channel line (malformed): {line}")
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip()
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    logging.debug(f"Skipping invalid channel URL (no valid protocol): {line}")
                    continue

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                            channel_count += 1
                        else:
                            logging.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}")
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
                        channel_count += 1
                    else:
                        logging.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}")
        logging.debug(f"Successfully extracted {channel_count} channels from URL: {url}.")
    except Exception as e:
        logging.error(f"Error extracting channels from {url}: {e}")
    return extracted_channels

def pre_screen_url(url):
    """根据配置对 URL 进行预筛选（协议、长度、无效模式）。"""
    if not isinstance(url, str) or not url:
        logging.debug(f"Pre-screening filtered (invalid type or empty): {url}")
        return False

    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        logging.debug(f"Pre-screening filtered (no valid protocol): {url}")
        return False

    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        logging.debug(f"Pre-screening filtered (contains illegal characters or spaces): {url}")
        return False

    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
            logging.debug(f"Pre-screening filtered (unsupported protocol): {url}")
            return False

        if not parsed_url.netloc:
            logging.debug(f"Pre-screening filtered (no network location): {url}")
            return False

        invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                logging.debug(f"Pre-screening filtered (invalid pattern): {url}")
                return False

        if len(url) < 15:
            logging.debug(f"Pre-screening filtered (URL too short): {url}")
            return False

        return True
    except ValueError as e:
        logging.debug(f"Pre-screening filtered (URL parse error): {url} - {e}")
        return False

def filter_and_modify_channels(channels):
    """过滤和修改频道名称及 URL。"""
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        if not pre_screen_url(url):
            logging.debug(f"Filtering channel (pre-screening failed): {name},{url}")
            continue
        pre_screened_count += 1

        if any(word in url for word in CONFIG.get('url_filter_words', [])):
            logging.debug(f"Filtering channel (URL matches blacklist): {name},{url}")
            continue

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            logging.debug(f"Filtering channel (name matches blacklist): {name},{url}")
            continue

        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    logging.debug(f"After URL pre-screening, {pre_screened_count} channels remain for further filtering.")
    return filtered_channels

# --- 频道有效性检查函数 ---
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达。"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} check failed: {e}")
        return False

def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达（需要 ffprobe）。"""
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("ffprobe not found or not working. RTMP stream check skipped.")
        return False
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} check timed out")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} check error: {e}")
        return False

def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达（尝试 UDP 连接）。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.debug(f"RTP URL {url} parse failed: missing host or port.")
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL {url} check failed: {e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} check error: {e}")
        return False

def check_p3p_url(url, timeout):
    """检查 P3P URL 是否可达（简单 TCP 连接和 HTTP 响应头检查）。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'

        if not host:
            logging.debug(f"P3P URL {url} parse failed: missing host.")
            return False

        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} check failed: {e}")
        return False

def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查单个频道的有效性和速度，并记录失败状态以便跳过。"""
    current_time = datetime.now()
    current_url_state = url_states.get(url, {})

    if 'stream_check_failed_at' in current_url_state:
        last_failed_time_str = current_url_state['stream_check_failed_at']
        try:
            last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
            if time_since_failed_hours < STREAM_SKIP_FAILED_HOURS:
                logging.debug(f"Skipping channel {channel_name} ({url}) as it failed within cooldown period ({STREAM_SKIP_FAILED_HOURS}h). Last failed at {last_failed_time_str}, {time_since_failed_hours:.2f}h ago.")
                return None, False
        except ValueError:
            logging.warning(f"Could not parse failed timestamp for URL {url}: {last_failed_time_str}")
            pass

    start_time = time.time()
    is_valid = False
    protocol_checked = False

    try:
        if url.startswith("http"):
            is_valid = check_http_url(url, timeout)
            protocol_checked = True
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, timeout)
            protocol_checked = True
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
            protocol_checked = True
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, timeout)
            protocol_checked = True
        else:
            logging.debug(f"Channel {channel_name}'s protocol is not supported: {url}")
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
            logging.debug(f"Channel {channel_name} ({url}) check successful, took {elapsed_time:.0f} ms.")
            return elapsed_time, True
        else:
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.debug(f"Channel {channel_name} ({url}) check failed.")
            return None, False
    except Exception as e:
        if url not in url_states:
            url_states[url] = {}
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
        url_states[url]['last_stream_checked'] = current_time.isoformat()
        logging.debug(f"Error checking channel {channel_name} ({url}): {e}")
        return None, False

def process_single_channel_line(channel_line, url_states):
    """处理单个频道行以进行有效性检查。"""
    if "://" not in channel_line:
        logging.debug(f"Skipping invalid channel line (no protocol): {channel_line}")
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG.get('channel_check_workers', 200)):
    """使用多线程检查频道有效性。"""
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"Starting multithreaded channel validity and speed detection for {total_channels} channels...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines}
        for i, future in enumerate(as_completed(futures)):
            checked_count += 1
            if checked_count % 100 == 0:
                logging.warning(f"Checked {checked_count}/{total_channels} channels...")
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"Exception occurred during channel line processing: {exc}")
    return results

# --- 文件合并和排序函数 ---
def generate_update_time_header():
    """为文件顶部生成更新时间信息。"""
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    """对频道进行分组并限制每个频道名称下的 URL 数量。"""
    grouped_channels = {}
    for line_content in lines:
        line_content = line_content.strip()
        if line_content:
            channel_name = line_content.split(',', 1)[0].strip()
            if channel_name not in grouped_channels:
                grouped_channels[channel_name] = []
            grouped_channels[channel_name].append(line_content)
    
    final_grouped_lines = []
    for channel_name in grouped_channels:
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            final_grouped_lines.append(ch_line + '\n')
    return final_grouped_lines

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt", url_states=None):
    """合并本地生成的频道列表文件，进行去重和基于 url_states 的清理。"""
    os.makedirs(local_channels_directory, exist_ok=True)

    existing_channels_data = []
    if os.path.exists(output_file_name):
        with open(output_file_name, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line and '#genre#' not in line:
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        existing_channels_data.append((parts[0].strip(), parts[1].strip()))

    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    
    uncategorized_file_in_root = "uncategorized_iptv.txt"
    if os.path.exists(uncategorized_file_in_root):
        all_iptv_files_in_dir.append(uncategorized_file_in_root)

    files_to_merge_paths = []
    processed_files = set()

    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        temp_path = os.path.join(local_channels_directory, file_name)
        root_path = file_name
        
        if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files:
            files_to_merge_paths.append(temp_path)
            processed_files.add(os.path.basename(temp_path))
        elif category == 'uncategorized' and os.path.basename(root_path) in all_iptv_files_in_dir and root_path not in processed_files:
             files_to_merge_paths.append(root_path)
             processed_files.add(os.path.basename(root_path))

    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
            if os.path.basename(file_name) == uncategorized_file_in_root:
                files_to_merge_paths.append(uncategorized_file_in_root)
            else:
                files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    new_channels_from_merged_files = set()
    for file_path in files_to_merge_paths:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                continue
            for line in lines:
                line = line.strip()
                if line and ',' in line and '#genre#' not in line:
                    name, url = line.split(',', 1)
                    new_channels_from_merged_files.add((name.strip(), url.strip()))

    combined_channels = existing_channels_data + list(new_channels_from_merged_files)
    final_channels_for_output = set()
    channels_for_checking = []

    unique_channels_to_check = set()
    for name, url in combined_channels:
        unique_channels_to_check.add((name, url))

    channels_for_checking_lines = [f"{name},{url}" for name, url in unique_channels_to_check]
    logging.warning(f"Total unique channels to check and filter for {output_file_name}: {len(channels_for_checking_lines)}")

    valid_channels_from_check = check_channels_multithreaded(channels_for_checking_lines, url_states)

    for elapsed_time, channel_line in valid_channels_from_check:
        name, url = channel_line.split(',', 1)
        url = url.strip()
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        if fail_count <= CHANNEL_FAIL_THRESHOLD:
            final_channels_for_output.add((name, url))
        else:
            logging.info(f"Removing channel '{name},{url}' from {output_file_name} due to excessive failures ({fail_count} > {CHANNEL_FAIL_THRESHOLD}).")

    sorted_final_channels = sorted(list(final_channels_for_output), key=lambda x: x[0])

    try:
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(generate_update_time_header())
            for name, url in sorted_final_channels:
                iptv_list_file.write(f"{name},{url}\n")
        logging.warning(f"\nAll regional channel list files merged, deduplicated, and cleaned. Output saved to: {output_file_name}")
    except Exception as e:
        logging.error(f"Error appending write to file '{output_file_name}': {e}")

# --- 远程 TXT 文件操作函数 ---
def read_txt_to_array_local(file_path):
    """从本地 TXT 文件读取内容到数组。"""
    return read_txt_to_array_local(file_path)

def write_array_to_txt_local(file_path, data_array, commit_message=None):
    """将数组内容写入本地 TXT 文件。"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write('\n'.join(data_array))
        logging.debug(f"Written {len(data_array)} lines to '{file_path}'.")
    except Exception as e:
        logging.error(f"Failed to write data to '{file_path}': {e}")

# --- GitHub URL 自动发现函数 ---
def auto_discover_github_urls(urls_file_path_local, github_token):
    """从 GitHub 自动发现新的 IPTV 源 URL，并记录每个关键字的 URL 计数。"""
    if not github_token:
        logging.warning("GitHub token not provided. Skipping GitHub URL auto-discovery.")
        return

    existing_urls = set(read_txt_to_array_local(urls_file_path_local))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.warning("Starting automatic discovery of new IPTV source URLs from GitHub...")
    keyword_url_counts = {keyword: 0 for keyword in SEARCH_KEYWORDS}

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        keyword_found_urls = set()
        if i > 0:
            logging.warning(f"Switching to next keyword: '{keyword}'. Waiting {GITHUB_API_RETRY_WAIT} seconds to avoid rate limits...")
            time.sleep(GITHUB_API_RETRY_WAIT)

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
                rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

                if rate_limit_remaining == 0:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API rate limit reached! Remaining requests: 0. Waiting {wait_seconds:.0f} seconds before retrying.")
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    logging.debug(f"No more results found on page {page} for keyword '{keyword}'.")
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    raw_url = None
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user = match.group(1)
                        repo = match.group(2)
                        branch = match.group(3)
                        file_path = match.group(4)
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}"
                    else:
                        logging.debug(f"Could not parse raw URL from html_url: {html_url}")
                        continue

                    if raw_url and raw_url not in existing_urls and raw_url not in found_urls:
                        try:
                            content_response = session.get(raw_url, timeout=5)
                            content_response.raise_for_status()
                            content = content_response.text
                            if re.search(r'#EXTM3U', content, re.IGNORECASE) or re.search(r'\.(m3u8|m3u)$', raw_url, re.IGNORECASE):
                                found_urls.add(raw_url)
                                keyword_found_urls.add(raw_url)
                                logging.debug(f"Found new IPTV source URL: {raw_url}")
                            else:
                                logging.debug(f"URL {raw_url} does not contain M3U content and is not an M3U file extension. Skipping.")
                        except requests.exceptions.RequestException as req_e:
                            logging.debug(f"Error fetching raw content for {raw_url}: {req_e}")
                        except Exception as exc:
                            logging.debug(f"Unexpected error during content check for {raw_url}: {exc}")

                logging.debug(f"Finished page {page} for keyword '{keyword}'. Found {len(keyword_found_urls)} new URLs.")
                page += 1

            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                    logging.error(f"GitHub API rate limit exceeded or access forbidden for keyword '{keyword}'. Error: {e}")
                    rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                    rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
                    if rate_limit_remaining == 0:
                        wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                        logging.warning(f"Rate limit hit for keyword '{keyword}'. Waiting {wait_seconds:.0f} seconds.")
                        time.sleep(wait_seconds)
                        continue
                else:
                    logging.error(f"Error searching GitHub for keyword '{keyword}': {e}")
                break
            except Exception as e:
                logging.error(f"An unexpected error occurred during GitHub search for keyword '{keyword}': {e}")
                break
        keyword_url_counts[keyword] = len(keyword_found_urls)

    if found_urls:
        updated_urls = sorted(list(existing_urls | found_urls))
        logging.warning(f"Discovered {len(found_urls)} new unique URLs. Total URLs to save: {len(updated_urls)}.")
        write_array_to_txt_local(urls_file_path_local, updated_urls)
    else:
        logging.warning("No new IPTV source URLs discovered.")

    for keyword, count in keyword_url_counts.items():
        logging.warning(f"Keyword '{keyword}' discovered {count} new URLs.")

# --- URL 清理函数 ---
def cleanup_urls_local(urls_file_path_local, url_states):
    """根据 URL_FAIL_THRESHOLD 和 URL_RETENTION_HOURS 清理本地 urls.txt 中的无效/失败 URL。"""
    all_urls = read_txt_to_array_local(urls_file_path_local)
    current_time = datetime.now()
    urls_to_keep = []
    removed_count = 0

    for url in all_urls:
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        last_failed_time_str = state.get('stream_check_failed_at')
        remove_url = False

        if fail_count > URL_FAIL_THRESHOLD:
            if last_failed_time_str:
                try:
                    last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
                    if (current_time - last_failed_datetime).total_seconds() / 3600 > URL_RETENTION_HOURS:
                        remove_url = True
                        logging.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) and retention period ({URL_RETENTION_HOURS}h) exceeded.")
                except ValueError:
                    logging.warning(f"Could not parse last_failed timestamp for URL {url}: {last_failed_time_str}, keeping it for now.")
            else:
                remove_url = True
                logging.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) with no last_failed_at timestamp.")

        if not remove_url:
            urls_to_keep.append(url)
        else:
            removed_count += 1
            url_states.pop(url, None)

    if removed_count > 0:
        logging.warning(f"Cleaned up {removed_count} URLs from {urls_file_path_local}.")
        write_array_to_txt_local(urls_file_path_local, urls_to_keep)
    else:
        logging.warning("No URLs needed cleanup from urls.txt.")

# --- 分类和文件保存函数 ---
def categorize_channels(channels):
    """根据频道名称关键字对频道进行分类。"""
    categorized_data = {category: [] for category in ORDERED_CATEGORIES}
    uncategorized_data = []

    for name, url in channels:
        found_category = False
        for category in ORDERED_CATEGORIES:
            category_keywords = CONFIG.get('category_keywords', {}).get(category, [])
            if any(keyword.lower() in name.lower() for keyword in category_keywords):
                categorized_data[category].append((name, url))
                found_category = True
                break
        if not found_category:
            uncategorized_data.append((name, url))
    return categorized_data, uncategorized_data

def process_and_save_channels_by_category(all_channels, url_states):
    """将频道分类并保存到对应的分类文件中。"""
    categorized_channels, uncategorized_channels = categorize_channels(all_channels)
    
    categorized_dir = "temp_channels"
    os.makedirs(categorized_dir, exist_ok=True)

    for category, channels in categorized_channels.items():
        output_file = os.path.join(categorized_dir, f"{category}_iptv.txt")
        logging.warning(f"Processing category: {category} with {len(channels)} channels.")
        sorted_channels = sorted(channels, key=lambda x: x[0])
        channels_to_write = [(0, f"{name},{url}") for name, url in sorted_channels]
        write_sorted_channels_to_file(output_file, channels_to_write)
    
    output_uncategorized_file = "uncategorized_iptv.txt"  # 保存到根目录
    logging.warning(f"Processing uncategorized channels: {len(uncategorized_channels)} channels.")
    sorted_uncategorized = sorted(uncategorized_channels, key=lambda x: x[0])
    uncategorized_to_write = [(0, f"{name},{url}") for name, url in sorted_uncategorized]
    write_sorted_channels_to_file(output_uncategorized_file, uncategorized_to_write)
    logging.warning(f"Uncategorized channels saved to: {output_uncategorized_file}")

# --- 主逻辑 ---
def main():
    logging.warning("Starting IPTV processing script...")

    # 步骤 1：加载 URL 状态（包括清理过期状态）
    url_states = load_url_states_local()
    logging.warning(f"Loaded {len(url_states)} URL states.")

    # 步骤 2：从 GitHub 自动发现新 URL
    auto_discover_github_urls(URLS_PATH, GITHUB_TOKEN)

    # 步骤 3：根据 URL_FAIL_THRESHOLD 和 URL_RETENTION_HOURS 清理 urls.txt
    cleanup_urls_local(URLS_PATH, url_states)

    # 步骤 4：从本地 urls.txt 加载 URL
    urls = read_txt_to_array_local(URLS_PATH)
    if not urls:
        logging.error("No URLs found in urls.txt. Exiting.")
        exit(1)
    logging.warning(f"Loaded {len(urls)} URLs from '{URLS_PATH}'.")

    # 步骤 5：使用多线程从所有 URL 获取内容并提取频道
    all_extracted_channels = []
    logging.warning(f"Starting channel extraction from {len(urls)} URLs...")
    with ThreadPoolExecutor(max_workers=CONFIG.get('url_fetch_workers', 50)) as executor:
        futures = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls}
        for i, future in enumerate(as_completed(futures)):
            if (i + 1) % 10 == 0:
                logging.warning(f"Processed {i + 1}/{len(urls)} URLs for channel extraction.")
            try:
                channels = future.result()
                if channels:
                    all_extracted_channels.extend(channels)
            except Exception as exc:
                logging.error(f"URL extraction generated an exception: {exc}")
    logging.warning(f"Finished channel extraction. Total channels extracted before filtering: {len(all_extracted_channels)}.")

    # 步骤 6：过滤和修改提取的频道
    filtered_and_modified_channels = filter_and_modify_channels(all_extracted_channels)
    logging.warning(f"Total channels after filtering and modification: {len(filtered_and_modified_channels)}.")
    
    # 步骤 7：将频道分类并保存到临时分类文件
    process_and_save_channels_by_category(filtered_and_modified_channels, url_states)

    # 步骤 8：合并本地频道文件，进行最终验证并基于 url_states 清理
    merge_local_channel_files("temp_channels", IPTV_LIST_PATH, url_states)

    # 步骤 9：再次保存所有频道检查状态
    save_url_states_local(url_states)
    logging.warning("Final channel check states saved to local.")

    # 步骤 10：清理临时文件
    try:
        if os.path.exists('iptv.txt'):
            os.remove('iptv.txt')
            logging.debug(f"Removed temporary file 'iptv.txt'.")
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.debug(f"Removed temporary file 'iptv_speed.txt'.")
        temp_dir = "temp_channels"
        if os.path.exists(temp_dir):
            for f_name in os.listdir(temp_dir):
                if f_name.endswith('_iptv.txt'):
                    os.remove(os.path.join(temp_dir, f_name))
                    logging.debug(f"Removed temporary channel file '{f_name}'.")
            if not os.listdir(temp_dir):
                os.rmdir(temp_dir)
                logging.debug(f"Removed empty directory '{temp_dir}'.")
        if os.path.exists('uncategorized_iptv.txt'):
            os.remove('uncategorized_iptv.txt')
            logging.debug(f"Removed 'uncategorized_iptv.txt' from root directory.")

    except Exception as e:
        logging.error(f"Error during temporary file cleanup: {e}")

    logging.warning("IPTV processing script finished.")

if __name__ == "__main__":
    main()
