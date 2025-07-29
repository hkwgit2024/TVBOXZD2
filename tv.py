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

# 配置日志记录
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 从环境变量获取配置
# Get configuration from environment variables
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')
IPTV_LIST_PATH = "iptv_list.txt" # 定义iptv_list.txt的路径 # Define the path for iptv_list.txt

# 检查环境变量是否已设置
# Check if environment variables are set
if not GITHUB_TOKEN:
    logging.error("错误：环境变量 'BOT' 未设置。") # Error: Environment variable 'BOT' not set.
    exit(1)
if not REPO_OWNER:
    logging.error("错误：环境变量 'REPO_OWNER' 未设置。") # Error: Environment variable 'REPO_OWNER' not set.
    exit(1)
if not REPO_NAME:
    logging.error("错误：环境变量 'REPO_NAME' 未设置。") # Error: Environment variable 'REPO_NAME' not set.
    exit(1)
if not CONFIG_PATH_IN_REPO:
    logging.error("错误：环境变量 'CONFIG_PATH' 未设置。") # Error: Environment variable 'CONFIG_PATH' not set.
    exit(1)
if not URLS_PATH_IN_REPO:
    logging.error("错误：环境变量 'URLS_PATH' 未设置。") # Error: Environment variable 'URLS_PATH' not set.
    exit(1)
if not URL_STATES_PATH_IN_REPO:
    logging.error("错误：环境变量 'URL_STATES_PATH' 未设置。") # Error: Environment variable 'URL_STATES_PATH' not set.
    exit(1)

# GitHub 仓库基础URL
# GitHub repository base URLs
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# --- GitHub 文件操作函数 ---
# --- GitHub file operations functions ---
def fetch_from_github(file_path_in_repo):
    """从 GitHub 仓库获取文件内容。""" # Fetch file content from GitHub repository.
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"从 GitHub 获取 {file_path_in_repo} 时出错: {e}") # Error fetching {file_path_in_repo} from GitHub: {e}
        return None

def get_current_sha(file_path_in_repo):
    """获取 GitHub 仓库中文件的当前 SHA。""" # Get the current SHA of a file in the GitHub repository.
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"获取 {file_path_in_repo} 的 SHA 时出错 (可能不存在): {e}") # Error getting SHA for {file_path_in_repo} (might not exist): {e}
        return None

def save_to_github(file_path_in_repo, content, commit_message):
    """将内容保存（创建或更新）到 GitHub 仓库。""" # Save (create or update) content to GitHub repository.
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
        logging.error(f"保存 {file_path_in_repo} 到 GitHub 时出错: {e}") # Error saving {file_path_in_repo} to GitHub: {e}
        logging.error(f"GitHub API 响应: {response.text if 'response' in locals() else 'N/A'}") # GitHub API response: {response.text if 'response' in locals() else 'N/A'}
        return False

def load_config():
    """从 GitHub 仓库加载并解析 YAML 配置文件。""" # Load and parse YAML configuration file from GitHub repository.
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"错误：远程配置文件 '{CONFIG_PATH_IN_REPO}' 中的 YAML 无效: {e}") # Error: Invalid YAML in remote config file '{CONFIG_PATH_IN_REPO}': {e}
            exit(1)
        except Exception as e:
            logging.error(f"加载远程配置文件 '{CONFIG_PATH_IN_REPO}' 时出错: {e}") # Error loading remote config file '{CONFIG_PATH_IN_REPO}': {e}
            exit(1)
    logging.error(f"无法从 GitHub 加载 '{CONFIG_PATH_IN_REPO}' 的配置。") # Could not load config from '{CONFIG_PATH_IN_REPO}' on GitHub.
    exit(1)

# 加载配置
# Load configuration
CONFIG = load_config()

# 从配置中获取参数
# Get parameters from configuration
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

# URL 和频道清理的新配置参数
# New configuration parameters for URL and channel cleanup
CHANNEL_FAIL_THRESHOLD = CONFIG.get('channel_fail_threshold', 5) # iptv_list.txt 中频道清理的阈值 # Threshold for channel cleanup in iptv_list.txt
URL_FAIL_THRESHOLD = CONFIG.get('url_fail_threshold', 5) # urls.txt 中 URL 清理的阈值 # Threshold for URL cleanup in urls.txt
URL_RETENTION_HOURS = CONFIG.get('url_retention_hours', 72) # urls.txt 中保留失败 URL 的小时数 # Hours to retain failed URLs in urls.txt

# 配置 requests 会话
# Configure requests session
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
# --- Local file operations functions ---
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组。""" # Read content from a local TXT file into an array.
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        lines = [line.strip() for line in lines if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到。") # File '{file_name}' not found.
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 时出错: {e}") # Error reading file '{file_name}': {e}
        return []

def read_existing_channels(file_path):
    """从文件中读取现有频道（名称、URL）组合进行去重。""" # Read existing channel (name, URL) combinations from a file for deduplication.
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
        pass  # 如果文件未找到，则返回空集合 # Return empty set if file not found
    except Exception as e:
        logging.error(f"读取文件 '{file_path}' 进行去重时出错: {e}") # Error reading file '{file_path}' for deduplication: {e}
    return existing_channels

def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道数据追加到文件，并进行去重。""" # Append sorted channel data to a file, with deduplication.
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
        logging.debug(f"已将 {len(all_channels - existing_channels)} 个新频道追加到 {file_path}") # Appended {len(all_channels - existing_channels)} new channels to {file_path}
    except Exception as e:
        logging.error(f"追加到文件 '{file_path}' 时出错: {e}") # Error appending to file '{file_path}': {e}

# --- URL 处理和频道提取函数 ---
# --- URL processing and channel extraction functions ---
def get_url_file_extension(url):
    """从 URL 获取文件扩展名。""" # Get the file extension from a URL.
    try:
        parsed_url = urlparse(url)
        extension = os.path.splitext(parsed_url.path)[1].lower()
        return extension
    except ValueError as e:
        logging.debug(f"获取 URL 扩展名失败: {url} - {e}") # Failed to get URL extension: {url} - {e}
        return ""

def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式内容转换为 TXT 格式（频道名称,URL）。""" # Convert M3U format content to TXT format (channel name,URL).
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
                channel_name = "未知频道" # Unknown Channel
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = ""
    return '\n'.join(txt_lines)

def clean_url_params(url):
    """清理 URL 参数，只保留方案、网络位置和路径。""" # Clean URL parameters, keeping only scheme, netloc, and path.
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.debug(f"清理 URL 参数失败: {url} - {e}") # Failed to clean URL parameters: {url} - {e}
        return url

# --- URL 状态管理函数 ---
# --- URL state management functions ---
def load_url_states_remote():
    """从远程加载 URL 状态 JSON 文件，并清理过期状态。""" # Load URL state JSON file from remote, and clean up expired states.
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    url_states = {}
    if content:
        try:
            url_states = json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"从远程 '{URL_STATES_PATH_IN_REPO}' 解码 JSON 时出错: {e}. 将从空状态开始。") # Error decoding JSON from remote '{URL_STATES_PATH_IN_REPO}': {e}. Starting with empty state.
            return {}
    
    # 清理过期状态
    # Clean up expired states
    current_time = datetime.now()
    updated_url_states = {}
    for url, state in url_states.items():
        if 'last_checked' in state:
            try:
                last_checked_datetime = datetime.fromisoformat(state['last_checked'])
                if (current_time - last_checked_datetime).days < URL_STATE_EXPIRATION_DAYS:
                    updated_url_states[url] = state
                else:
                    logging.debug(f"正在移除过期 URL 状态: {url} (上次检查时间 {state['last_checked']})") # Removing expired URL state: {url} (last checked on {state['last_checked']})
            except ValueError:
                logging.warning(f"无法解析 URL {url} 的 last_checked 时间戳: {state['last_checked']}, 正在保留其状态。") # Could not parse last_checked timestamp for URL {url}: {state['last_checked']}, keeping its state.
                updated_url_states[url] = state
        else: # 如果没有 last_checked，则暂时保留或根据其他标准决定 # If no last_checked, keep it for now or decide based on other criteria
            updated_url_states[url] = state
            
    return updated_url_states

def save_url_states_remote(url_states):
    """将 URL 状态保存到远程 JSON 文件。""" # Save URL states to remote JSON file.
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        success = save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态") # Update URL states
        if not success:
            logging.error(f"保存远程 URL 状态到 '{URL_STATES_PATH_IN_REPO}' 失败。") # Error saving remote URL states to '{URL_STATES_PATH_IN_REPO}'.
    except Exception as e:
        logging.error(f"保存 URL 状态到远程 '{URL_STATES_PATH_IN_REPO}' 时出错: {e}") # Error saving URL states to remote '{URL_STATES_PATH_IN_REPO}': {e}

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
    """尝试使用重试机制获取 URL 内容，并使用 ETag/Last-Modified/Content-Hash 避免重复下载。""" # Attempt to fetch URL content with retry mechanism, and use ETag/Last-Modified/Content-Hash to avoid re-download.
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
            logging.debug(f"URL 内容 {url} 未修改 (304)。跳过下载。") # URL content {url} not modified (304). Skipping download.
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL 内容 {url} 基于哈希值相同。跳过下载。") # URL content {url} is same based on hash. Skipping download.
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

        logging.debug(f"成功获取 URL 新内容: {url}。内容已更新。") # Successfully fetched new content for URL: {url}. Content updated.
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"获取 URL 时请求出错 (重试后): {url} - {e}") # Request error fetching URL (after retries): {url} - {e}
        return None
    except Exception as e:
        logging.error(f"获取 URL 时发生未知错误: {url} - {e}") # Unknown error fetching URL: {url} - {e}
        return None

def extract_channels_from_url(url, url_states):
    """从给定 URL 提取频道。""" # Extract channels from the given URL.
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
                    logging.debug(f"跳过无效频道行 (格式错误): {line}") # Skipping invalid channel line (malformed): {line}
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip()
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    logging.debug(f"跳过无效频道 URL (无有效协议): {line}") # Skipping invalid channel URL (no valid protocol): {line}
                    continue

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                            channel_count += 1
                        else:
                            logging.debug(f"跳过无效或预筛除的频道 URL: {channel_url}") # Skipping invalid or pre-screened channel URL: {channel_url}
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
                        channel_count += 1
                    else:
                        logging.debug(f"跳过无效或预筛除的频道 URL: {channel_url}") # Skipping invalid or pre-screened channel URL: {channel_url}
        logging.debug(f"成功从 URL 提取 {channel_count} 个频道: {url}。") # Successfully extracted {channel_count} channels from URL: {url}.
    except Exception as e:
        logging.error(f"从 {url} 提取频道时出错: {e}") # Error extracting channels from {url}: {e}
    return extracted_channels

def pre_screen_url(url):
    """根据配置对 URL 进行协议、长度和无效模式的预筛查。""" # Pre-screen URLs based on configuration for protocol, length, and invalid patterns.
    if not isinstance(url, str) or not url:
        logging.debug(f"预筛查已过滤 (无效类型或为空): {url}") # Pre-screening filtered (invalid type or empty): {url}
        return False

    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        logging.debug(f"预筛查已过滤 (无有效协议): {url}") # Pre-screening filtered (no valid protocol): {url}
        return False

    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        logging.debug(f"预筛查已过滤 (包含非法字符或空格): {url}") # Pre-screening filtered (contains illegal characters or spaces): {url}
        return False

    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
            logging.debug(f"预筛查已过滤 (不支持的协议): {url}") # Pre-screening filtered (unsupported protocol): {url}
            return False

        if not parsed_url.netloc:
            logging.debug(f"预筛查已过滤 (无网络位置): {url}") # Pre-screening filtered (no network location): {url}
            return False

        invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                logging.debug(f"预筛查已过滤 (无效模式): {url}") # Pre-screening filtered (invalid pattern): {url}
                return False

        if len(url) < 15:
            logging.debug(f"预筛查已过滤 (URL 过短): {url}") # Pre-screening filtered (URL too short): {url}
            return False

        return True
    except ValueError as e:
        logging.debug(f"预筛查已过滤 (URL 解析错误): {url} - {e}") # Pre-screening filtered (URL parse error): {url} - {e}
        return False

def filter_and_modify_channels(channels):
    """过滤和修改频道名称和 URL。""" # Filter and modify channel names and URLs.
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        if not pre_screen_url(url):
            logging.debug(f"正在过滤频道 (预筛查失败): {name},{url}") # Filtering channel (pre-screening failed): {name},{url}
            continue
        pre_screened_count += 1

        if any(word in url for word in CONFIG.get('url_filter_words', [])):
            logging.debug(f"正在过滤频道 (URL 匹配黑名单): {name},{url}") # Filtering channel (URL matches blacklist): {name},{url}
            continue

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            logging.debug(f"正在过滤频道 (名称匹配黑名单): {name},{url}") # Filtering channel (name matches blacklist): {name},{url}
            continue

        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    logging.debug(f"URL 预筛查后，还有 {pre_screened_count} 个频道待进一步过滤。") # After URL pre-screening, {pre_screened_count} channels remain for further filtering.
    return filtered_channels

# --- 频道有效性检查函数 ---
# --- Channel validity check functions ---
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达。""" # Check if HTTP/HTTPS URL is reachable.
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} 检查失败: {e}") # HTTP URL {url} check failed: {e}
        return False

def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达 (需要 ffprobe)。""" # Check if RTMP URL is reachable (requires ffprobe).
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("未找到或 ffprobe 无法工作。RTMP 流检查已跳过。") # ffprobe not found or not working. RTMP stream check skipped.
        return False
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} 检查超时") # RTMP URL {url} check timed out
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} 检查错误: {e}") # RTMP URL {url} check error: {e}
        return False

def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达 (通过尝试 UDP 连接)。""" # Check if RTP URL is reachable (by attempting UDP connection).
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.debug(f"RTP URL {url} 解析失败: 缺少主机或端口。") # RTP URL {url} parse failed: missing host or port.
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL {url} 检查失败: {e}") # RTP URL {url} check failed: {e}
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} 检查错误: {e}") # RTP URL {url} check error: {e}
        return False

def check_p3p_url(url, timeout):
    """检查 P3P URL 是否可达 (简单的 TCP 连接和 HTTP 响应头检查)。""" # Check if P3P URL is reachable (simple TCP connection and HTTP response header check).
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'

        if not host:
            logging.debug(f"P3P URL {url} 解析失败: 缺少主机。") # P3P URL {url} parse failed: missing host.
            return False

        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} 检查失败: {e}") # P3P URL {url} check failed: {e}
        return False

def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查单个频道的有效性和速度，并记录失败状态以便跳过。""" # Check single channel's validity and speed, and record failure status for skipping.
    current_time = datetime.now()
    current_url_state = url_states.get(url, {})

    if 'stream_check_failed_at' in current_url_state:
        last_failed_time_str = current_url_state['stream_check_failed_at']
        try:
            last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
            if time_since_failed_hours < STREAM_SKIP_FAILED_HOURS:
                logging.debug(f"跳过频道 {channel_name} ({url})，因为它在冷却期 ({STREAM_SKIP_FAILED_HOURS}小时) 内失败。上次失败时间：{last_failed_time_str}，距今 {time_since_failed_hours:.2f} 小时。") # Skipping channel {channel_name} ({url}) as it failed within cooldown period ({STREAM_SKIP_FAILED_HOURS}h). Last failed at {last_failed_time_str}, {time_since_failed_hours:.2f}h ago.
                return None, False
        except ValueError:
            logging.warning(f"无法解析 URL {url} 的失败时间戳: {last_failed_time_str}") # Could not parse failed timestamp for URL {url}: {last_failed_time_str}
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
            logging.debug(f"频道 {channel_name} 的协议不受支持: {url}") # Channel {channel_name}'s protocol is not supported: {url}
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
            logging.debug(f"频道 {channel_name} ({url}) 检查成功，耗时 {elapsed_time:.0f} 毫秒。") # Channel {channel_name} ({url}) check successful, took {elapsed_time:.0f} ms.
            return elapsed_time, True
        else:
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.debug(f"频道 {channel_name} ({url}) 检查失败。") # Channel {channel_name} ({url}) check failed.
            return None, False
    except Exception as e:
        if url not in url_states:
            url_states[url] = {}
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
        url_states[url]['last_stream_checked'] = current_time.isoformat()
        logging.debug(f"检查频道 {channel_name} ({url}) 时出错: {e}") # Error checking channel {channel_name} ({url}): {e}
        return None, False

def process_single_channel_line(channel_line, url_states):
    """处理单行频道进行有效性检查。""" # Process a single channel line for validity check.
    if "://" not in channel_line:
        logging.debug(f"跳过无效频道行 (无协议): {channel_line}") # Skipping invalid channel line (no protocol): {channel_line}
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
    """使用多线程检查频道有效性。""" # Check channel validity using multithreading.
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"正在启动 {total_channels} 个频道的并行有效性与速度检测...") # Starting multithreaded channel validity and speed detection for {total_channels} channels...
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines}
        for i, future in enumerate(as_completed(futures)):
            checked_count += 1
            if checked_count % 100 == 0:
                logging.warning(f"已检查 {checked_count}/{total_channels} 个频道...") # Checked {checked_count}/{total_channels} channels...
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"处理频道行时发生异常: {exc}") # Exception occurred during channel line processing: {exc}
    return results

# --- 文件合并和排序函数 ---
# --- File merge and sort functions ---
def generate_update_time_header():
    """为文件顶部生成更新时间信息。""" # Generate update time information for the top of the file.
    now = datetime.now()
    return [
        f"更新时间,#genre#\n", # Update Time
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    """分组频道并限制每个频道名称下的 URL 数量。""" # Group channels and limit the number of URLs under each channel name.
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
    """合并本地生成的频道列表文件，并根据 url_states 进行去重和清理。""" # Merge locally generated channel list files, with deduplication and cleanup based on url_states.
    # 确保 local_channels_directory 存在
    # Ensure the local_channels_directory exists
    os.makedirs(local_channels_directory, exist_ok=True) # Added this line to fix FileNotFoundError

    existing_channels_data = [] # 存储当前 iptv_list.txt 中频道的 (名称, URL) # To store (name, url) for channels from current iptv_list.txt
    # 读取现有的 iptv_list.txt 频道
    # Read existing iptv_list.txt channels
    if os.path.exists(output_file_name):
        with open(output_file_name, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line and '#genre#' not in line:
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        existing_channels_data.append((parts[0].strip(), parts[1].strip()))

    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    
    # 修改：也包括根目录下的 uncategorized_iptv.txt
    # MODIFICATION: Also include the uncategorized_iptv.txt from the root directory
    uncategorized_file_in_root = "uncategorized_iptv.txt"
    if os.path.exists(uncategorized_file_in_root):
        all_iptv_files_in_dir.append(uncategorized_file_in_root)

    files_to_merge_paths = []
    processed_files = set()

    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        # 检查 temp_channels 和根目录（用于 'uncategorized'）
        # Check both in temp_channels and root (for 'uncategorized')
        temp_path = os.path.join(local_channels_directory, file_name)
        root_path = file_name # For 'uncategorized_iptv.txt'
        
        if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files:
            files_to_merge_paths.append(temp_path)
            processed_files.add(os.path.basename(temp_path))
        elif category == 'uncategorized' and os.path.basename(root_path) in all_iptv_files_in_dir and root_path not in processed_files:
            files_to_merge_paths.append(root_path)
            processed_files.add(os.path.basename(root_path))
    
    for file_name in sorted(all_iptv_files_in_dir): # 现在 `all_iptv_files_in_dir` 包含完整路径或根目录的文件名
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

    # 合并现有频道和新频道
    # Combine existing and new channels
    combined_channels = existing_channels_data + list(new_channels_from_merged_files)

    # 根据 stream_fail_count 进行去重和过滤
    # Deduplicate and filter based on stream_fail_count
    final_channels_for_output = set()
    channels_for_checking = [] # 将被检查有效性的频道 # Channels that will be checked for validity

    # 首先，将所有频道（新旧）添加到列表中进行检查
    # First, add all channels (new and existing) to a list for checking
    # 我们使用集合来避免多次处理重复的（名称，URL）组合以进行唯一性检查
    # We use a set to avoid processing duplicate (name, url) combinations multiple times for checking unique_channels_to_check
    unique_channels_to_check = set()
    for name, url in combined_channels:
        unique_channels_to_check.add((name, url))

    # 转换为字符串列表以进行多线程检查
    # Convert to list of strings for multithreaded checking
    channels_for_checking_lines = [f"{name},{url}" for name, url in unique_channels_to_check]
    logging.warning(f"要检查和过滤 {output_file_name} 的唯一频道总数: {len(channels_for_checking_lines)}") # Total unique channels to check and filter for {output_file_name}: {len(channels_for_checking_lines)}

    # 对所有合并后的唯一频道执行有效性检查
    # Perform validity check on all combined unique channels
    # check_channels_multithreaded 函数将更新这些 URL 的 url_states
    # The check_channels_multithreaded function will update url_states for these URLs
    # 并只返回当前有效的。
    # and return only the currently valid ones.
    valid_channels_from_check = check_channels_multithreaded(channels_for_checking_lines, url_states)

    # 现在，根据更新后的 url_states 和 CHANNEL_FAIL_THRESHOLD 进行过滤
    # Now, filter based on updated url_states and CHANNEL_FAIL_THRESHOLD
    for elapsed_time, channel_line in valid_channels_from_check:
        name, url = channel_line.split(',', 1)
        url = url.strip()
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        if fail_count <= CHANNEL_FAIL_THRESHOLD:
            final_channels_for_output.add((name, url))
        else:
            logging.info(f"由于失败次数过多 ({fail_count} > {CHANNEL_FAIL_THRESHOLD})，正在从 {output_file_name} 中移除频道 '{name},{url}'。") # Removing channel '{name},{url}' from {output_file_name} due to excessive failures ({fail_count} > {CHANNEL_FAIL_THRESHOLD}).

    # 在写入之前对所有频道进行排序，以确保输出一致
    # Sort all_channels before writing to ensure consistent output
    sorted_final_channels = sorted(list(final_channels_for_output), key=lambda x: x[0])

    # 重写整个文件而不是追加，以确保顺序和整洁
    # Rewrite the entire file instead of appending, to ensure order and cleanliness
    try:
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(generate_update_time_header())
            for name, url in sorted_final_channels:
                iptv_list_file.write(f"{name},{url}\n")
        logging.warning(f"\n所有区域频道列表文件已合并、去重和清理。输出已保存到: {output_file_name}") # All regional channel list files merged, deduplicated, and cleaned. Output saved to: {output_file_name}
    except Exception as e:
        logging.error(f"追加写入文件 '{output_file_name}' 时出错: {e}") # Error appending write to file '{output_file_name}': {e}

# --- 远程 TXT 文件操作函数 ---
# --- Remote TXT file operations functions ---
def read_txt_to_array_remote(file_path_in_repo):
    """从远程 GitHub 仓库 TXT 文件读取内容到数组。""" # Read content from a remote GitHub repository TXT file into an array.
    content = fetch_from_github(file_path_in_repo)
    if content:
        lines = content.split('\n')
        return [line.strip() for line in lines if line.strip()]
    return []

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message):
    """将数组内容写入远程 GitHub 仓库 TXT 文件。""" # Write array content to a remote GitHub repository TXT file.
    content = '\n'.join(data_array)
    success = save_to_github(file_path_in_repo, content, commit_message)
    if not success:
        logging.error(f"写入数据到远程 '{file_path_in_repo}' 失败。") # Failed to write data to remote '{file_path_in_repo}'.

# --- GitHub URL 自动发现函数 ---
# --- GitHub URL auto-discovery function ---
def auto_discover_github_urls(urls_file_path_remote, github_token):
    """自动从 GitHub 发现新的 IPTV 源 URL，并记录每个关键字的 URL 计数。""" # Automatically discover new IPTV source URLs from GitHub, and record URL counts per keyword.
    if not github_token:
        logging.warning("环境变量 'BOT' 未设置。跳过 GitHub URL 自动发现。") # Environment variable 'BOT' not set. Skipping GitHub URL auto-discovery.
        return

    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.warning("正在启动从 GitHub 自动发现新的 IPTV 源 URL...") # Starting automatic discovery of new IPTV source URLs from GitHub...
    keyword_url_counts = {keyword: 0 for keyword in SEARCH_KEYWORDS}

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        keyword_found_urls = set()
        if i > 0:
            logging.warning(f"正在切换到下一个关键字: '{keyword}'。等待 {GITHUB_API_RETRY_WAIT} 秒以避免速率限制...") # Switching to next keyword: '{keyword}'. Waiting {GITHUB_API_RETRY_WAIT} seconds to avoid rate limits...
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
                    logging.warning(f"GitHub API 速率限制已达到！剩余请求: 0。等待 {wait_seconds:.0f} 秒后重试。") # GitHub API rate limit reached! Remaining requests: 0. Waiting {wait_seconds:.0f} seconds before retrying.
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    logging.debug(f"关键字 '{keyword}' 在第 {page} 页没有找到更多结果。") # No more results found on page {page} for keyword '{keyword}'.
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
                        logging.debug(f"无法从 html_url 解析原始 URL: {html_url}") # Could not parse raw URL from html_url: {html_url}
                        continue

                    if raw_url and raw_url not in existing_urls and raw_url not in found_urls:
                        # 检查内容是否包含 .m3u 或 .m3u8 模式
                        # Check content for .m3u or .m3u8 patterns
                        content_check_success = False
                        try:
                            content_response = session.get(raw_url, timeout=5)
                            content_response.raise_for_status()
                            content = content_response.text
                            if re.search(r'#EXTM3U', content, re.IGNORECASE) or re.search(r'\.(m3u8|m3u)$', raw_url, re.IGNORECASE):
                                found_urls.add(raw_url)
                                keyword_found_urls.add(raw_url)
                                logging.debug(f"发现新的 IPTV 源 URL: {raw_url}") # Found new IPTV source URL: {raw_url}
                                content_check_success = True
                            else:
                                logging.debug(f"URL {raw_url} 不包含 M3U 内容且不是 M3U 文件扩展名。跳过。") # URL {raw_url} does not contain M3U content and is not an M3U file extension. Skipping.
                        except requests.exceptions.RequestException as req_e:
                            logging.debug(f"获取 {raw_url} 的原始内容时出错: {req_e}") # Error fetching raw content for {raw_url}: {req_e}
                        except Exception as exc:
                            logging.debug(f"检查 {raw_url} 内容时发生意外错误: {exc}") # Unexpected error during content check for {raw_url}: {exc}
                logging.debug(f"关键字 '{keyword}' 的第 {page} 页完成。发现 {len(keyword_found_urls)} 个新 URL。") # Finished page {page} for keyword '{keyword}'. Found {len(keyword_found_urls)} new URLs.
                page += 1

            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                    logging.error(f"GitHub API 速率限制超出或关键字 '{keyword}' 访问被禁止。错误: {e}") # GitHub API rate limit exceeded or access forbidden for keyword '{keyword}'. Error: {e}
                    # 尝试解析速率限制头以等待（如果可能）
                    # Attempt to parse rate limit headers to wait if possible
                    rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                    rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
                    if rate_limit_remaining == 0:
                        wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                        logging.warning(f"关键字 '{keyword}' 达到速率限制。等待 {wait_seconds:.0f} 秒。") # Rate limit hit for keyword '{keyword}'. Waiting {wait_seconds:.0f} seconds.
                        time.sleep(wait_seconds)
                        continue # 等待后重试当前页面 # Retry current page after wait
                else:
                    logging.error(f"搜索 GitHub 关键字 '{keyword}' 时出错: {e}") # Error searching GitHub for keyword '{keyword}': {e}
                break # 其他错误时退出当前关键字循环 # Exit loop for current keyword on other errors
            except Exception as e:
                logging.error(f"在 GitHub 搜索关键字 '{keyword}' 时发生意外错误: {e}") # An unexpected error occurred during GitHub search for keyword '{keyword}': {e}
                break # 意外错误时退出当前关键字循环 # Exit loop for current keyword on unexpected errors

        keyword_url_counts[keyword] = len(keyword_found_urls)

    if found_urls:
        updated_urls = sorted(list(existing_urls | found_urls))
        logging.warning(f"在所有关键字中发现 {len(found_urls)} 个新 URL。总共有 {len(updated_urls)} 个 URL。") # Found {len(found_urls)} new URLs across all keywords. Total {len(updated_urls)} URLs.
        save_to_github(urls_file_path_remote, '\n'.join(updated_urls), "自动发现并添加新的 IPTV URL") # Auto-discovered and added new IPTV URLs
    else:
        logging.warning("未发现新的 IPTV 源 URL。") # No new IPTV source URLs found.

    logging.warning("GitHub URL 自动发现完成。") # GitHub URL auto-discovery completed.
    for keyword, count in keyword_url_counts.items():
        logging.warning(f"关键字 '{keyword}' 发现 {count} 个新 URL。") # Keyword '{keyword}' found {count} new URLs.

# --- 主 URL 处理和频道合并逻辑 ---
# --- Main URL processing and channel merging logic ---
def process_urls_and_merge_channels(urls_path_in_repo, url_states_path_in_repo, iptv_list_path):
    """处理远程 URL，提取频道，并合并到主 IPTV 列表。""" # Process remote URLs, extract channels, and merge into main IPTV list.
    url_states = load_url_states_remote()
    all_urls_to_process = read_txt_to_array_remote(urls_path_in_repo)
    
    # 清理 urls.txt 中的过期 URL
    # Clean up expired URLs in urls.txt
    cleaned_urls = []
    current_time = datetime.now()
    urls_removed_count = 0
    for url in all_urls_to_process:
        state = url_states.get(url, {})
        fail_count = state.get('fail_count', 0)
        last_failed_time_str = state.get('last_failed_at')

        if fail_count >= URL_FAIL_THRESHOLD and last_failed_time_str:
            try:
                last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
                time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
                if time_since_failed_hours >= URL_RETENTION_HOURS:
                    logging.info(f"由于多次失败 ({fail_count} 次) 且超出保留时间 ({URL_RETENTION_HOURS}h)，正在从 urls.txt 中移除 URL: {url}") # Removing URL: {url} from urls.txt due to multiple failures ({fail_count} times) and retention period exceeded ({URL_RETENTION_HOURS}h).
                    urls_removed_count += 1
                    # 从 url_states 中删除此 URL 的状态，因为它不再需要跟踪
                    # Delete state for this URL from url_states as it no longer needs to be tracked
                    url_states.pop(url, None) 
                    continue
            except ValueError:
                logging.warning(f"无法解析 URL {url} 的 last_failed_at 时间戳: {last_failed_time_str}") # Could not parse last_failed_at timestamp for URL {url}: {last_failed_time_str}
        cleaned_urls.append(url)
    
    if urls_removed_count > 0:
        logging.warning(f"已从 urls.txt 中移除 {urls_removed_count} 个过期 URL。") # Removed {urls_removed_count} expired URLs from urls.txt.
        write_array_to_txt_remote(urls_path_in_repo, sorted(list(set(cleaned_urls))), "清理 urls.txt 中的过期 URL") # Cleaned expired URLs in urls.txt

    urls_to_process = sorted(list(set(cleaned_urls))) # 确保唯一性并排序 # Ensure uniqueness and sort

    logging.warning(f"将处理 {len(urls_to_process)} 个 URL 以提取频道。") # Will process {len(urls_to_process)} URLs to extract channels.

    # 临时目录用于存储按类别分类的频道文件
    # Temporary directory for storing categorized channel files
    temp_channels_dir = "temp_channels"
    os.makedirs(temp_channels_dir, exist_ok=True) # 确保目录存在 # Ensure directory exists

    all_extracted_channels = []
    for url in urls_to_process:
        try:
            extracted_channels = extract_channels_from_url(url, url_states)
            if extracted_channels:
                filtered_channels = filter_and_modify_channels(extracted_channels)
                all_extracted_channels.extend(filtered_channels)
                
                # 更新 url_states 中的成功计数
                # Update success count in url_states
                if url not in url_states:
                    url_states[url] = {}
                url_states[url]['success_count'] = url_states[url].get('success_count', 0) + 1
                url_states[url]['fail_count'] = 0 # 重置失败计数 # Reset failure count
                url_states[url].pop('last_failed_at', None) # 移除上次失败时间 # Remove last failed time
            else:
                # 标记 URL 为失败
                # Mark URL as failed
                if url not in url_states:
                    url_states[url] = {}
                url_states[url]['fail_count'] = url_states[url].get('fail_count', 0) + 1
                url_states[url]['last_failed_at'] = current_time.isoformat()
                logging.debug(f"从 URL '{url}' 未提取到频道或提取失败，失败计数为 {url_states[url]['fail_count']}") # No channels extracted or extraction failed from URL '{url}', fail count is {url_states[url]['fail_count']}
        except Exception as e:
            # 捕获处理单个 URL 时的任何异常，并记录错误
            # Catch any exceptions during single URL processing and log the error
            logging.error(f"处理 URL '{url}' 时发生错误: {e}") # Error processing URL '{url}': {e}
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['fail_count'] = url_states[url].get('fail_count', 0) + 1
            url_states[url]['last_failed_at'] = current_time.isoformat()

    logging.warning(f"已从所有 URL 提取 {len(all_extracted_channels)} 个原始频道。") # Extracted {len(all_extracted_channels)} raw channels from all URLs.

    # 按照 ORDERED_CATEGORIES 顺序创建分类文件
    # Create categorized files based on ORDERED_CATEGORIES order
    categorized_channels = {category: [] for category in ORDERED_CATEGORIES}
    uncategorized_channels = []

    for name, url in all_extracted_channels:
        found_category = False
        for category in ORDERED_CATEGORIES:
            # 检查频道名称是否包含类别关键字（不区分大小写）
            # Check if channel name contains category keyword (case-insensitive)
            if category.lower() in name.lower():
                categorized_channels[category].append(f"{name},{url}")
                found_category = True
                break
        if not found_category:
            uncategorized_channels.append(f"{name},{url}")

    for category, channels in categorized_channels.items():
        if channels:
            output_file_path = os.path.join(temp_channels_dir, f"{category}_iptv.txt")
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(f"#{category},#genre#\n")
                for line in group_and_limit_channels(channels):
                    f.write(line)
            logging.warning(f"已为类别 '{category}' 创建文件: {output_file_path}，包含 {len(channels)} 个频道。") # Created file for category '{category}': {output_file_path}, with {len(channels)} channels.

    # 处理未分类的频道，写入根目录下的文件
    # Process uncategorized channels, write to a file in the root directory
    if uncategorized_channels:
        uncategorized_output_file = "uncategorized_iptv.txt"
        with open(uncategorized_output_file, 'w', encoding='utf-8') as f:
            f.write(f"#未分类,#genre#\n") # Uncategorized
            for line in group_and_limit_channels(uncategorized_channels):
                f.write(line)
        logging.warning(f"已创建未分类文件: {uncategorized_output_file}，包含 {len(uncategorized_channels)} 个频道。") # Created uncategorized file: {uncategorized_output_file}, with {len(uncategorized_channels)} channels.

    # 合并所有本地生成的频道文件到主 IPTV 列表
    # Merge all locally generated channel files into the main IPTV list
    merge_local_channel_files(temp_channels_dir, iptv_list_path, url_states)
    
    # 保存更新后的 URL 状态
    # Save updated URL states
    save_url_states_remote(url_states)

    logging.warning("所有频道处理完成。") # All channel processing completed.

# --- 清理函数 ---
# --- Cleanup functions ---
def cleanup_temp_files():
    """清理在处理过程中生成的临时文件和目录。""" # Clean up temporary files and directories created during processing.
    logging.warning("正在清理临时文件...") # Cleaning up temporary files...
    try:
        if os.path.exists('iptv.txt'): # 这个文件不是在当前脚本中生成的，可能是遗留的
            os.remove('iptv.txt')
            logging.debug(f"已移除临时文件 'iptv.txt'。") # Removed temporary file 'iptv.txt'.
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.debug(f"已移除临时文件 'iptv_speed.txt'。") # Removed temporary file 'iptv_speed.txt'.
        # 清理 temp_channels 目录中的 _iptv.txt 文件
        # Clean up _iptv.txt files in temp_channels directory
        temp_dir = "temp_channels"
        if os.path.exists(temp_dir):
            for f_name in os.listdir(temp_dir):
                if f_name.endswith('_iptv.txt'):
                    os.remove(os.path.join(temp_dir, f_name))
                    logging.debug(f"已移除临时频道文件 '{f_name}'。") # Removed temporary channel file '{f_name}'.
            # 如果目录为空，则可选地移除目录
            # Optionally remove the directory if it's empty
            if not os.listdir(temp_dir):
                os.rmdir(temp_dir)
                logging.debug(f"已移除空目录 '{temp_dir}'。") # Removed empty directory '{temp_dir}'.
        # --- 更正后的修改开始 ---
        # 也清理根目录中的 'uncategorized_iptv.txt'（如果已创建）
        # Also clean up the 'uncategorized_iptv.txt' from the root if it was created
        if os.path.exists('uncategorized_iptv.txt'): # 更正后的文件名 # Corrected file name
            os.remove('uncategorized_iptv.txt')
            logging.debug(f"已从根目录移除 'uncategorized_iptv.txt'。") # Removed 'uncategorized_iptv.txt' from root directory.
        # --- 更正后的修改结束 ---

    except Exception as e:
        logging.error(f"清理临时文件时出错: {e}") # Error cleaning up temporary files: {e}
    logging.warning("临时文件清理完成。") # Temporary file cleanup completed.

# --- 主执行流程 ---
# --- Main execution flow ---
if __name__ == "__main__":
    try:
        # 自动发现新的 URL
        # Auto-discover new URLs
        auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)
        
        # 处理 URL 并合并频道
        # Process URLs and merge channels
        process_urls_and_merge_channels(URLS_PATH_IN_REPO, URL_STATES_PATH_IN_REPO, IPTV_LIST_PATH)
        
    except Exception as e:
        logging.error(f"脚本执行过程中发生致命错误: {e}") # A fatal error occurred during script execution: {e}
    finally:
        cleanup_temp_files()
