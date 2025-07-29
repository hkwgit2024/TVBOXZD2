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
    [cite_start]raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}" [cite: 2]
    [cite_start]headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 2]
    try:
        [cite_start]response = requests.get(raw_url, headers=headers, timeout=10) [cite: 2]
        [cite_start]response.raise_for_status() [cite: 2]
        [cite_start]return response.text [cite: 2]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"Error fetching {file_path_in_repo} from GitHub: {e}") [cite: 2]
        [cite_start]return None [cite: 2]

def get_current_sha(file_path_in_repo):
    """获取 GitHub 仓库中文件的当前 SHA 值。"""
    [cite_start]api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 3]
    [cite_start]headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 3]
    try:
        [cite_start]response = requests.get(api_url, headers=headers, timeout=10) [cite: 3]
        [cite_start]response.raise_for_status() [cite: 3]
        [cite_start]return response.json().get('sha') [cite: 3]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.debug(f"Error getting SHA for {file_path_in_repo} (might not exist): {e}") [cite: 3]
        [cite_start]return None [cite: 3]

def save_to_github(file_path_in_repo, content, commit_message):
    """保存（创建或更新）内容到 GitHub 仓库。"""
    [cite_start]api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 3]
    [cite_start]sha = get_current_sha(file_path_in_repo) [cite: 3]
    
    headers = {
        [cite_start]"Authorization": f"token {GITHUB_TOKEN}", [cite: 4]
        [cite_start]"Content-Type": "application/json" [cite: 4]
    }
    
    [cite_start]encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8') [cite: 4]

    payload = {
        [cite_start]"message": commit_message, [cite: 4]
        [cite_start]"content": encoded_content, [cite: 4]
        [cite_start]"branch": "main" [cite: 4]
    }
    
    if sha:
        [cite_start]payload["sha"] = sha [cite: 4]
    
    try:
        [cite_start]response = requests.put(api_url, headers=headers, json=payload) [cite: 5]
        [cite_start]response.raise_for_status() [cite: 5]
        [cite_start]return True [cite: 5]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"Error saving {file_path_in_repo} to GitHub: {e}") [cite: 5]
        [cite_start]logging.error(f"GitHub API response: {response.text if 'response' in locals() else 'N/A'}") [cite: 5]
        [cite_start]return False [cite: 5]

def load_config():
    """从本地 config/config.yaml 加载并解析 YAML 配置文件。"""
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as file:
            [cite_start]return yaml.safe_load(file) [cite: 6]
    except FileNotFoundError:
        [cite_start]logging.error(f"Error: Config file '{CONFIG_PATH}' not found.") [cite: 6]
        [cite_start]exit(1) [cite: 6]
    except yaml.YAMLError as e:
        [cite_start]logging.error(f"Error: Invalid YAML in config file '{CONFIG_PATH}': {e}") [cite: 6]
        [cite_start]exit(1) [cite: 6]
    except Exception as e:
        [cite_start]logging.error(f"Error loading config file '{CONFIG_PATH}': {e}") [cite: 6]
        [cite_start]exit(1) [cite: 6]

# 加载配置
CONFIG = load_config()

# 从配置中获取参数
[cite_start]SEARCH_KEYWORDS = CONFIG.get('search_keywords', []) [cite: 6]
[cite_start]PER_PAGE = CONFIG.get('per_page', 100) [cite: 6]
[cite_start]MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5) [cite: 6]
[cite_start]GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20) [cite: 7]
[cite_start]GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 10) [cite: 7]
[cite_start]CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15) [cite: 7]
[cite_start]CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 6) [cite: 7]
[cite_start]MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200) [cite: 7]
[cite_start]NAME_FILTER_WORDS = CONFIG.get('name_filter_words', []) [cite: 7]
[cite_start]URL_FILTER_WORDS = CONFIG.get('url_filter_words', []) [cite: 7]
[cite_start]CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {}) [cite: 7]
[cite_start]ORDERED_CATEGORIES = CONFIG.get('ordered_categories', []) [cite: 7]
[cite_start]STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24) [cite: 7]
[cite_start]URL_STATE_EXPIRATION_DAYS = CONFIG.get('url_state_expiration_days', 90) [cite: 7]
[cite_start]CHANNEL_FAIL_THRESHOLD = CONFIG.get('channel_fail_threshold', 5) [cite: 7]
[cite_start]URL_FAIL_THRESHOLD = CONFIG.get('url_fail_threshold', 5) [cite: 7]
[cite_start]URL_RETENTION_HOURS = CONFIG.get('url_retention_hours', 72) [cite: 7]

# 配置 requests 会话
[cite_start]session = requests.Session() [cite: 7, 8]
[cite_start]session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"}) [cite: 8]
[cite_start]pool_size = CONFIG.get('requests_pool_size', 200) [cite: 8]
retry_strategy = Retry(
    [cite_start]total=CONFIG.get('requests_retry_total', 3), [cite: 8]
    [cite_start]backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1), [cite: 8]
    [cite_start]status_forcelist=[429, 500, 502, 503, 504], [cite: 8]
    [cite_start]allowed_methods=["HEAD", "GET", "OPTIONS"] [cite: 8]
)
[cite_start]adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy) [cite: 8]
[cite_start]session.mount("http://", adapter) [cite: 8]
[cite_start]session.mount("https://", adapter) [cite: 8]

# --- 本地文件操作函数 ---
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组。"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            [cite_start]lines = file.readlines() [cite: 8, 9]
        [cite_start]lines = [line.strip() for line in lines if line.strip()] [cite: 9]
        [cite_start]return lines [cite: 9]
    except FileNotFoundError:
        [cite_start]logging.warning(f"File '{file_name}' not found.") [cite: 9]
        [cite_start]return [] [cite: 9]
    except Exception as e:
        [cite_start]logging.error(f"Error reading file '{file_name}': {e}") [cite: 9]
        [cite_start]return [] [cite: 9]

def read_existing_channels(file_path):
    """从文件中读取现有的频道（名称，URL）组合以进行去重。"""
    [cite_start]existing_channels = set() [cite: 9]
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            [cite_start]for line in file: [cite: 10]
                [cite_start]line = line.strip() [cite: 10]
                [cite_start]if line and ',' in line and not line.startswith('#'): [cite: 10]
                    [cite_start]parts = line.split(',', 1) [cite: 10]
                    [cite_start]if len(parts) == 2: [cite: 10]
                        [cite_start]name, url = parts [cite: 11]
                        [cite_start]existing_channels.add((name.strip(), url.strip())) [cite: 11]
    except FileNotFoundError:
        [cite_start]pass [cite: 11]
    except Exception as e:
        [cite_start]logging.error(f"Error reading file '{file_path}' for deduplication: {e}") [cite: 11]
    [cite_start]return existing_channels [cite: 11]

def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道数据追加到文件，去重。"""
    [cite_start]existing_channels = read_existing_channels(file_path) [cite: 11]
    [cite_start]new_channels = set() [cite: 12]
    
    for _, line in data_list:
        if ',' in line:
            [cite_start]name, url = line.split(',', 1) [cite: 12]
            [cite_start]new_channels.add((name.strip(), url.strip())) [cite: 12]
    
    [cite_start]all_channels = existing_channels | new_channels [cite: 13]
    
    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            for name, url in all_channels:
                if (name, url) not in existing_channels:
                    [cite_start]file.write(f"{name},{url}\n") [cite: 13]
        [cite_start]logging.debug(f"Appended {len(all_channels - existing_channels)} new channels to {file_path}") [cite: 13]
    except Exception as e:
        [cite_start]logging.error(f"Error appending to file '{file_path}': {e}") [cite: 14]

# --- URL 处理和频道提取函数 ---
def get_url_file_extension(url):
    """从 URL 获取文件扩展名。"""
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 14]
        [cite_start]extension = os.path.splitext(parsed_url.path)[1].lower() [cite: 14]
        [cite_start]return extension [cite: 14]
    except ValueError as e:
        [cite_start]logging.debug(f"Failed to get URL extension: {url} - {e}") [cite: 14]
        [cite_start]return "" [cite: 14]

def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式内容转换为 TXT 格式（频道名称，URL）。"""
    [cite_start]lines = m3u_content.split('\n') [cite: 15]
    [cite_start]txt_lines = [] [cite: 15]
    [cite_start]channel_name = "未知频道" [cite: 15]
    for line in lines:
        [cite_start]line = line.strip() [cite: 15]
        [cite_start]if not line or line.startswith('#EXTM3U'): [cite: 15]
            [cite_start]continue [cite: 15]
        [cite_start]if line.startswith('#EXTINF'): [cite: 15]
            [cite_start]match = re.search(r'#EXTINF:.*?\,(.*)', line, re.IGNORECASE) [cite: 15]
            if match:
                [cite_start]channel_name = match.group(1).strip() or "未知频道" [cite: 16]
            else:
                [cite_start]channel_name = "未知频道" [cite: 16]
        [cite_start]elif re.match(r'^[a-zA-Z0-9+.-]+://', line) and not line.startswith('#'): [cite: 16]
            [cite_start]txt_lines.append(f"{channel_name},{line}") [cite: 16]
            [cite_start]channel_name = "未知频道" [cite: 16]
    [cite_start]return '\n'.join(txt_lines) [cite: 16]

def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径。"""
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 17]
        [cite_start]return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path [cite: 17]
    except ValueError as e:
        [cite_start]logging.debug(f"Failed to clean URL parameters: {url} - {e}") [cite: 17]
        [cite_start]return url [cite: 17]

def extract_channels_from_url(url, url_states):
    """从给定 URL 提取频道，支持多种文件格式。"""
    [cite_start]extracted_channels = [] [cite: 17]
    try:
        [cite_start]text = fetch_url_content_with_retry(url, url_states) [cite: 17]
        if text is None:
            [cite_start]return [] [cite: 18]

        [cite_start]extension = get_url_file_extension(url).lower() [cite: 18]
        if extension in [".m3u", ".m3u8"]:
            [cite_start]text = convert_m3u_to_txt(text) [cite: 18]
        elif extension in [".ts", ".flv", ".mp4", ".hls", ".dash"]:
            # 假设单视频文件，生成默认名称
            [cite_start]channel_name = f"Stream_{os.path.basename(urlparse(url).path)}" [cite: 18]
            if pre_screen_url(url):
                [cite_start]extracted_channels.append((channel_name, url)) [cite: 19]
                [cite_start]logging.debug(f"Extracted single stream: {channel_name},{url}") [cite: 19]
            [cite_start]return extracted_channels [cite: 19]
        elif extension not in [".txt", ".csv"]:
            [cite_start]logging.debug(f"Unsupported file extension for URL: {url}") [cite: 19]
            [cite_start]return [] [cite: 19]

        [cite_start]lines = text.split('\n') [cite: 20]
        [cite_start]channel_count = 0 [cite: 20]
        for line in lines:
            [cite_start]line = line.strip() [cite: 20]
            if not line or line.startswith('#'):
                [cite_start]continue [cite: 20]
            if "," in line and "://" in line:
                [cite_start]parts = line.split(',', 1) [cite: 21]
                if len(parts) != 2:
                    [cite_start]logging.debug(f"Skipping invalid channel line (malformed): {line}") [cite: 21]
                    [cite_start]continue [cite: 21]
                [cite_start]channel_name, channel_address_raw = parts [cite: 21]
                [cite_start]channel_name = channel_name.strip() or "未知频道" [cite: 22]
                [cite_start]channel_address_raw = channel_address_raw.strip() [cite: 22]

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    [cite_start]logging.debug(f"Skipping invalid channel URL (no valid protocol): {line}") [cite: 22]
                    [cite_start]continue [cite: 22]

                [cite_start]if '#' in channel_address_raw: [cite: 23]
                    [cite_start]url_list = channel_address_raw.split('#') [cite: 23]
                    for channel_url in url_list:
                        [cite_start]channel_url = clean_url_params(channel_url.strip()) [cite: 23]
                        [cite_start]if channel_url and pre_screen_url(channel_url): [cite: 24]
                            [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 24]
                            [cite_start]channel_count += 1 [cite: 24]
                        else:
                            [cite_start]logging.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}") [cite: 25]
                else:
                    [cite_start]channel_url = clean_url_params(channel_address_raw) [cite: 25]
                    [cite_start]if channel_url and pre_screen_url(channel_url): [cite: 25]
                        [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 26]
                        [cite_start]channel_count += 1 [cite: 26]
                    else:
                        [cite_start]logging.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}") [cite: 26]
            [cite_start]elif re.match(r'^[a-zA-Z0-9+.-]+://', line): [cite: 27]
                # 处理无名称的单 URL 行
                [cite_start]channel_name = f"Stream_{channel_count + 1}" [cite: 27]
                [cite_start]channel_url = clean_url_params(line) [cite: 27]
                if channel_url and pre_screen_url(channel_url):
                    [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 28]
                    [cite_start]channel_count += 1 [cite: 28]
                else:
                    [cite_start]logging.debug(f"Skipping invalid or pre-screened single URL: {line}") [cite: 28]
        [cite_start]logging.debug(f"Successfully extracted {channel_count} channels from URL: {url}.") [cite: 28]
    except Exception as e:
        [cite_start]logging.error(f"Error extracting channels from {url}: {e}") [cite: 29]
    [cite_start]return extracted_channels [cite: 29]

# --- URL 状态管理函数 ---
def load_url_states_local():
    """从本地 config/url_states.json 加载 URL 状态，并清理过期状态。"""
    [cite_start]url_states = {} [cite: 29]
    try:
        with open(URL_STATES_PATH, 'r', encoding='utf-8') as file:
            [cite_start]url_states = json.load(file) [cite: 29]
    except FileNotFoundError:
        [cite_start]logging.warning(f"URL states file '{URL_STATES_PATH}' not found. Starting with empty state.") [cite: 30]
    except json.JSONDecodeError as e:
        [cite_start]logging.error(f"Error decoding JSON from '{URL_STATES_PATH}': {e}. Starting with empty state.") [cite: 30]
        [cite_start]return {} [cite: 30]
    
    # 清理过期状态
    [cite_start]current_time = datetime.now() [cite: 30]
    [cite_start]updated_url_states = {} [cite: 30]
    for url, state in url_states.items():
        if 'last_checked' in state:
            try:
                [cite_start]last_checked_datetime = datetime.fromisoformat(state['last_checked']) [cite: 31]
                if (current_time - last_checked_datetime).days < URL_STATE_EXPIRATION_DAYS:
                    [cite_start]updated_url_states[url] = state [cite: 31]
                else:
                    [cite_start]logging.debug(f"Removing expired URL state: {url} (last checked on {state['last_checked']})") [cite: 31]
            except ValueError:
                [cite_start]logging.warning(f"Could not parse last_checked timestamp for URL {url}: {state['last_checked']}, keeping its state.") [cite: 32]
                [cite_start]updated_url_states[url] = state [cite: 32]
        else:
            [cite_start]updated_url_states[url] = state [cite: 32]
            
    [cite_start]return updated_url_states [cite: 32]

def save_url_states_local(url_states):
    """将 URL 状态保存到本地 config/url_states.json。"""
    try:
        [cite_start]os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True) [cite: 33]
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            [cite_start]json.dump(url_states, file, indent=4, ensure_ascii=False) [cite: 33]
    except Exception as e:
        [cite_start]logging.error(f"Error saving URL states to '{URL_STATES_PATH}': {e}") [cite: 33]

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
    """尝试带重试机制获取 URL 内容，并使用 ETag/Last-Modified/Content-Hash 避免重复下载。"""
    [cite_start]headers = {} [cite: 33]
    [cite_start]current_state = url_states.get(url, {}) [cite: 33]

    if 'etag' in current_state:
        [cite_start]headers['If-None-Match'] = current_state['etag'] [cite: 34]
    if 'last_modified' in current_state:
        [cite_start]headers['If-Modified-Since'] = current_state['last_modified'] [cite: 34]

    try:
        [cite_start]response = session.get(url, headers=headers, timeout=CHANNEL_FETCH_TIMEOUT) [cite: 34]
        [cite_start]response.raise_for_status() [cite: 34]

        if response.status_code == 304:
            [cite_start]logging.debug(f"URL content {url} not modified (304). Skipping download.") [cite: 35]
            if url not in url_states:
                [cite_start]url_states[url] = {} [cite: 35]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 35]
            [cite_start]return None [cite: 35]

        [cite_start]content = response.text [cite: 35]
        [cite_start]content_hash = hashlib.md5(content.encode('utf-8')).hexdigest() [cite: 35]

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            [cite_start]logging.debug(f"URL content {url} is same based on hash. Skipping download.") [cite: 36]
            if url not in url_states:
                [cite_start]url_states[url] = {} [cite: 36]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 36]
            [cite_start]return None [cite: 36]

        url_states[url] = {
            [cite_start]'etag': response.headers.get('ETag'), [cite: 37]
            [cite_start]'last_modified': response.headers.get('Last-Modified'), [cite: 37]
            [cite_start]'content_hash': content_hash, [cite: 37]
            [cite_start]'last_checked': datetime.now().isoformat() [cite: 37]
        }

        [cite_start]logging.debug(f"Successfully fetched new content for URL: {url}. Content updated.") [cite: 38]
        [cite_start]return content [cite: 38]

    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"Request error fetching URL (after retries): {url} - {e}") [cite: 38]
        [cite_start]return None [cite: 38]
    except Exception as e:
        [cite_start]logging.error(f"Unknown error fetching URL: {url} - {e}") [cite: 38]
        [cite_start]return None [cite: 38]

def pre_screen_url(url):
    """根据配置对 URL 进行预筛选（协议、长度、无效模式）。"""
    if not isinstance(url, str) or not url:
        [cite_start]logging.debug(f"Pre-screening filtered (invalid type or empty): {url}") [cite: 39]
        [cite_start]return False [cite: 39]

    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        [cite_start]logging.debug(f"Pre-screening filtered (no valid protocol): {url}") [cite: 39]
        [cite_start]return False [cite: 39]

    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        [cite_start]logging.debug(f"Pre-screening filtered (contains illegal characters or spaces): {url}") [cite: 39]
        [cite_start]return False [cite: 39]

    try:
        [cite_start]parsed_url = urlparse(url) [cite: 39]
        [cite_start]if parsed_url.scheme not in CONFIG.get('rules', {}).get('url_pre_screening', {}).get('allowed_protocols', []): [cite: 40]
            [cite_start]logging.debug(f"Pre-screening filtered (unsupported protocol): {url}") [cite: 40]
            [cite_start]return False [cite: 40]

        if not parsed_url.netloc:
            [cite_start]logging.debug(f"Pre-screening filtered (no network location): {url}") [cite: 40]
            [cite_start]return False [cite: 40]

        [cite_start]invalid_url_patterns = CONFIG.get('rules', {}).get('url_pre_screening', {}).get('invalid_url_patterns', []) [cite: 40]
        [cite_start]compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns] [cite: 41]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                [cite_start]logging.debug(f"Pre-screening filtered (invalid pattern): {url}") [cite: 41]
                [cite_start]return False [cite: 41]

        if len(url) < 15:
            [cite_start]logging.debug(f"Pre-screening filtered (URL too short): {url}") [cite: 41]
            [cite_start]return False [cite: 42]

        [cite_start]return True [cite: 42]
    except ValueError as e:
        [cite_start]logging.debug(f"Pre-screening filtered (URL parse error): {url} - {e}") [cite: 42]
        [cite_start]return False [cite: 42]

def filter_and_modify_channels(channels):
    """过滤和修改频道名称及 URL。"""
    [cite_start]filtered_channels = [] [cite: 42]
    [cite_start]pre_screened_count = 0 [cite: 42]
    for name, url in channels:
        if not pre_screen_url(url):
            [cite_start]logging.debug(f"Filtering channel (pre-screening failed): {name},{url}") [cite: 42]
            [cite_start]continue [cite: 43]
        [cite_start]pre_screened_count += 1 [cite: 43]

        if any(word in url for word in CONFIG.get('url_filter_words', [])):
            [cite_start]logging.debug(f"Filtering channel (URL matches blacklist): {name},{url}") [cite: 43]
            [cite_start]continue [cite: 43]

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            [cite_start]logging.debug(f"Filtering channel (name matches blacklist): {name},{url}") [cite: 43]
            [cite_start]continue [cite: 44]

        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items():
            [cite_start]name = name.replace(old_str, new_str) [cite: 44]
        [cite_start]filtered_channels.append((name, url)) [cite: 44]
    [cite_start]logging.debug(f"After URL pre-screening, {pre_screened_count} channels remain for further filtering.") [cite: 44]
    [cite_start]return filtered_channels [cite: 44]

# --- 频道有效性检查函数 ---
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达。"""
    try:
        [cite_start]response = session.head(url, timeout=timeout, allow_redirects=True) [cite: 44]
        [cite_start]return 200 <= response.status_code < 400 [cite: 45]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.debug(f"HTTP URL {url} check failed: {e}") [cite: 45]
        [cite_start]return False [cite: 45]

def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达（需要 ffprobe）。"""
    try:
        [cite_start]subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2) [cite: 45]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        [cite_start]logging.warning("ffprobe not found or not working. RTMP stream check skipped.") [cite: 46]
        [cite_start]return False [cite: 46]
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                stdout=subprocess.PIPE,
                                [cite_start]stderr=subprocess.PIPE, timeout=timeout) [cite: 46]
        [cite_start]return result.returncode == 0 [cite: 47]
    except subprocess.TimeoutExpired:
        [cite_start]logging.debug(f"RTMP URL {url} check timed out") [cite: 47]
        [cite_start]return False [cite: 47]
    except Exception as e:
        [cite_start]logging.debug(f"RTMP URL {url} check error: {e}") [cite: 47]
        [cite_start]return False [cite: 47]

def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达（尝试 UDP 连接）。"""
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 47]
        [cite_start]host = parsed_url.hostname [cite: 48]
        [cite_start]port = parsed_url.port [cite: 48]
        if not host or not port:
            [cite_start]logging.debug(f"RTP URL {url} parse failed: missing host or port.") [cite: 48]
            [cite_start]return False [cite: 48]

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            [cite_start]s.settimeout(timeout) [cite: 48]
            [cite_start]s.connect((host, port)) [cite: 48]
            [cite_start]s.sendto(b'', (host, port)) [cite: 49]
            [cite_start]s.recv(1) [cite: 49]
        [cite_start]return True [cite: 49]
    except (socket.timeout, socket.error) as e:
        [cite_start]logging.debug(f"RTP URL {url} check failed: {e}") [cite: 49]
        [cite_start]return False [cite: 49]
    except Exception as e:
        [cite_start]logging.debug(f"RTP URL {url} check error: {e}") [cite: 49]
        [cite_start]return False [cite: 49]

def check_p3p_url(url, timeout):
    """检查 P3P URL 是否可达（简单 TCP 连接和 HTTP 响应头检查）。"""
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 50]
        [cite_start]host = parsed_url.hostname [cite: 50]
        [cite_start]port = parsed_url.port if parsed_url.port else 80 [cite: 50]
        [cite_start]path = parsed_url.path if parsed_url.path else '/' [cite: 50]

        if not host:
            [cite_start]logging.debug(f"P3P URL {url} parse failed: missing host.") [cite: 50]
            [cite_start]return False [cite: 50]

        [cite_start]with socket.create_connection((host, port), timeout=timeout) as s: [cite: 51]
            [cite_start]request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n" [cite: 51]
            [cite_start]s.sendall(request.encode()) [cite: 51]
            [cite_start]response = s.recv(1024).decode('utf-8', errors='ignore') [cite: 51]
            [cite_start]return "P3P" in response or response.startswith("HTTP/1.") [cite: 51]
    except Exception as e:
        [cite_start]logging.debug(f"P3P URL {url} check failed: {e}") [cite: 51]
        [cite_start]return False [cite: 51]

def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查单个频道的有效性和速度，并记录失败状态以便跳过。"""
    [cite_start]current_time = datetime.now() [cite: 52]
    [cite_start]current_url_state = url_states.get(url, {}) [cite: 52]

    if 'stream_check_failed_at' in current_url_state:
        [cite_start]last_failed_time_str = current_url_state['stream_check_failed_at'] [cite: 52]
        try:
            [cite_start]last_failed_datetime = datetime.fromisoformat(last_failed_time_str) [cite: 52]
            [cite_start]time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600 [cite: 52]
            if time_since_failed_hours < STREAM_SKIP_FAILED_HOURS:
                [cite_start]logging.debug(f"Skipping channel {channel_name} ({url}) as it failed within cooldown period ({STREAM_SKIP_FAILED_HOURS}h). Last failed at {last_failed_time_str}, {time_since_failed_hours:.2f}h ago.") [cite: 54]
                [cite_start]return None, False [cite: 54]
        except ValueError:
            [cite_start]logging.warning(f"Could not parse failed timestamp for URL {url}: {last_failed_time_str}") [cite: 54]
            [cite_start]pass [cite: 54]

    [cite_start]start_time = time.time() [cite: 54]
    [cite_start]is_valid = False [cite: 54]
    [cite_start]protocol_checked = False [cite: 54]

    try:
        if url.startswith("http"):
            [cite_start]is_valid = check_http_url(url, timeout) [cite: 55]
            [cite_start]protocol_checked = True [cite: 55]
        elif url.startswith("p3p"):
            [cite_start]is_valid = check_p3p_url(url, timeout) [cite: 55]
            [cite_start]protocol_checked = True [cite: 55]
        elif url.startswith("rtmp"):
            [cite_start]is_valid = check_rtmp_url(url, timeout) [cite: 55]
            [cite_start]protocol_checked = True [cite: 56]
        elif url.startswith("rtp"):
            [cite_start]is_valid = check_rtp_url(url, timeout) [cite: 56]
            [cite_start]protocol_checked = True [cite: 56]
        else:
            [cite_start]logging.debug(f"Channel {channel_name}'s protocol is not supported: {url}") [cite: 56]
            if url not in url_states:
                [cite_start]url_states[url] = {} [cite: 56]
            [cite_start]url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat() [cite: 57]
            [cite_start]url_states[url].pop('stream_check_failed_at', None) [cite: 57]
            [cite_start]url_states[url].pop('stream_fail_count', None) [cite: 57]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 57]
            [cite_start]return None, False [cite: 57]

        [cite_start]elapsed_time = (time.time() - start_time) * 1000 [cite: 57]

        if is_valid:
            if url not in url_states:
                [cite_start]url_states[url] = {} [cite: 58]
            [cite_start]url_states[url].pop('stream_check_failed_at', None) [cite: 58]
            [cite_start]url_states[url].pop('stream_fail_count', None) [cite: 58]
            [cite_start]url_states[url]['last_successful_stream_check'] = current_time.isoformat() [cite: 58]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 58]
            [cite_start]logging.debug(f"Channel {channel_name} ({url}) check successful, took {elapsed_time:.0f} ms.") [cite: 58]
            [cite_start]return elapsed_time, True [cite: 59]
        else:
            if url not in url_states:
                [cite_start]url_states[url] = {} [cite: 59]
            [cite_start]url_states[url]['stream_check_failed_at'] = current_time.isoformat() [cite: 59]
            [cite_start]url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 [cite: 59]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 59]
            [cite_start]logging.debug(f"Channel {channel_name} ({url}) check failed.") [cite: 60]
            [cite_start]return None, False [cite: 60]
    except Exception as e:
        if url not in url_states:
            [cite_start]url_states[url] = {} [cite: 60]
        [cite_start]url_states[url]['stream_check_failed_at'] = current_time.isoformat() [cite: 60]
        [cite_start]url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 [cite: 61]
        [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 61]
        [cite_start]logging.debug(f"Error checking channel {channel_name} ({url}): {e}") [cite: 61]
        [cite_start]return None, False [cite: 61]

def process_single_channel_line(channel_line, url_states):
    """处理单个频道行以进行有效性检查。"""
    if "://" not in channel_line:
        [cite_start]logging.debug(f"Skipping invalid channel line (no protocol): {channel_line}") [cite: 61]
        [cite_start]return None, None [cite: 61]
    [cite_start]parts = channel_line.split(',', 1) [cite: 61]
    if len(parts) == 2:
        [cite_start]name, url = parts [cite: 62]
        [cite_start]url = url.strip() [cite: 62]
        [cite_start]elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states) [cite: 62]
        if is_valid:
            [cite_start]return elapsed_time, f"{name},{url}" [cite: 62]
    [cite_start]return None, None [cite: 62]

def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG.get('channel_check_workers', 200)):
    """使用多线程检查频道有效性。"""
    [cite_start]results = [] [cite: 62]
    [cite_start]checked_count = 0 [cite: 62]
    [cite_start]total_channels = len(channel_lines) [cite: 63]
    [cite_start]logging.warning(f"Starting multithreaded channel validity and speed detection for {total_channels} channels...") [cite: 63]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        [cite_start]futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines} [cite: 63]
        [cite_start]for i, future in enumerate(as_completed(futures)): [cite: 63]
            [cite_start]checked_count += 1 [cite: 63]
            if checked_count % 100 == 0:
                [cite_start]logging.warning(f"Checked {checked_count}/{total_channels} channels...") [cite: 63]
            try:
                [cite_start]elapsed_time, result_line = future.result() [cite: 63]
                [cite_start]if elapsed_time is not None and result_line is not None: [cite: 64]
                    [cite_start]results.append((elapsed_time, result_line)) [cite: 64]
            except Exception as exc:
                [cite_start]logging.warning(f"Exception occurred during channel line processing: {exc}") [cite: 64]
    [cite_start]return results [cite: 64]

# --- 文件合并和排序函数 ---
def generate_update_time_header():
    """为文件顶部生成更新时间信息。"""
    [cite_start]now = datetime.now() [cite: 64]
    return [
        [cite_start]f"更新时间,#genre#\n", [cite: 65]
        [cite_start]f"{now.strftime('%Y-%m-%d')},url\n", [cite: 65]
        [cite_start]f"{now.strftime('%H:%M:%S')},url\n" [cite: 65]
    ]

def group_and_limit_channels(lines):
    """对频道进行分组并限制每个频道名称下的 URL 数量。"""
    [cite_start]grouped_channels = {} [cite: 65]
    for line_content in lines:
        [cite_start]line_content = line_content.strip() [cite: 65]
        if line_content:
            [cite_start]channel_name = line_content.split(',', 1)[0].strip() [cite: 66]
            if channel_name not in grouped_channels:
                [cite_start]grouped_channels[channel_name] = [] [cite: 66]
            [cite_start]grouped_channels[channel_name].append(line_content) [cite: 66]
    
    [cite_start]final_grouped_lines = [] [cite: 66]
    for channel_name in grouped_channels:
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            [cite_start]final_grouped_lines.append(ch_line + '\n') [cite: 66]
    [cite_start]return final_grouped_lines [cite: 66]

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt", url_states=None):
    """合并本地生成的频道列表文件，进行去重和基于 url_states 的清理。"""
    [cite_start]os.makedirs(local_channels_directory, exist_ok=True) [cite: 66]

    [cite_start]existing_channels_data = [] [cite: 67]
    if os.path.exists(output_file_name):
        [cite_start]with open(output_file_name, 'r', encoding='utf-8') as f: [cite: 67]
            for line in f:
                [cite_start]line = line.strip() [cite: 67]
                if line and ',' in line and '#genre#' not in line:
                    [cite_start]parts = line.split(',', 1) [cite: 67]
                    [cite_start]if len(parts) == 2: [cite: 68]
                        [cite_start]existing_channels_data.append((parts[0].strip(), parts[1].strip())) [cite: 68]

    [cite_start]all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')] [cite: 68]
    
    [cite_start]uncategorized_file_in_root = "uncategorized_iptv.txt" [cite: 68]
    if os.path.exists(uncategorized_file_in_root):
        [cite_start]all_iptv_files_in_dir.append(uncategorized_file_in_root) [cite: 68]

    [cite_start]files_to_merge_paths = [] [cite: 68]
    [cite_start]processed_files = set() [cite: 68]

    for category in ORDERED_CATEGORIES:
        [cite_start]file_name = f"{category}_iptv.txt" [cite: 69]
        [cite_start]temp_path = os.path.join(local_channels_directory, file_name) [cite: 69]
        [cite_start]root_path = file_name [cite: 69]
        
        if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files:
            [cite_start]files_to_merge_paths.append(temp_path) [cite: 69]
            [cite_start]processed_files.add(os.path.basename(temp_path)) [cite: 69]
        elif category == 'uncategorized' and os.path.basename(root_path) in all_iptv_files_in_dir and root_path not in processed_files:
            [cite_start]files_to_merge_paths.append(root_path) [cite: 70]
            [cite_start]processed_files.add(os.path.basename(root_path)) [cite: 70]

    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
            if os.path.basename(file_name) == uncategorized_file_in_root:
                [cite_start]files_to_merge_paths.append(uncategorized_file_in_root) [cite: 70]
            else:
                [cite_start]files_to_merge_paths.append(os.path.join(local_channels_directory, file_name)) [cite: 70]
            [cite_start]processed_files.add(file_name) [cite: 71]

    [cite_start]new_channels_from_merged_files = set() [cite: 71]
    for file_path in files_to_merge_paths:
        with open(file_path, "r", encoding="utf-8") as file:
            [cite_start]lines = file.readlines() [cite: 71]
            if not lines:
                [cite_start]continue [cite: 71]
            for line in lines:
                [cite_start]line = line.strip() [cite: 72]
                if line and ',' in line and '#genre#' not in line:
                    [cite_start]name, url = line.split(',', 1) [cite: 72]
                    [cite_start]new_channels_from_merged_files.add((name.strip(), url.strip())) [cite: 72]

    [cite_start]combined_channels = existing_channels_data + list(new_channels_from_merged_files) [cite: 72]
    [cite_start]final_channels_for_output = set() [cite: 73]
    [cite_start]channels_for_checking = [] [cite: 73]

    [cite_start]unique_channels_to_check = set() [cite: 73]
    for name, url in combined_channels:
        [cite_start]unique_channels_to_check.add((name, url)) [cite: 73]

    [cite_start]channels_for_checking_lines = [f"{name},{url}" for name, url in unique_channels_to_check] [cite: 73]
    [cite_start]logging.warning(f"Total unique channels to check and filter for {output_file_name}: {len(channels_for_checking_lines)}") [cite: 74]

    [cite_start]valid_channels_from_check = check_channels_multithreaded(channels_for_checking_lines, url_states) [cite: 74]

    for elapsed_time, channel_line in valid_channels_from_check:
        [cite_start]name, url = channel_line.split(',', 1) [cite: 74]
        [cite_start]url = url.strip() [cite: 74]
        [cite_start]state = url_states.get(url, {}) [cite: 74]
        [cite_start]fail_count = state.get('stream_fail_count', 0) [cite: 74]
        if fail_count <= CHANNEL_FAIL_THRESHOLD:
            [cite_start]final_channels_for_output.add((name, url)) [cite: 74]
        else:
            [cite_start]logging.info(f"Removing channel '{name},{url}' from {output_file_name} due to excessive failures ({fail_count} > {CHANNEL_FAIL_THRESHOLD}).") [cite: 74]

    [cite_start]sorted_final_channels = sorted(list(final_channels_for_output), key=lambda x: x[0]) [cite: 75]

    try:
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            [cite_start]iptv_list_file.writelines(generate_update_time_header()) [cite: 75]
            for name, url in sorted_final_channels:
                [cite_start]iptv_list_file.write(f"{name},{url}\n") [cite: 75]
        [cite_start]logging.warning(f"\nAll regional channel list files merged, deduplicated, and cleaned. Output saved to: {output_file_name}") [cite: 76]
    except Exception as e:
        [cite_start]logging.error(f"Error appending write to file '{output_file_name}': {e}") [cite: 76]

# --- 远程 TXT 文件操作函数 ---
# 移除了重复的 read_txt_to_array_local 函数定义
# def read_txt_to_array_local(file_path):
#     """从本地 TXT 文件读取内容到数组。"""
#     return read_txt_to_array_local(file_path)

def write_array_to_txt_local(file_path, data_array, commit_message=None):
    """将数组内容写入本地 TXT 文件。"""
    try:
        [cite_start]os.makedirs(os.path.dirname(file_path), exist_ok=True) [cite: 76]
        with open(file_path, 'w', encoding='utf-8') as file:
            [cite_start]file.write('\n'.join(data_array)) [cite: 77]
        [cite_start]logging.debug(f"Written {len(data_array)} lines to '{file_path}'.") [cite: 77]
    except Exception as e:
        [cite_start]logging.error(f"Failed to write data to '{file_path}': {e}") [cite: 77]

# --- GitHub URL 自动发现函数 ---
def auto_discover_github_urls(urls_file_path_local, github_token):
    """从 GitHub 自动发现新的 IPTV 源 URL，并记录每个关键字的 URL 计数。"""
    if not github_token:
        [cite_start]logging.warning("GitHub token not provided. Skipping GitHub URL auto-discovery.") [cite: 77]
        [cite_start]return [cite: 77]

    [cite_start]existing_urls = set(read_txt_to_array_local(urls_file_path_local)) [cite: 78]
    [cite_start]found_urls = set() [cite: 78]
    headers = {
        [cite_start]"Accept": "application/vnd.github.v3.text-match+json", [cite: 78]
        [cite_start]"Authorization": f"token {github_token}" [cite: 78]
    }

    [cite_start]logging.warning("Starting automatic discovery of new IPTV source URLs from GitHub...") [cite: 78]
    [cite_start]keyword_url_counts = {keyword: 0 for keyword in SEARCH_KEYWORDS} [cite: 78]

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        [cite_start]keyword_found_urls = set() [cite: 78]
        if i > 0:
            [cite_start]logging.warning(f"Switching to next keyword: '{keyword}'. Waiting {GITHUB_API_RETRY_WAIT} seconds to avoid rate limits...") [cite: 79]
            [cite_start]time.sleep(GITHUB_API_RETRY_WAIT) [cite: 79]

        [cite_start]page = 1 [cite: 79]
        while page <= MAX_SEARCH_PAGES:
            params = {
                [cite_start]"q": keyword, [cite: 80]
                [cite_start]"sort": "indexed", [cite: 80]
                [cite_start]"order": "desc", [cite: 80]
                [cite_start]"per_page": PER_PAGE, [cite: 80]
                [cite_start]"page": page [cite: 80]
            }
            try:
                response = session.get(
                    [cite_start]f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}", [cite: 81]
                    headers=headers,
                    params=params,
                    timeout=GITHUB_API_TIMEOUT
                [cite_start]) [cite: 81]
                [cite_start]response.raise_for_status() [cite: 81]
                [cite_start]data = response.json() [cite: 82]

                [cite_start]rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0)) [cite: 82]
                [cite_start]rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0)) [cite: 82]

                if rate_limit_remaining == 0:
                    [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 [cite: 82]
                    [cite_start]logging.warning(f"GitHub API rate limit reached! Remaining requests: 0. Waiting {wait_seconds:.0f} seconds before retrying.") [cite: 84]
                    [cite_start]time.sleep(wait_seconds) [cite: 84]
                    [cite_start]continue [cite: 84]

                if not data.get('items'):
                    [cite_start]logging.debug(f"No more results found on page {page} for keyword '{keyword}'.") [cite: 84]
                    [cite_start]break [cite: 85]

                for item in data['items']:
                    [cite_start]html_url = item.get('html_url', '') [cite: 85]
                    [cite_start]raw_url = None [cite: 85]
                    [cite_start]match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url) [cite: 86]
                    if match:
                        [cite_start]user = match.group(1) [cite: 86]
                        [cite_start]repo = match.group(2) [cite: 86]
                        [cite_start]branch = match.group(3) [cite: 87]
                        [cite_start]file_path = match.group(4) [cite: 87]
                        [cite_start]raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}" [cite: 87]
                    else:
                        [cite_start]logging.debug(f"Could not parse raw URL from html_url: {html_url}") [cite: 88]
                        [cite_start]continue [cite: 88]

                    if raw_url and raw_url not in existing_urls and raw_url not in found_urls:
                        try:
                            [cite_start]content_response = session.get(raw_url, timeout=5) [cite: 89]
                            [cite_start]content_response.raise_for_status() [cite: 89]
                            [cite_start]content = content_response.text [cite: 89]
                            [cite_start]if re.search(r'#EXTM3U', content, re.IGNORECASE) or re.search(r'\.(m3u8|m3u|txt|csv|ts|flv|mp4|hls|dash)$', raw_url, re.IGNORECASE): [cite: 90]
                                [cite_start]found_urls.add(raw_url) [cite: 90]
                                [cite_start]keyword_found_urls.add(raw_url) [cite: 90]
                                [cite_start]logging.debug(f"Found new IPTV source URL: {raw_url}") [cite: 91]
                            else:
                                [cite_start]logging.debug(f"URL {raw_url} does not contain M3U content and is not a supported file extension. Skipping.") [cite: 92]
                        except requests.exceptions.RequestException as req_e:
                            [cite_start]logging.debug(f"Error fetching raw content for {raw_url}: {req_e}") [cite: 92]
                        except Exception as exc:
                            [cite_start]logging.debug(f"Unexpected error during content check for {raw_url}: {exc}") [cite: 93]

                [cite_start]logging.debug(f"Finished page {page} for keyword '{keyword}'. Found {len(keyword_found_urls)} new URLs.") [cite: 93]
                [cite_start]page += 1 [cite: 93]

            except requests.exceptions.RequestException as e:
                [cite_start]if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403: [cite: 94]
                    [cite_start]logging.error(f"GitHub API rate limit exceeded or access forbidden for keyword '{keyword}'. Error: {e}") [cite: 94]
                    [cite_start]rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0)) [cite: 94]
                    [cite_start]rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0)) [cite: 94]
                    if rate_limit_remaining == 0:
                        [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 [cite: 95]
                        [cite_start]logging.warning(f"Rate limit hit for keyword '{keyword}'. Waiting {wait_seconds:.0f} seconds.") [cite: 96]
                        [cite_start]time.sleep(wait_seconds) [cite: 96]
                        [cite_start]continue [cite: 96]
                else:
                    [cite_start]logging.error(f"Error searching GitHub for keyword '{keyword}': {e}") [cite: 96]
                [cite_start]break [cite: 97]
            except Exception as e:
                [cite_start]logging.error(f"An unexpected error occurred during GitHub search for keyword '{keyword}': {e}") [cite: 97]
                [cite_start]break [cite: 97]
        [cite_start]keyword_url_counts[keyword] = len(keyword_found_urls) [cite: 97]

    if found_urls:
        [cite_start]updated_urls = sorted(list(existing_urls | found_urls)) [cite: 97]
        [cite_start]logging.warning(f"Discovered {len(found_urls)} new unique URLs. Total URLs to save: {len(updated_urls)}.") [cite: 98]
        [cite_start]write_array_to_txt_local(urls_file_path_local, updated_urls) [cite: 98]
    else:
        [cite_start]logging.warning("No new IPTV source URLs discovered.") [cite: 98]

    for keyword, count in keyword_url_counts.items():
        [cite_start]logging.warning(f"Keyword '{keyword}' discovered {count} new URLs.") [cite: 98]

# --- URL 清理函数 ---
def cleanup_urls_local(urls_file_path_local, url_states):
    """根据 URL_FAIL_THRESHOLD 和 URL_RETENTION_HOURS 清理本地 urls.txt 中的无效/失败 URL。"""
    [cite_start]all_urls = read_txt_to_array_local(urls_file_path_local) [cite: 98]
    [cite_start]current_time = datetime.now() [cite: 99]
    [cite_start]urls_to_keep = [] [cite: 99]
    [cite_start]removed_count = 0 [cite: 99]

    [cite_start]for url in all_urls: [cite: 99]
        [cite_start]state = url_states.get(url, {}) [cite: 99]
        [cite_start]fail_count = state.get('stream_fail_count', 0) [cite: 99]
        [cite_start]last_failed_time_str = state.get('stream_check_failed_at') [cite: 99]
        [cite_start]remove_url = False [cite: 99]

        [cite_start]if fail_count > URL_FAIL_THRESHOLD: [cite: 99]
            if last_failed_time_str:
                try:
                    [cite_start]last_failed_datetime = datetime.fromisoformat(last_failed_time_str) [cite: 100]
                    if (current_time - last_failed_datetime).total_seconds() / 3600 > URL_RETENTION_HOURS:
                        [cite_start]remove_url = True [cite: 100]
                        [cite_start]logging.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) and retention period ({URL_RETENTION_HOURS}h) exceeded.") [cite: 100]
                except ValueError:
                    [cite_start]logging.warning(f"Could not parse last_failed timestamp for URL {url}: {last_failed_time_str}, keeping it for now.") [cite: 101]
            else:
                [cite_start]remove_url = True [cite: 101]
                [cite_start]logging.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) with no last_failed_at timestamp.") [cite: 102]

        if not remove_url:
            [cite_start]urls_to_keep.append(url) [cite: 102]
        else:
            [cite_start]removed_count += 1 [cite: 102]
            [cite_start]url_states.pop(url, None) [cite: 102]

    if removed_count > 0:
        [cite_start]logging.warning(f"Cleaned up {removed_count} URLs from {urls_file_path_local}.") [cite: 102]
        [cite_start]write_array_to_txt_local(urls_file_path_local, urls_to_keep) [cite: 102]
    else:
        [cite_start]logging.warning("No URLs needed cleanup from urls.txt.") [cite: 103]

# --- 分类和文件保存函数 ---
def categorize_channels(channels):
    """根据频道名称关键字对频道进行分类。"""
    [cite_start]categorized_data = {category: [] for category in ORDERED_CATEGORIES} [cite: 103]
    [cite_start]uncategorized_data = [] [cite: 103]

    for name, url in channels:
        [cite_start]found_category = False [cite: 103]
        for category in ORDERED_CATEGORIES:
            [cite_start]category_keywords = CONFIG.get('category_keywords', {}).get(category, []) [cite: 104]
            if any(keyword.lower() in name.lower() for keyword in category_keywords):
                [cite_start]categorized_data[category].append((name, url)) [cite: 104]
                [cite_start]found_category = True [cite: 104]
                [cite_start]break [cite: 104]
        if not found_category:
            [cite_start]uncategorized_data.append((name, url)) [cite: 104]
    [cite_start]return categorized_data, uncategorized_data [cite: 104]

def process_and_save_channels_by_category(all_channels, url_states):
    """将频道分类并保存到对应的分类文件中。"""
    [cite_start]categorized_channels, uncategorized_channels = categorize_channels(all_channels) [cite: 105]
    
    [cite_start]categorized_dir = "temp_channels" [cite: 105]
    [cite_start]os.makedirs(categorized_dir, exist_ok=True) [cite: 105]

    for category, channels in categorized_channels.items():
        [cite_start]output_file = os.path.join(categorized_dir, f"{category}_iptv.txt") [cite: 105]
        [cite_start]logging.warning(f"Processing category: {category} with {len(channels)} channels.") [cite: 105]
        [cite_start]sorted_channels = sorted(channels, key=lambda x: x[0]) [cite: 105]
        [cite_start]channels_to_write = [(0, f"{name},{url}") for name, url in sorted_channels] [cite: 105]
        [cite_start]write_sorted_channels_to_file(output_file, channels_to_write) [cite: 105]
    
    [cite_start]output_uncategorized_file = "uncategorized_iptv.txt"  # 保存到根目录 [cite: 105]
    [cite_start]logging.warning(f"Processing uncategorized channels: {len(uncategorized_channels)} channels.") [cite: 106]
    [cite_start]sorted_uncategorized = sorted(uncategorized_channels, key=lambda x: x[0]) [cite: 106]
    [cite_start]uncategorized_to_write = [(0, f"{name},{url}") for name, url in sorted_uncategorized] [cite: 106]
    [cite_start]write_sorted_channels_to_file(output_uncategorized_file, uncategorized_to_write) [cite: 106]
    [cite_start]logging.warning(f"Uncategorized channels saved to: {output_uncategorized_file}") [cite: 106]

# --- 主逻辑 ---
def main():
    [cite_start]logging.warning("Starting IPTV processing script...") [cite: 106]

    # 步骤 1：加载 URL 状态（包括清理过期状态）
    [cite_start]url_states = load_url_states_local() [cite: 107]
    [cite_start]logging.warning(f"Loaded {len(url_states)} URL states.") [cite: 107]

    # 步骤 2：从 GitHub 自动发现新 URL
    [cite_start]auto_discover_github_urls(URLS_PATH, GITHUB_TOKEN) [cite: 107]

    # 步骤 3：根据 URL_FAIL_THRESHOLD 和 URL_RETENTION_HOURS 清理 urls.txt
    [cite_start]cleanup_urls_local(URLS_PATH, url_states) [cite: 107]

    # 步骤 4：从本地 urls.txt 加载 URL
    [cite_start]urls = read_txt_to_array_local(URLS_PATH) [cite: 107]
    if not urls:
        [cite_start]logging.error("No URLs found in urls.txt. Exiting.") [cite: 108]
        [cite_start]exit(1) [cite: 108]
    [cite_start]logging.warning(f"Loaded {len(urls)} URLs from '{URLS_PATH}'.") [cite: 108]

    # 步骤 5：使用多线程从所有 URL 获取内容并提取频道
    [cite_start]all_extracted_channels = [] [cite: 108]
    [cite_start]logging.warning(f"Starting channel extraction from {len(urls)} URLs...") [cite: 108]
    with ThreadPoolExecutor(max_workers=CONFIG.get('url_fetch_workers', 50)) as executor:
        [cite_start]futures = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls} [cite: 109]
        for i, future in enumerate(as_completed(futures)):
            if (i + 1) % 10 == 0:
                [cite_start]logging.warning(f"Processed {i + 1}/{len(urls)} URLs for channel extraction.") [cite: 109]
            try:
                [cite_start]channels = future.result() [cite: 109]
                if channels:
                    [cite_start]all_extracted_channels.extend(channels) [cite: 109]
            except Exception as exc:
                [cite_start]logging.error(f"URL extraction generated an exception: {exc}") [cite: 110]
    [cite_start]logging.warning(f"Finished channel extraction. Total channels extracted before filtering: {len(all_extracted_channels)}.") [cite: 110]

    # 步骤 6：过滤和修改提取的频道
    [cite_start]filtered_and_modified_channels = filter_and_modify_channels(all_extracted_channels) [cite: 110]
    [cite_start]logging.warning(f"Total channels after filtering and modification: {len(filtered_and_modified_channels)}.") [cite: 110]
    
    # 步骤 7：将频道分类并保存到临时分类文件
    [cite_start]process_and_save_channels_by_category(filtered_and_modified_channels, url_states) [cite: 111]

    # 步骤 8：合并本地频道文件，进行最终验证并基于 url_states 清理
    [cite_start]merge_local_channel_files("temp_channels", IPTV_LIST_PATH, url_states) [cite: 111]

    # 步骤 9：再次保存所有频道检查状态
    [cite_start]save_url_states_local(url_states) [cite: 111]
    [cite_start]logging.warning("Final channel check states saved to local.") [cite: 111]

    # 步骤 10：清理临时文件
    try:
        if os.path.exists('iptv.txt'):
            [cite_start]os.remove('iptv.txt') [cite: 111]
            [cite_start]logging.debug(f"Removed temporary file 'iptv.txt'.") [cite: 111]
        if os.path.exists('iptv_speed.txt'):
            [cite_start]os.remove('iptv_speed.txt') [cite: 112]
            [cite_start]logging.debug(f"Removed temporary file 'iptv_speed.txt'.") [cite: 112]
        [cite_start]temp_dir = "temp_channels" [cite: 112]
        if os.path.exists(temp_dir):
            for f_name in os.listdir(temp_dir):
                if f_name.endswith('_iptv.txt'):
                    [cite_start]os.remove(os.path.join(temp_dir, f_name)) [cite: 112]
                    [cite_start]logging.debug(f"Removed temporary channel file '{f_name}'.") [cite: 112]
            if not os.listdir(temp_dir):
                [cite_start]os.rmdir(temp_dir) [cite: 113]
                [cite_start]logging.debug(f"Removed empty directory '{temp_dir}'.") [cite: 113]
        if os.path.exists('uncategorized_iptv.txt'):
            [cite_start]os.remove('uncategorized_iptv.txt') [cite: 113]
            [cite_start]logging.debug(f"Removed 'uncategorized_iptv.txt' from root directory.") [cite: 113]

    except Exception as e:
        [cite_start]logging.error(f"Error during temporary file cleanup: {e}") [cite: 113]

    [cite_start]logging.warning("IPTV processing script finished.") [cite: 113]

if __name__ == "__main__":
    [cite_start]main() [cite: 114]
