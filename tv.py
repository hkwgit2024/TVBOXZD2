import os [cite: 83]
import re [cite: 83]
import subprocess [cite: 83]
import socket [cite: 83]
import time [cite: 83]
from datetime import datetime [cite: 83]
import logging [cite: 83]
import requests [cite: 83]
from urllib.parse import urlparse [cite: 83]
from concurrent.futures import ThreadPoolExecutor, as_completed [cite: 83]
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type [cite: 83]
import json [cite: 83]
import hashlib [cite: 83]
from requests.adapters import HTTPAdapter [cite: 83]
from requests.packages.urllib3.util.retry import Retry [cite: 83]
import yaml [cite: 83]

# 配置日志
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s') [cite: 83]

# 从环境变量获取配置
GITHUB_TOKEN = os.getenv('BOT') [cite: 83]
REPO_OWNER = os.getenv('REPO_OWNER') [cite: 83]
REPO_NAME = os.getenv('REPO_NAME') [cite: 83]
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH') [cite: 83]
URLS_PATH_IN_REPO = os.getenv('URLS_PATH') [cite: 84]
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH') [cite: 84]

# 检查环境变量是否设置
if not GITHUB_TOKEN: [cite: 83]
    logging.error("错误：环境变量 'BOT' 未设置。") [cite: 83]
    exit(1) [cite: 83]
if not REPO_OWNER: [cite: 83]
    logging.error("错误：环境变量 'REPO_OWNER' 未设置。") [cite: 83]
    exit(1) [cite: 83]
if not REPO_NAME: [cite: 83]
    logging.error("错误：环境变量 'REPO_NAME' 未设置。") [cite: 83]
    exit(1) [cite: 83]
if not CONFIG_PATH_IN_REPO: [cite: 83]
    logging.error("错误：环境变量 'CONFIG_PATH' 未设置。") [cite: 83]
    exit(1) [cite: 84]
if not URLS_PATH_IN_REPO: [cite: 84]
    logging.error("错误：环境变量 'URLS_PATH' 未设置。") [cite: 84]
    exit(1) [cite: 84]
if not URL_STATES_PATH_IN_REPO: [cite: 84]
    logging.error("错误：环境变量 'URL_STATES_PATH' 未设置。") [cite: 84]
    exit(1) [cite: 84]

# GitHub 仓库的基础 URL
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main" [cite: 84]
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents" [cite: 84]
GITHUB_API_BASE_URL = "https://api.github.com" [cite: 84]
SEARCH_CODE_ENDPOINT = "/search/code" [cite: 84]

# --- GitHub 文件操作函数 ---
def fetch_from_github(file_path_in_repo): [cite: 84]
    """从 GitHub 仓库获取文件内容。""" [cite: 84]
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}" [cite: 84]
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 84]
    try: [cite: 84]
        response = requests.get(raw_url, headers=headers, timeout=10) [cite: 84]
        response.raise_for_status() [cite: 84]
        return response.text [cite: 84]
    except requests.exceptions.RequestException as e: [cite: 84, 85]
        logging.error(f"从 GitHub 获取 {file_path_in_repo} 发生错误：{e}") [cite: 85]
        return None [cite: 85]

def get_current_sha(file_path_in_repo): [cite: 85]
    """获取 GitHub 仓库中文件的当前 SHA 值。""" [cite: 85]
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 85]
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 85]
    try: [cite: 85]
        response = requests.get(api_url, headers=headers, timeout=10) [cite: 85]
        response.raise_for_status() [cite: 85]
        return response.json().get('sha') [cite: 85]
    except requests.exceptions.RequestException as e: [cite: 85]
        logging.debug(f"获取 {file_path_in_repo} 的 SHA 发生错误（可能不存在）：{e}") [cite: 85]
        return None [cite: 86]

def save_to_github(file_path_in_repo, content, commit_message): [cite: 86]
    """将内容保存（创建或更新）到 GitHub 仓库。""" [cite: 86]
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 86]
    sha = get_current_sha(file_path_in_repo) [cite: 86]
    
    headers = { [cite: 86]
        "Authorization": f"token {GITHUB_TOKEN}", [cite: 86]
        "Content-Type": "application/json" [cite: 86]
    } [cite: 86]
    
    import base64 [cite: 86]
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8') [cite: 86]

    payload = { [cite: 86]
        "message": commit_message, [cite: 86]
        "content": encoded_content, [cite: 86]
        "branch": "main" [cite: 87]
    } [cite: 87]
    
    if sha: [cite: 87]
        payload["sha"] = sha [cite: 87]
    
    try: [cite: 87]
        response = requests.put(api_url, headers=headers, json=payload) [cite: 87]
        response.raise_for_status() [cite: 87]
        return True [cite: 87]
    except requests.exceptions.RequestException as e: [cite: 87]
        logging.error(f"将 {file_path_in_repo} 保存到 GitHub 发生错误：{e}") [cite: 87]
        logging.error(f"GitHub API 响应：{response.text if 'response' in locals() else 'N/A'}") [cite: 87, 88]
        return False [cite: 88]

def load_config(): [cite: 88]
    """从 GitHub 仓库加载并解析 YAML 配置文件。""" [cite: 88]
    content = fetch_from_github(CONFIG_PATH_IN_REPO) [cite: 88]
    if content: [cite: 88]
        try: [cite: 88]
            return yaml.safe_load(content) [cite: 88]
        except yaml.YAMLError as e: [cite: 88]
            logging.error(f"错误：远程配置文件 '{CONFIG_PATH_IN_REPO}' 中的 YAML 无效：{e}") [cite: 88]
            exit(1) [cite: 88]
        except Exception as e: [cite: 89]
            logging.error(f"加载远程配置文件 '{CONFIG_PATH_IN_REPO}' 发生错误：{e}") [cite: 89]
            exit(1) [cite: 89]
    logging.error(f"无法从 GitHub 的 '{CONFIG_PATH_IN_REPO}' 加载配置。") [cite: 89]
    exit(1) [cite: 89]

# 加载配置
CONFIG = load_config() [cite: 89]

# 从配置中获取参数
SEARCH_KEYWORDS = CONFIG.get('search_keywords', []) [cite: 89]
PER_PAGE = CONFIG.get('per_page', 100) [cite: 89]
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5) [cite: 89]
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20) [cite: 89]
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 10) [cite: 89]
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15) [cite: 89]
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 6) [cite: 89]
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200) [cite: 89]
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', []) [cite: 89]
URL_FILTER_WORDS = CONFIG.get('url_filter_words', []) [cite: 89]
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {}) [cite: 89]
ORDERED_CATEGORIES = CONFIG.get('ordered_categories', []) [cite: 89]
STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24) [cite: 89]

# 配置 requests 会话
session = requests.Session() [cite: 89]
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"}) [cite: 89, 90]
pool_size = CONFIG.get('requests_pool_size', 200) [cite: 90]
retry_strategy = Retry( [cite: 90]
    total=CONFIG.get('requests_retry_total', 3), [cite: 90]
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1), [cite: 90]
    status_forcelist=[429, 500, 502, 503, 504], [cite: 90]
    allowed_methods=["HEAD", "GET", "OPTIONS"] [cite: 90]
) [cite: 90]
adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy) [cite: 90]
session.mount("http://", adapter) [cite: 90]
session.mount("https://", adapter) [cite: 90]

# --- 本地文件操作函数 ---
def read_txt_to_array_local(file_name): [cite: 90]
    """从本地 TXT 文件读取内容到数组。""" [cite: 90]
    try: [cite: 90]
        with open(file_name, 'r', encoding='utf-8') as file: [cite: 91]
            lines = file.readlines() [cite: 91]
            lines = [line.strip() for line in lines if line.strip()] [cite: 91]
            return lines [cite: 91]
    except FileNotFoundError: [cite: 91]
        logging.warning(f"文件 '{file_name}' 未找到。") [cite: 91]
        return [] [cite: 91]
    except Exception as e: [cite: 91]
        logging.error(f"读取文件 '{file_name}' 发生错误：{e}") [cite: 91]
        return [] [cite: 91]

def write_array_to_txt_local(file_name, data_array): [cite: 91]
    """将数组内容写入本地 TXT 文件。""" [cite: 91]
    try: [cite: 91]
        with open(file_name, 'w', encoding='utf-8') as file: [cite: 92]
            for item in data_array: [cite: 92]
                file.write(item + '\n') [cite: 92]
    except Exception as e: [cite: 92]
        logging.error(f"写入文件 '{file_name}' 发生错误：{e}") [cite: 92]

# --- 新增函数：清空目录中的 TXT 文件 ---
def clear_directory_txt_files(directory): [cite: 92]
    """清空指定目录中的所有 .txt 文件。""" [cite: 92]
    try: [cite: 92]
        for file_name in os.listdir(directory): [cite: 92]
            if file_name.endswith('.txt'): [cite: 92]
                file_path = os.path.join(directory, file_name) [cite: 93]
                os.remove(file_path) [cite: 93]
                logging.debug(f"已删除旧文件：{file_path}") [cite: 93]
    except Exception as e: [cite: 93]
        logging.error(f"清空目录 {directory} 中的 .txt 文件时发生错误：{e}") [cite: 93]

# --- URL 处理和频道提取函数 ---
def get_url_file_extension(url): [cite: 93]
    """获取 URL 的文件扩展名。""" [cite: 93]
    parsed_url = urlparse(url) [cite: 93]
    extension = os.path.splitext(parsed_url.path)[1].lower() [cite: 93]
    return extension [cite: 93]

def convert_m3u_to_txt(m3u_content): [cite: 93]
    """将 M3U 格式内容转换为 TXT 格式（频道名,URL）。""" [cite: 93]
    lines = m3u_content.split('\n') [cite: 94]
    txt_lines = [] [cite: 94]
    channel_name = "" [cite: 94]
    for line in lines: [cite: 94]
        line = line.strip() [cite: 94]
        if line.startswith("#EXTM3U"): [cite: 94]
            continue [cite: 94]
        if line.startswith("#EXTINF"): [cite: 94]
            match = re.search(r'#EXTINF:.*?\,(.*)', line) [cite: 94]
            if match: [cite: 94]
                channel_name = match.group(1).strip() [cite: 94]
            else: [cite: 95]
                channel_name = "未知频道" [cite: 95]
        elif line and not line.startswith('#'): [cite: 95]
            if channel_name: [cite: 95]
                txt_lines.append(f"{channel_name},{line}") [cite: 95]
            channel_name = "" [cite: 95]
    return '\n'.join(txt_lines) [cite: 95]

def clean_url_params(url): [cite: 95]
    """清理 URL 参数，只保留协议、域名和路径。""" [cite: 95]
    parsed_url = urlparse(url) [cite: 96]
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path [cite: 96]

# --- URL 状态管理函数 ---
def load_url_states_remote(): [cite: 96]
    """从远程加载 URL 状态 JSON 文件。""" [cite: 96]
    content = fetch_from_github(URL_STATES_PATH_IN_REPO) [cite: 96]
    if content: [cite: 96]
        try: [cite: 96]
            return json.loads(content) [cite: 96]
        except json.JSONDecodeError as e: [cite: 96]
            logging.error(f"解码远程 '{URL_STATES_PATH_IN_REPO}' 中的 JSON 发生错误：{e}。将从空状态开始。") [cite: 96]
            return {} [cite: 97]
    return {} [cite: 97]

def save_url_states_remote(url_states): [cite: 97]
    """保存 URL 状态到远程 JSON 文件。""" [cite: 97]
    try: [cite: 97]
        content = json.dumps(url_states, indent=4, ensure_ascii=False) [cite: 97]
        success = save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态") [cite: 97]
        if not success: [cite: 97]
            logging.error(f"将远程 URL 状态保存到 '{URL_STATES_PATH_IN_REPO}' 发生错误。") [cite: 97]
    except Exception as e: [cite: 97]
        logging.error(f"将 URL 状态保存到远程 '{URL_STATES_PATH_IN_REPO}' 发生错误：{e}") [cite: 97]

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException)) [cite: 97]
def fetch_url_content_with_retry(url, url_states): [cite: 97]
    """尝试获取 URL 内容，带重试机制，并利用 ETag/Last-Modified/Content-Hash 避免重复下载。""" [cite: 98]
    headers = {} [cite: 98]
    current_state = url_states.get(url, {}) [cite: 98]

    if 'etag' in current_state: [cite: 98]
        headers['If-None-Match'] = current_state['etag'] [cite: 98]
    if 'last_modified' in current_state: [cite: 98]
        headers['If-Modified-Since'] = current_state['last_modified'] [cite: 98]

    try: [cite: 98]
        response = session.get(url, headers=headers, timeout=CHANNEL_FETCH_TIMEOUT) [cite: 98]
        response.raise_for_status() [cite: 98]

        if response.status_code == 304: [cite: 98]
            logging.debug(f"URL 内容 {url} 未修改 (304)。跳过下载。") [cite: 99]
            if url not in url_states: [cite: 99]
                url_states[url] = {} [cite: 99]
            url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 99]
            return None [cite: 99]

        content = response.text [cite: 99]
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest() [cite: 99]

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash: [cite: 99]
            logging.debug(f"URL 内容 {url} 基于哈希是相同的。跳过下载。") [cite: 100]
            if url not in url_states: [cite: 100]
                url_states[url] = {} [cite: 100]
            url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 100]
            return None [cite: 100]

        url_states[url] = { [cite: 100]
            'etag': response.headers.get('ETag'), [cite: 101]
            'last_modified': response.headers.get('Last-Modified'), [cite: 101]
            'content_hash': content_hash, [cite: 101]
            'last_checked': datetime.now().isoformat() [cite: 101]
        } [cite: 101]

        logging.debug(f"成功获取 URL：{url} 的新内容。内容已更新。") [cite: 101]
        return content [cite: 101]

    except requests.exceptions.RequestException as e: [cite: 101]
        logging.error(f"获取 URL (重试后) 发生请求错误：{url} - {e}") [cite: 102]
        return None [cite: 102]
    except Exception as e: [cite: 102]
        logging.error(f"获取 URL 发生未知错误：{url} - {e}") [cite: 102]
        return None [cite: 102]

def extract_channels_from_url(url, url_states): [cite: 102]
    """从给定的 URL 中提取频道。""" [cite: 102]
    extracted_channels = [] [cite: 102]
    try: [cite: 102]
        text = fetch_url_content_with_retry(url, url_states) [cite: 102]
        if text is None: [cite: 102]
            return [] [cite: 102]

        if get_url_file_extension(url) in [".m3u", ".m3u8"]: [cite: 102]
            text = convert_m3u_to_txt(text) [cite: 103]

        lines = text.split('\n') [cite: 103]
        channel_count = 0 [cite: 103]
        for line in lines: [cite: 103]
            line = line.strip() [cite: 103]
            if "#genre#" not in line and "," in line and "://" in line: [cite: 103]
                parts = line.split(',', 1) [cite: 103]
                channel_name = parts[0].strip() [cite: 104]
                channel_address_raw = parts[1].strip() [cite: 104]

                if '#' in channel_address_raw: [cite: 104]
                    url_list = channel_address_raw.split('#') [cite: 104]
                    for channel_url in url_list: [cite: 104]
                        channel_url = clean_url_params(channel_url.strip()) [cite: 105]
                        if channel_url: [cite: 105]
                            extracted_channels.append((channel_name, channel_url)) [cite: 105]
                            channel_count += 1 [cite: 105]
                else: [cite: 106]
                    channel_url = clean_url_params(channel_address_raw) [cite: 106]
                    if channel_url: [cite: 106]
                        extracted_channels.append((channel_name, channel_url)) [cite: 106]
                        channel_count += 1 [cite: 107]
        logging.debug(f"成功从 URL：{url} 中提取 {channel_count} 个频道。") [cite: 107]
    except Exception as e: [cite: 107]
        logging.error(f"从 {url} 提取频道时发生错误：{e}") [cite: 107]
    return extracted_channels [cite: 107]

def pre_screen_url(url): [cite: 107]
    """预筛选 URL，根据配置检查协议、长度和无效模式。""" [cite: 107]
    if not isinstance(url, str) or not url: [cite: 107]
        return False [cite: 107]

    parsed_url = urlparse(url) [cite: 107]

    if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []): [cite: 108]
        return False [cite: 108]

    if not parsed_url.netloc: [cite: 108]
        return False [cite: 108]

    invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', []) [cite: 108]
    compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns] [cite: 108]
    for pattern in compiled_invalid_url_patterns: [cite: 108]
        if pattern.search(url): [cite: 108]
            logging.debug(f"预筛选过滤（无效模式）：{url}") [cite: 108]
            return False [cite: 108]

    if len(url) < 15: [cite: 108]
        return False [cite: 109]

    return True [cite: 109]

def filter_and_modify_channels(channels): [cite: 109]
    """过滤和修改频道名称及 URL。""" [cite: 109]
    filtered_channels = [] [cite: 109]
    pre_screened_count = 0 [cite: 109]
    for name, url in channels: [cite: 109]
        if not pre_screen_url(url): [cite: 109]
            logging.debug(f"正在过滤频道（预筛选失败）：{name},{url}") [cite: 109]
            continue [cite: 109]
        pre_screened_count += 1 [cite: 109]

        if any(word in url for word in CONFIG.get('url_filter_words', [])): [cite: 109]
            logging.debug(f"正在过滤频道（URL 匹配黑名单）：{name},{url}") [cite: 109]
            continue [cite: 110]

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])): [cite: 110]
            logging.debug(f"正在过滤频道（名称匹配黑名单）：{name},{url}") [cite: 110]
            continue [cite: 110]

        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items(): [cite: 110]
            name = name.replace(old_str, new_str) [cite: 110]
        filtered_channels.append((name, url)) [cite: 110]
    logging.debug(f"URL 预筛选后，剩余 {pre_screened_count} 个频道等待进一步过滤。") [cite: 110]
    return filtered_channels [cite: 110]

# --- 频道有效性检查函数 ---
def check_http_url(url, timeout): [cite: 110]
    """检查 HTTP/HTTPS URL 是否可达。""" [cite: 111]
    try: [cite: 111]
        response = session.head(url, timeout=timeout, allow_redirects=True) [cite: 111]
        return 200 <= response.status_code < 400 [cite: 111]
    except requests.exceptions.RequestException as e: [cite: 111]
        logging.debug(f"HTTP URL {url} 检查失败：{e}") [cite: 111]
        return False [cite: 111]

def check_rtmp_url(url, timeout): [cite: 111]
    """检查 RTMP URL 是否可达（需要 ffprobe）。""" [cite: 111]
    try: [cite: 111]
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2) [cite: 111]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired): [cite: 111]
        logging.warning("未找到 ffprobe 或其无法工作。RTMP 流检查已跳过。") [cite: 111]
        return False [cite: 112]
    try: [cite: 112]
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url], [cite: 112]
                               stdout=subprocess.PIPE, [cite: 112]
                               stderr=subprocess.PIPE, timeout=timeout) [cite: 112]
        return result.returncode == 0 [cite: 112]
    except subprocess.TimeoutExpired: [cite: 113]
        logging.debug(f"RTMP URL {url} 检查超时") [cite: 113]
        return False [cite: 113]
    except Exception as e: [cite: 113]
        logging.debug(f"RTMP URL {url} 检查错误：{e}") [cite: 113]
        return False [cite: 113]

def check_rtp_url(url, timeout): [cite: 113]
    """检查 RTP URL 是否可达（通过 UDP 尝试连接）。""" [cite: 113]
    try: [cite: 113]
        parsed_url = urlparse(url) [cite: 113]
        host = parsed_url.hostname [cite: 114]
        port = parsed_url.port [cite: 114]
        if not host or not port: [cite: 114]
            logging.debug(f"RTP URL {url} 解析失败：缺少主机或端口。") [cite: 114]
            return False [cite: 114]

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: [cite: 114]
            s.settimeout(timeout) [cite: 114]
            s.connect((host, port)) [cite: 114]
            s.sendto(b'', (host, port)) [cite: 114]
            s.recv(1) [cite: 115]
        return True [cite: 115]
    except (socket.timeout, socket.error) as e: [cite: 115]
        logging.debug(f"RTP URL {url} 检查失败：{e}") [cite: 115]
        return False [cite: 115]
    except Exception as e: [cite: 115]
        logging.debug(f"RTP URL {url} 检查错误：{e}") [cite: 115]
        return False [cite: 115]

def check_p3p_url(url, timeout): [cite: 115]
    """检查 P3P URL 是否可达（简单 TCP 连接和 HTTP 响应头检查）。""" [cite: 115]
    try: [cite: 115]
        parsed_url = urlparse(url) [cite: 116]
        host = parsed_url.hostname [cite: 116]
        port = parsed_url.port if parsed_url.port else 80 [cite: 116]
        path = parsed_url.path if parsed_url.path else '/' [cite: 116]

        if not host: [cite: 116]
            logging.debug(f"P3P URL {url} 解析失败：缺少主机。") [cite: 116]
            return False [cite: 116]

        with socket.create_connection((host, port), timeout=timeout) as s: [cite: 116]
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n" [cite: 116, 117]
            s.sendall(request.encode()) [cite: 117]
            response = s.recv(1024).decode('utf-8', errors='ignore') [cite: 117]
            return "P3P" in response or response.startswith("HTTP/1.") [cite: 117]
    except Exception as e: [cite: 117]
        logging.debug(f"P3P URL {url} 检查失败：{e}") [cite: 117]
        return False [cite: 117]

def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT): [cite: 117]
    """检查单个频道的有效性和速度，并记录失败状态以便跳过。""" [cite: 117]
    current_time = datetime.now() [cite: 118]
    current_url_state = url_states.get(url, {}) [cite: 118]

    if 'stream_check_failed_at' in current_url_state: [cite: 118]
        last_failed_time_str = current_url_state['stream_check_failed_at'] [cite: 118]
        try: [cite: 118]
            last_failed_datetime = datetime.fromisoformat(last_failed_time_str) [cite: 118]
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600 [cite: 118]
            if time_since_failed_hours < STREAM_SKIP_FAILED_HOURS: [cite: 118]
                logging.debug(f"跳过频道 {channel_name} ({url})，因为在冷却期 ({STREAM_SKIP_FAILED_HOURS}h) 内检测失败。上次失败于 {last_failed_time_str}，已过 {time_since_failed_hours:.2f}h。") [cite: 118]
                return None, False [cite: 119]
        except ValueError: [cite: 119]
            logging.warning(f"无法解析 URL {url} 的失败时间戳：{last_failed_time_str}") [cite: 119]
            pass [cite: 119]

    start_time = time.time() [cite: 119]
    is_valid = False [cite: 119]
    protocol_checked = False [cite: 119]

    try: [cite: 119]
        if url.startswith("http"): [cite: 119]
            is_valid = check_http_url(url, timeout) [cite: 119]
            protocol_checked = True [cite: 120]
        elif url.startswith("p3p"): [cite: 120]
            is_valid = check_p3p_url(url, timeout) [cite: 120]
            protocol_checked = True [cite: 120]
        elif url.startswith("rtmp"): [cite: 120]
            is_valid = check_rtmp_url(url, timeout) [cite: 120]
            protocol_checked = True [cite: 120]
        elif url.startswith("rtp"): [cite: 120]
            is_valid = check_rtp_url(url, timeout) [cite: 120]
            protocol_checked = True [cite: 121]
        else: [cite: 121]
            logging.debug(f"频道 {channel_name} 的协议不受支持：{url}") [cite: 121]
            if url not in url_states: [cite: 121]
                url_states[url] = {} [cite: 121]
            url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat() [cite: 121]
            url_states[url].pop('stream_check_failed_at', None) [cite: 121]
            url_states[url].pop('stream_fail_count', None) [cite: 122]
            url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 122]
            return None, False [cite: 122]

        elapsed_time = (time.time() - start_time) * 1000 [cite: 122]

        if is_valid: [cite: 122]
            if url not in url_states: [cite: 122]
                url_states[url] = {} [cite: 123]
            url_states[url].pop('stream_check_failed_at', None) [cite: 123]
            url_states[url].pop('stream_fail_count', None) [cite: 123]
            url_states[url]['last_successful_stream_check'] = current_time.isoformat() [cite: 123]
            url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 123]
            logging.debug(f"频道 {channel_name} ({url}) 检测成功，耗时 {elapsed_time:.0f} 毫秒。") [cite: 123]
            return elapsed_time, True [cite: 123]
        else: [cite: 124]
            if url not in url_states: [cite: 124]
                url_states[url] = {} [cite: 124]
            url_states[url]['stream_check_failed_at'] = current_time.isoformat() [cite: 124]
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 [cite: 124]
            url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 124]
            logging.debug(f"频道 {channel_name} ({url}) 检测失败。") [cite: 124]
            return None, False [cite: 124]
    except Exception as e: [cite: 125]
        if url not in url_states: [cite: 125]
            url_states[url] = {} [cite: 125]
        url_states[url]['stream_check_failed_at'] = current_time.isoformat() [cite: 125]
        url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 [cite: 125]
        url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 125]
        logging.debug(f"检查频道 {channel_name} ({url}) 时发生错误：{e}") [cite: 125]
        return None, False [cite: 125]

def process_single_channel_line(channel_line, url_states): [cite: 125]
    """处理单行频道数据，进行有效性检查。""" [cite: 125]
    if "://" not in channel_line: [cite: 126]
        logging.debug(f"跳过无效频道行（无协议）：{channel_line}") [cite: 126]
        return None, None [cite: 126]
    parts = channel_line.split(',', 1) [cite: 126]
    if len(parts) == 2: [cite: 126]
        name, url = parts [cite: 126]
        url = url.strip() [cite: 126]
        # 即使检查失败，也返回频道信息，以便后续决定是否保留
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states) [cite: 126]
        return elapsed_time, f"{name},{url}", is_valid
    return None, None, False # Added False for consistency

def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG.get('channel_check_workers', 200)): [cite: 126]
    """多线程检查频道有效性。""" [cite: 127]
    results = [] [cite: 127]
    checked_count = 0 [cite: 127]
    total_channels = len(channel_lines) [cite: 127]
    logging.warning(f"开始多线程频道有效性和速度检测，总计 {total_channels} 个频道...") [cite: 127]
    with ThreadPoolExecutor(max_workers=max_workers) as executor: [cite: 127]
        futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines} [cite: 127]
        for future in as_completed(futures): [cite: 127]
            checked_count += 1 [cite: 127]
            if checked_count % 100 == 0: [cite: 127]
                logging.warning(f"已检查 {checked_count}/{total_channels} 个频道...") [cite: 128]
            try: [cite: 128]
                elapsed_time, result_line, is_valid = future.result() # Modified to get is_valid
                # 无论是否有效，都添加到结果中，后续再根据状态筛选
                results.append((elapsed_time, result_line, is_valid))
            except Exception as exc: [cite: 129]
                logging.warning(f"频道行处理期间发生异常：{exc}") [cite: 129]

    return results [cite: 129]

# --- 文件合并和排序函数 ---
def write_sorted_channels_to_file(file_path, data_list): [cite: 129]
    """将排序后的频道数据写入文件。""" [cite: 129]
    with open(file_path, 'w', encoding='utf-8') as file: [cite: 129]
        for item in data_list: [cite: 130]
            file.write(item[1] + '\n') [cite: 130]

def sort_cctv_channels(channels): [cite: 130]
    """对央视频道进行数字排序。""" [cite: 130]
    def channel_key(channel_line): [cite: 130]
        channel_name_full = channel_line.split(',')[0].strip() [cite: 130]
        match = re.search(r'\d+', channel_name_full) [cite: 130]
        if match: [cite: 130]
            return int(match.group()) [cite: 130]
        return float('inf') [cite: 130]

    return sorted(channels, key=channel_key) [cite: 130]

def generate_update_time_header(): [cite: 130]
    """生成文件顶部的更新时间信息。""" [cite: 131]
    now = datetime.now() [cite: 131]
    return [ [cite: 131]
        f"更新时间,#genre#\n", [cite: 131]
        f"{now.strftime('%Y-%m-%d')},url\n", [cite: 131]
        f"{now.strftime('%H:%M:%S')},url\n" [cite: 131]
    ] [cite: 131]

def group_and_limit_channels(lines): [cite: 131]
    """对频道进行分组并限制每个频道名称下的 URL 数量。""" [cite: 131]
    grouped_channels = {} [cite: 131]
    for line_content in lines: [cite: 131]
        line_content = line_content.strip() [cite: 131]
        if line_content: [cite: 131]
            channel_name = line_content.split(',', 1)[0].strip() [cite: 131]
            if channel_name not in grouped_channels: [cite: 132]
                grouped_channels[channel_name] = [] [cite: 132]
            grouped_channels[channel_name].append(line_content) [cite: 132]

    final_grouped_lines = [] [cite: 132]
    for channel_name in grouped_channels: [cite: 132]
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]: [cite: 132]
            final_grouped_lines.append(ch_line + '\n') [cite: 132]
    return final_grouped_lines [cite: 132]

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt"): [cite: 132]
    """合并本地生成的频道列表文件。""" [cite: 132]
    final_output_lines = [] [cite: 133]
    final_output_lines.extend(generate_update_time_header()) [cite: 133]

    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')] [cite: 133]

    files_to_merge_paths = [] [cite: 133]
    processed_files = set() [cite: 133]

    for category in ORDERED_CATEGORIES: [cite: 133]
        file_name = f"{category}_iptv.txt" [cite: 133]
        if file_name in all_iptv_files_in_dir and file_name not in processed_files: [cite: 133]
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name)) [cite: 133]
            processed_files.add(file_name) [cite: 134]

    for file_name in sorted(all_iptv_files_in_dir): [cite: 134]
        if file_name not in processed_files: [cite: 134]
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name)) [cite: 134]
            processed_files.add(file_name) [cite: 134]

    for file_path in files_to_merge_paths: [cite: 134]
        with open(file_path, "r", encoding="utf-8") as file: [cite: 134]
            lines = file.readlines() [cite: 134]
            if not lines: [cite: 134]
                continue [cite: 134]

            header = lines[0].strip() [cite: 134]
            if '#genre#' in header: [cite: 134]
                final_output_lines.append(header + '\n') [cite: 135]
                final_output_lines.extend(group_and_limit_channels(lines[1:])) [cite: 135]
            else: [cite: 135]
                logging.warning(f"文件 {file_path} 未以类别标题开头。跳过。") [cite: 135]

    iptv_list_file_path = output_file_name [cite: 135]
    with open(iptv_list_file_path, "w", encoding='utf-8') as iptv_list_file: [cite: 135]
        iptv_list_file.writelines(final_output_lines) [cite: 136]

    logging.warning(f"\n所有区域频道列表文件已合并。输出已保存到：{iptv_list_file_path}") [cite: 136]

# --- 远程 TXT 文件操作函数 ---
def read_txt_to_array_remote(file_path_in_repo): [cite: 136]
    """从远程 GitHub 仓库的 TXT 文件读取内容到数组。""" [cite: 136]
    content = fetch_from_github(file_path_in_repo) [cite: 136]
    if content: [cite: 136]
        lines = content.split('\n') [cite: 136]
        return [line.strip() for line in lines if line.strip()] [cite: 136]
    return [] [cite: 136]

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message): [cite: 136]
    """将数组内容写入远程 GitHub 仓库的 TXT 文件。""" [cite: 136]
    content = '\n'.join(data_array) [cite: 136]
    success = save_to_github(file_path_in_repo, content, commit_message) [cite: 136]
    if not success: [cite: 137]
        logging.error(f"将数据写入远程 '{file_path_in_repo}' 失败。") [cite: 137]

# --- GitHub URL 自动发现函数 ---
def auto_discover_github_urls(urls_file_path_remote, github_token): [cite: 137]
    """自动从 GitHub 发现新的 IPTV 源 URL，并记录每个关键词找到的 URL 数量。""" [cite: 137]
    if not github_token: [cite: 137]
        logging.warning("环境变量 'BOT' 未设置。跳过 GitHub URL 自动发现。") [cite: 137]
        return [cite: 137]

    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote)) [cite: 137]
    found_urls = set() [cite: 137]
    headers = { [cite: 137]
        "Accept": "application/vnd.github.v3.text-match+json", [cite: 137]
        "Authorization": f"token {github_token}" [cite: 137]
    } [cite: 138]

    logging.warning("正在开始从 GitHub 自动发现新的 IPTV 源 URL...") [cite: 138]

    # 记录每个关键词找到的 URL 数量
    keyword_url_counts = {keyword: 0 for keyword in SEARCH_KEYWORDS} [cite: 138]

    for i, keyword in enumerate(SEARCH_KEYWORDS): [cite: 138]
        keyword_found_urls = set()  # 记录当前关键词找到的 URL
        if i > 0: [cite: 138]
            logging.warning(f"切换到下一个关键词：'{keyword}'。等待 {GITHUB_API_RETRY_WAIT} 秒以避免速率限制...") [cite: 138]
            time.sleep(GITHUB_API_RETRY_WAIT) [cite: 138]

        page = 1 [cite: 138]
        while page <= MAX_SEARCH_PAGES: [cite: 139]
            params = { [cite: 139]
                "q": keyword, [cite: 139]
                "sort": "indexed", [cite: 139]
                "order": "desc", [cite: 139]
                "per_page": PER_PAGE, [cite: 139]
                "page": page [cite: 140]
            } [cite: 140]
            try: [cite: 140]
                response = session.get( [cite: 140]
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}", [cite: 140]
                    headers=headers, [cite: 140]
                    params=params, [cite: 140]
                    timeout=GITHUB_API_TIMEOUT [cite: 140]
                ) [cite: 141]
                response.raise_for_status() [cite: 141]
                data = response.json() [cite: 141]

                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0)) [cite: 141]
                rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0)) [cite: 141]

                if rate_limit_remaining == 0: [cite: 141]
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5 [cite: 142]
                    logging.warning(f"GitHub API 速率限制已达到！剩余请求：0。等待 {wait_seconds:.0f} 秒后重试。") [cite: 142]
                    time.sleep(wait_seconds) [cite: 142]
                    continue [cite: 142]

                if not data.get('items'): [cite: 142]
                    logging.debug(f"在关键词 '{keyword}' 的第 {page} 页上未找到更多结果。") [cite: 143]
                    break [cite: 143]

                for item in data['items']: [cite: 143]
                    html_url = item.get('html_url', '') [cite: 143]
                    raw_url = None [cite: 143]

                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url) [cite: 143, 144]
                    if match: [cite: 144]
                        user = match.group(1) [cite: 144]
                        repo = match.group(2) [cite: 144]
                        branch = match.group(3) [cite: 144]
                        path = match.group(4) [cite: 145]
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}" [cite: 145]

                    if raw_url: [cite: 145]
                        cleaned_url = clean_url_params(raw_url) [cite: 145]
                        if cleaned_url.startswith("https://raw.githubusercontent.com/") and \
                           cleaned_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and \
                           pre_screen_url(cleaned_url): [cite: 146, 147]
                            found_urls.add(cleaned_url) [cite: 147]
                            keyword_found_urls.add(cleaned_url) [cite: 147]
                            logging.debug(f"已发现原始 GitHub URL（通过预筛选）：{cleaned_url}") [cite: 147]
                        else: [cite: 147]
                            logging.debug(f"正在跳过非原始 GitHub M3U/M3U8/TXT 链接或未通过预筛选：{raw_url}") [cite: 148]
                    else: [cite: 148]
                        logging.debug(f"无法从 HTML URL 构造原始 URL：{html_url}") [cite: 148]

                if len(data['items']) < PER_PAGE: [cite: 148]
                    break [cite: 149]

                page += 1 [cite: 149]
                time.sleep(2) [cite: 149]

            except requests.exceptions.RequestException as e: [cite: 149]
                logging.error(f"GitHub API 请求失败（关键词：{keyword}，页码：{page}）：{e}") [cite: 149]
                if response.status_code == 403: [cite: 150]
                    rate_limit_reset_time = int(response.headers.get('X-RateLimit-Reset', 0)) [cite: 150]
                    wait_seconds = max(0, rate_limit_reset_time - time.time()) + 5 [cite: 150]
                    logging.warning(f"GitHub API 速率限制已达到！等待 {wait_seconds:.0f} 秒后重试。") [cite: 150]
                    time.sleep(wait_seconds) [cite: 150]
                    continue [cite: 151]
                else: [cite: 151]
                    break [cite: 151]
            except Exception as e: [cite: 151]
                logging.error(f"GitHub URL 自动发现期间发生未知错误：{e}") [cite: 151]
                break [cite: 151]

    # 记录当前关键词找到的 URL 数量
    keyword_url_counts[keyword] = len(keyword_found_urls) [cite: 152]
    logging.warning(f"关键词 '{keyword}' 找到 {keyword_url_counts[keyword]} 个有效 URL。") [cite: 152]

    # 总结每个关键词的 URL 数量并建议删除无效关键词
    logging.warning("\n=== 关键词搜索结果总结 ===") [cite: 152]
    low_result_threshold = 5  # 定义结果较少的阈值
    low_or_no_result_keywords = [] [cite: 152]
    for keyword, count in keyword_url_counts.items(): [cite: 152]
        logging.warning(f"关键词 '{keyword}'：{count} 个 URL") [cite: 153]
        if count <= low_result_threshold: [cite: 153]
            low_or_no_result_keywords.append((keyword, count)) [cite: 153]

    if low_or_no_result_keywords: [cite: 153]
        logging.warning(f"\n建议从 config.yaml 的 search_keywords 中删除以下结果较少（≤{low_result_threshold}）或无结果的关键词，以节省时间和 API 请求：") [cite: 153]
        for keyword, count in low_or_no_result_keywords: [cite: 153]
            logging.warning(f"  - '{keyword}' （找到 {count} 个 URL）") [cite: 154]
    else: [cite: 154]
        logging.warning("所有关键词均有合理数量的搜索结果，无需删除。") [cite: 154]

    new_urls_count = 0 [cite: 154]
    for url in found_urls: [cite: 154]
        if url not in existing_urls: [cite: 154]
            existing_urls.add(url) [cite: 154]
            new_urls_count += 1 [cite: 154]

    if new_urls_count > 0: [cite: 154]
        updated_urls = list(existing_urls) [cite: 154]
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "通过 GitHub 发现的新 URL 更新 urls.txt") [cite: 154]
        logging.warning(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URL 到 {urls_file_path_remote}。总 URL 数：{len(updated_urls)}") [cite: 155]
    else: [cite: 155]
        logging.warning("未发现新的 GitHub IPTV 源 URL。") [cite: 155]

    logging.warning("GitHub URL 自动发现完成。") [cite: 155]

# --- 主程序逻辑 ---
def main(): [cite: 155]
    # 步骤 1: 自动发现新的 GitHub URL
    auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN) [cite: 155]

    # 步骤 2: 读取所有待处理的 URL
    urls = read_txt_to_array_remote(URLS_PATH_IN_REPO) [cite: 155]
    if not urls: [cite: 155]
        logging.warning(f"在远程 '{URLS_PATH_IN_REPO}' 中未找到 URL，脚本将提前退出。") [cite: 155]
        return [cite: 156]

    # 步骤 3: 加载历史 URL 状态
    url_states = load_url_states_remote() [cite: 156]
    logging.warning(f"已加载 {len(url_states)} 个历史 URL 状态。") [cite: 156]

    # 步骤 4: 从所有源提取频道，并更新 URL 内容状态
    all_extracted_channels = set() [cite: 156]
    with ThreadPoolExecutor(max_workers=5) as executor: [cite: 156]
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls} [cite: 156]
        for future in as_completed(future_to_url): [cite: 156]
            url = future_to_url[future] [cite: 156]
            try: [cite: 156]
                result_channels = future.result() [cite: 157]
                for name, addr in result_channels: [cite: 157]
                    all_extracted_channels.add((name, addr)) [cite: 157]
            except Exception as exc: [cite: 157]
                logging.error(f"处理源 '{url}' 时发生异常：{exc}") [cite: 157]

    # 步骤 5: 保存更新后的 URL 内容状态
    save_url_states_remote(url_states) [cite: 158]
    logging.warning(f"\n从所有源提取了 {len(all_extracted_channels)} 个原始频道。") [cite: 158]

    # 步骤 6: 过滤和清理频道
    filtered_channels = filter_and_modify_channels(list(all_extracted_channels)) [cite: 158]
    # unique_filtered_channels 包含了所有经过预筛选、黑名单过滤和名称替换的频道
    unique_filtered_channels = list(set(filtered_channels)) [cite: 158]
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels] [cite: 158]

    logging.warning(f"\n过滤和清理后，剩余 {len(unique_filtered_channels_str)} 个唯一频道。") [cite: 158]

    # 步骤 7: 多线程检查频道有效性及速度
    # 这里的 valid_channels_with_speed 包含了 (elapsed_time, channel_line, is_valid)
    checked_channels_data = check_channels_multithreaded(unique_filtered_channels_str, url_states) [cite: 158]
    
    # NEW: Filter channels based on validity and historical data from url_states
    final_valid_channels = []
    for elapsed_time, channel_line, is_valid in checked_channels_data:
        if channel_line is None:
            continue
        
        name, url = channel_line.split(',', 1)
        url = url.strip()
        
        current_state = url_states.get(url, {})
        # Decide whether to include a channel. For "append" mode, we might want to be less strict.
        # Option A: Only include if currently valid (original behavior)
        # if is_valid:
        #    final_valid_channels.append((elapsed_time, channel_line))
        
        # Option B: Include if currently valid OR if it was previously valid and not failed too many times
        # This is a more "append" like approach, trying to retain channels unless they are consistently bad.
        # You can adjust STREAM_FAIL_THRESHOLD in config or directly here.
        STREAM_FAIL_THRESHOLD = CONFIG.get('stream_fail_threshold', 3) # Example: Add to your config.yaml
        if is_valid or (current_state.get('last_successful_stream_check') and \
                        current_state.get('stream_fail_count', 0) < STREAM_FAIL_THRESHOLD):
            final_valid_channels.append((elapsed_time, channel_line))
        elif 'last_successful_stream_check' in current_state and \
             (datetime.now() - datetime.fromisoformat(current_state['last_successful_stream_check'])).total_seconds() / 3600 < CONFIG.get('stream_retention_hours', 72): # Example: Retain for 72 hours even if temporarily down
             final_valid_channels.append((elapsed_time, channel_line))

    # Sort final_valid_channels by speed (elapsed_time)
    final_valid_channels.sort(key=lambda x: x[0] if x[0] is not None else float('inf'))

    logging.warning(f"最终将包含在列表中的有效且响应的频道数量：{len(final_valid_channels)}")

    # 步骤 8: 保存所有频道检测后的最新状态
    save_url_states_remote(url_states) [cite: 158]
    logging.warning("频道检测状态已保存到远程。") [cite: 158]

    # 步骤 9: 将有效频道写入临时文件
    # Note: This file will contain all channels decided to be included based on the new logic.
    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt') [cite: 159]
    write_sorted_channels_to_file(iptv_speed_file_path, final_valid_channels) [cite: 159]

    # 步骤 10: 准备本地频道目录和模板
    local_channels_directory = os.path.join(os.getcwd(), '地方频道') [cite: 159]
    os.makedirs(local_channels_directory, exist_ok=True) [cite: 159]
    # 清空目录中的 TXT 文件，这样每次运行都会重新生成分类文件，但最终合并时可以根据需求决定是否追加
    clear_directory_txt_files(local_channels_directory) [cite: 159]

    template_directory = os.path.join(os.getcwd(), '频道模板') [cite: 159]
    os.makedirs(template_directory, exist_ok=True) [cite: 159]
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')] [cite: 159]

    channels_for_matching = read_txt_to_array_local(iptv_speed_file_path) [cite: 159]

    all_template_channel_names = set() [cite: 159]
    for template_file in template_files: [cite: 159]
        names_from_current_template = read_txt_to_array_local(os.path.join(template_directory, template_file)) [cite: 159]
        all_template_channel_names.update(names_from_current_template) [cite: 159]

    # 步骤 11: 根据模板分类和写入频道文件
    for template_file in template_files: [cite: 159]
        template_channels_names = set(read_txt_to_array_local(os.path.join(template_directory, template_file))) [cite: 159]
        template_name = os.path.splitext(template_file)[0] [cite: 160]

        current_template_matched_channels = [] [cite: 160]
        for channel_line in channels_for_matching: [cite: 160]
            channel_name = channel_line.split(',', 1)[0].strip() [cite: 160]
            if channel_name in template_channels_names: [cite: 160]
                current_template_matched_channels.append(channel_line) [cite: 160]

        if "央视" in template_name or "CCTV" in template_name: [cite: 160]
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels) [cite: 160]
            logging.warning(f"已按数字对 '{template_name}' 频道进行排序。") [cite: 161]

        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt") [cite: 161]
        with open(output_file_path, 'w', encoding='utf-8') as f: [cite: 161]
            f.write(f"{template_name},#genre#\n") [cite: 161]
            for channel in current_template_matched_channels: [cite: 161]
                f.write(channel + '\n') [cite: 161]
        logging.warning(f"频道列表已写入：'{template_name}_iptv.txt'，包含 {len(current_template_matched_channels)} 个频道。") [cite: 161]

    # 步骤 12: 合并所有分类的频道文件，生成最终 IPTV 列表
    final_iptv_list_output_file = "iptv_list.txt" [cite: 161]
    # merge_local_channel_files 已经使用 'w' 模式写入，会覆盖。
    # 如果要实现“追加”，则需要更复杂的逻辑，例如先读取远程的iptv_list.txt，然后合并所有当前有效的频道，并去除重复项。
    # 但通常情况下，最终的iptv_list.txt应该是最新有效频道列表，而不是不断追加所有历史频道。
    # 这里保持其现有逻辑，即每次生成最新的有效列表。
    merge_local_channel_files(local_channels_directory, final_iptv_list_output_file) [cite: 162]

    # 步骤 13: 上传最终的 IPTV 列表到 GitHub
    try: [cite: 162]
        with open(final_iptv_list_output_file, "r", encoding="utf-8") as f: [cite: 162]
            final_iptv_content = f.read() [cite: 162]
        # save_to_github 函数本身就是“覆盖或创建”模式，通过 SHA 值来判断是否是更新。
        # 如果你想的是“追加”到 GitHub 上的现有文件，那就需要先 fetch_from_github 读取文件内容，然后将新内容追加到读取的内容中，再保存。
        # 但对于 iptv_list.txt，通常期望它是一个最新的、经过筛选和验证的列表，而不是一个不断增长的累积列表。
        # 因此，这里的 save_to_github 保持原样，它会上传最新的完整列表。
        save_to_github(f"output/{final_iptv_list_output_file}", final_iptv_content, "更新最终 IPTV 列表") [cite: 162]
        logging.warning(f"已将 {final_iptv_list_output_file} 推送到远程仓库。") [cite: 162]
    except Exception as e: [cite: 162]
        logging.error(f"无法将 {final_iptv_list_output_file} 推送到 GitHub：{e}") [cite: 163]

    # 步骤 14: 找出并保存未匹配的频道名称
    unmatched_channels_list = [] [cite: 163]
    for channel_line in channels_for_matching: [cite: 163]
        channel_name = channel_line.split(',', 1)[0].strip() [cite: 163]
        if channel_name not in all_template_channel_names: [cite: 163]
            unmatched_channels_list.append(channel_line) [cite: 163]

    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt') [cite: 163]
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f: [cite: 164]
        for channel_line in unmatched_channels_list: [cite: 164]
            f.write(channel_line.split(',')[0].strip() + '\n') [cite: 164]
    logging.warning(f"\n已保存不匹配但已检测到的频道列表到：'{unmatched_output_file_path}'，总共 {len(unmatched_channels_list)} 个频道。") [cite: 164]

    # 步骤 15: 清理临时文件
    try: [cite: 164]
        if os.path.exists('iptv.txt'): [cite: 164]
            os.remove('iptv.txt') [cite: 164]
            logging.debug(f"已删除临时文件 'iptv.txt'。") [cite: 164]
        if os.path.exists('iptv_speed.txt'): [cite: 164]
            os.remove('iptv_speed.txt') [cite: 164]
            logging.debug(f"已删除临时文件 'iptv_speed.txt'。") [cite: 164]
    except OSError as e: [cite: 164]
        logging.warning(f"删除临时文件时发生错误：{e}") [cite: 164]

if __name__ == "__main__": [cite: 164]
    main()
