import os
import re
import subprocess
import socket
import time
from datetime import datetime
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

# 配置日志
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# 从环境变量获取配置
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')

# 检查环境变量是否设置
if not GITHUB_TOKEN:
    logging.error("错误：环境变量 'BOT' 未设置。")
    exit(1)
if not REPO_OWNER:
    logging.error("错误：环境变量 'REPO_OWNER' 未设置。")
    exit(1)
if not REPO_NAME:
    logging.error("错误：环境变量 'REPO_NAME' 未设置。")
    exit(1)
if not CONFIG_PATH_IN_REPO:
    logging.error("错误：环境变量 'CONFIG_PATH' 未设置。")
    exit(1)
if not URLS_PATH_IN_REPO:
    logging.error("错误：环境变量 'URLS_PATH' 未设置。")
    exit(1)
if not URL_STATES_PATH_IN_REPO:
    logging.error("错误：环境变量 'URL_STATES_PATH' 未设置。")
    exit(1)

# GitHub 仓库的基础 URL
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

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
        logging.error(f"从 GitHub 获取 {file_path_in_repo} 发生错误：{e}")
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
        logging.debug(f"获取 {file_path_in_repo} 的 SHA 发生错误（可能不存在）：{e}")
        return None

def save_to_github(file_path_in_repo, content, commit_message):
    """将内容保存（创建或更新）到 GitHub 仓库。"""
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
        logging.error(f"GitHub API 响应：{response.text if 'response' in locals() else 'N/A'}")
        return False

def load_config():
    """从 GitHub 仓库加载并解析 YAML 配置文件。"""
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"错误：远程配置文件 '{CONFIG_PATH_IN_REPO}' 中的 YAML 无效：{e}")
            exit(1)
        except Exception as e:
            logging.error(f"加载远程配置文件 '{CONFIG_PATH_IN_REPO}' 发生错误：{e}")
            exit(1)
    logging.error(f"无法从 GitHub 的 '{CONFIG_PATH_IN_REPO}' 加载配置。")
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
STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24) # 新增：跳过失败视频流的冷却时间（小时）

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
        logging.warning(f"文件 '{file_name}' 未找到。")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 发生错误：{e}")
        return []

def write_array_to_txt_local(file_name, data_array):
    """将数组内容写入本地 TXT 文件。"""
    try:
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 发生错误：{e}")

# --- URL 处理和频道提取函数 ---
def get_url_file_extension(url):
    """获取 URL 的文件扩展名。"""
    parsed_url = urlparse(url)
    extension = os.path.splitext(parsed_url.path)[1].lower()
    return extension

def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式内容转换为 TXT 格式（频道名,URL）。"""
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
    """清理 URL 参数，只保留协议、域名和路径。"""
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

# --- URL 状态管理函数 ---
def load_url_states_remote():
    """从远程加载 URL 状态 JSON 文件。"""
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"解码远程 '{URL_STATES_PATH_IN_REPO}' 中的 JSON 发生错误：{e}。将从空状态开始。")
            return {}
    return {}

def save_url_states_remote(url_states):
    """保存 URL 状态到远程 JSON 文件。"""
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        success = save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态")
        if not success:
            logging.error(f"将远程 URL 状态保存到 '{URL_STATES_PATH_IN_REPO}' 发生错误。")
    except Exception as e:
        logging.error(f"将 URL 状态保存到远程 '{URL_STATES_PATH_IN_REPO}' 发生错误：{e}")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
    """
    尝试获取 URL 内容，带重试机制，并利用 ETag/Last-Modified/Content-Hash 避免重复下载。
    会更新 url_states 中的 etag, last_modified, content_hash 和 last_checked。
    """
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
            logging.debug(f"URL 内容 {url} 未修改 (304)。跳过下载。")
            # 即使304，也更新 last_checked
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None # 表示内容未更新，无需处理

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL 内容 {url} 基于哈希是相同的。跳过下载。")
            # 即使哈希相同，也更新 last_checked
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None # 表示内容未更新，无需处理

        # 内容有更新，保存新状态
        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }
        # 注意: 这里不立即保存 url_states_remote，因为提取多个 URL 后统一保存更高效。
        # 实际保存会在 main 函数中进行。

        logging.debug(f"成功获取 URL：{url} 的新内容。内容已更新。")
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"获取 URL (重试后) 发生请求错误：{url} - {e}")
        return None
    except Exception as e:
        logging.error(f"获取 URL 发生未知错误：{url} - {e}")
        return None

def extract_channels_from_url(url, url_states):
    """从给定的 URL 中提取频道。"""
    extracted_channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states)
        if text is None: # 内容未更新或获取失败
            return []

        if get_url_file_extension(url) in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)

        lines = text.split('\n')
        channel_count = 0
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
                            channel_count += 1
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url:
                        extracted_channels.append((channel_name, channel_url))
                        channel_count += 1
        logging.debug(f"成功从 URL：{url} 中提取 {channel_count} 个频道。")
    except Exception as e:
        logging.error(f"从 {url} 提取频道时发生错误：{e}")
    return extracted_channels

def pre_screen_url(url):
    """预筛选 URL，根据配置检查协议、长度和无效模式。"""
    if not isinstance(url, str) or not url:
        return False

    parsed_url = urlparse(url)

    if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
        return False

    if not parsed_url.netloc:
        return False

    invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
    for pattern in compiled_invalid_url_patterns:
        if pattern.search(url):
            logging.debug(f"预筛选过滤（无效模式）：{url}")
            return False

    if len(url) < 15: # 简单的长度过滤，避免异常短链接
        return False

    return True

def filter_and_modify_channels(channels):
    """过滤和修改频道名称及 URL。"""
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        if not pre_screen_url(url):
            logging.debug(f"正在过滤频道（预筛选失败）：{name},{url}")
            continue
        pre_screened_count += 1

        if any(word in url for word in CONFIG.get('url_filter_words', [])):
            logging.debug(f"正在过滤频道（URL 匹配黑名单）：{name},{url}")
            continue

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            logging.debug(f"正在过滤频道（名称匹配黑名单）：{name},{url}")
            continue

        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    logging.debug(f"URL 预筛选后，剩余 {pre_screened_count} 个频道等待进一步过滤。")
    return filtered_channels

# --- 频道有效性检查函数 ---
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达。"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} 检查失败：{e}")
        return False

def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达（需要 ffprobe）。"""
    try:
        # 尝试运行 ffprobe -h 来检查是否安装且可用
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("未找到 ffprobe 或其无法工作。RTMP 流检查已跳过。")
        return False # ffprobe 不可用，直接返回 False
    try:
        # 使用 ffprobe 检查 RTMP 流
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} 检查超时")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} 检查错误：{e}")
        return False

def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达（通过 UDP 尝试连接）。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.debug(f"RTP URL {url} 解析失败：缺少主机或端口。")
            return False

        # RTP 通常使用 UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # 发送一个空包，尝试触发响应（有些服务器可能不响应空包，但连接本身是验证）
            s.sendto(b'', (host, port))
            # 尝试接收一个字节，如果成功则认为可达
            s.recv(1)
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL {url} 检查失败：{e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} 检查错误：{e}")
        return False

def check_p3p_url(url, timeout):
    """检查 P3P URL 是否可达（简单 TCP 连接和 HTTP 响应头检查）。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80 # P3P 通常是 HTTP 端口
        path = parsed_url.path if parsed_url.path else '/'

        if not host:
            logging.debug(f"P3P URL {url} 解析失败：缺少主机。")
            return False

        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            # 检查响应中是否包含 P3P 头部或是一个有效的 HTTP 响应开头
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} 检查失败：{e}")
        return False

def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT):
    """
    检查单个频道的有效性和速度，并记录失败状态以便跳过。
    参数:
        channel_name (str): 频道名称。
        url (str): 频道 URL。
        url_states (dict): 存储所有 URL 状态的字典，用于读写。
        timeout (int): 检查超时时间。
    返回:
        tuple: (elapsed_time, is_valid) 如果有效则返回响应时间，否则返回 None。
    """
    current_time = datetime.now()
    
    # 获取该 URL 的当前状态
    current_url_state = url_states.get(url, {})

    # ===== 新增逻辑：检查是否需要跳过 =====
    if 'stream_check_failed_at' in current_url_state:
        last_failed_time_str = current_url_state['stream_check_failed_at']
        try:
            last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
            # 检查距离上次失败是否在冷却期内
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
            if time_since_failed_hours < STREAM_SKIP_FAILED_HOURS:
                logging.debug(f"跳过频道 {channel_name} ({url})，因为在冷却期 ({STREAM_SKIP_FAILED_HOURS}h) 内检测失败。上次失败于 {last_failed_time_str}，已过 {time_since_failed_hours:.2f}h。")
                return None, False # 跳过检测，返回无效
        except ValueError:
            logging.warning(f"无法解析 URL {url} 的失败时间戳：{last_failed_time_str}")
            # 如果时间戳格式错误，继续检测 (或选择直接跳过)
            pass

    start_time = time.time()
    is_valid = False
    protocol_checked = False # 标记是否进行了协议检查

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
            logging.debug(f"频道 {channel_name} 的协议不受支持：{url}")
            # 更新状态为不支持的协议，不计入失败计数
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat()
            # 清除之前的失败记录，因为它不是真正的“失败”
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_stream_checked'] = current_time.isoformat() # 记录最后检测时间
            return None, False

        elapsed_time = (time.time() - start_time) * 1000

        # ===== 新增逻辑：更新成功/失败状态 =====
        if is_valid:
            if url not in url_states:
                url_states[url] = {}
            # 成功了就清除失败记录
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_successful_stream_check'] = current_time.isoformat()
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.debug(f"频道 {channel_name} ({url}) 检测成功，耗时 {elapsed_time:.0f} 毫秒。")
            return elapsed_time, True
        else:
            # 失败了，记录失败时间并增加失败次数
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.debug(f"频道 {channel_name} ({url}) 检测失败。")
            return None, False
    except Exception as e:
        # 异常也视为失败
        if url not in url_states:
            url_states[url] = {}
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
        url_states[url]['last_stream_checked'] = current_time.isoformat()
        logging.debug(f"检查频道 {channel_name} ({url}) 时发生错误：{e}")
        return None, False

def process_single_channel_line(channel_line, url_states):
    """处理单行频道数据，进行有效性检查。"""
    if "://" not in channel_line:
        logging.debug(f"跳过无效频道行（无协议）：{channel_line}")
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states) # 传递 url_states
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG.get('channel_check_workers', 200)):
    """多线程检查频道有效性。"""
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"开始多线程频道有效性和速度检测，总计 {total_channels} 个频道...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 传递 url_states 给每一个 Future
        futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines}
        for future in as_completed(futures):
            checked_count += 1
            if checked_count % 100 == 0:
                logging.warning(f"已检查 {checked_count}/{total_channels} 个频道...")
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"频道行处理期间发生异常：{exc}")

    return results

# --- 文件合并和排序函数 ---
def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道数据写入文件。"""
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    """对央视频道进行数字排序。"""
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        if match:
            return int(match.group())
        return float('inf') # 没有数字的排在最后

    return sorted(channels, key=channel_key)

def generate_update_time_header():
    """生成文件顶部的更新时间信息。"""
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
        # 限制每个频道名称下的 URL 数量
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            final_grouped_lines.append(ch_line + '\n')
    return final_grouped_lines

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt"):
    """合并本地生成的频道列表文件。"""
    final_output_lines = []
    final_output_lines.extend(generate_update_time_header())

    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]

    files_to_merge_paths = []
    processed_files = set()

    # 优先按照 ORDERED_CATEGORIES 的顺序合并
    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files_in_dir and file_name not in processed_files:
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    # 然后合并所有剩余的 _iptv.txt 文件（按字母顺序）
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

    iptv_list_file_path = output_file_name
    with open(iptv_list_file_path, "w", encoding='utf-8') as iptv_list_file:
        iptv_list_file.writelines(final_output_lines)

    logging.warning(f"\n所有区域频道列表文件已合并。输出已保存到：{iptv_list_file_path}")

# --- 远程 TXT 文件操作函数 ---
def read_txt_to_array_remote(file_path_in_repo):
    """从远程 GitHub 仓库的 TXT 文件读取内容到数组。"""
    content = fetch_from_github(file_path_in_repo)
    if content:
        lines = content.split('\n')
        return [line.strip() for line in lines if line.strip()]
    return []

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message):
    """将数组内容写入远程 GitHub 仓库的 TXT 文件。"""
    content = '\n'.join(data_array)
    success = save_to_github(file_path_in_repo, content, commit_message)
    if not success:
        logging.error(f"将数据写入远程 '{file_path_in_repo}' 失败。")

# --- GitHub URL 自动发现函数 ---
def auto_discover_github_urls(urls_file_path_remote, github_token):
    """自动从 GitHub 发现新的 IPTV 源 URL。"""
    if not github_token:
        logging.warning("环境变量 'BOT' 未设置。跳过 GitHub URL 自动发现。")
        return

    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.warning("正在开始从 GitHub 自动发现新的 IPTV 源 URL...")

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if i > 0:
            logging.warning(f"切换到下一个关键词：'{keyword}'。等待 {GITHUB_API_RETRY_WAIT} 秒以避免速率限制...")
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
                    logging.warning(f"GitHub API 速率限制已达到！剩余请求：0。等待 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    logging.debug(f"在关键词 '{keyword}' 的第 {page} 页上未找到更多结果。")
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    raw_url = None

                    # 从 html_url 构造 raw_url
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user = match.group(1)
                        repo = match.group(2)
                        branch = match.group(3)
                        path = match.group(4)
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"

                    if raw_url:
                        cleaned_url = clean_url_params(raw_url)
                        if cleaned_url.startswith("https://raw.githubusercontent.com/") and \
                           cleaned_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and \
                           pre_screen_url(cleaned_url): # 再次通过预筛选
                            found_urls.add(cleaned_url)
                            logging.debug(f"已发现原始 GitHub URL（通过预筛选）：{cleaned_url}")
                        else:
                            logging.debug(f"正在跳过非原始 GitHub M3U/M3U8/TXT 链接或未通过预筛选：{raw_url}")
                    else:
                        logging.debug(f"无法从 HTML URL 构造原始 URL：{html_url}")

                if len(data['items']) < PER_PAGE: # 如果返回的条目少于每页限制，说明已是最后一页
                    break

                page += 1
                time.sleep(2) # 页面之间的延迟，避免频繁请求

            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API 请求失败（关键词：{keyword}，页码：{page}）：{e}")
                if response.status_code == 403:
                    rate_limit_reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_seconds = max(0, rate_limit_reset_time - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制已达到！等待 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue # 重新尝试当前页面
                else:
                    break # 其他请求错误则停止当前关键词的搜索
            except Exception as e:
                logging.error(f"GitHub URL 自动发现期间发生未知错误：{e}")
                break

    new_urls_count = 0
    for url in found_urls:
        if url not in existing_urls:
            existing_urls.add(url)
            new_urls_count += 1

    if new_urls_count > 0:
        updated_urls = list(existing_urls)
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "通过 GitHub 发现的新 URL 更新 urls.txt")
        logging.warning(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URL 到 {urls_file_path_remote}。总 URL 数：{len(updated_urls)}")
    else:
        logging.warning("未发现新的 GitHub IPTV 源 URL。")

    logging.warning("GitHub URL 自动发现完成。")

# --- 主程序逻辑 ---
def main():
    # 步骤 1: 自动发现新的 GitHub URL
    auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)

    # 步骤 2: 读取所有待处理的 URL
    urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
    if not urls:
        logging.warning(f"在远程 '{URLS_PATH_IN_REPO}' 中未找到 URL，脚本将提前退出。")
        return

    # 步骤 3: 加载历史 URL 状态
    url_states = load_url_states_remote()
    logging.warning(f"已加载 {len(url_states)} 个历史 URL 状态。")

    # 步骤 4: 从所有源提取频道，并更新 URL 内容状态
    all_extracted_channels = set()
    # 使用多线程并行获取所有 URL 的内容并提取频道
    with ThreadPoolExecutor(max_workers=5) as executor: # 可以根据并发需求调整线程数
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result_channels = future.result()
                for name, addr in result_channels:
                    all_extracted_channels.add((name, addr))
            except Exception as exc:
                logging.error(f"处理源 '{url}' 时发生异常：{exc}")

    # 步骤 5: 保存更新后的 URL 内容状态 (etag, content_hash 等)
    save_url_states_remote(url_states)
    logging.warning(f"\n从所有源提取了 {len(all_extracted_channels)} 个原始频道。")

    # 步骤 6: 过滤和清理频道
    filtered_channels = filter_and_modify_channels(list(all_extracted_channels)) # 转换为列表以便过滤
    unique_filtered_channels = list(set(filtered_channels)) # 确保唯一性
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]

    logging.warning(f"\n过滤和清理后，剩余 {len(unique_filtered_channels_str)} 个唯一频道。")

    # 步骤 7: 多线程检查频道有效性及速度
    # 传递 url_states 以便 check_channel_validity_and_speed 函数可以读写状态
    valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str, url_states)
    logging.warning(f"有效且响应的频道数量：{len(valid_channels_with_speed)}")

    # 步骤 8: 保存所有频道检测后的最新状态 (包括视频流检测失败记录)
    save_url_states_remote(url_states)
    logging.warning("频道检测状态已保存到远程。")

    # 步骤 9: 将有效频道写入临时文件
    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_sorted_channels_to_file(iptv_speed_file_path, valid_channels_with_speed)

    # 步骤 10: 准备本地频道目录和模板
    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    os.makedirs(local_channels_directory, exist_ok=True)
    clear_directory_txt_files(local_channels_directory) # 清空旧的分类文件

    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True) # 确保模板目录存在
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]

    channels_for_matching = read_txt_to_array_local(iptv_speed_file_path)

    # 收集所有模板中的频道名称，以便找出未匹配的
    all_template_channel_names = set()
    for template_file in template_files:
        names_from_current_template = read_txt_to_array_local(os.path.join(template_directory, template_file))
        all_template_channel_names.update(names_from_current_template)

    # 步骤 11: 根据模板分类和写入频道文件
    for template_file in template_files:
        template_channels_names = set(read_txt_to_array_local(os.path.join(template_directory, template_file)))
        template_name = os.path.splitext(template_file)[0]

        current_template_matched_channels = []
        for channel_line in channels_for_matching:
            channel_name = channel_line.split(',', 1)[0].strip()
            if channel_name in template_channels_names:
                current_template_matched_channels.append(channel_line)

        # 特殊处理央视频道排序
        if "央视" in template_name or "CCTV" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.warning(f"已按数字对 '{template_name}' 频道进行排序。")

        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.warning(f"频道列表已写入：'{template_name}_iptv.txt'，包含 {len(current_template_matched_channels)} 个频道。")

    # 步骤 12: 合并所有分类的频道文件，生成最终 IPTV 列表
    final_iptv_list_output_file = "iptv_list.txt"
    merge_local_channel_files(local_channels_directory, final_iptv_list_output_file)

    # 步骤 13: 上传最终的 IPTV 列表到 GitHub
    try:
        with open(final_iptv_list_output_file, "r", encoding="utf-8") as f:
            final_iptv_content = f.read()
        save_to_github(f"output/{final_iptv_list_output_file}", final_iptv_content, "更新最终 IPTV 列表")
        logging.warning(f"已将 {final_iptv_list_output_file} 推送到远程仓库。")
    except Exception as e:
        logging.error(f"无法将 {final_iptv_list_output_file} 推送到 GitHub：{e}")

    # 步骤 14: 找出并保存未匹配的频道名称
    unmatched_channels_list = []
    for channel_line in channels_for_matching:
        channel_name = channel_line.split(',', 1)[0].strip()
        if channel_name not in all_template_channel_names:
            unmatched_channels_list.append(channel_line)

    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels_list:
            # 只写入频道名称，方便人工审核
            f.write(channel_line.split(',')[0].strip() + '\n')
    logging.warning(f"\n已保存不匹配但已检测到的频道列表到：'{unmatched_output_file_path}'，总共 {len(unmatched_channels_list)} 个频道。")

    # 步骤 15: 清理临时文件
    try:
        # 删除 'iptv.txt' 和 'iptv_speed.txt' (如果存在)
        if os.path.exists('iptv.txt'): # 注意：脚本中似乎没有生成 iptv.txt，但保留删除逻辑
            os.remove('iptv.txt')
            logging.debug(f"已删除临时文件 'iptv.txt'。")
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.debug(f"已删除临时文件 'iptv_speed.txt'。")
    except OSError as e:
        logging.warning(f"删除临时文件时发生错误：{e}")

if __name__ == "__main__":
    main()
