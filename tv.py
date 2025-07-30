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

# 配置日志系统，支持文件和控制台输出
def setup_logging(config):
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转以避免过大
    参数:
        config: 配置文件字典，包含日志级别和日志文件路径
    返回:
        配置好的日志记录器
    """
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # 文件处理器，支持日志文件轮转，最大10MB，保留5个备份
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    """加载并解析 YAML 配置文件
    参数:
        config_path: 配置文件路径，默认为 'config/config.yaml'
    返回:
        解析后的配置字典
    """
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
# URLS_PATH: 存储 IPTV 源 URL 的文件路径
# URL_STATES_PATH: 存储 URL 状态的文件路径
# IPTV_LIST_PATH: 最终 IPTV 列表文件路径
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
    content_cache = TTLCache(maxsize=1000, ttl=CONFIG['url_state']['cache_ttl'])

# 配置 requests 会话
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
pool_size = CONFIG['network']['requests_pool_size']
retry_strategy = Retry(
    total=3,  # 增加重试次数
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
    """记录函数执行时间的装饰器，用于性能分析
    参数:
        func: 被装饰的函数
    返回:
        包装后的函数，记录执行时间
    """
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
    """从 GitHub 仓库获取文件内容
    参数:
        file_path_in_repo: 仓库中的文件路径
    返回:
        文件内容字符串，或 None（如果失败）
    """
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = session.get(raw_url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"错误：从 GitHub 获取 {file_path_in_repo} 失败: {e}")
        return None

@performance_monitor
def get_current_sha(file_path_in_repo):
    """获取 GitHub 仓库中文件的当前 SHA 值
    参数:
        file_path_in_repo: 仓库中的文件路径
    返回:
        文件的 SHA 值，或 None（如果失败）
    """
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = session.get(api_url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"获取 {file_path_in_repo} 的 SHA 值失败（可能不存在）: {e}")
        return None

@performance_monitor
def save_to_github(file_path_in_repo, content, commit_message):
    """保存内容到 GitHub 仓库（创建或更新）
    参数:
        file_path_in_repo: 仓库中的文件路径
        content: 要保存的内容
        commit_message: 提交信息
    返回:
        布尔值，表示保存是否成功
    """
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
    """从本地 TXT 文件读取内容到数组
    参数:
        file_name: 文件路径
    返回:
        包含文件每行内容的列表
    """
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
    """读取现有频道以进行去重
    参数:
        file_path: 频道文件路径
    返回:
        包含现有频道名称和 URL 的集合
    """
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
    """将排序后的频道数据写入文件，去重
    参数:
        file_path: 输出文件路径
        data_list: 包含频道数据的列表
    """
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
        logging.debug(f"写入 {len(all_channels)} 个频道到 {file_path}")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

# --- URL 处理和频道提取函数 ---
@performance_monitor
def get_url_file_extension(url):
    """获取 URL 的文件扩展名
    参数:
        url: 要解析的 URL
    返回:
        文件扩展名（小写），或空字符串（如果失败）
    """
    try:
        parsed_url = urlparse(url)
        return os.path.splitext(parsed_url.path)[1].lower()
    except ValueError as e:
        logging.debug(f"获取 URL 扩展名失败: {url} - {e}")
        return ""

@performance_monitor
def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式转换为 TXT 格式（频道名称，URL）
    参数:
        m3u_content: M3U 文件内容
    返回:
        转换后的 TXT 格式字符串
    """
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = "未知频道"
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#EXTM3U'):
            continue
        if line.startswith('#EXTINF'):
            match = re.search(r'#EXTINF:.*?\,(.*)', line, re.IGNORECASE)
            channel_name = match.group(1).strip() or "未知频道" if match else "未知频道"
        elif re.match(r'^[a-zA-Z0-9+.-]+://', line) and not line.startswith('#'):
            txt_lines.append(f"{channel_name},{line}")
        channel_name = "未知频道"
    return '\n'.join(txt_lines)

@performance_monitor
def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径
    参数:
        url: 要清理的 URL
    返回:
        清理后的 URL 字符串
    """
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.debug(f"清理 URL 参数失败: {url} - {e}")
        return url

@performance_monitor
def extract_channels_from_url(url, url_states, source_tracker):
    """从 URL 提取频道，支持多种文件格式
    参数:
        url: 要提取频道的 URL
        url_states: URL 状态字典
        source_tracker: 跟踪频道来源的字典
    返回:
        提取的频道列表
    """
    extracted_channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states)
        if text is None:
            return []

        extension = get_url_file_extension(url).lower()
        if extension in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)
        elif extension in [".ts", ".flv", ".mp4", ".hls", ".dash"]:
            channel_name = f"Stream_{os.path.basename(urlparse(url).path)}"
            if pre_screen_url(url):
                extracted_channels.append((channel_name, url))
                source_tracker[(channel_name, url)] = url
                logging.debug(f"提取单一流: {channel_name},{url}")
            return extracted_channels
        elif extension not in [".txt", ".csv"]:
            logging.debug(f"不支持的文件扩展名: {url}")
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
                    logging.debug(f"跳过无效频道行（格式错误）: {line}")
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip() or "未知频道"
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    logging.debug(f"跳过无效频道 URL（无有效协议）: {line}")
                    continue

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                            source_tracker[(channel_name, channel_url)] = url
                            channel_count += 1
                        else:
                            logging.debug(f"跳过无效或预筛选失败的频道 URL: {channel_url}")
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
                        source_tracker[(channel_name, channel_url)] = url
                        channel_count += 1
                    else:
                        logging.debug(f"跳过无效或预筛选失败的频道 URL: {channel_url}")
            elif re.match(r'^[a-zA-Z0-9+.-]+://', line):
                channel_name = f"Stream_{channel_count + 1}"
                channel_url = clean_url_params(line)
                if channel_url and pre_screen_url(channel_url):
                    extracted_channels.append((channel_name, channel_url))
                    source_tracker[(channel_name, channel_url)] = url
                    channel_count += 1
                else:
                    logging.debug(f"跳过无效或预筛选失败的单一 URL: {line}")
        logging.debug(f"成功从 {url} 提取 {channel_count} 个频道")
    except Exception as e:
        logging.error(f"从 {url} 提取频道失败: {e}")
    return extracted_channels

# --- URL 状态管理函数 ---
@performance_monitor
def load_url_states_local():
    """加载 URL 状态并清理过期状态
    返回:
        清理后的 URL 状态字典
    """
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
    for url, state in url_states.items():
        if 'last_checked' in state:
            try:
                last_checked_datetime = datetime.fromisoformat(state['last_checked'])
                if (current_time - last_checked_datetime).days < CONFIG['url_state']['expiration_days']:
                    updated_url_states[url] = state
                else:
                    logging.debug(f"移除过期 URL 状态: {url}（最后检查于 {state['last_checked']}）")
            except ValueError:
                logging.warning(f"无法解析 URL {url} 的 last_checked 时间戳: {state['last_checked']}")
                updated_url_states[url] = state
        else:
            updated_url_states[url] = state
    return updated_url_states

@performance_monitor
def save_url_states_local(url_states):
    """保存 URL 状态到本地文件
    参数:
        url_states: URL 状态字典
    """
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
def fetch_url_content_with_retry(url, url_states):
    """带重试机制获取 URL 内容，使用缓存和 ETag/Last-Modified/Content-Hash
    参数:
        url: 要获取内容的 URL
        url_states: URL 状态字典
    返回:
        URL 内容，或 None（如果失败或内容未变更）
    """
    if CONFIG['url_state']['cache_enabled'] and url in content_cache:
        logging.debug(f"从缓存读取 URL 内容: {url}")
        return content_cache[url]

    headers = {}
    current_state = url_states.get(url, {})
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']

    try:
        response = session.get(url, headers=headers, timeout=15)
        response.raise_for_status()

        if response.status_code == 304:
            logging.debug(f"URL 内容未变更 (304): {url}")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL 内容未变更（哈希相同）: {url}")
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

        if CONFIG['url_state']['cache_enabled']:
            content_cache[url] = content
            cache_file = os.path.join(CONFIG['url_state']['cache_dir'], f"{hashlib.md5(url.encode()).hexdigest()}.txt")
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(content)

        logging.debug(f"成功获取新内容: {url}")
        return content
    except requests.exceptions.RequestException as e:
        logging.error(f"请求 URL 失败（重试后）: {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"获取 URL 内容未知错误: {url} - {e}")
        return None

@performance_monitor
def pre_screen_url(url):
    """根据配置预筛选 URL（协议、长度、无效模式）
    参数:
        url: 要筛选的 URL
    返回:
        布尔值，表示 URL 是否通过筛选
    """
    if not isinstance(url, str) or not url:
        logging.debug(f"预筛选过滤（无效类型或空）: {url}")
        return False

    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        logging.debug(f"预筛选过滤（无有效协议）: {url}")
        return False

    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        logging.debug(f"预筛选过滤（包含非法字符或空格）: {url}")
        return False

    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in CONFIG['url_pre_screening']['allowed_protocols']:
            logging.debug(f"预筛选过滤（不支持的协议）: {url}")
            return False

        if not parsed_url.netloc:
            logging.debug(f"预筛选过滤（无网络位置）: {url}")
            return False

        invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns']
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                logging.debug(f"预筛选过滤（无效模式）: {url}")
                return False

        if len(url) < 15:
            logging.debug(f"预筛选过滤（URL 过短）: {url}")
            return False

        return True
    except ValueError as e:
        logging.debug(f"预筛选过滤（URL 解析错误）: {url} - {e}")
        return False

@performance_monitor
def filter_and_modify_channels(channels):
    """过滤和修改频道名称及 URL
    参数:
        channels: 包含频道名称和 URL 的列表
    返回:
        过滤和修改后的频道列表
    """
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        if not pre_screen_url(url):
            logging.debug(f"过滤频道（预筛选失败）: {name},{url}")
            continue
        pre_screened_count += 1

        # 应用名称替换
        new_name = name
        for old_str, new_str in CONFIG['channel_name_replacements'].items():
            new_name = re.sub(old_str, new_str, new_name, flags=re.IGNORECASE)
        new_name = new_name.strip()

        # 过滤关键字
        if any(word.lower() in new_name.lower() for word in CONFIG['name_filter_words']):
            logging.debug(f"过滤频道（名称匹配黑名单）: {name},{url}")
            continue

        filtered_channels.append((new_name, url))
    logging.debug(f"URL 预筛选后剩余 {pre_screened_count} 个频道进行进一步过滤")
    return filtered_channels

# --- 频道有效性检查函数 ---
@performance_monitor
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达
    参数:
        url: 要检查的 URL
        timeout: 超时时间（秒）
    返回:
        布尔值，表示 URL 是否可达
    """
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL 检查失败: {url} - {e}")
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达
    参数:
        url: 要检查的 URL
        timeout: 超时时间（秒）
    返回:
        布尔值，表示 URL 是否可达
    """
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
        logging.debug(f"RTMP URL 检查超时: {url}")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL 检查错误: {url} - {e}")
        return False

@performance_monitor
def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达
    参数:
        url: 要检查的 URL
        timeout: 超时时间（秒）
    返回:
        布尔值，表示 URL 是否可达
    """
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.debug(f"RTP URL 解析失败（缺少主机或端口）: {url}")
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL 检查失败: {url} - {e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL 检查错误: {url} - {e}")
        return False

@performance_monitor
def check_p3p_url(url, timeout):
    """检查 P3P URL 是否可达
    参数:
        url: 要检查的 URL
        timeout: 超时时间（秒）
    返回:
        布尔值，表示 URL 是否可达
    """
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'

        if not host:
            logging.debug(f"P3P URL 解析失败（缺少主机）: {url}")
            return False

        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL 检查失败: {url} - {e}")
        return False

@performance_monitor
def check_webrtc_url(url, timeout):
    """检查 WebRTC URL 是否可达（简单检查 ICE 服务器可用性）
    参数:
        url: 要检查的 URL
        timeout: 超时时间（秒）
    返回:
        布尔值，表示 URL 是否可达（占位实现）
    """
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme == 'webrtc':
            return False
        # 这里仅模拟检查，实际 WebRTC 需要更复杂的 ICE/TURN/STUN 验证
        return True  # 占位，需根据实际需求实现
    except Exception as e:
        logging.debug(f"WebRTC URL 检查失败: {url} - {e}")
        return False

@performance_monitor
def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CONFIG['network']['check_timeout']):
    """检查单个频道的有效性和速度
    参数:
        channel_name: 频道名称
        url: 频道 URL
        url_states: URL 状态字典
        timeout: 检查超时时间（秒）
    返回:
        元组 (响应时间, 是否有效)
    """
    current_time = datetime.now()
    current_url_state = url_states.get(url, {})

    if 'stream_check_failed_at' in current_url_state:
        try:
            last_failed_datetime = datetime.fromisoformat(current_url_state['stream_check_failed_at'])
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
            if time_since_failed_hours < CONFIG['channel_retention']['stream_retention_hours']:
                logging.debug(f"跳过频道 {channel_name} ({url})，因其在冷却期内（{CONFIG['channel_retention']['stream_retention_hours']}h），上次失败于 {time_since_failed_hours:.2f}h 前")
                return None, False
        except ValueError:
            logging.warning(f"无法解析 URL {url} 的失败时间戳: {current_url_state['stream_check_failed_at']}")

    start_time = time.time()
    is_valid = False
    protocol_checked = False

    try:
        if url.startswith("http"):
            is_valid = check_http_url(url, timeout)
            protocol_checked = True
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
            protocol_checked = True
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, timeout)
            protocol_checked = True
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, timeout)
            protocol_checked = True
        elif url.startswith("webrtc"):
            is_valid = check_webrtc_url(url, timeout)
            protocol_checked = True
        else:
            logging.debug(f"频道 {channel_name} 的协议不支持: {url}")
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
            logging.debug(f"频道 {channel_name} ({url}) 检查成功，耗时 {elapsed_time:.0f} ms")
            return elapsed_time, True
        else:
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.debug(f"频道 {channel_name} ({url}) 检查失败")
            return None, False
    except Exception as e:
        if url not in url_states:
            url_states[url] = {}
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
        url_states[url]['last_stream_checked'] = current_time.isoformat()
        logging.debug(f"检查频道 {channel_name} ({url}) 错误: {e}")
        return None, False

@performance_monitor
def process_single_channel_line(channel_line, url_states):
    """处理单个频道行以进行有效性检查
    参数:
        channel_line: 频道行（格式为 "名称,URL"）
        url_states: URL 状态字典
    返回:
        元组 (响应时间, 频道行)，若无效则返回 (None, None)
    """
    if "://" not in channel_line:
        logging.debug(f"跳过无效频道行（无协议）: {channel_line}")
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

@performance_monitor
def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG['network']['channel_check_workers']):
    """多线程检查频道有效性
    参数:
        channel_lines: 频道行列表
        url_states: URL 状态字典
        max_workers: 最大线程数
    返回:
        有效频道的列表，包含响应时间和频道行
    """
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"开始多线程检查 {total_channels} 个频道的有效性和速度")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines}
        for i, future in enumerate(as_completed(futures)):
            checked_count += 1
            if checked_count % CONFIG['performance_monitor']['log_interval'] == 0:
                logging.warning(f"已检查 {checked_count}/{total_channels} 个频道")
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"处理频道行时发生异常: {exc}")
    return results

# --- 文件合并和排序函数 ---
@performance_monitor
def generate_update_time_header():
    """生成文件顶部更新时间信息
    返回:
        包含更新时间和格式的标题行列表
    """
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d %H:%M:%S')},url\n"
    ]

@performance_monitor
def group_and_limit_channels(lines):
    """对频道分组并限制每个频道名称下的 URL 数量
    参数:
        lines: 频道行列表
    返回:
        分组并限制后的频道行列表
    """
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
        for ch_line in grouped_channels[channel_name][:CONFIG.get('max_channel_urls_per_group', 100)]:
            final_grouped_lines.append(ch_line + '\n')
    return final_grouped_lines

# 增加一个辅助函数，用于从CONFIG加载路径
def get_config_path(keys, default=None):
    """根据键路径从 CONFIG 获取配置值。"""
    value = CONFIG
    for key in keys:
        value = value.get(key)
        if value is None:
            return default
    return value

@time_decorator("merge_local_channel_files")
@log_decorator
def merge_local_channel_files(local_channels_directory, final_iptv_file_path, url_states):
    """
    合并临时频道文件到最终的 IPTV 列表文件。

    Args:
        local_channels_directory (str): 临时频道文件所在的目录（例如 'temp_channels'）。
        final_iptv_file_path (str): 最终 IPTV 列表文件的完整路径。
        url_states (dict): URL 状态字典，用于避免重复写入已知的URL。
    """
    logging.info(f"开始合并本地频道文件，目录: {local_channels_directory}")

    # 用于存储所有找到的频道 (name, url) 对
    new_channels_from_merged_files = set()
    
    # 确保临时频道目录存在
    if not os.path.exists(local_channels_directory):
        logging.warning(f"临时频道目录 '{local_channels_directory}' 不存在，跳过合并。")
        return

    # 遍历临时频道目录，收集所有有效的频道文件
    files_to_merge_paths = []
    for filename in os.listdir(local_channels_directory):
        if filename.endswith('_iptv.txt') or filename == 'uncategorized_iptv.txt': # 明确包含 uncategorized_iptv.txt
            file_path = os.path.join(local_channels_directory, filename)
            if os.path.isfile(file_path):
                files_to_merge_paths.append(file_path)

    if not files_to_merge_paths:
        logging.warning(f"在 '{local_channels_directory}' 中没有找到任何需要合并的频道文件。")
    else:
        # 对文件路径进行排序，以确保合并顺序一致性
        files_to_merge_paths.sort()
        logging.info(f"找到 {len(files_to_merge_paths)} 个要合并的文件。")

        for file_path in files_to_merge_paths:
            logging.debug(f"正在读取合并文件: {file_path}")
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        # 确保行是有效的频道行，跳过空行和以 #genre# 开头的分类行
                        if line and ',' in line and not line.startswith('#genre#'):
                            try:
                                name, url = line.split(',', 1)
                                new_channels_from_merged_files.add((name.strip(), url.strip()))
                            except ValueError:
                                logging.warning(f"跳过无效的频道行: {line} (文件: {file_path})")
            except Exception as e:
                logging.error(f"读取合并文件 '{file_path}' 失败: {e}")

    logging.info(f"从临时文件中合并了 {len(new_channels_from_merged_files)} 个不重复的频道。")

    # 获取最终输出路径和目录
    output_dir = os.path.dirname(final_iptv_file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True) # 确保目录存在

    # 用于跟踪已写入的频道，避免重复
    written_channels = set()

    # 将合并后的频道写入最终文件
    logging.info(f"将所有有效频道写入最终文件: {final_iptv_file_path}")
    try:
        with open(final_iptv_file_path, "w", encoding="utf-8") as final_file:
            final_file.write("#EXTM3U\n") # M3U文件头

            ordered_categories = get_config_path(['ordered_categories'], [])
            category_keywords = get_config_path(['category_keywords'], {})
            category_aliases = get_config_path(['category_aliases'], {})

            # 处理类别别名，将别名映射到最终类别
            resolved_category_keywords = {}
            for category, keywords in category_keywords.items():
                resolved_category_keywords[category] = keywords
            for alias, target in category_aliases.items():
                if target in resolved_category_keywords:
                    resolved_category_keywords[alias] = resolved_category_keywords[target]
                else:
                    logging.warning(f"配置中存在无效的类别别名目标: '{target}' (别名: '{alias}')")

            # 按照配置中的顺序写入分类频道
            categorized_channels = defaultdict(list)
            
            # 先对所有频道进行分类
            for name, url in new_channels_from_merged_files:
                assigned_category = "未分类频道"
                name_lower = name.lower()

                # 尝试通过关键词匹配进行分类
                for category in ordered_categories:
                    keywords = resolved_category_keywords.get(category, [])
                    if any(kw.lower() in name_lower for kw in keywords):
                        assigned_category = category
                        break # 匹配到第一个类别就停止

                categorized_channels[assigned_category].append((name, url))

            # 按照 ordered_categories 的顺序写入
            for category in ordered_categories:
                channels_in_this_category = categorized_channels.get(category, [])
                if channels_in_this_category:
                    final_file.write(f"\n#EXTINF:-1 group-title=\"{category}\",{category}频道\n")
                    # 对每个类别内的频道按名称排序
                    for name, url in sorted(channels_in_this_category, key=lambda x: x[0]):
                        if (name, url) not in written_channels:
                            final_file.write(f"#EXTINF:-1,{name}\n")
                            final_file.write(f"{url}\n")
                            written_channels.add((name, url))

            # 最后写入未分类频道
            uncategorized_list = categorized_channels.get("未分类频道", [])
            if uncategorized_list:
                final_file.write(f"\n#EXTINF:-1 group-title=\"未分类频道\",未分类频道\n")
                for name, url in sorted(uncategorized_list, key=lambda x: x[0]):
                    if (name, url) not in written_channels:
                        final_file.write(f"#EXTINF:-1,{name}\n")
                        final_file.write(f"{url}\n")
                        written_channels.add((name, url))
            
        logging.info("频道列表合并并写入成功。")
        
    except Exception as e:
        logging.error(f"合并并写入最终 IPTV 文件 '{final_iptv_file_path}' 失败: {e}")

    logging.info(f"合并完成。最终文件 '{final_iptv_file_path}' 已生成。")


# --- 主要执行逻辑 ---
# 假设 time_decorator 和 log_decorator 在您的原始代码中已经定义
# 如果没有，您可能需要手动添加它们的定义或根据您的实际情况进行调整。
# 比如：
def time_decorator(func_name):
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            logging.info(f"函数 {func_name} 执行耗时: {end_time - start_time:.4f} 秒")
            return result
        return wrapper
    return decorator

def log_decorator(func):
    def wrapper(*args, **kwargs):
        logging.debug(f"进入函数: {func.__name__}")
        result = func(*args, **kwargs)
        logging.debug(f"退出函数: {func.__name__}")
        return result
    return wrapper

@time_decorator("main")
@log_decorator
def main():
    repo_owner = CONFIG['github']['repo_owner']
    repo_name = CONFIG['github']['repo_name']
    
    # 确保 URLS_PATH 和 URL_STATES_PATH 所在的目录存在
    os.makedirs(os.path.dirname(URLS_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)

    # 1. 加载 URL 状态
    url_states = load_url_states_local()
    logging.info(f"加载了 {len(url_states)} 条 URL 状态。")

    # 2. 从 GitHub 获取 URL 列表
    github_urls_content = fetch_from_github(CONFIG['github']['urls_file'])
    if github_urls_content:
        # 将 GitHub 上的 URL 列表保存到本地
        with open(URLS_PATH, 'w', encoding='utf-8') as f:
            f.write(github_urls_content)
        logging.info(f"成功从 GitHub 同步 {CONFIG['github']['urls_file']} 到本地。")
    else:
        logging.error(f"从 GitHub 获取 {CONFIG['github']['urls_file']} 失败，将尝试使用本地文件。")
    
    # 从本地文件读取 URL 列表
    urls = read_txt_to_array_local(URLS_PATH)
    if not urls:
        logging.error("没有可用的 URL 列表，程序退出。")
        return
    
    urls = [url.strip() for url in urls if url.strip()]
    urls_to_process = [url for url in urls if pre_screen_url(url)]
    logging.info(f"初步筛选后，共有 {len(urls_to_process)} 个有效 URL 待处理。")
    
    # 用于跟踪每个频道是从哪个原始 URL 提取的
    source_tracker = {} 

    # 3. 多线程提取频道
    extracted_channels_raw = []
    logging.info(f"开始多线程从 {len(urls_to_process)} 个 URL 提取频道...")
    with ThreadPoolExecutor(max_workers=CONFIG['network']['url_fetch_workers']) as executor:
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states, source_tracker): url for url in urls_to_process}
        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                channels = future.result()
                if channels:
                    extracted_channels_raw.extend(channels)
                if (i + 1) % CONFIG['performance_monitor']['log_interval'] == 0:
                    logging.info(f"已处理 {i + 1}/{len(urls_to_process)} 个 URL。")
            except Exception as exc:
                logging.error(f"URL '{url}' 生成异常: {exc}")
    logging.info(f"所有 URL 处理完毕，共提取到 {len(extracted_channels_raw)} 个原始频道。")

    # 4. 过滤和修改频道
    filtered_and_modified_channels = filter_and_modify_channels(extracted_channels_raw)
    logging.info(f"过滤和修改后，剩余 {len(filtered_and_modified_channels)} 个频道。")

    # 5. 去重并初步分类
    unique_channels = set(filtered_and_modified_channels)
    logging.info(f"去重后，剩余 {len(unique_channels)} 个唯一频道。")

    # 按照配置的 category_keywords 和 ordered_categories 进行初步分类
    categorized_channels = defaultdict(list)
    uncategorized_channels = []

    # 确保 resolved_category_keywords 包含所有别名映射
    resolved_category_keywords = {}
    for category, keywords in CONFIG.get('category_keywords', {}).items():
        resolved_category_keywords[category] = keywords
    for alias, target in CONFIG.get('category_aliases', {}).items():
        if target in resolved_category_keywords:
            resolved_category_keywords[alias] = resolved_category_keywords[target]

    for name, url in unique_channels:
        assigned_category = None
        name_lower = name.lower()
        for category in CONFIG.get('ordered_categories', []):
            keywords = resolved_category_keywords.get(category, [])
            if any(kw.lower() in name_lower for kw in keywords):
                categorized_channels[category].append((name, url))
                assigned_category = category
                break
        if assigned_category is None:
            uncategorized_channels.append((name, url))

    logging.info("频道初步分类完成。")

    # 6. 保存临时分类文件
    temp_channels_dir = CONFIG['output']['paths']['channels_dir']
    os.makedirs(temp_channels_dir, exist_ok=True)
    logging.info(f"临时频道文件保存目录: {temp_channels_dir}")

    for category, channels in categorized_channels.items():
        if category != "未分类频道": # 未分类频道单独处理
            file_path = os.path.join(temp_channels_dir, f"{category}_iptv.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                for name, url in sorted(channels, key=lambda x: x[0]):
                    f.write(f"{name},{url}\n")
            logging.debug(f"分类频道 '{category}' 保存到: {file_path}，共 {len(channels)} 条。")

    # 保存未分类的临时文件到 temp_channels 目录
    uncategorized_temp_file_path = os.path.join(temp_channels_dir, "uncategorized_iptv.txt")
    if uncategorized_channels:
        try:
            with open(uncategorized_temp_file_path, "w", encoding='utf-8') as uncat_file:
                for name, url in sorted(uncategorized_channels, key=lambda x: x[0]):
                    uncat_file.write(f"{name},{url}\n")
            logging.warning(f"临时未分类频道保存到: {uncategorized_temp_file_path}，共 {len(uncategorized_channels)} 条。")
        except Exception as e:
            logging.error(f"写入临时未分类文件 '{uncategorized_temp_file_path}' 失败: {e}")
    else:
        # 如果没有未分类频道，确保删除旧的临时未分类文件，避免影响后续合并
        if os.path.exists(uncategorized_temp_file_path):
            os.remove(uncategorized_temp_file_path)
            logging.info(f"没有未分类频道，已删除旧的临时未分类文件: {uncategorized_temp_file_path}")


    # 7. 合并本地频道文件并检查有效性
    # merge_local_channel_files 函数现在会处理 uncategorized_iptv.txt 文件的正确路径
    merge_local_channel_files(temp_channels_dir, IPTV_LIST_PATH, url_states)

    # 8. 保存 URL 状态
    save_url_states_local(url_states)
    logging.info("URL 状态已保存。")

    # 9. 将最终的 IPTV 列表文件上传到 GitHub
    final_iptv_content = None
    try:
        with open(IPTV_LIST_PATH, 'r', encoding='utf-8') as f:
            final_iptv_content = f.read()
    except FileNotFoundError:
        logging.error(f"最终 IPTV 文件 '{IPTV_LIST_PATH}' 未找到，无法上传到 GitHub。")
        final_iptv_content = None

    if final_iptv_content:
        save_to_github(CONFIG['github']['output_file'], final_iptv_content, "更新 IPTV 列表")
        logging.info(f"最终 IPTV 列表文件已上传到 GitHub: {CONFIG['github']['output_file']}")
    else:
        logging.warning("没有内容可以上传到 GitHub。")

    logging.info("所有任务完成！")

# 辅助函数，用于根据检查结果重新分类频道（用于最终输出）
def categorize_channels(channels):
    categorized = defaultdict(list)
    uncategorized = []
    final_ordered_categories = []

    # 确保 resolved_category_keywords 包含所有别名映射
    resolved_category_keywords = {}
    for category, keywords in CONFIG.get('category_keywords', {}).items():
        resolved_category_keywords[category] = keywords
    for alias, target in CONFIG.get('category_aliases', {}).items():
        if target in resolved_category_keywords:
            resolved_category_keywords[alias] = resolved_category_keywords[target]

    # 根据 ordered_categories 建立有序类别列表
    for cat in CONFIG.get('ordered_categories', []):
        final_ordered_categories.append(cat)
    if "其他频道" not in final_ordered_categories: # 确保“其他频道”总是存在于末尾
        final_ordered_categories.append("其他频道")

    for name, url in channels:
        assigned = False
        name_lower = name.lower()
        for category in CONFIG.get('ordered_categories', []):
            keywords = resolved_category_keywords.get(category, [])
            if any(kw.lower() in name_lower for kw in keywords):
                categorized[category].append((name, url))
                assigned = True
                break
        if not assigned:
            uncategorized.append((name, url))
    
    # 将 uncategorized_channels_checked 赋值给其他频道
    categorized_channels_checked = categorized
    uncategorized_channels_checked = uncategorized
    
    return categorized_channels_checked, uncategorized_channels_checked, final_ordered_categories


if __name__ == "__main__":
    main()
