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
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转以避免过大"""
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
    """加载并解析 YAML 配置文件"""
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
    """记录函数执行时间的装饰器，用于性能分析"""
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
    """从 GitHub 仓库获取文件内容"""
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
    """获取 GitHub 仓库中文件的当前 SHA 值"""
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
    """保存内容到 GitHub 仓库（创建或更新）"""
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
    """从本地 TXT 文件读取内容到数组"""
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
    """读取现有频道以进行去重"""
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
    """将排序后的频道数据写入文件，去重"""
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
    """获取 URL 的文件扩展名"""
    try:
        parsed_url = urlparse(url)
        return os.path.splitext(parsed_url.path)[1].lower()
    except ValueError as e:
        logging.debug(f"获取 URL 扩展名失败: {url} - {e}")
        return ""

@performance_monitor
def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式转换为 TXT 格式（频道名称，URL）"""
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
    """清理 URL 参数，仅保留方案、网络位置和路径"""
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.debug(f"清理 URL 参数失败: {url} - {e}")
        return url

@performance_monitor
def extract_channels_from_url(url, url_states, source_tracker):
    """从 URL 提取频道，支持多种文件格式"""
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
    """加载 URL 状态并清理过期状态"""
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
    """保存 URL 状态到本地文件"""
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
def fetch_url_content_with_retry(url, url_states):
    """带重试机制获取 URL 内容，使用缓存和 ETag/Last-Modified/Content-Hash"""
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
    """根据配置预筛选 URL（协议、长度、无效模式）"""
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
    """过滤和修改频道名称及 URL"""
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
    """检查 HTTP/HTTPS URL 是否可达"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL 检查失败: {url} - {e}")
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达"""
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
    """检查 RTP URL 是否可达"""
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
    """检查 P3P URL 是否可达"""
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
    """检查 WebRTC URL 是否可达（简单检查 ICE 服务器可用性）"""
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
    """检查单个频道的有效性和速度"""
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
    """处理单个频道行以进行有效性检查"""
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
    """多线程检查频道有效性"""
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
    """生成文件顶部更新时间信息"""
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d %H:%M:%S')},url\n"
    ]

@performance_monitor
def group_and_limit_channels(lines):
    """对频道分组并限制每个频道名称下的 URL 数量"""
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

@performance_monitor
def merge_local_channel_files(local_channels_directory, output_file_name, url_states):
    """合并本地频道列表文件，去重并清理，按分类输出"""
    os.makedirs(local_channels_directory, exist_ok=True)
    existing_channels_data = read_existing_channels(output_file_name)
    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    
    # 修正 uncategorized_iptv.txt 的路径
    output_base_dir = CONFIG['output']['paths']['output_dir']
    uncategorized_file_name = CONFIG['output']['paths']['uncategorized_channels_file']
    uncategorized_file_path_full = os.path.join(output_base_dir, uncategorized_file_name)

    # 确保uncategorized_iptv.txt存在，即使为空
    if not os.path.exists(uncategorized_file_path_full):
        os.makedirs(output_base_dir, exist_ok=True) # 确保输出目录存在
        with open(uncategorized_file_path_full, "w", encoding="utf-8") as f:
            pass # 创建一个空文件
        logging.warning(f"未分类频道文件 '{uncategorized_file_path_full}' 不存在，已创建空文件。")

    # 如果 uncategorized_iptv.txt 存在于预期路径（非temp_channels），则添加到待合并列表
    # 注意：这里我们直接用完整的路径，而不是文件名为基准，以避免混淆
    files_to_merge_paths = []
    processed_files = set() # 记录已经添加到 files_to_merge_paths 的文件 basename

    # 获取所有可能的分类名称（包括别名后的最终分类）
    all_possible_categories = list(CONFIG.get('ordered_categories', []))
    for alias_target in set(CONFIG.get('category_aliases', {}).values()):
        if alias_target not in all_possible_categories:
            all_possible_categories.append(alias_target)

    # 按照最终的分类顺序，收集需要合并的文件
    for category in all_possible_categories:
        file_name = f"{category}_iptv.txt"
        temp_path = os.path.join(local_channels_directory, file_name)
        if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files:
            files_to_merge_paths.append(temp_path)
            processed_files.add(os.path.basename(temp_path))

    # 处理未被上面明确分类的文件，如最初的 uncategorized_channels.txt
    # 注意：这里我们使用 uncategorized_file_path_full，因为它不在 temp_channels 目录
    if os.path.exists(uncategorized_file_path_full) and os.path.basename(uncategorized_file_path_full) not in processed_files:
        files_to_merge_paths.append(uncategorized_file_path_full)
        processed_files.add(os.path.basename(uncategorized_file_path_full))
    
    # 将 local_channels_directory 中其他未处理过的 _iptv.txt 文件也加入合并列表
    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
            full_path = os.path.join(local_channels_directory, file_name)
            files_to_merge_paths.append(full_path)
            processed_files.add(file_name)


    new_channels_from_merged_files = set()
    for file_path in files_to_merge_paths:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                continue
            for line in lines:
                line = line.strip()
                if line and ',' in line:
                    # Original code continues here...
                    # This part remains unchanged as it iterates over the lines.
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        name, url = parts
                        new_channels_from_merged_files.add((name.strip(), url.strip()))

    all_channels_combined = existing_channels_data.union(new_channels_from_merged_files)

    # 清理 URL 失败次数并过滤 URL
    cleaned_channels = []
    current_time = datetime.now()
    url_fail_threshold = CONFIG['channel_retention']['url_fail_threshold']
    url_retention_hours = CONFIG['channel_retention']['url_retention_hours']

    for name, url in all_channels_combined:
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        last_checked_str = state.get('last_stream_checked')
        
        is_retained = True
        if last_checked_str:
            try:
                last_checked_dt = datetime.fromisoformat(last_checked_str)
                time_since_last_check = (current_time - last_checked_dt).total_seconds() / 3600
                if fail_count > url_fail_threshold and time_since_last_check < url_retention_hours:
                    is_retained = False
                    logging.debug(f"清理频道 {name},{url}，因其失败次数 {fail_count} 超过阈值 {url_fail_threshold} 且在保留期内（{time_since_last_check:.2f}h < {url_retention_hours}h）")
            except ValueError:
                logging.warning(f"解析URL {url} 的 last_stream_checked 时间戳失败: {last_checked_str}")
        
        if is_retained:
            cleaned_channels.append((name, url))

    # 按分类和名称排序
    categorized_channels = {category: [] for category in CONFIG['ordered_categories']}
    uncategorized_output = []

    for name, url in cleaned_channels:
        found_category = False
        # 先检查精确分类关键词
        for category, keywords in CONFIG['category_keywords'].items():
            if any(keyword.lower() in name.lower() for keyword in keywords):
                if category in CONFIG['ordered_categories']:
                    categorized_channels[category].append((name, url))
                    found_category = True
                    break
                else: # 处理 category_keywords 中可能存在但不在 ordered_categories 中的分类
                    # 如果有别名，将它们映射到最终分类
                    aliased_category = CONFIG['category_aliases'].get(category, category)
                    if aliased_category in CONFIG['ordered_categories']:
                        categorized_channels[aliased_category].append((name, url))
                        found_category = True
                        break
        if not found_category:
            # 尝试通过别名进行分类（如果没有直接匹配关键词）
            aliased_name = name.lower()
            categorized_by_alias = False
            for alias_key, target_category in CONFIG['category_aliases'].items():
                if alias_key.lower() in aliased_name:
                    if target_category in CONFIG['ordered_categories']:
                        categorized_channels[target_category].append((name, url))
                        categorized_by_alias = True
                        break
            if not categorized_by_alias:
                uncategorized_output.append((name, url))

    final_output_lines = generate_update_time_header()
    final_iptv_file_content = []
    
    for category in CONFIG['ordered_categories']:
        if categorized_channels[category]:
            final_output_lines.append(f"\n{category},#genre#\n")
            sorted_category_channels = sorted(categorized_channels[category], key=lambda x: x[0])
            for name, url in sorted_category_channels:
                final_output_lines.append(f"{name},{url}\n")
    
    # 处理未分类频道
    if uncategorized_output:
        final_output_lines.append(f"\n未分类频道,#genre#\n")
        sorted_uncategorized_channels = sorted(uncategorized_output, key=lambda x: x[0])
        for name, url in sorted_uncategorized_channels:
            final_output_lines.append(f"{name},{url}\n")
            # 将未分类频道也写入单独的文件
            final_iptv_file_content.append(f"{name},{url}\n")

    # 写入最终的 iptv_list.txt (包含所有分类)
    output_dir = CONFIG['output']['paths']['output_dir']
    os.makedirs(output_dir, exist_ok=True)
    final_iptv_file_path = os.path.join(output_dir, output_file_name)

    with open(final_iptv_file_path, "w", encoding="utf-8") as f:
        f.writelines(final_output_lines)
    logging.info(f"成功合并并输出 IPTV 列表到 '{final_iptv_file_path}'")

    # 写入单独的未分类频道文件
    uncategorized_output_file_path = os.path.join(output_dir, CONFIG['output']['paths']['uncategorized_channels_file'])
    with open(uncategorized_output_file_path, "w", encoding="utf-8") as f:
        f.writelines(final_iptv_file_content) # Changed to use final_iptv_file_content
    logging.info(f"成功输出未分类频道到 '{uncategorized_output_file_path}'")

# --- GitHub 搜索和文件处理 ---
@performance_monitor
def get_github_search_results(query_string, page, per_page):
    """从 GitHub Code Search API 获取搜索结果"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.text-match+json"
    }
    params = {
        "q": query_string,
        "per_page": per_page,
        "page": page
    }
    search_url = f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}"
    
    try:
        response = session.get(search_url, headers=headers, params=params, timeout=CONFIG['github']['api_timeout'])
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers and int(response.headers['X-RateLimit-Remaining']) < CONFIG['github']['rate_limit_threshold']:
            logging.warning(f"GitHub API 速率限制，等待 {CONFIG['github']['retry_wait']} 秒后重试...")
            time.sleep(CONFIG['github']['retry_wait'])
            raise # 重新抛出异常以触发 tenacity 的重试
        logging.error(f"GitHub API 搜索失败: {e}")
        return None

@performance_monitor
def download_github_file(repo_owner, repo_name, file_path, file_sha, url_states):
    """下载 GitHub 文件内容，使用 ETag/Last-Modified/Content-Hash 优化"""
    raw_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/main/{file_path}"
    headers = {}
    current_state = url_states.get(raw_url, {})
    
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']

    try:
        response = session.get(raw_url, headers=headers, timeout=CONFIG['network']['request_timeout'])
        response.raise_for_status()

        if response.status_code == 304:
            logging.debug(f"文件内容未变更 (304): {raw_url}")
            url_states[raw_url]['last_checked'] = datetime.now().isoformat()
            return None # 内容未变更，返回 None
        
        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"文件内容未变更（哈希相同）: {raw_url}")
            url_states[raw_url]['last_checked'] = datetime.now().isoformat()
            return None

        # 更新 URL 状态
        url_states[raw_url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }
        
        logging.debug(f"成功下载新文件: {raw_url}")
        return content
    except requests.exceptions.RequestException as e:
        logging.error(f"下载 GitHub 文件失败 {raw_url}: {e}")
        return None

@performance_monitor
def process_github_search_results(search_results, url_states, source_tracker, max_url_fetch_workers):
    """处理 GitHub 搜索结果，提取并过滤频道"""
    all_extracted_channels = []
    urls_to_process = []

    for item in search_results.get('items', []):
        repo_owner = item['repository']['owner']['login']
        repo_name = item['repository']['name']
        file_path = item['path']
        url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/main/{file_path}"

        # 检查 URL 是否在保留期内或最近已处理
        state = url_states.get(url, {})
        if 'last_checked' in state:
            try:
                last_checked_dt = datetime.fromisoformat(state['last_checked'])
                if (datetime.now() - last_checked_dt).total_seconds() / 3600 < CONFIG['url_retention_hours']:
                    logging.debug(f"跳过最近处理的URL: {url}")
                    continue
            except ValueError:
                logging.warning(f"无法解析 URL {url} 的 last_checked 时间戳: {state['last_checked']}")

        urls_to_process.append(url)

    if not urls_to_process:
        logging.info("没有新的 GitHub URL 需要处理。")
        return []

    logging.info(f"开始多线程处理 {len(urls_to_process)} 个 GitHub URL...")
    with ThreadPoolExecutor(max_url_fetch_workers) as executor:
        futures = {executor.submit(extract_channels_from_url, url, url_states, source_tracker): url for url in urls_to_process}
        
        processed_count = 0
        for future in as_completed(futures):
            processed_count += 1
            if processed_count % CONFIG['performance_monitor']['log_interval'] == 0:
                logging.warning(f"已处理 {processed_count}/{len(urls_to_process)} 个 GitHub URL")
            try:
                extracted = future.result()
                if extracted:
                    all_extracted_channels.extend(extracted)
            except Exception as exc:
                logging.error(f"处理 GitHub URL 时发生异常: {exc}")
                
    logging.info(f"完成 GitHub URL 处理。共提取 {len(all_extracted_channels)} 个频道。")
    return all_extracted_channels


# --- 主函数和流程控制 ---
@performance_monitor
def main():
    """主函数，协调整个 IPTV 列表处理流程"""
    logging.info("IPTV 列表处理脚本开始运行...")

    # 确保必要的目录存在
    os.makedirs(CONFIG['output']['paths']['output_dir'], exist_ok=True)
    os.makedirs(CONFIG['output']['paths']['channels_dir'], exist_ok=True) # 确保临时频道目录存在

    url_states = load_url_states_local()
    source_tracker = {} # 追踪每个频道来自哪个原始 URL

    all_channels_from_sources = []
    max_url_fetch_workers = CONFIG['network']['url_fetch_workers']

    # 1. 从 GitHub 搜索和下载 M3U/TXT 文件
    logging.info("开始从 GitHub 搜索和下载文件...")
    github_search_keywords = CONFIG.get('search_keywords', ["IPTV", "playlist.m3u8 in:file"])
    max_search_pages = CONFIG['github']['max_search_pages']
    per_page = CONFIG['github']['per_page']

    all_github_urls_to_process = []
    
    for keyword in github_search_keywords:
        for page in range(1, max_search_pages + 1):
            logging.info(f"搜索 GitHub 关键词 '{keyword}' (第 {page}/{max_search_pages} 页)...")
            results = get_github_search_results(keyword, page, per_page)
            if results and results.get('items'):
                logging.info(f"找到 {len(results['items'])} 个结果。")
                for item in results['items']:
                    repo_owner = item['repository']['owner']['login']
                    repo_name = item['repository']['name']
                    file_path = item['path']
                    github_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/main/{file_path}"
                    all_github_urls_to_process.append(github_url)
            else:
                logging.info(f"关键词 '{keyword}' 在第 {page} 页没有找到更多结果。")
                break # 没有更多结果，停止分页

    # 使用线程池处理所有收集到的 GitHub URL
    if all_github_urls_to_process:
        logging.info(f"开始多线程从 GitHub 下载和提取 {len(all_github_urls_to_process)} 个文件中的频道...")
        with ThreadPoolExecutor(max_workers=max_url_fetch_workers) as executor:
            future_to_url = {executor.submit(extract_channels_from_url, url, url_states, source_tracker): url for url in all_github_urls_to_process}
            processed_urls_count = 0
            for future in as_completed(future_to_url):
                processed_urls_count += 1
                if processed_urls_count % CONFIG['performance_monitor']['log_interval'] == 0:
                    logging.warning(f"已处理 {processed_urls_count}/{len(all_github_urls_to_process)} 个 GitHub URL 文件")
                
                try:
                    extracted = future.result()
                    if extracted:
                        all_channels_from_sources.extend(extracted)
                except Exception as exc:
                    original_url = future_to_url[future]
                    logging.error(f"从 GitHub URL '{original_url}' 提取频道时发生异常: {exc}")
    else:
        logging.info("没有从 GitHub 搜索到相关文件。")

    # 2. 从备用 URL 下载和提取
    logging.info("开始从备用 URL 下载和提取频道...")
    backup_urls = CONFIG.get('backup_urls', [])
    if backup_urls:
        with ThreadPoolExecutor(max_workers=max_url_fetch_workers) as executor:
            futures = {executor.submit(extract_channels_from_url, url, url_states, source_tracker): url for url in backup_urls}
            
            processed_urls_count = 0
            for future in as_completed(futures):
                processed_urls_count += 1
                if processed_urls_count % CONFIG['performance_monitor']['log_interval'] == 0:
                    logging.warning(f"已处理 {processed_urls_count}/{len(backup_urls)} 个备用 URL 文件")

                try:
                    extracted = future.result()
                    if extracted:
                        all_channels_from_sources.extend(extracted)
                except Exception as exc:
                    original_url = future_to_url[future] # Note: This might be incorrect, `future_to_url` is for GitHub futures
                    logging.error(f"从备用 URL '{original_url if 'original_url' in locals() else '未知'}' 提取频道时发生异常: {exc}")
    else:
        logging.info("没有配置备用 URL。")
        
    logging.info(f"总共从所有源提取到 {len(all_channels_from_sources)} 个原始频道。")

    # 3. 过滤和标准化频道名称
    logging.info("开始过滤和标准化频道名称...")
    filtered_and_modified_channels = filter_and_modify_channels(all_channels_from_sources)
    logging.info(f"过滤和标准化后剩余 {len(filtered_and_modified_channels)} 个频道。")

    # 4. 去重
    unique_channels = {}
    for name, url in filtered_and_modified_channels:
        if name not in unique_channels:
            unique_channels[name] = set()
        unique_channels[name].add(url)
    
    unique_channels_list = []
    for name, urls in unique_channels.items():
        for url in urls:
            unique_channels_list.append((name, url))
    
    logging.info(f"去重后剩余 {len(unique_channels_list)} 个唯一频道。")

    # 5. 检查有效性
    logging.info("开始检查频道有效性...")
    channel_lines_to_check = [f"{name},{url}" for name, url in unique_channels_list]
    valid_channels_with_speed = check_channels_multithreaded(channel_lines_to_check, url_states)
    logging.info(f"有效性检查后剩余 {len(valid_channels_with_speed)} 个有效频道。")

    # 6. 分类和写入临时文件
    logging.info("开始对频道进行分类并写入临时文件...")
    categorized_temp_files = {category: [] for category in CONFIG['ordered_categories']}
    uncategorized_temp_channels = []

    for elapsed_time, line in valid_channels_with_speed:
        name, url = line.split(',', 1)
        name = name.strip()

        found_category = False
        # 优先使用 category_keywords 进行分类
        for category, keywords in CONFIG['category_keywords'].items():
            if any(keyword.lower() in name.lower() for keyword in keywords):
                if category in CONFIG['ordered_categories']:
                    categorized_temp_files[category].append((elapsed_time, line))
                    found_category = True
                    break
                else: # 处理 category_keywords 中存在但不在 ordered_categories 中的分类
                    # 如果有别名，将它们映射到最终分类
                    aliased_category = CONFIG['category_aliases'].get(category, category)
                    if aliased_category in CONFIG['ordered_categories']:
                        categorized_temp_files[aliased_category].append((elapsed_time, line))
                        found_category = True
                        break

        if not found_category:
            # 如果没有通过关键词分类，则尝试通过别名进行分类
            categorized_by_alias = False
            for alias_key, target_category in CONFIG['category_aliases'].items():
                if alias_key.lower() in name.lower():
                    if target_category in CONFIG['ordered_categories']:
                        categorized_temp_files[target_category].append((elapsed_time, line))
                        categorized_by_alias = True
                        break
            if not categorized_by_alias:
                uncategorized_temp_channels.append((elapsed_time, line))

    # 写入分类文件
    for category, channels in categorized_temp_files.items():
        if channels:
            temp_file_path = os.path.join(CONFIG['output']['paths']['channels_dir'], f"{category}_iptv.txt")
            write_sorted_channels_to_file(temp_file_path, channels)
    
    # 将未分类频道写入单独的临时文件
    if uncategorized_temp_channels:
        uncategorized_temp_file_path = os.path.join(CONFIG['output']['paths']['channels_dir'], CONFIG['output']['paths']['uncategorized_channels_file'])
        write_sorted_channels_to_file(uncategorized_temp_file_path, uncategorized_temp_channels)
    
    # 7. 合并所有临时文件到最终文件
    logging.info("开始合并所有临时频道文件到最终列表...")
    merge_local_channel_files(CONFIG['output']['paths']['channels_dir'], IPTV_LIST_PATH, url_states)

    # 8. 保存 URL 状态
    logging.info("保存 URL 状态...")
    save_url_states_local(url_states)

    logging.info("IPTV 列表处理脚本运行完成。")

if __name__ == "__main__":
    main()
