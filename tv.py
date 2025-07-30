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
    logging.info(f"日志系统初始化完成。日志文件: {log_file}，日志级别设置为: {logging.getLevelName(logger.level)}")
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config_data = yaml.safe_load(file)
            logging.info(f"成功加载配置文件: {config_path}")
            return config_data
    except FileNotFoundError:
        logging.critical(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.critical(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.critical(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 配置文件路径
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
# 在加载配置后，重新设置日志级别，因为 setup_logging 可能会在CONFIG完全加载前被调用
logger = setup_logging(CONFIG)
log_level_from_config = CONFIG.get('logging', {}).get('log_level', 'INFO').upper()
logger.setLevel(getattr(logging, log_level_from_config))
logging.info(f"日志级别已根据配置文件设置为: {log_level_from_config}")


# 检查环境变量 GITHUB_TOKEN
GITHUB_TOKEN = os.getenv('BOT')
if not GITHUB_TOKEN:
    logging.critical("错误：未设置环境变量 'BOT'。请在GitHub Secrets中配置 BOT 环境变量。")
    exit(1)

# 从配置中获取文件路径
URLS_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'urls.txt')
URL_STATES_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'url_states.json')
IPTV_LIST_PATH = CONFIG['output']['paths']['final_iptv_file']
UNCATEGORIZED_CHANNELS_FILE = CONFIG['output']['paths']['uncategorized_channels_file']
CHANNELS_DIR = CONFIG['output']['paths']['channels_dir']

# GitHub API 基础 URL
# 请替换为您的仓库信息
REPO_OWNER = CONFIG['github']['repo_owner']
REPO_NAME = CONFIG['github']['repo_name']
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# 初始化缓存
content_cache = None
if CONFIG['url_state']['cache_enabled']:
    os.makedirs(CONFIG['url_state']['cache_dir'], exist_ok=True)
    content_cache = TTLCache(maxsize=1000, ttl=CONFIG['url_state']['cache_ttl'])
    logging.info(f"URL内容缓存已启用，最大大小: 1000，TTL: {CONFIG['url_state']['cache_ttl']}秒。")

# 配置 requests 会话
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
pool_size = CONFIG['network']['requests_pool_size']
retry_strategy = Retry(
    total=CONFIG['network']['requests_retry_total'],
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
logging.info(f"Requests会话已配置，连接池大小: {pool_size}，重试次数: {CONFIG['network']['requests_retry_total']}")

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
        logging.info(f"正在从 GitHub 获取文件: {file_path_in_repo} (URL: {raw_url})")
        response = session.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        logging.info(f"成功从 GitHub 获取文件: {file_path_in_repo}")
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
        response = session.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        sha = response.json().get('sha')
        logging.debug(f"获取 {file_path_in_repo} 的 SHA 值: {sha}")
        return sha
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
        logging.info(f"文件 {file_path_in_repo} 已存在，正在更新。")
    else:
        logging.info(f"文件 {file_path_in_repo} 不存在，正在创建。")

    try:
        response = session.put(api_url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info(f"成功保存 {file_path_in_repo} 到 GitHub。")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"错误：保存 {file_path_in_repo} 到 GitHub 失败: {e} (Response: {e.response.text if e.response else 'N/A'})")
        return False

# --- 本地文件操作函数 ---
@performance_monitor
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]
        logging.info(f"成功从本地文件 '{file_name}' 读取 {len(lines)} 行数据。")
        return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到，返回空列表。")
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
        logging.debug(f"从 '{file_path}' 读取了 {len(existing_channels)} 个现有频道用于去重。")
    except FileNotFoundError:
        logging.debug(f"去重文件 '{file_path}' 未找到，假定无现有频道。")
        pass
    except Exception as e:
        logging.error(f"读取文件 '{file_path}' 进行去重失败: {e}")
    return existing_channels

@performance_monitor
def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道数据追加到文件，去重"""
    existing_channels = read_existing_channels(file_path)
    new_channels = set()
    for _, line in data_list: # data_list现在直接是(name, url)对
        if ',' in line: # 确保行是 name,url 格式
            name, url = line.split(',', 1)
            new_channels.add((name.strip(), url.strip()))
    
    
    channels_to_append = []
    for name, url in sorted(list(new_channels), key=lambda x: x[0]):
        if (name, url) not in existing_channels:
            channels_to_append.append((name, url))

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'a', encoding='utf-8') as file:
            for name, url in channels_to_append:
                file.write(f"{name},{url}\n")
        logging.debug(f"追加 {len(channels_to_append)} 个新频道到 {file_path}")
    except Exception as e:
        logging.error(f"追加写入文件 '{file_path}' 失败: {e}")

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
    logging.debug(f"M3U内容转换为TXT格式，提取了 {len(txt_lines)} 条记录。")
    return '\n'.join(txt_lines)

@performance_monitor
def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径"""
    try:
        parsed_url = urlparse(url)
        # 移除查询参数和片段标识符
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
            logging.debug(f"未从URL {url} 获取到内容或内容未变更。")
            return []

        extension = get_url_file_extension(url).lower()
        if extension in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)
        elif extension in [".ts", ".flv", ".mp4", ".hls", ".dash"]:
            channel_name = f"Stream_{os.path.basename(urlparse(url).path)}"
            if pre_screen_url(url):
                extracted_channels.append((channel_name, url))
                source_tracker[(channel_name, url)] = url
                logging.debug(f"提取单一流: {channel_name},{url} from {url}")
            return extracted_channels
        elif extension not in [".txt", ".csv"]:
            
            logging.debug(f"不支持的文件扩展名或缺失: {extension} for URL {url}")
            return []

        lines = text.split('\n')
        channel_count = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 兼容 name,url 和 纯url 格式
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
                    for channel_url_single in url_list:
                        channel_url = clean_url_params(channel_url_single.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                            source_tracker[(channel_name, channel_url)] = url
                            channel_count += 1
                        else:
                            logging.debug(f"跳过无效或预筛选失败的频道 URL: {channel_url_single}")
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
                        source_tracker[(channel_name, channel_url)] = url
                        channel_count += 1
                    else:
                        logging.debug(f"跳过无效或预筛选失败的频道 URL: {channel_address_raw}")
            elif re.match(r'^[a-zA-Z0-9+.-]+://', line):
                channel_name = f"Stream_{channel_count + 1}"
                channel_url = clean_url_params(line)
                if channel_url and pre_screen_url(channel_url):
                    extracted_channels.append((channel_name, channel_url))
                    source_tracker[(channel_name, channel_url)] = url
                    channel_count += 1
                else:
                    logging.debug(f"跳过无效或预筛选失败的单一 URL: {line}")
        logging.debug(f"成功从 {url} 提取 {channel_count} 个频道。")
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
        logging.info(f"从 '{URL_STATES_PATH}' 加载了 {len(url_states)} 个URL状态。")
    except FileNotFoundError:
        logging.warning(f"URL 状态文件 '{URL_STATES_PATH}' 未找到，使用空状态。")
    except json.JSONDecodeError as e:
        logging.error(f"解析 '{URL_STATES_PATH}' 的 JSON 失败: {e}，返回空状态。")
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
                logging.warning(f"无法解析 URL {url} 的 last_checked 时间戳: '{state['last_checked']}'，保留状态。")
                updated_url_states[url] = state
        else:
            updated_url_states[url] = state
    logging.info(f"清理过期状态后，剩余 {len(updated_url_states)} 个有效URL状态。")
    return updated_url_states

@performance_monitor
def save_url_states_local(url_states):
    """保存 URL 状态到本地文件"""
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
        logging.info(f"已将 {len(url_states)} 个URL状态保存到 '{URL_STATES_PATH}'。")
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}")

@retry(stop=stop_after_attempt(CONFIG['network']['max_retries_per_url']), wait=wait_fixed(5), reraise=True)
def fetch_url_content_with_retry(url, url_states):
    """带重试机制获取 URL 内容，使用缓存和 ETag/Last-Modified/Content-Hash"""
    if CONFIG['url_state']['cache_enabled'] and url in content_cache:
        logging.debug(f"从缓存读取 URL 内容: {url}")
        return content_cache[url]

    headers = {}
    current_state = url_states.get(url, {})
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
        logging.debug(f"为 {url} 添加 If-None-Match 头: {current_state['etag']}")
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']
        logging.debug(f"为 {url} 添加 If-Modified-Since 头: {current_state['last_modified']}")

    try:
        response = session.get(url, headers=headers, timeout=CONFIG['network']['request_timeout'])
        response.raise_for_status()

        if response.status_code == 304:
            logging.debug(f"URL 内容未变更 (304 Not Modified): {url}")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL 内容未变更（内容哈希相同）: {url}")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        # 内容有更新，保存新状态
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
            logging.debug(f"URL内容已写入缓存文件: {cache_file}")

        logging.debug(f"成功获取并更新URL内容: {url}")
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
    
    # 检查URL是否包含协议头
    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        logging.debug(f"预筛选过滤（无有效协议）: {url}")
        return False

    # 检查是否包含非法字符或空格
    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        logging.debug(f"预筛选过滤（包含非法字符或空格）: {url}")
        return False
        
    try:
        parsed_url = urlparse(url)
        # 检查协议
        if parsed_url.scheme not in CONFIG['url_pre_screening']['allowed_protocols']:
            logging.debug(f"预筛选过滤（不支持的协议）: {url} (协议: {parsed_url.scheme})")
            return False
        
        # 检查网络位置（域名或IP）是否存在
        if not parsed_url.netloc:
            logging.debug(f"预筛选过滤（无网络位置）: {url}")
            return False

        # 检查无效模式
        invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns']
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                logging.debug(f"预筛选过滤（匹配无效模式 '{pattern.pattern}'）: {url}")
                return False
        
        # 检查URL长度
        
        if len(url) < 15: 
            logging.debug(f"预筛选过滤（URL 过短，长度 {len(url)} < 15）: {url}")
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
        
        if any(word.lower() in url.lower() for word in CONFIG.get('url_filter_words', [])):
            logging.debug(f"过滤频道（URL 匹配黑名单词）: {name},{url}")
            continue
        
        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            logging.debug(f"过滤频道（名称匹配黑名单词）: {name},{url}")
            continue
            
        modified_name = name
        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items():
            modified_name = re.sub(old_str, new_str, modified_name, flags=re.IGNORECASE)
        
        filtered_channels.append((modified_name, url))
    
    logging.info(f"URL 预筛选后剩余 {pre_screened_count} 个频道，进一步过滤和修改后得到 {len(filtered_channels)} 个频道。")
    return filtered_channels

# --- 频道有效性检查函数 ---
@performance_monitor
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        is_valid = 200 <= response.status_code < 400
        if not is_valid:
            logging.debug(f"HTTP URL 检查失败: {url} (Status: {response.status_code})")
        return is_valid
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL 检查失败: {url} - {e}")
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达 (需要 ffprobe)"""
    # 检查ffprobe是否可用
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("ffprobe 未找到或不可用，跳过 RTMP 检查。请安装 ffmpeg/ffprobe。")
        return False

    try:
        # ffprobe尝试连接RTMP流，如果能获取到流信息则认为有效
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        is_valid = result.returncode == 0
        if not is_valid:
            logging.debug(f"RTMP URL 检查失败: {url} (ffprobe return code: {result.returncode}, stderr: {result.stderr.decode()})")
        return is_valid
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL 检查超时: {url}")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL 检查错误: {url} - {e}")
        return False

@performance_monitor
def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达 (模拟简单检查，实际需要更复杂的 RTP 协议解析)"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port

        if not host or not port:
            logging.debug(f"RTP URL 格式错误（无主机或端口）: {url}")
            return False

        # 尝试创建一个UDP socket并连接，模拟发送/接收数据
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # 尝试连接，但这只是TCP行为，对UDP不完全适用，但可用于检查地址有效性
            s.connect((host, port))
            # 实际 RTP 流需要发送和接收数据包，这里仅作简单可达性判断
            logging.debug(f"RTP URL (UDP) 简单可达性检查通过: {url}")
            return True
    except socket.timeout:
        logging.debug(f"RTP URL (UDP) 检查超时: {url}")
        return False
    except socket.error as e:
        logging.debug(f"RTP URL (UDP) 检查失败: {url} - {e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL 检查错误: {url} - {e}")
        return False

@performance_monitor
def check_udp_url(url, timeout):
    """检查 UDP URL 是否可达 (同 RTP 检查，因为 UDP 是底层协议)"""
    return check_rtp_url(url, timeout)

@performance_monitor
def check_channel_validity(channel_tuple, validation_config):
    """检查单个频道 URL 的有效性"""
    name, url = channel_tuple
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme.lower()
    timeout = validation_config['connection_timeout']

    is_valid = False
    if scheme in ['http', 'https']:
        is_valid = check_http_url(url, timeout)
    elif scheme == 'rtmp':
        is_valid = check_rtmp_url(url, timeout)
    elif scheme in ['rtp', 'udp']:
        is_valid = check_udp_url(url, timeout)
    else:
        logging.debug(f"跳过不支持协议的频道验证: {name}, {url} (协议: {scheme})")
        return channel_tuple, False

    if not is_valid:
        logging.debug(f"频道 '{name}' (URL: {url}) 被标记为无效。")
    return channel_tuple, is_valid

@performance_monitor
def validate_channels_concurrently(channels, validation_config):
    """并发验证频道列表的有效性"""
    valid_channels = []
    
    # 检查CPU核心数以决定线程池大小
    max_workers = validation_config['max_validation_workers']
    if max_workers == -1:
        max_workers = os.cpu_count() or 1
    logging.info(f"开始并发验证 {len(channels)} 个频道，使用 {max_workers} 个工作线程。")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 假设 tqdm 模块可用
        try:
            from tqdm import tqdm
        except ImportError:
            logging.warning("tqdm 模块未安装，进度条将不显示。请运行 'pip install tqdm' 安装。")
            tqdm = lambda x, **kwargs: x # 占位符，不显示进度条

        future_to_channel = {executor.submit(check_channel_validity, ch, validation_config): ch for ch in channels}
        
        for future in tqdm(as_completed(future_to_channel), total=len(channels), desc="验证频道有效性"):
            channel_tuple = future_to_channel[future]
            try:
                original_channel, is_valid = future.result()
                if is_valid:
                    valid_channels.append(original_channel)
            except Exception as e:
                logging.error(f"验证频道 {channel_tuple} 时发生错误: {e}")

    logging.info(f"频道验证完成。总共 {len(channels)} 个频道，其中 {len(valid_channels)} 个有效。")
    return valid_channels

# --- 频道搜索和获取函数 ---
@performance_monitor
def get_github_trending(search_keywords):
    """获取 GitHub Trending 仓库列表"""
    all_repos = []
    github_headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    for keyword in search_keywords:
        
        search_url = f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}?q={keyword}+in:file+extension:m3u+extension:txt&sort=indexed&order=desc"
        try:
            logging.info(f"正在从GitHub API搜索代码: {search_url}")
            response = session.get(search_url, headers=github_headers, timeout=15)
            response.raise_for_status()
            search_results = response.json().get('items', [])
            
            
            for item in search_results:
                repo_html_url = item['repository']['html_url']
                if repo_html_url not in all_repos:
                    all_repos.append(repo_html_url)
            logging.info(f"从GitHub代码搜索获取到 {len(search_results)} 个与关键词 '{keyword}' 相关的代码项，从中提取 {len(all_repos)} 个唯一仓库URL。")
        except requests.exceptions.RequestException as e:
            logging.error(f"从GitHub代码搜索获取数据失败 (关键词: {keyword}): {e}")
        time.sleep(1)
    return list(set(all_repos))

@performance_monitor
def get_m3u_from_github_repo(repo_url):
    """从 GitHub 仓库的文件内容中查找m3u8链接"""
    m3u_urls = []
    try:
        parsed_repo_url = urlparse(repo_url)
        path_parts = parsed_repo_url.path.strip('/').split('/')
        if len(path_parts) < 2:
            logging.warning(f"无法从仓库URL解析所有者和名称: {repo_url}")
            return []
        
        repo_owner = path_parts[0]
        repo_name = path_parts[1]

        
        contents_api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents"
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        
        logging.debug(f"尝试获取仓库 {repo_url} 的内容列表: {contents_api_url}")
        response = session.get(contents_api_url, headers=headers, timeout=10)
        response.raise_for_status()
        contents = response.json()

        potential_raw_urls = []
        for item in contents:
            if item['type'] == 'file' and (item['name'].lower().endswith(('.m3u', '.m3u8', '.txt', '.conf')) or 'readme' in item['name'].lower()):
                potential_raw_urls.append(item['download_url'])

        for file_url in potential_raw_urls:
            try:
                logging.debug(f"尝试从文件URL {file_url} 获取内容查找m3u8链接。")
                file_content_response = session.get(file_url, timeout=5)
                if file_content_response.status_code == 200:
                    found_links = re.findall(r'(https?://[^\s]+\.m3u8)', file_content_response.text)
                    m3u_urls.extend(found_links)
                    logging.debug(f"从 {file_url} 找到 {len(found_links)} 个m3u8链接。")
                    if found_links:
                        pass
            except requests.exceptions.RequestException as e:
                logging.debug(f"访问文件 {file_url} 失败: {e}")
        
    except requests.exceptions.RequestException as e:
        logging.error(f"从GitHub仓库 {repo_url} 获取文件内容失败: {e}")
    except Exception as e:
        logging.error(f"处理GitHub仓库 {repo_url} 失败: {e}")
    return list(set(m3u_urls))

@performance_monitor
def load_channels_from_local_files(file_paths):
    all_channels = []
    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if ',' in line and not line.startswith('#'):
                        name, url = line.split(',', 1)
                        all_channels.append((name.strip(), url.strip()))
            logging.info(f"从本地文件加载频道成功: {file_path}, 数量: {len(all_channels)}")
        except FileNotFoundError:
            logging.warning(f"本地文件未找到: {file_path}")
        except Exception as e:
            logging.error(f"加载本地文件失败 {file_path}: {e}")
    return all_channels

@performance_monitor
def search_channels(search_keywords, backup_urls, local_file_paths, invalid_url_patterns):
    """
    搜索并获取所有频道，包括来自GitHub Trending、备用URL和本地文件的频道。
    在提取过程中进行初步的URL预筛选。
    """
    all_channels = []
    source_tracker = {}

    logging.info("开始从本地文件加载频道...")
    local_channels = load_channels_from_local_files(local_file_paths)
    all_channels.extend(local_channels)
    for name, url in local_channels:
        source_tracker[(name, url)] = 'local_file'
    logging.info(f"已从本地文件加载 {len(local_channels)} 个频道。")

    logging.info("开始从GitHub Trending获取仓库URL...")
    github_repo_urls = get_github_trending(search_keywords)
    logging.info(f"从GitHub Trending获取到 {len(github_repo_urls)} 个仓库URL。")

    for repo_url in tqdm(github_repo_urls, desc="从GitHub仓库获取m3u链接"):
        m3u_urls = get_m3u_from_github_repo(repo_url)
        for m3u_url in m3u_urls:
            channels_from_github = extract_channels_from_url(m3u_url, url_states, source_tracker)
            all_channels.extend(channels_from_github)
        time.sleep(0.1)

    logging.info("开始从备用URL获取频道...")
    for url in tqdm(backup_urls, desc="从备用URL获取频道"):
        channels_from_url = extract_channels_from_url(url, url_states, source_tracker)
        all_channels.extend(channels_from_url)
        time.sleep(0.1)

    logging.info(f"所有源初步提取后总频道数: {len(all_channels)}")
    return all_channels

@performance_monitor
def remove_duplicate_channels(channels):
    """
    对频道列表进行去重，基于 (名称, URL) 对。
    如果名称相同但URL不同，则视为不同频道。
    如果 (名称, URL) 完全相同，则只保留一个。
    """
    unique_channels = {}
    for name, url in channels:
        channel_key = (name.strip(), url.strip())
        if channel_key not in unique_channels:
            unique_channels[channel_key] = True
            
    result = list(unique_channels.keys())
    logging.info(f"频道去重完成。去重前 {len(channels)} 个，去重后 {len(result)} 个。")
    return result

def clean_channel_name(name):
    """清理频道名称，移除特定字符和模式。"""
    # 移除方括号内的内容，例如 [超清]
    clean_name = re.sub(r'\[.*?\]', '', name)
    # 移除括号内的内容，例如 (HD)
    clean_name = re.sub(r'\(.*?\)', '', clean_name)
    # 移除特定符号
    clean_name = re.sub(r'[.-_]', '', clean_name)
    return clean_name.strip()

# --- 频道分类和文件合并函数 ---
def categorize_channel(channel_name, category_keywords):
    """根据关键词将频道归类。"""
    clean_name = clean_channel_name(channel_name)
    for category, keywords in category_keywords.items():
        for keyword in keywords:
            if keyword in clean_name:
                logging.debug(f"频道 '{channel_name}' 匹配到关键词 '{keyword}', 归类为 '{category}'")
                return category
    logging.debug(f"频道 '{channel_name}' 未匹配到任何分类关键词，归类为 '未分类'")
    return "未分类"

@performance_monitor
def process_and_save_channels_by_category(all_channels, config):
    """
    根据配置中的分类关键词，将所有频道分类并保存到不同的临时文件。
    未分类的频道也会单独保存。
    """
    category_keywords = config['channel_categories']['category_keywords']
    channels_dir = CHANNELS_DIR
    uncategorized_file_path = UNCATEGORIZED_CHANNELS_FILE
    
    os.makedirs(channels_dir, exist_ok=True)
    logging.info(f"临时分类文件将保存到目录: {channels_dir}")

    channel_by_category_file_paths = {}
    categorized_channels = {category: [] for category in config['channel_categories']['ordered_categories'] + ["未分类"]}

    # 为每个分类预设文件路径并清空旧文件
    for category in config['channel_categories']['ordered_categories'] + ["未分类"]:
        file_name = f"{category}_iptv.txt"
        file_path = os.path.join(channels_dir, file_name)
        channel_by_category_file_paths[category] = file_path
        # 清空旧的分类文件
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.debug(f"已清空旧的分类文件: {file_path}")
        logging.info(f"准备处理分类 '{category}', 对应文件: {file_path}")

    # 清空未分类文件 (如果它应该独立存在且路径不同于其他分类文件)
    
    if os.path.exists(uncategorized_file_path):
        os.remove(uncategorized_file_path)
        logging.debug(f"已清空旧的未分类文件: {uncategorized_file_path}")
    logging.info(f"准备处理未分类频道文件: {uncategorized_file_path}")


    for channel_name, channel_url in tqdm(all_channels, desc="处理频道分类"):
        category = categorize_channel(channel_name, category_keywords)
        categorized_channels[category].append((channel_name, channel_url))
        logging.debug(f"频道 '{channel_name}' 已添加到 '{category}' 分类列表")

    # 将分类好的频道写入各自的临时文件
    for category, channels in categorized_channels.items():
        if channels:
            file_path = channel_by_category_file_paths.get(category)
            if file_path:
                try:
                    with open(file_path, 'a', encoding='utf-8') as f:
                        for name, url in channels:
                            f.write(f"{name},{url}\n")
                    logging.info(f"已将 {len(channels)} 个频道写入文件: {file_path}")
                except Exception as e:
                    logging.error(f"写入文件 {file_path} 失败: {e}")
            else:
                logging.warning(f"未找到分类 '{category}' 对应的文件路径。")
        else:
            logging.info(f"分类 '{category}' 中没有频道，跳过文件写入。")

    # 特殊处理未分类频道文件 (如果它应该独立存在)
    if "未分类" in categorized_channels and categorized_channels["未分类"]:
        try:
            with open(uncategorized_file_path, 'a', encoding='utf-8') as f:
                for name, url in categorized_channels["未分类"]:
                    f.write(f"{name},{url}\n")
            logging.info(f"已将 {len(categorized_channels['未分类'])} 个未分类频道写入文件: {uncategorized_file_path}")
        except Exception as e:
            logging.error(f"写入未分类文件 {uncategorized_file_path} 失败: {e}")
    else:
        logging.info(f"没有未分类频道，或未分类文件未配置输出。")
        
        if os.path.exists(uncategorized_file_path) and os.path.getsize(uncategorized_file_path) == 0:
            os.remove(uncategorized_file_path)
            logging.info(f"已删除空的未分类文件: {uncategorized_file_path}")


@performance_monitor
def merge_local_channel_files(config):
    """
    读取按分类保存的临时文件，并按照 ordered_categories 的顺序合并到最终的iptv_list.txt。
    """
    channels_dir = CHANNELS_DIR
    ordered_categories = config['channel_categories']['ordered_categories']
    
    # 清空最终的iptv_list.txt文件并写入M3U头和更新时间
    with open(IPTV_LIST_PATH, 'w', encoding='utf-8') as f:
        f.write(f"#EXTM3U\n")
        f.write(f"# 更新时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        logging.info(f"已清空并初始化文件: {IPTV_LIST_PATH}。")

    # 用于确保每个频道只被添加一次，避免因为多个分类包含相同频道而重复
    added_channels_to_final_list = set() 

    # 按照 ordered_categories 的顺序合并文件，最后处理未分类
    all_categories_to_merge = ordered_categories + ["未分类"]
    logging.info(f"频道合并顺序：{all_categories_to_merge}")

    for category in all_categories_to_merge:
        file_name = f"{category}_iptv.txt"
        file_path = os.path.join(channels_dir, file_name)
        
        if os.path.exists(file_path):
            try:
                channels_in_current_category = []
                with open(file_path, 'r', encoding='utf-8') as f:
                    logging.info(f"开始合并分类 '{category}' 的频道文件: {file_path}")
                    for line in f:
                        line = line.strip()
                        if ',' in line:
                            name, url = line.split(',', 1)
                            channel_key = (name.strip(), url.strip())
                            if channel_key not in added_channels_to_final_list:
                                channels_in_current_category.append(channel_key)
                                added_channels_to_final_list.add(channel_key)
                    
                    if channels_in_current_category:
                        with open(IPTV_LIST_PATH, 'a', encoding='utf-8') as out_f:
                            out_f.write(f"\n#EXTGRP:{category}\n")
                            out_f.write(f"{category},#genre#\n")
                            for name, url in channels_in_current_category:
                                out_f.write(f"{name},{url}\n")
                        logging.info(f"已将 {len(channels_in_current_category)} 个来自 '{category}' 分类的频道合并到 {IPTV_LIST_PATH}。")
                    else:
                        logging.info(f"分类 '{category}' 文件中没有新的频道可合并。")

            except Exception as e:
                logging.error(f"合并文件 {file_path} 失败: {e}")
        else:
            logging.info(f"分类文件 '{file_path}' 不存在，跳过合并。")

# 主函数
def main():
    logging.info("--- IPTV 爬取脚本开始运行 ---")

    # 1. 加载 URL 状态
    logging.info("步骤 1: 加载 URL 状态...")
    url_states = load_url_states_local() # url_states在这里被赋值
    logging.info("步骤 1 完成。")

    # 2. 从本地和网络获取所有频道
    logging.info("步骤 2: 搜索和获取所有频道...")
    # 移除 'global url_states'，因为 url_states 已经被正确地作为参数传递给 extract_channels_from_url
    all_channels_from_sources = search_channels(
        CONFIG['search_sources']['github_trending']['keywords'],
        CONFIG['search_sources']['backup_urls'],
        CONFIG['search_sources']['local_files']['paths'],
        CONFIG['url_pre_screening']['invalid_url_patterns']
    )
    logging.info(f"步骤 2 完成。从所有源获取到 {len(all_channels_from_sources)} 个原始频道。")

    # 3. 过滤和修改频道名称/URL
    logging.info("步骤 3: 过滤和修改频道名称及URL...")
    filtered_and_modified_channels = filter_and_modify_channels(all_channels_from_sources)
    logging.info(f"步骤 3 完成。过滤和修改后剩余 {len(filtered_and_modified_channels)} 个频道。")

    # 4. 频道去重 (全局去重)
    logging.info("步骤 4: 对所有频道进行全局去重...")
    unique_channels = remove_duplicate_channels(filtered_and_modified_channels)
    logging.info(f"步骤 4 完成。全局去重后剩余 {len(unique_channels)} 个频道。")

    # 5. 验证频道有效性 (并发)
    logging.info("步骤 5: 验证频道有效性 (可能耗时较长)...")
    valid_channels = validate_channels_concurrently(unique_channels, CONFIG['channel_validation'])
    logging.info(f"步骤 5 完成。验证后 {len(valid_channels)} 个频道被认为是有效的。")

    # 6. 清理 temp_channels 目录 (在分类处理前清理)
    if os.path.exists(CHANNELS_DIR):
        import shutil
        shutil.rmtree(CHANNELS_DIR)
        logging.info(f"已清理旧的临时分类目录: {CHANNELS_DIR}")
    os.makedirs(CHANNELS_DIR, exist_ok=True)

    # 7. 处理并保存分类频道到临时文件
    logging.info("步骤 7: 处理并保存分类频道到临时文件...")
    process_and_save_channels_by_category(valid_channels, CONFIG)
    logging.info("步骤 7 完成。")

    # 8. 合并本地分类文件到最终的iptv_list.txt
    logging.info("步骤 8: 合并本地分类文件到最终的iptv_list.txt...")
    merge_local_channel_files(CONFIG)
    logging.info("步骤 8 完成。")

    # 9. 保存 URL 状态
    logging.info("步骤 9: 保存 URL 状态...")
    save_url_states_local(url_states)
    logging.info("步骤 9 完成。")

    logging.info("--- IPTV 爬取脚本运行结束 ---")

if __name__ == "__main__":
    main()
