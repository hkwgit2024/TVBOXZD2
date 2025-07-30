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
        [cite_start]with open(config_path, 'r', encoding='utf-8') as file: # [cite: 3]
            [cite_start]config = yaml.safe_load(file) # [cite: 3]
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    [cite_start]except Exception as e: # [cite: 3, 4]
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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; [cite_start]Win64; x64) AppleWebKit/537.36" # [cite: 5]
})
pool_size = CONFIG['network']['requests_pool_size']
retry_strategy = Retry(
    total=3,  # 增加重试次数
    [cite_start]backoff_factor=CONFIG['network']['requests_retry_backoff_factor'], # [cite: 5]
    [cite_start]status_forcelist=[429, 500, 502, 503, 504], # [cite: 5]
    [cite_start]allowed_methods=["HEAD", "GET", "OPTIONS"] # [cite: 5]
)
adapter = HTTPAdapter(
    [cite_start]pool_connections=pool_size, # [cite: 5]
    [cite_start]pool_maxsize=pool_size, # [cite: 5]
    [cite_start]max_retries=retry_strategy # [cite: 5]
)
[cite_start]session.mount("http://", adapter) # [cite: 5]
[cite_start]session.mount("https://", adapter) # [cite: 5]

# 性能监控装饰器
def performance_monitor(func):
    """记录函数执行时间的装饰器，用于性能分析"""
    if not CONFIG['performance_monitor']['enabled']:
        return func
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        [cite_start]elapsed_time = time.time() - start_time # [cite: 6]
        [cite_start]logging.info(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒") # [cite: 6]
        return result
    return wrapper

# --- GitHub 文件操作函数 ---
@performance_monitor
def fetch_from_github(file_path_in_repo):
    """从 GitHub 仓库获取文件内容"""
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        [cite_start]response = session.get(raw_url, headers=headers, timeout=15) # [cite: 6]
        [cite_start]response.raise_for_status() # [cite: 6]
        [cite_start]return response.text # [cite: 6]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"错误：从 GitHub 获取 {file_path_in_repo} 失败: {e}") # [cite: 7]
        return None

@performance_monitor
def get_current_sha(file_path_in_repo):
    """获取 GitHub 仓库中文件的当前 SHA 值"""
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        [cite_start]response = session.get(api_url, headers=headers, timeout=15) # [cite: 7]
        [cite_start]response.raise_for_status() # [cite: 7]
        [cite_start]return response.json().get('sha') # [cite: 7]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.debug(f"获取 {file_path_in_repo} 的 SHA 值失败（可能不存在）: {e}") # [cite: 7]
    [cite_start]return None # [cite: 8]

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
    [cite_start]if sha: # [cite: 9]
        [cite_start]payload["sha"] = sha # [cite: 9]
    try:
        [cite_start]response = session.put(api_url, headers=headers, json=payload) # [cite: 9]
        [cite_start]response.raise_for_status() # [cite: 9]
        [cite_start]return True # [cite: 9]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"错误：保存 {file_path_in_repo} 到 GitHub 失败: {e}") # [cite: 9]
        return False

# --- 本地文件操作函数 ---
@performance_monitor
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组"""
    try:
        [cite_start]with open(file_name, 'r', encoding='utf-8') as file: # [cite: 9, 10]
            [cite_start]lines = [line.strip() for line in file if line.strip()] # [cite: 10]
        [cite_start]return lines # [cite: 10]
    except FileNotFoundError:
        [cite_start]logging.warning(f"文件 '{file_name}' 未找到") # [cite: 10]
        return []
    except Exception as e:
        [cite_start]logging.error(f"读取文件 '{file_name}' 失败: {e}") # [cite: 10]
        return []

@performance_monitor
def read_existing_channels(file_path):
    """读取现有频道以进行去重"""
    existing_channels = set()
    try:
        [cite_start]with open(file_path, 'r', encoding='utf-8') as file: # [cite: 11]
            [cite_start]for line in file: # [cite: 11]
                [cite_start]line = line.strip() # [cite: 11]
                [cite_start]if line and ',' in line and not line.startswith('#'): # [cite: 11]
                    [cite_start]parts = line.split(',', 1) # [cite: 11]
                    [cite_start]if len(parts) == 2: # [cite: 12]
                        [cite_start]existing_channels.add((parts[0].strip(), parts[1].strip())) # [cite: 12]
    except FileNotFoundError:
        pass
    except Exception as e:
        [cite_start]logging.error(f"读取文件 '{file_path}' 进行去重失败: {e}") # [cite: 12]
    return existing_channels

@performance_monitor
def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道数据写入文件，去重"""
    existing_channels = read_existing_channels(file_path)
    new_channels = set()
    [cite_start]for _, line in data_list: # [cite: 13]
        [cite_start]if ',' in line: # [cite: 13]
            [cite_start]name, url = line.split(',', 1) # [cite: 13]
            [cite_start]new_channels.add((name.strip(), url.strip())) # [cite: 13]
    [cite_start]all_channels = existing_channels | new_channels # [cite: 13, 14]
    try:
        [cite_start]os.makedirs(os.path.dirname(file_path), exist_ok=True) # [cite: 14]
        [cite_start]with open(file_path, 'w', encoding='utf-8') as file: # [cite: 14]
            [cite_start]for name, url in sorted(all_channels, key=lambda x: x[0]): # [cite: 14]
                [cite_start]file.write(f"{name},{url}\n") # [cite: 14]
        [cite_start]logging.debug(f"写入 {len(all_channels)} 个频道到 {file_path}") # [cite: 14]
    except Exception as e:
        [cite_start]logging.error(f"写入文件 '{file_path}' 失败: {e}") # [cite: 14]

# --- URL 处理和频道提取函数 ---
@performance_monitor
def get_url_file_extension(url):
    """获取 URL 的文件扩展名"""
    try:
        [cite_start]parsed_url = urlparse(url) # [cite: 15]
        [cite_start]return os.path.splitext(parsed_url.path)[1].lower() # [cite: 15]
    except ValueError as e:
        [cite_start]logging.debug(f"获取 URL 扩展名失败: {url} - {e}") # [cite: 15]
        return ""

@performance_monitor
def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式转换为 TXT 格式（频道名称，URL）"""
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = "未知频道"
    for line in lines:
        line = line.strip()
        [cite_start]if not line or line.startswith('#EXTM3U'): # [cite: 16]
            continue
        [cite_start]if line.startswith('#EXTINF'): # [cite: 16]
            [cite_start]match = re.search(r'#EXTINF:.*?\,(.*)', line, re.IGNORECASE) # [cite: 16]
            [cite_start]channel_name = match.group(1).strip() or "未知频道" if match else "未知频道" # [cite: 16]
        [cite_start]elif re.match(r'^[a-zA-Z0-9+.-]+://', line) and not line.startswith('#'): # [cite: 16]
            [cite_start]txt_lines.append(f"{channel_name},{line}") # [cite: 16]
        [cite_start]channel_name = "未知频道" # [cite: 17]
    [cite_start]return '\n'.join(txt_lines) # [cite: 17]

@performance_monitor
def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径"""
    try:
        [cite_start]parsed_url = urlparse(url) # [cite: 17]
        [cite_start]return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path # [cite: 17]
    except ValueError as e:
        [cite_start]logging.debug(f"清理 URL 参数失败: {url} - {e}") # [cite: 17]
        return url

@performance_monitor
def extract_channels_from_url(url, url_states, source_tracker):
    """从 URL 提取频道，支持多种文件格式"""
    extracted_channels = []
    try:
        [cite_start]text = fetch_url_content_with_retry(url, url_states) # [cite: 18]
        [cite_start]if text is None: # [cite: 18]
            [cite_start]return [] # [cite: 18]

        [cite_start]extension = get_url_file_extension(url).lower() # [cite: 18]
        [cite_start]if extension in [".m3u", ".m3u8"]: # [cite: 18]
            [cite_start]text = convert_m3u_to_txt(text) # [cite: 18]
        [cite_start]elif extension in [".ts", ".flv", ".mp4", ".hls", ".dash"]: # [cite: 18]
            [cite_start]channel_name = f"Stream_{os.path.basename(urlparse(url).path)}" # [cite: 18]
            [cite_start]if pre_screen_url(url): # [cite: 19]
                [cite_start]extracted_channels.append((channel_name, url)) # [cite: 19]
                [cite_start]source_tracker[(channel_name, url)] = url # [cite: 19]
                [cite_start]logging.debug(f"提取单一流: {channel_name},{url}") # [cite: 19]
            return extracted_channels
        [cite_start]elif extension not in [".txt", ".csv"]: # [cite: 19]
            [cite_start]logging.debug(f"不支持的文件扩展名: {url}") # [cite: 19]
            [cite_start]return [] # [cite: 20]

        [cite_start]lines = text.split('\n') # [cite: 20]
        [cite_start]channel_count = 0 # [cite: 20]
        [cite_start]for line in lines: # [cite: 20]
            [cite_start]line = line.strip() # [cite: 20]
            [cite_start]if not line or line.startswith('#'): # [cite: 20]
                continue
            [cite_start]if "," in line and "://" in line: # [cite: 21]
                [cite_start]parts = line.split(',', 1) # [cite: 21]
                [cite_start]if len(parts) != 2: # [cite: 21]
                    [cite_start]logging.debug(f"跳过无效频道行（格式错误）: {line}") # [cite: 21]
                    continue
                [cite_start]channel_name, channel_address_raw = parts # [cite: 22]
                [cite_start]channel_name = channel_name.strip() or "未知频道" # [cite: 22]
                [cite_start]channel_address_raw = channel_address_raw.strip() # [cite: 22]

                [cite_start]if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw): # [cite: 22]
                    [cite_start]logging.debug(f"跳过无效频道 URL（无有效协议）: {line}") # [cite: 22]
                    [cite_start]continue # [cite: 23]

                [cite_start]if '#' in channel_address_raw: # [cite: 23]
                    [cite_start]url_list = channel_address_raw.split('#') # [cite: 23]
                    [cite_start]for channel_url in url_list: # [cite: 23]
                        [cite_start]channel_url = clean_url_params(channel_url.strip()) # [cite: 23, 24]
                        [cite_start]if channel_url and pre_screen_url(channel_url): # [cite: 24]
                            [cite_start]extracted_channels.append((channel_name, channel_url)) # [cite: 24]
                            [cite_start]source_tracker[(channel_name, channel_url)] = url # [cite: 24]
                            [cite_start]channel_count += 1 # [cite: 25]
                        else:
                            [cite_start]logging.debug(f"跳过无效或预筛选失败的频道 URL: {channel_url}") # [cite: 25]
                else:
                    [cite_start]channel_url = clean_url_params(channel_address_raw) # [cite: 26]
                    [cite_start]if channel_url and pre_screen_url(channel_url): # [cite: 26]
                        [cite_start]extracted_channels.append((channel_name, channel_url)) # [cite: 26]
                        [cite_start]source_tracker[(channel_name, channel_url)] = url # [cite: 26]
                        [cite_start]channel_count += 1 # [cite: 27]
                    else:
                        [cite_start]logging.debug(f"跳过无效或预筛选失败的频道 URL: {channel_url}") # [cite: 27]
            [cite_start]elif re.match(r'^[a-zA-Z0-9+.-]+://', line): # [cite: 27]
                [cite_start]channel_name = f"Stream_{channel_count + 1}" # [cite: 27, 28]
                [cite_start]channel_url = clean_url_params(line) # [cite: 28]
                [cite_start]if channel_url and pre_screen_url(channel_url): # [cite: 28]
                    [cite_start]extracted_channels.append((channel_name, channel_url)) # [cite: 28]
                    [cite_start]source_tracker[(channel_name, channel_url)] = url # [cite: 28]
                    [cite_start]channel_count += 1 # [cite: 28]
                else:
                    [cite_start]logging.debug(f"跳过无效或预筛选失败的单一 URL: {line}") # [cite: 29]
        [cite_start]logging.debug(f"成功从 {url} 提取 {channel_count} 个频道") # [cite: 29]
    except Exception as e:
        [cite_start]logging.error(f"从 {url} 提取频道失败: {e}") # [cite: 29]
    return extracted_channels

# --- URL 状态管理函数 ---
@performance_monitor
def load_url_states_local():
    """加载 URL 状态并清理过期状态"""
    url_states = {}
    try:
        [cite_start]with open(URL_STATES_PATH, 'r', encoding='utf-8') as file: # [cite: 30]
            [cite_start]url_states = json.load(file) # [cite: 30]
    except FileNotFoundError:
        [cite_start]logging.warning(f"URL 状态文件 '{URL_STATES_PATH}' 未找到，使用空状态") # [cite: 30]
    except json.JSONDecodeError as e:
        [cite_start]logging.error(f"解析 '{URL_STATES_PATH}' 的 JSON 失败: {e}") # [cite: 30]
        return {}
    
    [cite_start]current_time = datetime.now() # [cite: 30]
    [cite_start]updated_url_states = {} # [cite: 30]
    [cite_start]for url, state in url_states.items(): # [cite: 30]
        [cite_start]if 'last_checked' in state: # [cite: 30]
            [cite_start]try: # [cite: 31]
                [cite_start]last_checked_datetime = datetime.fromisoformat(state['last_checked']) # [cite: 31]
                [cite_start]if (current_time - last_checked_datetime).days < CONFIG['url_state']['expiration_days']: # [cite: 31]
                    [cite_start]updated_url_states[url] = state # [cite: 31]
                else:
                    [cite_start]logging.debug(f"移除过期 URL 状态: {url}（最后检查于 {state['last_checked']}）") # [cite: 32]
            except ValueError:
                [cite_start]logging.warning(f"无法解析 URL {url} 的 last_checked 时间戳: {state['last_checked']}") # [cite: 32]
                [cite_start]updated_url_states[url] = state # [cite: 32]
        else:
            [cite_start]updated_url_states[url] = state # [cite: 32]
    return updated_url_states

@performance_monitor
def save_url_states_local(url_states):
    """保存 URL 状态到本地文件"""
    try:
        [cite_start]os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True) # [cite: 33]
        [cite_start]with open(URL_STATES_PATH, 'w', encoding='utf-8') as file: # [cite: 33]
            [cite_start]json.dump(url_states, file, indent=4, ensure_ascii=False) # [cite: 33]
    except Exception as e:
        [cite_start]logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}") # [cite: 33]

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
def fetch_url_content_with_retry(url, url_states):
    """带重试机制获取 URL 内容，使用缓存和 ETag/Last-Modified/Content-Hash"""
    [cite_start]if CONFIG['url_state']['cache_enabled'] and url in content_cache: # [cite: 33]
        [cite_start]logging.debug(f"从缓存读取 URL 内容: {url}") # [cite: 33]
        [cite_start]return content_cache[url] # [cite: 33]

    [cite_start]headers = {} # [cite: 34]
    [cite_start]current_state = url_states.get(url, {}) # [cite: 34]
    [cite_start]if 'etag' in current_state: # [cite: 34]
        [cite_start]headers['If-None-Match'] = current_state['etag'] # [cite: 34]
    [cite_start]if 'last_modified' in current_state: # [cite: 34]
        [cite_start]headers['If-Modified-Since'] = current_state['last_modified'] # [cite: 34]

    try:
        [cite_start]response = session.get(url, headers=headers, timeout=15) # [cite: 34]
        [cite_start]response.raise_for_status() # [cite: 34]

        [cite_start]if response.status_code == 304: # [cite: 34]
            [cite_start]logging.debug(f"URL 内容未变更 (304): {url}") # [cite: 34]
            [cite_start]if url not in url_states: # [cite: 35]
                [cite_start]url_states[url] = {} # [cite: 35]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() # [cite: 35]
            [cite_start]return None # [cite: 35]

        [cite_start]content = response.text # [cite: 35]
        [cite_start]content_hash = hashlib.md5(content.encode('utf-8')).hexdigest() # [cite: 35]

        [cite_start]if 'content_hash' in current_state and current_state['content_hash'] == content_hash: # [cite: 35]
            [cite_start]logging.debug(f"URL 内容未变更（哈希相同）: {url}") # [cite: 35]
            [cite_start]if url not in url_states: # [cite: 36]
                [cite_start]url_states[url] = {} # [cite: 36]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() # [cite: 36]
            [cite_start]return None # [cite: 36]

        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            [cite_start]'content_hash': content_hash, # [cite: 37]
            [cite_start]'last_checked': datetime.now().isoformat() # [cite: 37]
        }

        [cite_start]if CONFIG['url_state']['cache_enabled']: # [cite: 37]
            [cite_start]content_cache[url] = content # [cite: 37]
            [cite_start]cache_file = os.path.join(CONFIG['url_state']['cache_dir'], f"{hashlib.md5(url.encode()).hexdigest()}.txt") # [cite: 37]
            [cite_start]with open(cache_file, 'w', encoding='utf-8') as f: # [cite: 37]
                [cite_start]f.write(content) # [cite: 37]

        [cite_start]logging.debug(f"成功获取新内容: {url}") # [cite: 38]
        return content
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"请求 URL 失败（重试后）: {url} - {e}") # [cite: 38]
        return None
    except Exception as e:
        [cite_start]logging.error(f"获取 URL 内容未知错误: {url} - {e}") # [cite: 38]
        return None

@performance_monitor
def pre_screen_url(url):
    """根据配置预筛选 URL（协议、长度、无效模式）"""
    [cite_start]if not isinstance(url, str) or not url: # [cite: 38, 39]
        [cite_start]logging.debug(f"预筛选过滤（无效类型或空）: {url}") # [cite: 39]
        return False

    [cite_start]if not re.match(r'^[a-zA-Z0-9+.-]+://', url): # [cite: 39]
        [cite_start]logging.debug(f"预筛选过滤（无有效协议）: {url}") # [cite: 39]
        return False

    [cite_start]if re.search(r'[^\x00-\x7F]', url) or ' ' in url: # [cite: 39]
        [cite_start]logging.debug(f"预筛选过滤（包含非法字符或空格）: {url}") # [cite: 39]
        return False

    try:
        [cite_start]parsed_url = urlparse(url) # [cite: 39]
        [cite_start]if parsed_url.scheme not in CONFIG['url_pre_screening']['allowed_protocols']: # [cite: 39, 40]
            [cite_start]logging.debug(f"预筛选过滤（不支持的协议）: {url}") # [cite: 40]
            return False

        [cite_start]if not parsed_url.netloc: # [cite: 40]
            [cite_start]logging.debug(f"预筛选过滤（无网络位置）: {url}") # [cite: 40]
            return False

        [cite_start]invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns'] # [cite: 40]
        [cite_start]compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns] # [cite: 40]
        [cite_start]for pattern in compiled_invalid_url_patterns: # [cite: 40]
            [cite_start]if pattern.search(url): # [cite: 41]
                [cite_start]logging.debug(f"预筛选过滤（无效模式）: {url}") # [cite: 41]
                return False

        [cite_start]if len(url) < 15: # [cite: 41]
            [cite_start]logging.debug(f"预筛选过滤（URL 过短）: {url}") # [cite: 41]
            return False

        [cite_start]return True # [cite: 41]
    except ValueError as e:
        [cite_start]logging.debug(f"预筛选过滤（URL 解析错误）: {url} - {e}") # [cite: 41, 42]
        return False

@performance_monitor
def filter_and_modify_channels(channels):
    """过滤和修改频道名称及 URL"""
    filtered_channels = []
    pre_screened_count = 0
    [cite_start]for name, url in channels: # [cite: 42]
        [cite_start]if not pre_screen_url(url): # [cite: 42]
            [cite_start]logging.debug(f"过滤频道（预筛选失败）: {name},{url}") # [cite: 42]
            continue
        [cite_start]pre_screened_count += 1 # [cite: 42]

        # 应用名称替换
        [cite_start]new_name = name # [cite: 42, 43]
        [cite_start]for old_str, new_str in CONFIG['channel_name_replacements'].items(): # [cite: 43]
            [cite_start]new_name = re.sub(old_str, new_str, new_name, flags=re.IGNORECASE) # [cite: 43]
        [cite_start]new_name = new_name.strip() # [cite: 43]

        # 过滤关键字
        [cite_start]if any(word.lower() in new_name.lower() for word in CONFIG['name_filter_words']): # [cite: 43]
            [cite_start]logging.debug(f"过滤频道（名称匹配黑名单）: {name},{url}") # [cite: 43]
            continue

        [cite_start]filtered_channels.append((new_name, url)) # [cite: 43]
    [cite_start]logging.debug(f"URL 预筛选后剩余 {pre_screened_count} 个频道进行进一步过滤") # [cite: 44]
    return filtered_channels

# --- 频道有效性检查函数 ---
@performance_monitor
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达"""
    try:
        [cite_start]response = session.head(url, timeout=timeout, allow_redirects=True) # [cite: 44]
        [cite_start]return 200 <= response.status_code < 400 # [cite: 44]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.debug(f"HTTP URL 检查失败: {url} - {e}") # [cite: 44]
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达"""
    try:
        [cite_start]subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2) # [cite: 45]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        [cite_start]logging.warning("ffprobe 未找到或不可用，跳过 RTMP 检查") # [cite: 45]
        return False
    try:
        result = subprocess.run(
            [cite_start]['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url], # [cite: 45]
            [cite_start]stdout=subprocess.PIPE, # [cite: 45]
            [cite_start]stderr=subprocess.PIPE, # [cite: 45]
            [cite_start]timeout=timeout # [cite: 46]
        )
        [cite_start]return result.returncode == 0 # [cite: 46]
    except subprocess.TimeoutExpired:
        [cite_start]logging.debug(f"RTMP URL 检查超时: {url}") # [cite: 46]
        return False
    except Exception as e:
        [cite_start]logging.debug(f"RTMP URL 检查错误: {url} - {e}") # [cite: 46]
        return False

@performance_monitor
def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达"""
    try:
        [cite_start]parsed_url = urlparse(url) # [cite: 46, 47]
        [cite_start]host = parsed_url.hostname # [cite: 47]
        [cite_start]port = parsed_url.port # [cite: 47]
        [cite_start]if not host or not port: # [cite: 47]
            [cite_start]logging.debug(f"RTP URL 解析失败（缺少主机或端口）: {url}") # [cite: 47]
            return False

        [cite_start]with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: # [cite: 47]
            [cite_start]s.settimeout(timeout) # [cite: 47]
            [cite_start]s.connect((host, port)) # [cite: 47]
            [cite_start]s.sendto(b'', (host, port)) # [cite: 48]
            [cite_start]s.recv(1) # [cite: 48]
        [cite_start]return True # [cite: 48]
    except (socket.timeout, socket.error) as e:
        [cite_start]logging.debug(f"RTP URL 检查失败: {url} - {e}") # [cite: 48]
        return False
    except Exception as e:
        [cite_start]logging.debug(f"RTP URL 检查错误: {url} - {e}") # [cite: 48]
        return False

@performance_monitor
def check_p3p_url(url, timeout):
    """检查 P3P URL 是否可达"""
    [cite_start]try: # [cite: 49]
        [cite_start]parsed_url = urlparse(url) # [cite: 49]
        [cite_start]host = parsed_url.hostname # [cite: 49]
        [cite_start]port = parsed_url.port if parsed_url.port else 80 # [cite: 49]
        [cite_start]path = parsed_url.path if parsed_url.path else '/' # [cite: 49]

        [cite_start]if not host: # [cite: 49]
            [cite_start]logging.debug(f"P3P URL 解析失败（缺少主机）: {url}") # [cite: 49]
            return False

        [cite_start]with socket.create_connection((host, port), timeout=timeout) as s: # [cite: 49]
            [cite_start]request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n" # [cite: 50]
            [cite_start]s.sendall(request.encode()) # [cite: 50]
            [cite_start]response = s.recv(1024).decode('utf-8', errors='ignore') # [cite: 50]
            [cite_start]return "P3P" in response or response.startswith("HTTP/1.") # [cite: 50]
    except Exception as e:
        [cite_start]logging.debug(f"P3P URL 检查失败: {url} - {e}") # [cite: 50]
        return False

@performance_monitor
def check_webrtc_url(url, timeout):
    """检查 WebRTC URL 是否可达（简单检查 ICE 服务器可用性）"""
    try:
        [cite_start]parsed_url = urlparse(url) # [cite: 51]
        [cite_start]if not parsed_url.scheme == 'webrtc': # [cite: 51]
            return False
        # 这里仅模拟检查，实际 WebRTC 需要更复杂的 ICE/TURN/STUN 验证
        return True  # 占位，需根据实际需求实现
    except Exception as e:
        [cite_start]logging.debug(f"WebRTC URL 检查失败: {url} - {e}") # [cite: 51]
        return False

@performance_monitor
def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CONFIG['network']['check_timeout']):
    """检查单个频道的有效性和速度"""
    [cite_start]current_time = datetime.now() # [cite: 52]
    [cite_start]current_url_state = url_states.get(url, {}) # [cite: 52]

    [cite_start]if 'stream_check_failed_at' in current_url_state: # [cite: 52]
        [cite_start]try: # [cite: 52]
            [cite_start]last_failed_datetime = datetime.fromisoformat(current_url_state['stream_check_failed_at']) # [cite: 52]
            [cite_start]time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600 # [cite: 52]
            [cite_start]if time_since_failed_hours < CONFIG['channel_retention']['stream_retention_hours']: # [cite: 52]
                [cite_start]logging.debug(f"跳过频道 {channel_name} ({url})，因其在冷却期内（{CONFIG['channel_retention']['stream_retention_hours']}h），上次失败于 {time_since_failed_hours:.2f}h 前") # [cite: 52]
                [cite_start]return None, False # [cite: 53]
        except ValueError:
            [cite_start]logging.warning(f"无法解析 URL {url} 的失败时间戳: {current_url_state['stream_check_failed_at']}") # [cite: 53]

    [cite_start]start_time = time.time() # [cite: 53]
    [cite_start]is_valid = False # [cite: 53]
    [cite_start]protocol_checked = False # [cite: 53]

    try:
        [cite_start]if url.startswith("http"): # [cite: 53]
            [cite_start]is_valid = check_http_url(url, timeout) # [cite: 53, 54]
            [cite_start]protocol_checked = True # [cite: 54]
        [cite_start]elif url.startswith("rtmp"): # [cite: 54]
            [cite_start]is_valid = check_rtmp_url(url, timeout) # [cite: 54]
            [cite_start]protocol_checked = True # [cite: 54]
        [cite_start]elif url.startswith("rtp"): # [cite: 54]
            [cite_start]is_valid = check_rtp_url(url, timeout) # [cite: 54]
            [cite_start]protocol_checked = True # [cite: 54]
        [cite_start]elif url.startswith("p3p"): # [cite: 54]
            [cite_start]is_valid = check_p3p_url(url, timeout) # [cite: 55]
            [cite_start]protocol_checked = True # [cite: 55]
        [cite_start]elif url.startswith("webrtc"): # [cite: 55]
            [cite_start]is_valid = check_webrtc_url(url, timeout) # [cite: 55]
            [cite_start]protocol_checked = True # [cite: 55]
        else:
            [cite_start]logging.debug(f"频道 {channel_name} 的协议不支持: {url}") # [cite: 55]
            [cite_start]if url not in url_states: # [cite: 55, 56]
                [cite_start]url_states[url] = {} # [cite: 56]
            [cite_start]url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat() # [cite: 56]
            [cite_start]url_states[url].pop('stream_check_failed_at', None) # [cite: 56]
            [cite_start]url_states[url].pop('stream_fail_count', None) # [cite: 56]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() # [cite: 56]
            return None, False

        [cite_start]elapsed_time = (time.time() - start_time) * 1000 # [cite: 56]

        [cite_start]if is_valid: # [cite: 57]
            [cite_start]if url not in url_states: # [cite: 57]
                [cite_start]url_states[url] = {} # [cite: 57]
            [cite_start]url_states[url].pop('stream_check_failed_at', None) # [cite: 57]
            [cite_start]url_states[url].pop('stream_fail_count', None) # [cite: 57]
            [cite_start]url_states[url]['last_successful_stream_check'] = current_time.isoformat() # [cite: 57]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() # [cite: 57]
            [cite_start]logging.debug(f"频道 {channel_name} ({url}) 检查成功，耗时 {elapsed_time:.0f} ms") # [cite: 58]
            return elapsed_time, True
        else:
            [cite_start]if url not in url_states: # [cite: 58]
                [cite_start]url_states[url] = {} # [cite: 58]
            [cite_start]url_states[url]['stream_check_failed_at'] = current_time.isoformat() # [cite: 58]
            [cite_start]url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 # [cite: 58]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() # [cite: 59]
            [cite_start]logging.debug(f"频道 {channel_name} ({url}) 检查失败") # [cite: 59]
            return None, False
    except Exception as e:
        [cite_start]if url not in url_states: # [cite: 59]
            [cite_start]url_states[url] = {} # [cite: 59]
        [cite_start]url_states[url]['stream_check_failed_at'] = current_time.isoformat() # [cite: 59]
        [cite_start]url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 # [cite: 59]
        [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() # [cite: 60]
        [cite_start]logging.debug(f"检查频道 {channel_name} ({url}) 错误: {e}") # [cite: 60]
        return None, False

@performance_monitor
def process_single_channel_line(channel_line, url_states):
    """处理单个频道行以进行有效性检查"""
    [cite_start]if "://" not in channel_line: # [cite: 60]
        [cite_start]logging.debug(f"跳过无效频道行（无协议）: {channel_line}") # [cite: 60]
        return None, None
    [cite_start]parts = channel_line.split(',', 1) # [cite: 60]
    [cite_start]if len(parts) == 2: # [cite: 60]
        [cite_start]name, url = parts # [cite: 61]
        [cite_start]url = url.strip() # [cite: 61]
        [cite_start]elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states) # [cite: 61]
        [cite_start]if is_valid: # [cite: 61]
            [cite_start]return elapsed_time, f"{name},{url}" # [cite: 61]
    return None, None

@performance_monitor
def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG['network']['channel_check_workers']):
    """多线程检查频道有效性"""
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    [cite_start]logging.warning(f"开始多线程检查 {total_channels} 个频道的有效性和速度") # [cite: 61]
    [cite_start]with ThreadPoolExecutor(max_workers=max_workers) as executor: # [cite: 61]
        [cite_start]futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines} # [cite: 61]
        [cite_start]for i, future in enumerate(as_completed(futures)): # [cite: 62]
            [cite_start]checked_count += 1 # [cite: 62]
            [cite_start]if checked_count % CONFIG['performance_monitor']['log_interval'] == 0: # [cite: 62]
                [cite_start]logging.warning(f"已检查 {checked_count}/{total_channels} 个频道") # [cite: 62]
            try:
                [cite_start]elapsed_time, result_line = future.result() # [cite: 62, 63]
                [cite_start]if elapsed_time is not None and result_line is not None: # [cite: 63]
                    [cite_start]results.append((elapsed_time, result_line)) # [cite: 63]
            except Exception as exc:
                [cite_start]logging.warning(f"处理频道行时发生异常: {exc}") # [cite: 63]
    return results

# --- 文件合并和排序函数 ---
@performance_monitor
def generate_update_time_header():
    """生成文件顶部更新时间信息"""
    [cite_start]now = datetime.now() # [cite: 63]
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d %H:%M:%S')},url\n"
    [cite_start]] # [cite: 64]

@performance_monitor
def group_and_limit_channels(lines):
    """对频道分组并限制每个频道名称下的 URL 数量"""
    grouped_channels = {}
    [cite_start]for line_content in lines: # [cite: 64]
        [cite_start]line_content = line_content.strip() # [cite: 64]
        [cite_start]if line_content: # [cite: 64]
            [cite_start]channel_name = line_content.split(',', 1)[0].strip() # [cite: 64]
            [cite_start]if channel_name not in grouped_channels: # [cite: 64]
                [cite_start]grouped_channels[channel_name] = [] # [cite: 64]
            [cite_start]grouped_channels[channel_name].append(line_content) # [cite: 65]
    
    [cite_start]final_grouped_lines = [] # [cite: 65]
    [cite_start]for channel_name in grouped_channels: # [cite: 65]
        [cite_start]for ch_line in grouped_channels[channel_name][:CONFIG.get('max_channel_urls_per_group', 100)]: # [cite: 65]
            [cite_start]final_grouped_lines.append(ch_line + '\n') # [cite: 65]
    return final_grouped_lines

@performance_monitor
def merge_local_channel_files(local_channels_directory, output_file_name, url_states):
    """合并本地频道列表文件，去重并清理，按分类输出"""
    [cite_start]os.makedirs(local_channels_directory, exist_ok=True) # [cite: 65]
    [cite_start]existing_channels_data = read_existing_channels(output_file_name) # [cite: 65]
    [cite_start]all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')] # [cite: 65]
    
    [cite_start]uncategorized_file_in_root = CONFIG['output']['paths']['uncategorized_channels_file'] # [cite: 65]
    [cite_start]if os.path.exists(uncategorized_file_in_root): # [cite: 65]
        [cite_start]all_iptv_files_in_dir.append(uncategorized_file_in_root) # [cite: 66]

    [cite_start]files_to_merge_paths = [] # [cite: 66]
    [cite_start]processed_files = set() # [cite: 66]

    [cite_start]for category in CONFIG.get('ordered_categories', []): # [cite: 66]
        [cite_start]file_name = f"{category}_iptv.txt" # [cite: 66]
        [cite_start]temp_path = os.path.join(local_channels_directory, file_name) # [cite: 66]
        [cite_start]root_path = file_name # [cite: 66]
        
        [cite_start]if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files: # [cite: 66]
            [cite_start]files_to_merge_paths.append(temp_path) # [cite: 66]
            [cite_start]processed_files.add(os.path.basename(temp_path)) # [cite: 67]
        [cite_start]elif category == '其他频道' and os.path.basename(root_path) in all_iptv_files_in_dir and root_path not in processed_files: # [cite: 67]
            [cite_start]files_to_merge_paths.append(root_path) # [cite: 67]
            [cite_start]processed_files.add(os.path.basename(root_path)) # [cite: 67]

    [cite_start]for file_name in sorted(all_iptv_files_in_dir): # [cite: 67]
        [cite_start]if file_name not in processed_files: # [cite: 67]
            [cite_start]if os.path.basename(file_name) == uncategorized_file_in_root: # [cite: 67]
                [cite_start]files_to_merge_paths.append(uncategorized_file_in_root) # [cite: 67]
            else:
                [cite_start]files_to_merge_paths.append(os.path.join(local_channels_directory, file_name)) # [cite: 68]
            [cite_start]processed_files.add(file_name) # [cite: 68]

    [cite_start]new_channels_from_merged_files = set() # [cite: 68]
    [cite_start]for file_path in files_to_merge_paths: # [cite: 68]
        [cite_start]with open(file_path, "r", encoding="utf-8") as file: # [cite: 68]
            [cite_start]lines = file.readlines() # [cite: 68]
            [cite_start]if not lines: # [cite: 68, 69]
                continue
            [cite_start]for line in lines: # [cite: 69]
                [cite_start]line = line.strip() # [cite: 69]
                [cite_start]if line and ',' in line and '#genre#' not in line: # [cite: 69]
                    [cite_start]name, url = line.split(',', 1) # [cite: 69]
                    [cite_start]new_channels_from_merged_files.add((name.strip(), url.strip())) # [cite: 70]

    [cite_start]combined_channels = existing_channels_data | new_channels_from_merged_files # [cite: 70, 71]
    [cite_start]channels_for_checking_lines = [f"{name},{url}" for name, url in combined_channels] # [cite: 71]
    [cite_start]logging.warning(f"总计 {len(channels_for_checking_lines)} 个唯一频道待检查和过滤") # [cite: 71]

    [cite_start]valid_channels_from_check = check_channels_multithreaded(channels_for_checking_lines, url_states) # [cite: 71]

    # 按分类重新组织有效频道
    # 修正了第795行的语法错误
    categorized_channels, uncategorized_channels = categorize_channels(
        [(name, url) for _, line in valid_channels_from_check for name, url in [line.split(',', 1)]]
    )

    # 保存合并后的主文件，按分类输出
    try:
        [cite_start]with open(output_file_name, "w", encoding='utf-8') as iptv_list_file: # [cite: 71]
            [cite_start]iptv_list_file.writelines(generate_update_time_header()) # [cite: 71, 72]
            [cite_start]for category in CONFIG.get('ordered_categories', []): # [cite: 72]
                [cite_start]if category in categorized_channels and categorized_channels[category]: # [cite: 72]
                    [cite_start]iptv_list_file.write(f"{category},#genre#\n") # [cite: 72]
                    [cite_start]for name, url in sorted(categorized_channels[category], key=lambda x: x[0]): # [cite: 72]
                        [cite_start]iptv_list_file.write(f"{name},{url}\n") # [cite: 73]
            [cite_start]if uncategorized_channels: # [cite: 73]
                [cite_start]iptv_list_file.write("其他频道,#genre#\n") # [cite: 73]
                [cite_start]for name, url in sorted(uncategorized_channels, key=lambda x: x[0]): # [cite: 73]
                    [cite_start]iptv_list_file.write(f"{name},{url}\n") # [cite: 73]
        [cite_start]logging.warning(f"所有频道列表文件合并、去重、分类完成，输出保存到: {output_file_name}") # [cite: 73]
    except Exception as e:
        [cite_start]logging.error(f"写入文件 '{output_file_name}' 失败: {e}") # [cite: 74]

    # 保存未分类频道
    try:
        [cite_start]with open(uncategorized_file_in_root, "w", encoding='utf-8') as uncat_file: # [cite: 74]
            [cite_start]for name, url in sorted(uncategorized_channels, key=lambda x: x[0]): # [cite: 74]
                [cite_start]uncat_file.write(f"{name},{url}\n") # [cite: 74]
        [cite_start]logging.warning(f"未分类频道保存到: {uncategorized_file_in_root}") # [cite: 74]
    except Exception as e:
        [cite_start]logging.error(f"写入未分类文件 '{uncategorized_file_in_root}' 失败: {e}") # [cite: 74]

# --- 远程 TXT 文件操作函数 ---
@performance_monitor
def write_array_to_txt_local(file_path, data_array, commit_message=None):
    """将数组内容写入本地 TXT 文件"""
    [cite_start]try: # [cite: 75]
        [cite_start]os.makedirs(os.path.dirname(file_path), exist_ok=True) # [cite: 75]
        [cite_start]with open(file_path, 'w', encoding='utf-8') as file: # [cite: 75]
            [cite_start]file.write('\n'.join(data_array)) # [cite: 75]
        [cite_start]logging.debug(f"写入 {len(data_array)} 行到 '{file_path}'") # [cite: 75]
    except Exception as e:
        [cite_start]logging.error(f"写入文件 '{file_path}' 失败: {e}") # [cite: 75]

# --- GitHub URL 自动发现函数 ---
@performance_monitor
def auto_discover_github_urls(urls_file_path_local, github_token):
    """从 GitHub 自动发现新的 IPTV 源 URL"""
    [cite_start]if not github_token: # [cite: 75, 76]
        [cite_start]logging.warning("未提供 GitHub token，跳过 URL 自动发现") # [cite: 76]
        return

    [cite_start]existing_urls = set(read_txt_to_array_local(urls_file_path_local)) # [cite: 76]
    [cite_start]for backup_url in CONFIG.get('backup_urls', []): # [cite: 76]
        try:
            [cite_start]response = session.get(backup_url, timeout=15) # [cite: 76]
            [cite_start]response.raise_for_status() # [cite: 76]
            [cite_start]existing_urls.update([line.strip() for line in response.text.split('\n') if line.strip()]) # [cite: 76]
        except Exception as e:
            [cite_start]logging.warning(f"从备用 URL {backup_url} 获取失败: {e}") # [cite: 77]

    [cite_start]found_urls = set() # [cite: 77]
    headers = {
        [cite_start]"Accept": "application/vnd.github.v3.text-match+json", # [cite: 77]
        [cite_start]"Authorization": f"token {github_token}" # [cite: 77]
    }

    [cite_start]logging.warning("开始从 GitHub 自动发现新的 IPTV 源 URL") # [cite: 77]
    [cite_start]keyword_url_counts = {keyword: 0 for keyword in CONFIG.get('search_keywords', [])} # [cite: 77]

    [cite_start]for i, keyword in enumerate(CONFIG.get('search_keywords', [])): # [cite: 78]
        [cite_start]keyword_found_urls = set() # [cite: 78]
        [cite_start]if i > 0: # [cite: 78]
            [cite_start]logging.warning(f"切换到下一个关键词: '{keyword}'，等待 {CONFIG['github']['retry_wait']} 秒以避免速率限制") # [cite: 78]
            [cite_start]time.sleep(CONFIG['github']['retry_wait']) # [cite: 78]

        [cite_start]page = 1 # [cite: 78]
        [cite_start]while page <= CONFIG['github']['max_search_pages']: # [cite: 78]
            params = {
                [cite_start]"q": keyword, # [cite: 79]
                [cite_start]"sort": "indexed", # [cite: 79]
                [cite_start]"order": "desc", # [cite: 79]
                [cite_start]"per_page": CONFIG['github']['per_page'], # [cite: 79]
                [cite_start]"page": page # [cite: 79]
            }
            try:
                response = session.get(
                    [cite_start]f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}", # [cite: 79, 80]
                    [cite_start]headers=headers, # [cite: 80]
                    [cite_start]params=params, # [cite: 80]
                    [cite_start]timeout=CONFIG['github']['api_timeout'] # [cite: 80]
                )
                [cite_start]response.raise_for_status() # [cite: 80]
                [cite_start]data = response.json() # [cite: 81]

                [cite_start]rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0)) # [cite: 81]
                [cite_start]rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0)) # [cite: 81]

                [cite_start]if rate_limit_remaining == 0: # [cite: 81]
                    [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 # [cite: 81]
                    [cite_start]logging.warning(f"GitHub API 速率限制达到，剩余请求: 0，等待 {wait_seconds:.0f} 秒") # [cite: 82]
                    [cite_start]time.sleep(wait_seconds) # [cite: 82]
                    continue

                [cite_start]if not data.get('items'): # [cite: 82]
                    [cite_start]logging.debug(f"关键词 '{keyword}' 在第 {page} 页无结果") # [cite: 82, 83]
                    [cite_start]break # [cite: 83]

                [cite_start]for item in data['items']: # [cite: 83]
                    [cite_start]html_url = item.get('html_url', '') # [cite: 83, 84]
                    [cite_start]raw_url = None # [cite: 84]
                    [cite_start]match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url) # [cite: 84]
                    [cite_start]if match: # [cite: 84]
                        [cite_start]user, repo, branch, file_path = match.groups() # [cite: 84]
                        [cite_start]raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}" # [cite: 84]
                    else:
                        [cite_start]logging.debug(f"无法解析 raw URL: {html_url}") # [cite: 85]
                        continue

                    [cite_start]if raw_url and raw_url not in existing_urls and raw_url not in found_urls: # [cite: 85]
                        [cite_start]try: # [cite: 86]
                            [cite_start]content_response = session.get(raw_url, timeout=5) # [cite: 86]
                            [cite_start]content_response.raise_for_status() # [cite: 86]
                            [cite_start]content = content_response.text # [cite: 86, 87]
                            [cite_start]if re.search(r'#EXTM3U', content, re.IGNORECASE) or re.search(r'\.(m3u8|m3u|txt|csv|ts|flv|mp4|hls|dash)$', raw_url, re.IGNORECASE): # [cite: 87]
                                [cite_start]found_urls.add(raw_url) # [cite: 87]
                                [cite_start]keyword_found_urls.add(raw_url) # [cite: 87]
                                [cite_start]logging.debug(f"发现新的 IPTV 源 URL: {raw_url}") # [cite: 88]
                            else:
                                [cite_start]logging.debug(f"URL {raw_url} 不包含 M3U 内容或不支持的文件扩展名，跳过") # [cite: 88]
                        [cite_start]except requests.exceptions.RequestException as req_e: # [cite: 89]
                            [cite_start]logging.debug(f"获取 {raw_url} 内容失败: {req_e}") # [cite: 89]
                        [cite_start]except Exception as exc: # [cite: 89, 90]
                            [cite_start]logging.debug(f"检查 {raw_url} 内容时发生意外错误: {exc}") # [cite: 90]

                [cite_start]logging.debug(f"完成关键词 '{keyword}' 第 {page} 页，发现 {len(keyword_found_urls)} 个新 URL") # [cite: 90]
                [cite_start]page += 1 # [cite: 90]

            [cite_start]except requests.exceptions.RequestException as e: # [cite: 90, 91]
                [cite_start]if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403: # [cite: 91]
                    [cite_start]logging.error(f"GitHub API 速率限制或访问被拒绝，关键词 '{keyword}': {e}") # [cite: 91]
                    [cite_start]if rate_limit_remaining == 0: # [cite: 91]
                        [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 # [cite: 91]
                        [cite_start]logging.warning(f"关键词 '{keyword}' 速率限制，等待 {wait_seconds:.0f} 秒") # [cite: 91, 92]
                    [cite_start]time.sleep(wait_seconds) # [cite: 92]
                    continue
                else:
                    [cite_start]logging.error(f"搜索 GitHub 关键词 '{keyword}' 失败: {e}") # [cite: 92]
                [cite_start]break # [cite: 93]
            except Exception as e:
                [cite_start]logging.error(f"搜索 GitHub 关键词 '{keyword}' 时发生意外错误: {e}") # [cite: 93]
                break
        [cite_start]keyword_url_counts[keyword] = len(keyword_found_urls) # [cite: 93]

    [cite_start]if found_urls: # [cite: 93]
        [cite_start]updated_urls = sorted(list(existing_urls | found_urls)) # [cite: 93, 94]
        [cite_start]logging.warning(f"发现 {len(found_urls)} 个新唯一 URL，总计保存 {len(updated_urls)} 个 URL") # [cite: 94]
        [cite_start]write_array_to_txt_local(urls_file_path_local, updated_urls) # [cite: 94]
    else:
        [cite_start]logging.warning("未发现新的 IPTV 源 URL") # [cite: 94]

    [cite_start]for keyword, count in keyword_url_counts.items(): # [cite: 94]
        [cite_start]logging.warning(f"关键词 '{keyword}' 发现 {count} 个新 URL") # [cite: 95]

# --- URL 清理函数 ---
@performance_monitor
def cleanup_urls_local(urls_file_path_local, url_states):
    """清理无效或失败的 URL"""
    [cite_start]all_urls = read_txt_to_array_local(urls_file_path_local) # [cite: 95]
    [cite_start]current_time = datetime.now() # [cite: 95]
    [cite_start]urls_to_keep = [] # [cite: 95]
    [cite_start]removed_count = 0 # [cite: 95]

    [cite_start]for url in all_urls: # [cite: 95]
        [cite_start]state = url_states.get(url, {}) # [cite: 95]
        [cite_start]fail_count = state.get('stream_fail_count', 0) # [cite: 95]
        [cite_start]last_failed_time_str = state.get('stream_check_failed_at') # [cite: 95]
        [cite_start]remove_url = False # [cite: 95]

        [cite_start]if fail_count > CONFIG['channel_retention']['url_fail_threshold']: # [cite: 95]
            [cite_start]if last_failed_time_str: # [cite: 95]
                [cite_start]try: # [cite: 96]
                    [cite_start]last_failed_datetime = datetime.fromisoformat(last_failed_time_str) # [cite: 96]
                    [cite_start]if (current_time - last_failed_datetime).total_seconds() / 3600 > CONFIG['channel_retention']['url_retention_hours']: # [cite: 96]
                        [cite_start]remove_url = True # [cite: 96]
                        [cite_start]logging.info(f"移除 URL '{url}'，因失败次数过多 ({fail_count}) 且超出保留时间 ({CONFIG['channel_retention']['url_retention_hours']}h)") # [cite: 96]
                except ValueError:
                    [cite_start]logging.warning(f"无法解析 URL {url} 的最后失败时间戳: {last_failed_time_str}") # [cite: 97]
            else:
                [cite_start]remove_url = True # [cite: 97]
                [cite_start]logging.info(f"移除 URL '{url}'，因失败次数过多 ({fail_count}) 且无最后失败时间戳") # [cite: 97]

        [cite_start]if not remove_url: # [cite: 97]
            [cite_start]urls_to_keep.append(url) # [cite: 98]
        else:
            [cite_start]removed_count += 1 # [cite: 98]
            [cite_start]url_states.pop(url, None) # [cite: 98]

    [cite_start]if removed_count > 0: # [cite: 98]
        [cite_start]logging.warning(f"从 {urls_file_path_local} 清理 {removed_count} 个 URL") # [cite: 98]
        [cite_start]write_array_to_txt_local(urls_file_path_local, urls_to_keep) # [cite: 98]
    else:
        [cite_start]logging.warning("无需清理 urls.txt 中的 URL") # [cite: 98]

# --- 分类和文件保存函数 ---
@performance_monitor
def categorize_channels(channels):
    """根据频道名称关键字分类"""
    [cite_start]categorized_data = {category: [] for category in CONFIG.get('ordered_categories', [])} # [cite: 98, 99]
    [cite_start]uncategorized_data = [] # [cite: 99]

    [cite_start]for name, url in channels: # [cite: 99]
        [cite_start]found_category = False # [cite: 99]
        [cite_start]for category in CONFIG.get('ordered_categories', []): # [cite: 99]
            [cite_start]category_keywords = CONFIG['category_keywords'].get(category, []) # [cite: 99]
            [cite_start]if any(keyword.lower() in name.lower() for keyword in category_keywords): # [cite: 99]
                [cite_start]categorized_data[category].append((name, url)) # [cite: 99]
                [cite_start]found_category = True # [cite: 100]
                break
        [cite_start]if not found_category: # [cite: 100]
            [cite_start]uncategorized_data.append((name, url)) # [cite: 100]
    return categorized_data, uncategorized_data

@performance_monitor
def process_and_save_channels_by_category(all_channels, url_states, source_tracker):
    """将频道分类并保存到对应文件"""
    [cite_start]categorized_channels, uncategorized_channels = categorize_channels(all_channels) # [cite: 100]
    [cite_start]categorized_dir = CONFIG['output']['paths']['channels_dir'] # [cite: 100]
    [cite_start]os.makedirs(categorized_dir, exist_ok=True) # [cite: 100]

    [cite_start]for category, channels in categorized_channels.items(): # [cite: 100]
        [cite_start]output_file = os.path.join(categorized_dir, f"{category}_iptv.txt") # [cite: 100]
        [cite_start]logging.warning(f"处理分类: {category}，包含 {len(channels)} 个频道") # [cite: 101]
        [cite_start]sorted_channels = sorted(channels, key=lambda x: x[0]) # [cite: 101]
        [cite_start]channels_to_write = [(0, f"{name},{url}") for name, url in sorted_channels] # [cite: 101]
        [cite_start]write_sorted_channels_to_file(output_file, channels_to_write) # [cite: 101]
    
    [cite_start]output_uncategorized_file = CONFIG['output']['paths']['uncategorized_channels_file'] # [cite: 101]
    [cite_start]logging.warning(f"处理未分类频道: {len(uncategorized_channels)} 个频道") # [cite: 101]
    [cite_start]sorted_uncategorized = sorted(uncategorized_channels, key=lambda x: x[0]) # [cite: 101]
    [cite_start]uncategorized_to_write = [(0, f"{name},{url}") for name, url in sorted_uncategorized] # [cite: 101]
    [cite_start]write_sorted_channels_to_file(output_uncategorized_file, uncategorized_to_write) # [cite: 101]
    [cite_start]logging.warning(f"未分类频道保存到: {output_uncategorized_file}") # [cite: 101]

# --- 主逻辑 ---
@performance_monitor
def main():
    """主函数，执行 IPTV 处理流程"""
    [cite_start]logging.warning("开始执行 IPTV 处理脚本") # [cite: 102]
    [cite_start]total_start_time = time.time() # [cite: 102]

    # 步骤 1：加载 URL 状态
    [cite_start]url_states = load_url_states_local() # [cite: 102]
    [cite_start]logging.warning(f"加载 {len(url_states)} 个 URL 状态") # [cite: 102]

    # 步骤 2：从 GitHub 自动发现新 URL
    [cite_start]auto_discover_github_urls(URLS_PATH, GITHUB_TOKEN) # [cite: 102]

    # 步骤 3：清理无效 URL
    [cite_start]cleanup_urls_local(URLS_PATH, url_states) # [cite: 102]

    # 步骤 4：加载 URL 列表
    [cite_start]urls = read_txt_to_array_local(URLS_PATH) # [cite: 102]
    [cite_start]if not urls: # [cite: 102]
        [cite_start]logging.error("未在 urls.txt 中找到 URL，退出") # [cite: 102]
        exit(1)
    [cite_start]logging.warning(f"从 '{URLS_PATH}' 加载 {len(urls)} 个 URL") # [cite: 103]

    # 步骤 5：多线程提取频道
    [cite_start]all_extracted_channels = [] # [cite: 103]
    [cite_start]source_tracker = {} # [cite: 103]
    [cite_start]logging.warning(f"开始从 {len(urls)} 个 URL 提取频道") # [cite: 103]
    [cite_start]with ThreadPoolExecutor(max_workers=CONFIG['network']['url_fetch_workers']) as executor: # [cite: 103]
        [cite_start]futures = {executor.submit(extract_channels_from_url, url, url_states, source_tracker): url for url in urls} # [cite: 103]
        [cite_start]for i, future in enumerate(as_completed(futures)): # [cite: 103]
            [cite_start]if (i + 1) % CONFIG['performance_monitor']['log_interval'] == 0: # [cite: 103, 104]
                [cite_start]logging.warning(f"已处理 {i + 1}/{len(urls)} 个 URL") # [cite: 104]
            try:
                [cite_start]channels = future.result() # [cite: 104]
                [cite_start]if channels: # [cite: 104]
                    [cite_start]all_extracted_channels.extend(channels) # [cite: 104]
            [cite_start]except Exception as exc: # [cite: 104, 105]
                [cite_start]logging.error(f"URL 提取异常: {exc}") # [cite: 105]
    [cite_start]logging.warning(f"完成频道提取，过滤前总计提取 {len(all_extracted_channels)} 个频道") # [cite: 105]

    # 步骤 6：过滤和修改频道
    [cite_start]filtered_and_modified_channels = filter_and_modify_channels(all_extracted_channels) # [cite: 105]
    [cite_start]logging.warning(f"过滤和修改后剩余 {len(filtered_and_modified_channels)} 个频道") # [cite: 105]

    # 步骤 7：分类并保存频道
    [cite_start]process_and_save_channels_by_category(filtered_and_modified_channels, url_states, source_tracker) # [cite: 106]

    # 步骤 8：合并频道文件
    [cite_start]merge_local_channel_files(CONFIG['output']['paths']['channels_dir'], IPTV_LIST_PATH, url_states) # [cite: 106]

    # 步骤 9：保存 URL 状态
    [cite_start]save_url_states_local(url_states) # [cite: 106]
    [cite_start]logging.warning("最终频道检查状态已保存") # [cite: 106]

    # 步骤 10：清理临时文件（保留未分类文件）
    try:
        [cite_start]temp_files = ['iptv.txt', 'iptv_speed.txt'] # [cite: 106]
        [cite_start]for temp_file in temp_files: # [cite: 106]
            [cite_start]if os.path.exists(temp_file): # [cite: 106]
                [cite_start]os.remove(temp_file) # [cite: 106]
                [cite_start]logging.debug(f"移除临时文件 '{temp_file}'") # [cite: 106]
        [cite_start]temp_dir = CONFIG['output']['paths']['channels_dir'] # [cite: 106]
        [cite_start]if os.path.exists(temp_dir): # [cite: 106]
            [cite_start]for f_name in os.listdir(temp_dir): # [cite: 106]
                [cite_start]if f_name.endswith('_iptv.txt'): # [cite: 107]
                    [cite_start]os.remove(os.path.join(temp_dir, f_name)) # [cite: 107]
                    [cite_start]logging.debug(f"移除临时频道文件 '{f_name}'") # [cite: 107]
            [cite_start]if not os.listdir(temp_dir): # [cite: 107]
                [cite_start]os.rmdir(temp_dir) # [cite: 107]
                [cite_start]logging.debug(f"移除空目录 '{temp_dir}'") # [cite: 107]
        [cite_start]logging.warning(f"保留未分类文件 '{CONFIG['output']['paths']['uncategorized_channels_file']}'") # [cite: 108]
    except Exception as e:
        [cite_start]logging.error(f"清理临时文件失败: {e}") # [cite: 108]

    [cite_start]total_elapsed_time = time.time() - total_start_time # [cite: 108]
    [cite_start]logging.warning(f"IPTV 处理脚本完成，总耗时 {total_elapsed_time:.2f} 秒") # [cite: 108]

if __name__ == "__main__":
    main()
