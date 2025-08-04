#加载配置：从 config/config.yaml 文件中加载配置。

#读取源 URL：从 urls.txt 文件中读取 IPTV 源 URL。

#并发处理：使用多线程并发地从每个 URL 中提取频道。

#格式转换：将 .m3u 或 .m3u8 文件内容转换为统一的频道名称和 URL 格式。

#本地保存：将提取到的频道列表保存到本地的 .txt 文件中。


import os
import re
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
import logging
import logging.handlers
import time
from datetime import datetime, timedelta
from cachetools import TTLCache

# 配置日志系统
def setup_logging(config):
    """
    配置日志系统，支持文件和控制台输出。
    """
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=1
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    """
    加载并解析 YAML 配置文件。
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

# 全局配置和日志设置
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 从配置中获取文件路径
URLS_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'urls.txt')
URL_STATES_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'url_states.json')
IPTV_LIST_PATH = CONFIG['output']['paths']['final_iptv_file']
IPTV_LIST_TEMP_PATH = "iptv_list_temp.txt"

# GitHub API 基础 URL
GITHUB_RAW_CONTENT_BASE_URL = "https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = "https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"

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
    total=3,
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
    """记录函数执行时间的装饰器"""
    if not CONFIG['performance_monitor']['enabled']:
        return func
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        logging.info(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒")
        return result
    return wrapper

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
def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道数据写入文件，去重"""
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
    
    new_channels = set()
    for name, url in data_list:
        new_channels.add((name.strip(), url.strip()))
    
    all_channels = existing_channels.union(new_channels)
    
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            for name, url in sorted(list(all_channels), key=lambda x: x[0]):
                file.write(f"{name},{url}\n")
        logging.info(f"写入 {len(all_channels)} 个频道到 {file_path}")
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
        logging.info(f"获取 URL 扩展名失败: {url} - {e}")
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
            channel_name = match.group(1).strip() if match and match.group(1).strip() else "未知频道"
        elif re.match(r'^[a-zA-Z0-9+.-]+://', line) and not line.startswith('#'):
            txt_lines.append(f"{channel_name},{line}")
            channel_name = "未知频道"
    return '\n'.join(txt_lines)

@performance_monitor
def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径"""
    try:
        parsed_url = urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    except ValueError as e:
        logging.info(f"清理 URL 参数失败: {url} - {e}")
        return url

@performance_monitor
def pre_screen_url(url):
    """对 URL 进行预筛选，排除已知无效或不想要的 URL"""
    return not any(s in url.lower() for s in CONFIG.get('filters', {}).get('url_blacklist', []))

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
def fetch_url_content_with_retry(url):
    """带重试机制获取 URL 内容"""
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"获取 URL 内容失败: {url} - {e}")
        return None

@performance_monitor
def extract_channels_from_url(url):
    """从 URL 提取频道，支持多种文件格式"""
    extracted_channels = []
    try:
        start_time = time.time()
        text = fetch_url_content_with_retry(url)
        if text is None:
            logging.info(f"URL {url} 获取失败，跳过")
            return []

        extension = get_url_file_extension(url).lower()
        if extension in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)
        elif extension not in [".txt", ".csv"]:
            logging.info(f"不支持的文件扩展名: {url}")
            return []

        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if "," in line and "://" in line:
                parts = line.split(',', 1)
                if len(parts) != 2:
                    logging.info(f"跳过无效频道行（格式错误）: {line}")
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip() or "未知频道"
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    logging.info(f"跳过无效频道 URL（无有效协议）: {line}")
                    continue

                channel_url = clean_url_params(channel_address_raw)
                if channel_url and pre_screen_url(channel_url):
                    extracted_channels.append((channel_name, channel_url))
                else:
                    logging.info(f"跳过无效或预筛选失败的频道 URL: {channel_url}")
        
        logging.info(f"成功从 {url} 提取 {len(extracted_channels)} 个频道，耗时 {time.time() - start_time:.2f} 秒")
        return extracted_channels
    except Exception as e:
        logging.error(f"从 {url} 提取频道失败: {e}")
        return []

def main():
    """主函数，负责执行 IPTV 频道处理工作流"""
    
    # 步骤 1: 读取 IPTV 源 URL 文件
    urls_list = read_txt_to_array_local(URLS_PATH)
    if not urls_list:
        logging.warning("未找到任何 IPTV 源 URL，请检查 urls.txt 文件")
        return

    # 步骤 2: 并发处理 URL 并提取频道
    all_extracted_channels = []
    with ThreadPoolExecutor(max_workers=CONFIG['network']['max_workers']) as executor:
        future_to_url = {executor.submit(extract_channels_from_url, url): url for url in urls_list}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                channels = future.result()
                all_extracted_channels.extend(channels)
            except Exception as e:
                logging.error(f"URL {url} 的处理过程中发生异常: {e}")
    
    logging.info(f"从所有源共提取到 {len(all_extracted_channels)} 个频道")
    
    # 步骤 3: 将提取的频道保存到临时文件
    write_sorted_channels_to_file(IPTV_LIST_TEMP_PATH, all_extracted_channels)
    logging.info(f"所有提取到的频道已保存到 '{IPTV_LIST_TEMP_PATH}'")

if __name__ == '__main__':
    main()
