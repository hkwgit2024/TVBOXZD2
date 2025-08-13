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
from tqdm import tqdm

# 配置日志系统，支持文件和控制台输出
def setup_logging(config):
    log_level = getattr(logging, config['logging']['log_level'], logging.DEBUG)  # 改为 DEBUG 以记录更多细节
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

# 加载分类配置
def load_category_config(config_path="config/demo.txt"):
    category_config = {
        'ordered_categories': [],
        'category_keywords': {},
        'category_aliases': {}
    }
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            current_category = None
            for line in file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.endswith(',#genre#'):
                    category_name = line.replace(',#genre#', '').strip()
                    current_category = category_name
                    if current_category not in category_config['ordered_categories']:
                        category_config['ordered_categories'].append(current_category)
                    category_config['category_keywords'][current_category] = []
                elif current_category:
                    keywords = [kw.strip() for kw in line.split('|') if kw.strip()]  # 使用 | 分隔变体
                    category_config['category_keywords'][current_category].extend(keywords)
        logging.info("分类配置文件 config/demo.txt 加载成功")
        return category_config
    except FileNotFoundError:
        logging.error(f"错误：未找到分类配置文件 '{config_path}'")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载分类配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 配置文件路径
CONFIG_PATH = "config/config.yaml"
CATEGORY_CONFIG_PATH = "config/demo.txt"
INPUT_CHANNELS_PATH = "output/iptv.txt"
FINAL_IPTV_LIST_PATH = "output/iptv_list.txt"
UNCATEGORIZED_CHANNELS_PATH = "output/uncategorized.txt"
URL_STATES_PATH = "output/url_states.json"
CONFIG = load_config(CONFIG_PATH)
CATEGORY_CONFIG = load_category_config(CATEGORY_CONFIG_PATH)
setup_logging(CONFIG)

# 配置 requests 会话
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
pool_size = CONFIG['network']['requests_pool_size']
retry_strategy = Retry(
    total=5,  # 增加重试次数
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
    if not CONFIG['performance_monitor']['enabled']:
        return func
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        logging.info(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒")
        return result
    return wrapper

# 从本地 TXT 文件读取内容到数组
@performance_monitor
def read_channels_from_local(file_name):
    channels = []
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ',' in line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        name, url = parts[0].strip(), parts[1].strip()
                        logging.debug(f"读取频道: {name}, URL: {url}")
                        channels.append((name, url))
    except FileNotFoundError:
        logging.error(f"错误：未找到输入频道文件 '{file_name}'")
        exit(1)
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        exit(1)
    logging.info(f"从 {file_name} 读取 {len(channels)} 个频道")
    return channels

# 读取现有频道以进行去重
@performance_monitor
def read_existing_channels_from_file(file_path):
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
    logging.info(f"从 {file_path} 读取 {len(existing_channels)} 个现有频道用于去重")
    return existing_channels

# 频道有效性检查函数
@performance_monitor
def check_http_url(url, timeout):
    try:
        response = session.head(url, timeout=timeout)
        is_valid = 200 <= response.status_code < 400
        logging.debug(f"HTTP 检查: {url}, 状态码: {response.status_code}, 有效: {is_valid}")
        return is_valid
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP 检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    try:
        result = subprocess.run(['ffprobe', '-timeout', str(timeout * 1000000), url],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        is_valid = result.returncode == 0
        logging.debug(f"RTMP 检查: {url}, 返回码: {result.returncode}, 有效: {is_valid}")
        return is_valid
    except Exception as e:
        logging.debug(f"RTMP 检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_rtp_url(url, timeout):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 5000
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            logging.debug(f"RTP 检查: {url}, 有效: True")
            return True
    except Exception as e:
        logging.debug(f"RTP 检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_channel_validity_and_speed(name, url, url_states):
    start_time = time.time()
    is_valid = False
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme.lower()

    # 应用 URL 预筛选规则
    for pattern in CONFIG['url_pre_screening']['invalid_url_patterns']:
        if re.search(pattern, url, re.IGNORECASE):
            logging.debug(f"URL {url} 被预筛选规则 {pattern} 过滤")
            return None, False

    if protocol in ['http', 'https']:
        is_valid = check_http_url(url, CONFIG['network']['check_timeout'])
    elif protocol == 'rtmp':
        is_valid = check_rtmp_url(url, CONFIG['network']['check_timeout'])
    elif protocol in ['rtp', 'rtsp']:
        is_valid = check_rtp_url(url, CONFIG['network']['check_timeout'])
    else:
        logging.warning(f"不支持的协议: {protocol} for {url}")
        return None, False

    elapsed_time = time.time() - start_time if is_valid else None
    logging.debug(f"频道检查: {name}, URL: {url}, 有效: {is_valid}, 耗时: {elapsed_time if elapsed_time else 'N/A'} 秒")
    return elapsed_time, is_valid

def process_single_channel_line(line, url_states):
    parts = line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

@performance_monitor
def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG['network']['channel_check_workers']):
    results = []
    total_channels = len(channel_lines)
    logging.warning(f"开始多线程检查 {total_channels} 个频道的有效性和速度")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines}
        for future in tqdm(as_completed(futures), total=total_channels, desc="检查频道有效性"):
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"处理频道行时发生异常: {exc}")
    logging.info(f"检查完成，发现 {len(results)} 个有效频道")
    return results

# 分类和文件保存函数
@performance_monitor
def categorize_channels(channels):
    categorized_data = {category: [] for category in CATEGORY_CONFIG['ordered_categories']}
    uncategorized_data = []

    for name, url in channels:
        # 规范化频道名称：移除分辨率、HD/SD、数字后缀、连字符、中英文符号
        cleaned_name = re.sub(r'\s*\(\d+p\)|[hH][dD]|[sS][dD]|ipv6-\d|[-_\s]|\d+$|[东联港澳版]+|[综艺新闻少儿体育电影国际音乐纪录片频道台]*$', '', name.lower().strip())
        cleaned_name = re.sub(r'[^\w\s]', '', cleaned_name)  # 移除特殊字符
        found_category = False
        for category in CATEGORY_CONFIG['ordered_categories']:
            category_keywords = CATEGORY_CONFIG['category_keywords'].get(category, [])
            # 使用宽松正则匹配，忽略大小写
            for kw in category_keywords:
                kw_cleaned = re.sub(r'[^\w\s]', '', kw.lower().strip())
                if re.search(rf'\b{re.escape(kw_cleaned)}\b', cleaned_name, re.IGNORECASE):
                    categorized_data[category].append((name, url))
                    logging.debug(f"频道 {name} 匹配到类别 {category}，关键词: {kw}")
                    found_category = True
                    break
            if found_category:
                break
        if not found_category:
            uncategorized_data.append((name, url))
            logging.debug(f"频道 {name} 未匹配任何类别，归为未分类")
            
    categorized_data_cleaned = {k: v for k, v in categorized_data.items() if v}
    final_ordered_categories = [cat for cat in CATEGORY_CONFIG['ordered_categories'] if cat in categorized_data_cleaned]
    
    logging.info(f"分类结果：{len(categorized_data_cleaned)} 个分类，{len(uncategorized_data)} 个未分类频道")
    return categorized_data_cleaned, uncategorized_data, final_ordered_categories

@performance_monitor
def generate_update_time_header():
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d %H:%M:%S')},url\n"
    ]

@performance_monitor
def save_channels_to_final_files(valid_channels, output_file_path, uncategorized_file_path):
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    os.makedirs(os.path.dirname(uncategorized_file_path), exist_ok=True)

    unique_channels = sorted(list(set(valid_channels)), key=lambda x: x[0])
    logging.warning(f"去重后得到 {len(unique_channels)} 个唯一有效频道")

    categorized_channels_checked, uncategorized_channels_checked, final_ordered_categories_checked = categorize_channels(unique_channels)

    try:
        with open(output_file_path, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(generate_update_time_header())
            for category in final_ordered_categories_checked:
                if category in categorized_channels_checked and categorized_channels_checked[category]:
                    iptv_list_file.write(f"{category},#genre#\n")
                    for name, url in sorted(categorized_channels_checked[category], key=lambda x: x[0]):
                        iptv_list_file.write(f"{name},{url}\n")
        logging.warning(f"所有频道列表文件合并、去重、分类完成，输出保存到: {output_file_path}")
    except Exception as e:
        logging.error(f"写入文件 '{output_file_path}' 失败: {e}")

    try:
        with open(uncategorized_file_path, "w", encoding='utf-8') as uncat_file:
            uncat_file.writelines(generate_update_time_header())
            for name, url in sorted(uncategorized_channels_checked, key=lambda x: x[0]):
                uncat_file.write(f"{name},{url}\n")
        logging.warning(f"未分类频道保存到: {uncategorized_file_path}")
    except Exception as e:
        logging.error(f"写入未分类文件 '{uncategorized_file_path}' 失败: {e}")

# 主逻辑
@performance_monitor
def main():
    logging.warning("开始执行 IPTV 频道检查和分类脚本")
    total_start_time = time.time()

    url_states = {}
    input_channels_lines = []
    try:
        with open(INPUT_CHANNELS_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '://' in line and ',' in line:
                    input_channels_lines.append(line)
                    logging.debug(f"解析输入行: {line}")
    except FileNotFoundError:
        logging.error(f"错误：未找到输入文件 '{INPUT_CHANNELS_PATH}'。请确保该文件存在。")
        return
    
    if not input_channels_lines:
        logging.warning(f"输入文件 '{INPUT_CHANNELS_PATH}' 中没有可用的频道行，退出。")
        return

    valid_channels_with_speed = check_channels_multithreaded(input_channels_lines, url_states)
    
    valid_channels_list = [(line.split(',', 1)[0], line.split(',', 1)[1]) for _, line in valid_channels_with_speed]
    
    if not valid_channels_list:
        logging.warning("没有发现有效的频道，不生成输出文件。")
        return

    save_channels_to_final_files(valid_channels_list, FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH)

    total_elapsed_time = time.time() - total_start_time
    logging.warning(f"IPTV 频道检查和分类脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
