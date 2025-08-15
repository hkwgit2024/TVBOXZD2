# Version 1.5 - 优化版：增强可用性检查与名称匹配的准确性
# Date: August 15, 2025
# 优化点: 修正 normalize_name 函数，实现更精准的频道名称匹配

import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import logging.handlers
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed
import yaml
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm
from collections import defaultdict
import difflib

# --- 配置和加载模块 ---
CONFIG_PATH = "config/config.yaml"
CATEGORY_CONFIG_PATH = "config/demo.txt"
INPUT_CHANNELS_PATH = "output/iptv.txt"
FINAL_IPTV_LIST_PATH = "output/iptv_list.txt"
UNCATEGORIZED_CHANNELS_PATH = "output/uncategorized.txt"

def setup_logging(config):
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转"""
    log_level = getattr(logging, config.get('logging', {}).get('log_level', 'DEBUG').upper(), logging.DEBUG)
    log_file = config.get('logging', {}).get('log_file', 'logs/iptv_checker.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(log_level)

    if not logger.handlers:
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

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    logging.debug("日志系统配置完成")
    return logger

def load_config(config_path):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file) or {}
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'。")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

def load_category_config(config_path):
    """加载并解析分类配置文件，去重关键词"""
    category_config = {
        'ordered_categories': [],
        'category_keywords': defaultdict(set),
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
                elif current_category:
                    keywords = [kw.strip() for kw in line.split('|') if kw.strip()]
                    category_config['category_keywords'][current_category].update(keywords)

        category_config['category_keywords'] = {k: list(v) for k, v in category_config['category_keywords'].items()}
        logging.info("分类配置文件 config/demo.txt 加载成功")
        return category_config
    except FileNotFoundError:
        logging.error(f"错误：未找到分类配置文件 '{config_path}'")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载分类配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 全局配置和会话对象
CONFIG = load_config(CONFIG_PATH)
CATEGORY_CONFIG = load_category_config(CATEGORY_CONFIG_PATH)
setup_logging(CONFIG)

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
pool_size = CONFIG.get('network', {}).get('requests_pool_size', 100)
retry_strategy = Retry(
    total=CONFIG.get('network', {}).get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('network', {}).get('requests_retry_backoff_factor', 1),
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

def performance_monitor(func):
    """记录函数执行时间"""
    if not CONFIG.get('performance_monitor', {}).get('enabled', False):
        return func
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        logging.info(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒")
        return result
    return wrapper

# --- 频道检查模块 ---
@performance_monitor
def read_channels_from_file(file_name):
    """从本地 TXT 文件读取频道内容"""
    channels = []
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ',' in line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        channels.append((parts[0].strip(), parts[1].strip()))
        logging.debug(f"从 {file_name} 读取 {len(channels)} 个频道")
    except FileNotFoundError:
        logging.error(f"错误：未找到输入频道文件 '{file_name}'")
        return None
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return None
    return channels

@performance_monitor
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达，使用 ffprobe"""
    try:
        result = subprocess.run(['ffprobe', '-v', 'quiet', '-timeout', str(timeout), '-i', url],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except Exception as e:
        logging.debug(f"RTMP检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达，使用 socket"""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 5000
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except Exception as e:
        logging.debug(f"RTP检查失败: {url}, 错误: {e}")
        return False

def check_channel_validity(channel, url_states, timeout):
    """检查单个频道的有效性，返回 (name, url) 或 None"""
    name, url = channel
    if url in url_states:
        return (name, url) if url_states[url] else None

    parsed_url = urlparse(url)
    protocol = parsed_url.scheme.lower()
    is_valid = False

    if protocol in ['http', 'https']:
        is_valid = check_http_url(url, timeout)
    elif protocol == 'rtmp':
        is_valid = check_rtmp_url(url, timeout)
    elif protocol in ['rtp', 'rtsp']:
        is_valid = check_rtp_url(url, timeout)
    else:
        logging.warning(f"不支持的协议: {protocol} for {url}")

    url_states[url] = is_valid
    return (name, url) if is_valid else None

@performance_monitor
def check_channels_multithreaded(channels, max_workers, timeout):
    """多线程检查频道有效性"""
    valid_channels = []
    url_states = {}
    total_channels = len(channels)
    logging.warning(f"开始多线程检查 {total_channels} 个频道的有效性")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_channel_validity, channel, url_states, timeout): channel for channel in channels}
        for future in tqdm(as_completed(futures), total=total_channels, desc="检查频道有效性"):
            try:
                result = future.result()
                if result:
                    valid_channels.append(result)
            except Exception as exc:
                logging.warning(f"处理频道时发生异常: {exc}")

    logging.warning(f"有效频道数: {len(valid_channels)}")
    return valid_channels

# --- 频道分类和管理模块 ---
def normalize_name(name):
    """优化后的规范化频道名称，保留关键数字、字母和特殊字符，移除修饰词"""
    # 将名称转换为小写
    cleaned = name.lower()
    # 定义需要移除的常见修饰词
    noise_words = ['\(.*?\)', '\[.*?\]', '高清', '超清', '流畅', '备用', '测试', '网络', '直播', '在线', 'live', 'ipv6', 'ipv4', '东联', '港澳版']
    # 移除修饰词
    for word in noise_words:
        cleaned = re.sub(word, '', cleaned, flags=re.IGNORECASE)
    # 移除多余的空格和横线
    cleaned = re.sub(r'[\s\-]+', '', cleaned).strip()
    return cleaned or name.strip()

@performance_monitor
def group_variants(channels, threshold=0.85):
    """使用相似度聚类频道变体"""
    groups = defaultdict(list)
    processed_channels = set()

    for name, url in channels:
        if (name, url) in processed_channels:
            continue

        cleaned_name = normalize_name(name)
        matched_group = None

        for key in groups.keys():
            if difflib.SequenceMatcher(None, cleaned_name, key).ratio() > threshold:
                matched_group = key
                break

        if matched_group:
            groups[matched_group].append((name, url))
        else:
            groups[cleaned_name].append((name, url))

        processed_channels.add((name, url))

    logging.debug(f"变体聚类结果 (共 {len(groups)} 组): {groups}")
    return groups

@performance_monitor
def categorize_channels(channels, replacements):
    """根据关键字分类频道，优先使用精确映射，再使用相似度匹配"""
    categorized_data = defaultdict(list)
    uncategorized_data = []

    # 步骤1: 使用精确映射处理频道名称
    processed_channels = []
    for name, url in channels:
        effective_name = replacements.get(name, name)
        processed_channels.append((effective_name, url))

    # 步骤2: 聚类处理后的频道
    grouped_variants = group_variants(processed_channels)

    # 步骤3: 根据分类配置进行归类
    for main_cleaned, group in grouped_variants.items():
        found_category = False
        for category in CATEGORY_CONFIG['ordered_categories']:
            category_keywords = CATEGORY_CONFIG['category_keywords'].get(category, [])
            for kw in category_keywords:
                normalized_kw = normalize_name(kw)
                if difflib.SequenceMatcher(None, main_cleaned, normalized_kw).ratio() > 0.85:
                    categorized_data[category].extend(group)
                    found_category = True
                    break
            if found_category:
                break

        if not found_category:
            uncategorized_data.extend(group)

    categorized_data = {k: v for k, v in categorized_data.items() if v}
    final_ordered_categories = [cat for cat in CATEGORY_CONFIG['ordered_categories'] if cat in categorized_data]
    return categorized_data, uncategorized_data, final_ordered_categories

# --- 保存模块 ---
@performance_monitor
def save_channels_to_files(categorized_data, uncategorized_data, ordered_categories, output_file, uncat_file):
    """将分类结果保存到最终文件"""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    os.makedirs(os.path.dirname(uncat_file), exist_ok=True)

    header = [
        f"更新时间,#genre#\n",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n"
    ]

    try:
        with open(output_file, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(header)
            for category in ordered_categories:
                if category in categorized_data and categorized_data[category]:
                    iptv_list_file.write(f"\n{category},#genre#\n")
                    for name, url in sorted(categorized_data[category], key=lambda x: x[0]):
                        iptv_list_file.write(f"{name},{url}\n")
        logging.warning(f"所有有效频道已分类并保存到: {output_file}")
    except Exception as e:
        logging.error(f"写入文件 '{output_file}' 失败: {e}")

    try:
        with open(uncat_file, "w", encoding='utf-8') as uncat_file:
            uncat_file.writelines(header)
            if uncategorized_data:
                uncat_file.write(f"\n未分类频道,#genre#\n")
                for name, url in sorted(uncategorized_data, key=lambda x: x[0]):
                    uncat_file.write(f"{name},{url}\n")
        logging.warning(f"未分类频道已保存到: {uncat_file}")
    except Exception as e:
        logging.error(f"写入未分类文件 '{uncat_file}' 失败: {e}")

# --- 主函数 ---
@performance_monitor
def main():
    """主函数，执行 IPTV 频道检查、分类和保存流程"""
    logging.warning("开始执行 IPTV 频道检查和分类脚本...")
    total_start_time = time.time()
    
    # 从配置文件中获取精确替换规则
    replacements = CONFIG.get('channel_name_replacements', {})

    input_channels = read_channels_from_file(INPUT_CHANNELS_PATH)
    if input_channels is None:
        return

    unique_channels = list(set(input_channels))
    logging.warning(f"从输入文件读取 {len(input_channels)} 个频道，去重后得到 {len(unique_channels)} 个")

    if not unique_channels:
        logging.warning(f"输入文件 '{INPUT_CHANNELS_PATH}' 为空或无有效频道行，退出。")
        return

    timeout = CONFIG.get('network', {}).get('check_timeout', 30)
    workers = CONFIG.get('network', {}).get('channel_check_workers', 50)
    valid_channels = check_channels_multithreaded(unique_channels, workers, timeout)

    if not valid_channels:
        logging.warning("没有发现有效的频道，不生成输出文件。")
        return

    # 传递 replacements 字典给 categorize_channels 函数
    categorized_channels, uncategorized_channels, ordered_categories = categorize_channels(valid_channels, replacements)
    save_channels_to_files(categorized_channels, uncategorized_channels, ordered_categories, FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH)

    total_elapsed_time = time.time() - total_start_time
    logging.warning(f"IPTV 频道检查和分类脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
