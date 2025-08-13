# Version 1.2 - Optimized for robust variant clustering and logging
# Date: August 13, 2025
# Improvements: Enhanced normalize_name, lowered clustering threshold, dynamic fetch_new_channels_from_web, robust logging

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

# 配置日志系统
def setup_logging(config):
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转"""
    log_level = getattr(logging, config.get('logging', {}).get('log_level', 'DEBUG'), logging.DEBUG)
    log_file = config.get('logging', {}).get('log_file', 'logs/iptv_checker.log')
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
    logging.debug("日志系统配置完成")
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

# 加载分类配置
def load_category_config(config_path="config/demo.txt"):
    """加载并解析分类配置文件"""
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
                    keywords = [kw.strip() for kw in line.split('|') if kw.strip()]
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
CONFIG = load_config(CONFIG_PATH)
CATEGORY_CONFIG = load_category_config(CATEGORY_CONFIG_PATH)
setup_logging(CONFIG)

# 配置 requests 会话
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

# 性能监控装饰器
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

# 读取频道文件
@performance_monitor
def read_channels_from_local(file_name):
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
        exit(1)
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        exit(1)
    return channels

# 去重
@performance_monitor
def read_existing_channels_from_file(file_path):
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

# 检查 URL 有效性
@performance_monitor
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达"""
    try:
        response = session.head(url, timeout=timeout)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.warning(f"HTTP检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达"""
    try:
        result = subprocess.run(['ffprobe', '-timeout', str(timeout * 1000000), url],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except Exception as e:
        logging.warning(f"RTMP检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_rtp_url(url, timeout):
    """检查 RTP URL 是否可达"""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 5000
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except Exception as e:
        logging.warning(f"RTP检查失败: {url}, 错误: {e}")
        return False

@performance_monitor
def check_channel_validity_and_speed(name, url, url_states):
    """检查频道有效性和响应速度"""
    start_time = time.time()
    is_valid = False
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme.lower()

    if protocol in ['http', 'https']:
        is_valid = check_http_url(url, CONFIG.get('network', {}).get('check_timeout', 30))
    elif protocol == 'rtmp':
        is_valid = check_rtmp_url(url, CONFIG.get('network', {}).get('check_timeout', 30))
    elif protocol in ['rtp', 'rtsp']:
        is_valid = check_rtp_url(url, CONFIG.get('network', {}).get('check_timeout', 30))
    else:
        logging.warning(f"不支持的协议: {protocol} for {url}")
        return None, False

    elapsed_time = time.time() - start_time if is_valid else None
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
def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG.get('network', {}).get('channel_check_workers', 50)):
    """多线程检查频道有效性"""
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
    logging.debug(f"有效频道数: {len(results)}")
    return results

# 规范化频道名称
def normalize_name(name):
    """规范化频道名称，移除分辨率后缀、HD/SD、数字后缀、连字符、外语字符等"""
    cleaned = re.sub(r'\s*\(\d+p\)|HD|SD|ipv6-\d| \d|[-_]|Dự phòng|[^\u4e00-\u9fff\w]', '', name.lower().strip())
    return cleaned or name.lower()

# 智能聚类变体
def group_variants(channels, threshold=0.75):
    """使用相似度聚类频道变体"""
    groups = defaultdict(list)
    for name, url in channels:
        cleaned = normalize_name(name)
        matched = False
        for existing_group in list(groups.keys()):
            if difflib.SequenceMatcher(None, cleaned, existing_group).ratio() > threshold:
                groups[existing_group].append((name, url))
                matched = True
                break
        if not matched:
            groups[cleaned].append((name, url))
    logging.debug(f"变体聚类结果: {groups}")
    return groups

# 动态提取新分类
def fetch_new_channels_from_web(channels):
    """基于输入频道提取新分类"""
    categories = defaultdict(list)
    for name, _ in channels:
        cleaned = normalize_name(name)
        if '卫视' in cleaned:
            categories['卫视频道'].append(name)
        elif '新闻' in cleaned or 'new' in cleaned.lower():
            categories['新闻频道'].append(name)
        elif '体育' in cleaned or 'sport' in cleaned.lower() or 'football' in cleaned.lower():
            categories['体育频道'].append(name)
        elif '卡通' in cleaned or 'kids' in cleaned.lower() or 'cartoon' in cleaned.lower():
            categories['少儿频道'].append(name)
        elif '电影' in cleaned or 'cinema' in cleaned.lower() or 'film' in cleaned.lower():
            categories['电影频道'].append(name)
        elif '时尚' in cleaned or 'fashion' in cleaned.lower():
            categories['时尚频道'].append(name)
        elif '宗教' in cleaned or 'tv' in cleaned.lower():
            categories['宗教频道'].append(name)
        else:
            categories['其他频道'].append(name)
    logging.info(f"从输入频道提取分类: {categories}")
    return categories

# 自动更新 demo.txt
def auto_update_demo(new_categories):
    """自动追加新频道到 demo.txt"""
    try:
        with open(CATEGORY_CONFIG_PATH, 'a', encoding='utf-8') as f:
            for cat, chans in new_categories.items():
                f.write(f"{cat},#genre#\n")
                f.write('|'.join(chans) + '\n')
        logging.info("自动更新 demo.txt 完成")
    except Exception as e:
        logging.error(f"自动更新 demo.txt 失败: {e}")

# 分类频道
@performance_monitor
def categorize_channels(channels):
    """根据关键字分类频道"""
    categorized_data = {category: [] for category in CATEGORY_CONFIG['ordered_categories']}
    uncategorized_data = []
    grouped_variants = group_variants(channels)
    
    for main_cleaned, group in grouped_variants.items():
        found_category = False
        for category in CATEGORY_CONFIG['ordered_categories']:
            category_keywords = CATEGORY_CONFIG['category_keywords'].get(category, [])
            if any(kw.lower() in main_cleaned for kw in category_keywords):
                for name, url in group:
                    categorized_data[category].append((name, url))
                found_category = True
                break
        if not found_category:
            uncategorized_data.extend(group)
            variants = '|'.join([g[0] for g in group])
            logging.info(f"建议添加新关键词到 demo.txt: {category}:{variants}")
    
    categorized_data_cleaned = {k: v for k, v in categorized_data.items() if v}
    all_final_categories = list(categorized_data_cleaned.keys())
    final_ordered_categories = [cat for cat in CATEGORY_CONFIG['ordered_categories'] if cat in all_final_categories]
    for cat in sorted(all_final_categories):
        if cat not in final_ordered_categories:
            final_ordered_categories.append(cat)
    
    return categorized_data_cleaned, uncategorized_data, final_ordered_categories

# 生成更新时间头
@performance_monitor
def generate_update_time_header():
    """生成文件顶部更新时间信息"""
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d %H:%M:%S')},url\n"
    ]

# 保存分类结果
@performance_monitor
def save_channels_to_final_files(valid_channels, output_file_path, uncategorized_file_path):
    """将有效频道分类并保存"""
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
    """主函数，执行 IPTV 频道检查、分类和保存流程"""
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
    except FileNotFoundError:
        logging.error(f"错误：未找到输入文件 '{INPUT_CHANNELS_PATH}'。请确保该文件存在。")
        return
    
    if not input_channels_lines:
        logging.warning(f"输入文件 '{INPUT_CHANNELS_PATH}' 为空或无有效频道行，退出。")
        return
    
    valid_channels_with_speed = check_channels_multithreaded(input_channels_lines, url_states)
    valid_channels_list = [(line.split(',', 1)[0], line.split(',', 1)[1]) for _, line in valid_channels_with_speed]
    
    if not valid_channels_list:
        logging.warning("没有发现有效的频道，不生成输出文件。")
        return
    
    save_channels_to_final_files(valid_channels_list, FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH)
    new_categories = fetch_new_channels_from_web(valid_channels_list)
    auto_update_demo(new_categories)
    
    total_elapsed_time = time.time() - total_start_time
    logging.warning(f"IPTV 频道检查和分类脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
