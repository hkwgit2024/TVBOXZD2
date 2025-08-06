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
import yaml
import threading
from tqdm import tqdm

# --- 配置和工具函数 (与原脚本保持一致) ---

# 配置日志系统
def setup_logging(config):
    """配置日志系统，支持文件和控制台输出"""
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(log_level)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=1
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

CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

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

# 文件路径
URL_STATES_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'url_states.json')
INPUT_IPTV_LIST_PATH = 'output/iptv.txt'
CHANNELS_DIR = CONFIG['output']['paths']['channels_dir']
UNSORTED_CHANNELS_PATH = os.path.join(CHANNELS_DIR, 'uncategorized_channels.txt')

# 加载 URL 状态，用于冷却期判断和去重
def load_url_states_local():
    """加载 URL 状态"""
    try:
        if os.path.exists(URL_STATES_PATH):
            with open(URL_STATES_PATH, 'r', encoding='utf-8') as file:
                return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.warning(f"加载 URL 状态文件失败: {e}，使用空状态")
    return {}

# 保存 URL 状态
def save_url_states_local(url_states):
    """保存 URL 状态到本地文件"""
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}")

# 检查 HTTP/HTTPS URL
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        return False

# 检查 RTMP URL
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达"""
    # 简化实现，实际需要 ffprobe
    # 检查 ffprobe 是否可用
    try:
        subprocess.run(['ffprobe', '-version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=2)
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
        return False
    except Exception as e:
        return False

# 检查单个频道的有效性和速度
def check_channel_validity_and_speed(channel_name, url, url_states, timeout):
    """检查单个频道的有效性和速度，并更新状态"""
    current_time = datetime.now()
    current_url_state = url_states.get(url, {})

    # 检查冷却期
    if 'stream_check_failed_at' in current_url_state:
        try:
            last_failed_datetime = datetime.fromisoformat(current_url_state['stream_check_failed_at'])
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
            if time_since_failed_hours < CONFIG['channel_retention']['stream_retention_hours']:
                # 在冷却期内，不检查，直接返回无效
                return None, False
        except ValueError:
            pass

    start_time = time.time()
    is_valid = False

    try:
        if url.startswith("http"):
            is_valid = check_http_url(url, timeout)
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
        else:
            is_valid = False # 简单处理不支持的协议

        elapsed_time = (time.time() - start_time) * 1000

        if is_valid:
            url_states.pop(url, {})
            url_states[url] = {
                'last_successful_stream_check': current_time.isoformat(),
                'last_stream_checked': current_time.isoformat()
            }
            return elapsed_time, True
        else:
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = url_states[url].get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            return None, False
    except Exception as e:
        if url not in url_states:
            url_states[url] = {}
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = url_states[url].get('stream_fail_count', 0) + 1
        url_states[url]['last_stream_checked'] = current_time.isoformat()
        return None, False

def process_single_channel_line(channel_line, url_states_lock, url_states, timeout):
    """在多线程中处理单个频道行"""
    if "://" not in channel_line:
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        name = name.strip()
        
        with url_states_lock:
            elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states, timeout)

        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

def check_channels_multithreaded(channel_lines, url_states, max_workers):
    """多线程检查频道有效性，带进度条"""
    results = []
    total_channels = len(channel_lines)
    logging.warning(f"开始多线程检查 {total_channels} 个频道的有效性和速度")
    
    url_states_lock = threading.Lock()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                process_single_channel_line, line, url_states_lock, url_states, CONFIG['network']['check_timeout']
            ): line for line in channel_lines
        }
        
        with tqdm(total=total_channels, desc="检查频道", unit="个") as pbar:
            for future in as_completed(futures):
                try:
                    elapsed_time, result_line = future.result()
                    if elapsed_time is not None and result_line is not None:
                        results.append((elapsed_time, result_line))
                except Exception as exc:
                    logging.warning(f"处理频道行时发生异常: {exc}")
                pbar.update(1)

    logging.warning(f"多线程检查完成，发现 {len(results)} 个有效频道")
    return results

def categorize_channels(channels):
    """根据频道名称关键字分类，并应用类别别名进行规范化"""
    categorized_data = {category: [] for category in CONFIG.get('ordered_categories', [])}
    uncategorized_data = []

    category_aliases = CONFIG.get('category_aliases', {})

    for name, url in channels:
        found_category = False
        for category in CONFIG.get('ordered_categories', []):
            category_keywords = CONFIG['category_keywords'].get(category, [])
            if any(keyword.lower() in name.lower() for keyword in category_keywords):
                final_category = category_aliases.get(category, category)
                if final_category not in categorized_data:
                    categorized_data[final_category] = []
                categorized_data[final_category].append((name, url))
                found_category = True
                break
        
        if not found_category:
            uncategorized_data.append((name, url))
            
    categorized_data_cleaned = {k: v for k, v in categorized_data.items() if v}
    all_final_categories = list(categorized_data_cleaned.keys())
    for alias_target in set(category_aliases.values()):
        if alias_target not in all_final_categories:
            all_final_categories.append(alias_target)
            
    final_ordered_categories = [cat for cat in CONFIG.get('ordered_categories', []) if cat in all_final_categories]
    for cat in sorted(all_final_categories):
        if cat not in final_ordered_categories:
            final_ordered_categories.append(cat)

    return categorized_data_cleaned, uncategorized_data, final_ordered_categories

def process_and_save_channels_by_category(all_channels, output_dir):
    """将频道分类并保存到对应文件"""
    categorized_channels, uncategorized_channels, final_ordered_categories = categorize_channels(all_channels)
    os.makedirs(output_dir, exist_ok=True)

    # 写入主文件
    main_output_file = os.path.join(output_dir, 'iptv.txt')
    logging.warning(f"开始写入主 IPTV 文件: {main_output_file}")
    with open(main_output_file, 'w', encoding='utf-8') as f:
        f.write(f"更新时间,#genre#\n")
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n")
        
        for category in final_ordered_categories:
            channels = categorized_channels.get(category)
            if channels:
                f.write(f"{category},#genre#\n")
                sorted_channels = sorted(channels, key=lambda x: x[0])
                for name, url in sorted_channels:
                    f.write(f"{name},{url}\n")
    logging.warning(f"主 IPTV 文件写入完成，包含 {len(all_channels)} 个频道")
    
    # 写入未分类文件
    output_uncategorized_file = os.path.join(output_dir, 'uncategorized.txt')
    if uncategorized_channels:
        logging.warning(f"发现 {len(uncategorized_channels)} 个未分类频道，保存到 {output_uncategorized_file}")
        sorted_uncategorized = sorted(uncategorized_channels, key=lambda x: x[0])
        with open(output_uncategorized_file, 'w', encoding='utf-8') as f:
            for name, url in sorted_uncategorized:
                f.write(f"{name},{url}\n")
    else:
        logging.warning("未发现未分类频道")
        if os.path.exists(output_uncategorized_file):
            os.remove(output_uncategorized_file)

def main():
    """主函数，从 output/iptv.txt 读取频道进行检查和分类"""
    logging.warning("开始执行频道检查和分类脚本")
    start_time = time.time()
    
    # 步骤 1: 读取输入文件
    try:
        with open(INPUT_IPTV_LIST_PATH, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and '#genre#' not in line and '://' in line]
        if not lines:
            logging.error(f"输入文件 '{INPUT_IPTV_LIST_PATH}' 中没有找到有效的频道列表，脚本退出")
            return
        # 移除文件头部的更新时间
        if ',' in lines[0]:
            parts = lines[0].split(',', 1)
            if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', parts[0]):
                lines = lines[1:]

    except FileNotFoundError:
        logging.error(f"错误：未找到输入文件 '{INPUT_IPTV_LIST_PATH}'，请确保已存在")
        return
    except Exception as e:
        logging.error(f"读取文件 '{INPUT_IPTV_LIST_PATH}' 失败: {e}")
        return

    # 步骤 2: 加载 URL 状态
    url_states = load_url_states_local()
    logging.warning(f"加载 {len(url_states)} 个 URL 状态，准备进行频道检查...")
    
    # 步骤 3: 多线程检查频道有效性
    valid_channels_raw = check_channels_multithreaded(lines, url_states, max_workers=CONFIG['network']['channel_check_workers'])

    # 步骤 4: 提取并去重有效频道
    unique_channels = {}
    for _, line in valid_channels_raw:
        if ',' in line:
            name, url = line.split(',', 1)
            name = name.strip()
            url = url.strip()
            # 使用名称和URL作为键进行去重
            unique_channels[(name, url)] = True

    final_valid_channels = list(unique_channels.keys())
    logging.warning(f"去重后得到 {len(final_valid_channels)} 个有效频道")

    # 步骤 5: 分类并保存结果
    process_and_save_channels_by_category(final_valid_channels, CHANNELS_DIR)

    # 步骤 6: 保存最新的 URL 状态
    save_url_states_local(url_states)
    logging.warning("频道检查状态已保存")
    
    end_time = time.time()
    logging.warning(f"脚本执行完成，总耗时 {end_time - start_time:.2f} 秒")

if __name__ == "__main__":
    main()
