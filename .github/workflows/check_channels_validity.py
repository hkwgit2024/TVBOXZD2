# check_channels_validity.py

import os
import re
import subprocess
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm
import yaml

# --- 配置和加载模块 ---
CONFIG_PATH = "config/config.yaml"
INPUT_CHANNELS_PATH = "output/iptv.txt"
VALID_CHANNELS_PATH = "output/valid_channels_temp.txt"  # 新增一个临时文件用于保存有效频道

def load_config(config_path):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file) or {}
            print("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        print(f"错误：未找到配置文件 '{config_path}'。")
        exit(1)
    except yaml.YAMLError as e:
        print(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        print(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 全局配置和会话对象
CONFIG = load_config(CONFIG_PATH)

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
        print(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒")
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
        print(f"从 {file_name} 读取 {len(channels)} 个频道")
    except FileNotFoundError:
        print(f"错误：未找到输入频道文件 '{file_name}'")
        return None
    except Exception as e:
        print(f"读取文件 '{file_name}' 失败: {e}")
        return None
    return channels

@performance_monitor
def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否可达"""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 400
    except requests.exceptions.RequestException as e:
        return False

@performance_monitor
def check_rtmp_url(url, timeout):
    """检查 RTMP URL 是否可达，使用 ffprobe"""
    try:
        result = subprocess.run(['ffprobe', '-v', 'quiet', '-timeout', str(timeout), '-i', url],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except Exception as e:
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
        print(f"不支持的协议: {protocol} for {url}")

    url_states[url] = is_valid
    return (name, url) if is_valid else None

@performance_monitor
def check_channels_multithreaded(channels, max_workers, timeout):
    """多线程检查频道有效性"""
    valid_channels = []
    url_states = {}
    total_channels = len(channels)
    print(f"开始多线程检查 {total_channels} 个频道的有效性")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_channel_validity, channel, url_states, timeout): channel for channel in channels}
        for future in tqdm(as_completed(futures), total=total_channels, desc="检查频道有效性"):
            try:
                result = future.result()
                if result:
                    valid_channels.append(result)
            except Exception as exc:
                print(f"处理频道时发生异常: {exc}")

    print(f"有效频道数: {len(valid_channels)}")
    return valid_channels

def save_valid_channels(channels, file_name):
    """将有效频道保存到文件中"""
    os.makedirs(os.path.dirname(file_name), exist_ok=True)
    try:
        with open(file_name, 'w', encoding='utf-8') as f:
            for name, url in channels:
                f.write(f"{name},{url}\n")
        print(f"有效频道列表已保存到: {file_name}")
    except Exception as e:
        print(f"保存文件 '{file_name}' 失败: {e}")

# --- 主函数 ---
def main():
    """主函数，执行 IPTV 频道检查流程"""
    print("开始执行 IPTV 频道有效性检查脚本...")
    total_start_time = time.time()

    input_channels = read_channels_from_file(INPUT_CHANNELS_PATH)
    if input_channels is None:
        return

    unique_channels = list(set(input_channels))
    print(f"从输入文件读取 {len(input_channels)} 个频道，去重后得到 {len(unique_channels)} 个")

    if not unique_channels:
        print(f"输入文件 '{INPUT_CHANNELS_PATH}' 为空或无有效频道行，退出。")
        return

    timeout = CONFIG.get('network', {}).get('check_timeout', 30)
    workers = CONFIG.get('network', {}).get('channel_check_workers', 50)
    valid_channels = check_channels_multithreaded(unique_channels, workers, timeout)

    if not valid_channels:
        print("没有发现有效的频道，不生成输出文件。")
        return

    save_valid_channels(valid_channels, VALID_CHANNELS_PATH)

    total_elapsed_time = time.time() - total_start_time
    print(f"IPTV 频道有效性检查脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
