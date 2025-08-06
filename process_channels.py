import os
import re
import subprocess
import time
from datetime import datetime
import logging
import logging.handlers
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
from cachetools import TTLCache
from tqdm import tqdm

# 配置日志系统
def setup_logging(config):
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file'].replace('main.log', 'process_channels.log')
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

# 配置文件路径
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 从配置中获取文件路径
URLS_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'urls.txt')
URL_STATES_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'url_states.json')
IPTV_LIST_PATH = 'output/iptv.txt' # 更改为新的输出文件路径
os.makedirs(os.path.dirname(IPTV_LIST_PATH), exist_ok=True)

# 初始化缓存
if CONFIG['url_state']['cache_enabled']:
    os.makedirs(CONFIG['url_state']['cache_dir'], exist_ok=True)
    content_cache = TTLCache(maxsize=1000, ttl=CONFIG['url_state']['cache_ttl'])

# 配置 requests 会话
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
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

# --- 辅助函数 ---
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

def get_url_file_extension(url):
    """获取 URL 的文件扩展名"""
    try:
        parsed_url = urlparse(url)
        return os.path.splitext(parsed_url.path)[1].lower()
    except ValueError as e:
        logging.info(f"获取 URL 扩展名失败: {url} - {e}")
        return ""

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

def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径"""
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.info(f"清理 URL 参数失败: {url} - {e}")
        return url

def pre_screen_url(url):
    """根据配置预筛选 URL（协议、长度、无效模式）"""
    if not isinstance(url, str) or not url:
        return False
    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        return False
    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        return False
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in CONFIG['url_pre_screening']['allowed_protocols']:
            return False
        if not parsed_url.netloc:
            return False
        invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns']
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                return False
        if len(url) < 15:
            return False
        return True
    except ValueError as e:
        logging.info(f"预筛选过滤（URL 解析错误）: {url} - {e}")
        return False

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
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        if response.status_code == 304:
            logging.debug(f"URL 内容未变更 (304): {url}")
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL 内容未变更（哈希相同）: {url}")
            return None

        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }

        if CONFIG['url_state']['cache_enabled']:
            content_cache[url] = content

        logging.info(f"成功获取新内容: {url}")
        return content
    except requests.exceptions.Timeout:
        logging.error(f"请求 URL 超时: {url}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"请求 URL 失败（重试后）: {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"获取 URL 内容未知错误: {url} - {e}")
        return None

def load_url_states_local():
    """加载 URL 状态"""
    url_states = {}
    try:
        with open(URL_STATES_PATH, 'r', encoding='utf-8') as file:
            url_states = json.load(file)
    except FileNotFoundError:
        logging.warning(f"URL 状态文件 '{URL_STATES_PATH}' 未找到，使用空状态")
    except json.JSONDecodeError as e:
        logging.error(f"解析 '{URL_STATES_PATH}' 的 JSON 失败: {e}")
        return {}
    return url_states

def save_url_states_local(url_states):
    """保存 URL 状态到本地文件"""
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}")

def extract_channels_from_url(url, url_states):
    """从 URL 提取频道，支持多种文件格式"""
    extracted_channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states)
        if text is None:
            return []

        extension = get_url_file_extension(url).lower()
        if extension in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)
        elif extension not in [".txt", ".csv", ""]:
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
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip() or "未知频道"
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    continue

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
    except Exception as e:
        logging.error(f"从 {url} 提取频道失败: {e}")
    return extracted_channels

def filter_and_modify_channels(channels):
    """过滤和修改频道名称及 URL"""
    filtered_channels = []
    for name, url in channels:
        if not pre_screen_url(url):
            continue
        new_name = name
        for old_str, new_str in CONFIG['channel_name_replacements'].items():
            new_name = re.sub(old_str, new_str, new_name, flags=re.IGNORECASE)
        new_name = new_name.strip()
        if any(word.lower() in new_name.lower() for word in CONFIG['name_filter_words']):
            continue
        filtered_channels.append((new_name, url))
    return filtered_channels

def write_channels_to_file(file_path, channels):
    """将频道数据写入文件，并去重"""
    seen_channels = set()
    unique_channels = []
    for name, url in channels:
        if (name, url) not in seen_channels:
            seen_channels.add((name, url))
            unique_channels.append((name, url))

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            for name, url in sorted(unique_channels, key=lambda x: x[0]):
                file.write(f"{name},{url}\n")
        logging.warning(f"成功将 {len(unique_channels)} 个唯一频道写入 '{file_path}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")


def main():
    """主函数，执行频道提取、过滤和去重流程"""
    logging.warning("开始执行频道提取和过滤脚本")
    total_start_time = time.time()

    url_states = load_url_states_local()
    urls = read_txt_to_array_local(URLS_PATH)
    if not urls:
        logging.error("未在 urls.txt 中找到 URL，退出")
        exit(1)
    logging.warning(f"从 '{URLS_PATH}' 加载 {len(urls)} 个 URL")

    all_extracted_channels = []
    urls_to_process = urls
    
    with ThreadPoolExecutor(max_workers=CONFIG['network']['url_fetch_workers']) as executor:
        futures = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls_to_process}
        
        with tqdm(total=len(urls_to_process), desc="提取频道", unit="URL") as pbar:
            for future in as_completed(futures):
                try:
                    channels = future.result()
                    if channels:
                        all_extracted_channels.extend(channels)
                except Exception as exc:
                    logging.error(f"URL 提取异常: {exc}")
                pbar.update(1)

    logging.warning(f"完成频道提取，过滤前总计提取 {len(all_extracted_channels)} 个频道")
    
    # 过滤和修改频道
    filtered_and_modified_channels = filter_and_modify_channels(all_extracted_channels)
    logging.warning(f"过滤和修改后剩余 {len(filtered_and_modified_channels)} 个频道")

    # 保存去重后的频道列表
    write_channels_to_file(IPTV_LIST_PATH, filtered_and_modified_channels)

    # 保存 URL 状态
    save_url_states_local(url_states)
    logging.warning("URL 状态已保存")

    total_elapsed_time = time.time() - total_start_time
    logging.warning(f"频道提取、过滤和去重脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
