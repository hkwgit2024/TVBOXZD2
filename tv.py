import os
import re
import subprocess
import socket
import time
from datetime import datetime, timedelta
import logging
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
import base64

# --- 配置日志 ---
LOG_FILE = 'iptv_crawler.log'
logging.basicConfig(
    level=logging.INFO, # 默认日志级别改为 INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'), # 记录到文件
        logging.StreamHandler() # 同时输出到控制台
    ]
)

# --- 从环境变量获取配置 ---
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')

# 检查环境变量是否设置
if not GITHUB_TOKEN:
    logging.error("错误：环境变量 'BOT' 未设置。请检查你的 CI/CD 配置。")
    exit(1)
if not REPO_OWNER:
    logging.error("错误：环境变量 'REPO_OWNER' 未设置。请检查你的 CI/CD 配置。")
    exit(1)
if not REPO_NAME:
    logging.error("错误：环境变量 'REPO_NAME' 未设置。请检查你的 CI/CD 配置。")
    exit(1)
if not CONFIG_PATH:
    logging.error("错误：环境变量 'CONFIG_PATH' 未设置。请检查你的 CI/CD 配置。")
    exit(1)
if not URLS_PATH_IN_REPO:
    logging.error("错误：环境变量 'URLS_PATH' 未设置。请检查你的 CI/CD 配置。")
    exit(1)
if not URL_STATES_PATH_IN_REPO:
    logging.error("错误：环境变量 'URL_STATES_PATH' 未设置。请检查你的 CI/CD 配置。")
    exit(1)

# GitHub API 基础 URL
GITHUB_API_BASE = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# --- 常量定义 ---
TEMP_IPTV_FILE = 'iptv.txt' # 存放抓取到的所有有效频道的临时文件
TEMP_IPTV_SPEED_FILE = 'iptv_speed.txt' # 如果有测速功能，可能是测速结果
UNMATCHED_CHANNELS_FILE = "unmatched_channels.txt" # 存放未匹配分类的频道名称列表
FINAL_IPTV_LIST_FILE = "iptv_list.txt" # 最终生成的 IPTV 列表文件

# --- 配置重试机制 ---
# 对于 HTTP 请求的重试策略
retry_strategy = Retry(
    total=3,                # 总重试次数
    backoff_factor=1,       # 退避因子，每次重试等待时间倍增
    status_forcelist=[429, 500, 502, 503, 504],  # 对这些状态码进行重试
    allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"] # 允许重试的方法
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.mount("https://", adapter)
http.mount("http://", adapter)

# --- 全局变量 ---
CONFIG = {}
URL_STATES = {}
ORDERED_CATEGORIES = [] # 存储配置中定义的有序分类

# --- 辅助函数 ---
def calculate_md5(data):
    """计算数据的 MD5 值"""
    return hashlib.md5(data).hexdigest()

def clean_url_params(url):
    """
    清理 URL 中的特定参数，但保留核心路径和查询参数。
    主要删除常见的缓存buster参数（以下划线或问号开头）。
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # 过滤掉以下划线或问号开头的参数
    # doseq=True 确保列表值参数被正确编码 (e.g., ?param=a&param=b)
    filtered_params = {k: v for k, v in query_params.items() if not k.startswith('_') and not k.startswith('?')}
    
    new_query = urlencode(filtered_params, doseq=True)
    
    # 重构 URL，只替换查询部分
    cleaned_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment
    ))
    return cleaned_url

# --- GitHub API 交互函数 ---
@retry(stop=stop_after_attempt(5), wait=wait_fixed(2), reraise=True)
def get_github_file_content(path):
    """
    从 GitHub 获取文件内容。
    """
    url = f"{GITHUB_API_BASE}/{path}"
    logging.debug(f"正在从 GitHub 获取文件：{url}")
    try:
        response = http.get(url, headers=HEADERS)
        response.raise_for_status()
        content = response.json()
        if content and 'content' in content:
            return base64.b64decode(content['content']).decode('utf-8'), content['sha']
        return None, None
    except requests.exceptions.RequestException as e:
        logging.error(f"从 GitHub 获取文件 '{path}' 失败: {e}")
        raise

@retry(stop=stop_after_attempt(5), wait=wait_fixed(2), reraise=True)
def get_current_sha(path):
    """
    获取 GitHub 上文件的当前 SHA 值。如果文件不存在，返回 None。
    """
    url = f"{GITHUB_API_BASE}/{path}"
    logging.debug(f"正在获取文件 '{path}' 的 SHA 值...")
    try:
        response = http.get(url, headers=HEADERS)
        if response.status_code == 404:
            logging.info(f"文件 '{path}' 在 GitHub 上不存在 (404)。")
            return None
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        # 对于其他非 404 的错误，记录为错误
        logging.error(f"获取文件 '{path}' 的 SHA 发生错误: {e}")
        raise

@retry(stop=stop_after_attempt(5), wait=wait_fixed(2), reraise=True)
def update_github_file(path, content, message, sha=None):
    """
    更新 GitHub 上的文件。
    """
    url = f"{GITHUB_API_BASE}/{path}"
    logging.info(f"正在更新 GitHub 文件：{path}")
    data = {
        "message": message,
        "content": base64.b64encode(content.encode('utf-8')).decode('utf-8'),
        "branch": "main" # 假定操作 main 分支
    }
    if sha:
        data["sha"] = sha # 必须提供 SHA 来更新现有文件
    
    try:
        response = http.put(url, headers=HEADERS, json=data)
        response.raise_for_status()
        logging.info(f"文件 '{path}' 更新成功。")
        return response.json().get('content', {}).get('sha')
    except requests.exceptions.RequestException as e:
        logging.error(f"更新 GitHub 文件 '{path}' 失败: {e}")
        raise

# --- 配置加载函数 ---
def load_config():
    """
    加载并验证配置文件。
    """
    global CONFIG, ORDERED_CATEGORIES
    config_file_content, _ = get_github_file_content(CONFIG_PATH)
    if not config_file_content:
        logging.error(f"无法加载配置文件 '{CONFIG_PATH}'。请确保文件存在且可访问。")
        exit(1)
    
    try:
        CONFIG = yaml.safe_load(config_file_content)
        logging.info("配置加载成功。")
    except yaml.YAMLError as e:
        logging.error(f"解析配置文件 '{CONFIG_PATH}' 失败: {e}")
        exit(1)

    # 验证关键配置项
    required_keys = ['rules', 'categories', 'check_timeout', 'request_timeout', 'channel_check_workers']
    for key in required_keys:
        if key not in CONFIG:
            logging.error(f"配置中缺少关键项: '{key}'。请检查 '{CONFIG_PATH}' 文件。")
            logging.warning(f"参考示例配置: 请检查 'config.yaml.example' 文件以获取正确的配置结构。")
            exit(1)
            
    # 填充有序分类
    ORDERED_CATEGORIES = [item['name'] for item in CONFIG.get('categories', [])]
    if not ORDERED_CATEGORIES:
        logging.warning("配置中未找到 'categories' 或其为空。频道将按默认顺序排序。")

    # 确保 URL_STATES 文件存在
    global URL_STATES
    url_states_content, _ = get_github_file_content(URL_STATES_PATH_IN_REPO)
    if url_states_content:
        try:
            URL_STATES = json.loads(url_states_content)
            logging.info("URL 状态文件加载成功。")
        except json.JSONDecodeError as e:
            logging.warning(f"解析 URL 状态文件 '{URL_STATES_PATH_IN_REPO}' 失败: {e}。将从空状态开始。")
            URL_STATES = {}
    else:
        logging.info(f"URL 状态文件 '{URL_STATES_PATH_IN_REPO}' 不存在或为空，将从空状态开始。")
        URL_STATES = {}


# --- URL 和频道处理函数 ---
@retry(stop=stop_after_attempt(3), wait=wait_fixed(1), retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url):
    """
    使用重试机制获取 URL 内容，并进行缓存检查。
    """
    global URL_STATES
    
    current_state = URL_STATES.get(url, {})
    headers = {}
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']

    try:
        response = http.get(url, headers=headers, timeout=CONFIG['request_timeout'])
        response.raise_for_status()

        if response.status_code == 304:
            logging.debug(f"URL {url} 内容未修改 (304 Not Modified)。")
            # 即使未修改，也更新检查时间
            URL_STATES[url]['last_checked'] = datetime.now().isoformat()
            # 返回 None 表示内容未变，可以继续使用旧内容。
            # 这里返回旧的 content_hash，以便调用方可以根据需要使用旧数据
            return None, current_state.get('content_hash') 
        
        content = response.text
        content_hash = calculate_md5(content.encode('utf-8'))

        # 如果内容哈希相同，也视为未修改
        if current_state.get('content_hash') == content_hash:
            logging.debug(f"URL {url} 内容哈希未修改，使用缓存内容。")
            URL_STATES[url]['last_checked'] = datetime.now().isoformat()
            return None, content_hash

        # 更新状态
        URL_STATES[url] = {
            'etag': response.headers.get('ETag', ''),
            'last_modified': response.headers.get('Last-Modified', ''),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }
        logging.info(f"已获取并更新 URL {url} 的内容。")
        return content, content_hash

    except requests.exceptions.Timeout:
        logging.warning(f"获取 URL '{url}' 超时。")
        return None, None
    except requests.exceptions.RequestException as e:
        logging.warning(f"获取 URL '{url}' 发生网络错误: {e}")
        return None, None
    except Exception as e:
        logging.error(f"获取 URL '{url}' 发生未知错误: {e}")
        return None, None

def extract_channels_from_url(url_item):
    """
    从给定的 URL 中提取频道。
    url_item 是一个字典，包含 'url' 和可能的 'category' 信息。
    """
    url = url_item['url']
    logging.info(f"正在从 URL '{url}' 提取频道...")
    content, _ = fetch_url_content_with_retry(url) # content_hash在这里不需要直接使用

    if content is None:
        logging.warning(f"无法获取 URL '{url}' 的内容或内容未更新，跳过频道提取。")
        return []

    channels = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            parts = line.split(',', 1)
            if len(parts) == 2:
                name = parts[0].strip()
                channel_url = parts[1].strip()
                channels.append({"name": name, "url": channel_url})
    logging.info(f"从 URL '{url}' 提取到 {len(channels)} 个频道。")
    return channels

def get_channel_urls(urls_config):
    """
    从配置的 URL 列表中并行提取所有频道。
    """
    all_channels = []
    urls_to_process = []

    # 检查 URL 状态，避免重复抓取近期已检查的 URL
    for url_item in urls_config:
        url = url_item['url']
        last_checked_str = URL_STATES.get(url, {}).get('last_checked')
        if last_checked_str:
            last_checked = datetime.fromisoformat(last_checked_str)
            # 如果上次检查在 6 小时内，跳过抓取
            if datetime.now() - last_checked < timedelta(hours=6):
                logging.info(f"URL '{url}' 最近已检查过 (上次检查：{last_checked_str})，跳过抓取。")
                continue
        urls_to_process.append(url_item) # 传递整个 url_item
    
    if not urls_to_process:
        logging.info("所有频道源 URL 均在近期已检查，无需重新抓取。")
        return []

    logging.info(f"准备从 {len(urls_to_process)} 个 URL 抓取频道内容...")
    # 使用线程池并行处理
    with ThreadPoolExecutor(max_workers=5) as executor: # 可以根据需要调整 worker 数量
        future_to_url_item = {executor.submit(extract_channels_from_url, url_item): url_item for url_item in urls_to_process}
        for future in as_completed(future_to_url_item):
            url_item = future_to_url_item[future]
            try:
                channels = future.result()
                all_channels.extend(channels)
            except Exception as exc:
                logging.error(f"处理 URL '{url_item['url']}' 时发生异常: {exc}")
    
    logging.info(f"已从 {len(urls_to_process)} 个 URL 中提取到 {len(all_channels)} 个频道。")
    return all_channels

# --- 频道校验函数 ---
def check_ffprobe_exists():
    """检查系统是否安装了 ffprobe"""
    try:
        subprocess.run(['ffprobe', '-h'], capture_output=True, check=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

FFPROBE_AVAILABLE = check_ffprobe_exists()
if not FFPROBE_AVAILABLE:
    logging.warning("警告：未检测到 'ffprobe'。RTMP、RTP 和 P3P 流的有效性将无法检查。")

def check_rtmp_url(url, timeout):
    """
    使用 ffprobe 检查 RTMP、RTP 或 P3P 流的有效性。
    需要系统安装 ffprobe。
    """
    if not FFPROBE_AVAILABLE:
        logging.debug(f"ffprobe 不可用，跳过 RTMP/RTP/P3P 流检查：{url}")
        return False

    ffprobe_path = 'ffprobe' # 假设 ffprobe 在 PATH 中
    
    command = [
        ffprobe_path,
        '-v', 'quiet',
        '-print_format', 'json',
        '-show_format',
        '-select_streams', 'v:0', # 尝试获取视频流信息
        '-timeout', str(int(timeout * 1000000)), # ffprobe timeout 单位是微秒
        '-i', url
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and ("streams" in result.stdout or "format" in result.stdout):
            # 简单的检查，只要ffprobe能解析出流信息就认为有效
            return True
        else:
            logging.debug(f"ffprobe 检查失败，URL: {url}, 返回码: {result.returncode}, 输出: {result.stderr or result.stdout}")
            return False
    except subprocess.TimeoutExpired:
        logging.debug(f"ffprobe 检查 RTMP/RTP/P3P URL '{url}' 超时。")
        return False
    except Exception as e:
        logging.debug(f"ffprobe 检查 RTMP/RTP/P3P URL '{url}' 发生错误: {e}")
        return False

def check_channel(channel):
    """
    检查单个频道的 URL 是否有效。
    """
    name = channel["name"]
    url = channel["url"]
    parsed_url = urlparse(url)
    
    # 过滤掉不符合规则的频道
    for rule in CONFIG['rules']:
        if rule['type'] == 'exclude':
            if 'keyword' in rule and re.search(rule['keyword'], name, re.IGNORECASE):
                logging.debug(f"频道 '{name}' (URL: {url}) 因名称匹配排除规则 '{rule['keyword']}' 被跳过。")
                return None
            if 'url_pattern' in rule and re.search(rule['url_pattern'], url, re.IGNORECASE):
                logging.debug(f"频道 '{name}' (URL: {url}) 因 URL 匹配排除规则 '{rule['url_pattern']}' 被跳过。")
                return None
        if rule['type'] == 'include':
            # 包含规则，如果名称或 URL 不匹配任何包含规则，则跳过
            # 注意：此处逻辑是“如果所有包含规则都不匹配，则跳过”，这可能需要根据实际需求调整
            # 当前实现是：只要有一个包含规则不匹配就跳过
            if 'keyword' in rule and not re.search(rule['keyword'], name, re.IGNORECASE):
                logging.debug(f"频道 '{name}' (URL: {url}) 因名称不匹配包含规则 '{rule['keyword']}' 被跳过。")
                return None
            if 'url_pattern' in rule and not re.search(rule['url_pattern'], url, re.IGNORECASE):
                logging.debug(f"频道 '{name}' (URL: {url}) 因 URL 不匹配包含规则 '{rule['url_pattern']}' 被跳过。")
                return None

    # 根据协议进行检查
    if parsed_url.scheme in ['http', 'https']:
        try:
            response = http.head(url, timeout=CONFIG['check_timeout'], allow_redirects=True)
            if response.status_code == 200:
                logging.debug(f"频道 '{name}' (URL: {url}) HTTP/HTTPS 状态码 200。")
                return channel
            elif 300 <= response.status_code < 400:
                logging.debug(f"频道 '{name}' (URL: {url}) HTTP/HTTPS 发生重定向 (状态码 {response.status_code})。")
                # 可以选择是否追踪重定向后的 URL，并返回新的 URL
                # return {"name": name, "url": response.url} 
                return channel # 暂时只返回原始频道，如果重定向后的 URL 也是有效的，则认为原始 URL 也可达
            else:
                logging.debug(f"频道 '{name}' (URL: {url}) HTTP/HTTPS 状态码 {response.status_code}。")
                return None
        except requests.exceptions.RequestException as e:
            logging.debug(f"频道 '{name}' (URL: {url}) HTTP/HTTPS 请求失败: {e}")
            return None
    elif parsed_url.scheme in ['rtmp', 'rtp', 'p3p']:
        # 对于流媒体协议，使用 ffprobe 检查
        if check_rtmp_url(url, CONFIG['check_timeout']):
            logging.debug(f"频道 '{name}' (URL: {url}) RTMP/RTP/P3P 检查成功。")
            return channel
        else:
            logging.debug(f"频道 '{name}' (URL: {url}) RTMP/RTP/P3P 检查失败。")
            return None
    elif parsed_url.scheme == 'udp':
        # UDP 流通常不需要 HTTP 请求，而是尝试连接
        try:
            host = parsed_url.hostname
            port = parsed_url.port
            if host and port:
                # 尝试连接 UDP 端口，但不发送数据
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(CONFIG['check_timeout'])
                    sock.connect((host, port))
                    logging.debug(f"频道 '{name}' (URL: {url}) UDP 连接成功。")
                    return channel
            return None
        except socket.error as e:
            logging.debug(f"频道 '{name}' (URL: {url}) UDP 连接失败: {e}")
            return None
    else:
        logging.debug(f"频道 '{name}' (URL: {url}) 使用不支持的协议 '{parsed_url.scheme}'。")
        return None

def check_channels_multithreaded(channels):
    """
    多线程检查频道列表。
    """
    valid_channels = []
    unmatched_names = set() # 存储不匹配的频道名称
    
    total_channels = len(channels)
    logging.info(f"开始多线程检查 {total_channels} 个频道。")

    with ThreadPoolExecutor(max_workers=CONFIG['channel_check_workers']) as executor:
        future_to_channel = {executor.submit(check_channel, ch): ch for ch in channels}
        
        for i, future in enumerate(as_completed(future_to_channel)):
            original_channel = future_to_channel[future]
            try:
                valid_ch = future.result()
                if valid_ch:
                    valid_channels.append(valid_ch)
                    # 检查是否匹配分类，如果不匹配则加入未匹配列表
                    matched_category = False
                    for category_item in CONFIG['categories']:
                        if re.search(category_item['pattern'], valid_ch['name'], re.IGNORECASE):
                            matched_category = True
                            break
                    if not matched_category:
                        unmatched_names.add(valid_ch['name'])
                
                # 打印进度
                if (i + 1) % 100 == 0 or (i + 1) == total_channels:
                    logging.info(f"已检查 {i + 1}/{total_channels} 个频道...")

            except Exception as exc:
                logging.error(f"频道 '{original_channel['name']}' (URL: {original_channel['url']}) 检查时发生异常: {exc}")
    
    logging.info(f"频道检查完成。发现 {len(valid_channels)} 个有效频道。")
    if unmatched_names:
        logging.warning(f"发现 {len(unmatched_names)} 个未匹配分类的有效频道名称。")
    return valid_channels, list(unmatched_names)

# --- 文件合并和写入函数 ---
def sort_channels_by_category(channels):
    """
    根据配置中的类别规则对频道进行排序。
    """
    sorted_channels_dict = {category: [] for category in ORDERED_CATEGORIES}
    other_channels = []

    for channel in channels:
        matched = False
        for category_item in CONFIG['categories']:
            # 尝试匹配分类模式
            if re.search(category_item['pattern'], channel['name'], re.IGNORECASE):
                sorted_channels_dict[category_item['name']].append(channel)
                matched = True
                break
        if not matched:
            other_channels.append(channel) # 放到“其他”类别

    # 按照配置的顺序组合
    final_m3u_lines = ["#EXTM3U"] # M3U 文件开头
    
    for category in ORDERED_CATEGORIES:
        category_channels = sorted(sorted_channels_dict[category], key=lambda x: (x['name'], x['url']))
        if category_channels:
            final_m3u_lines.append(f"\n#EXTINF:-1 group-title=\"{category}\",{category}") # 类别标题
            for ch in category_channels:
                final_m3u_lines.append(f"#EXTINF:-1 group-title=\"{category}\",{ch['name']}")
                final_m3u_lines.append(ch['url'])
    
    # 添加“其他”频道
    if other_channels:
        other_channels_sorted = sorted(other_channels, key=lambda x: (x['name'], x['url']))
        final_m3u_lines.append(f"\n#EXTINF:-1 group-title=\"其他\",其他") # 其他类别标题
        for ch in other_channels_sorted:
            final_m3u_lines.append(f"#EXTINF:-1 group-title=\"其他\",{ch['name']}")
            final_m3u_lines.append(ch['url'])

    return "\n".join(final_m3u_lines)

def write_unmatched_channels_to_file(unmatched_channels_list, unmatched_output_file_path):
    """
    将不匹配分类的频道名称写入文件，并进行去重合并。
    """
    existing_unmatched_names = set()
    try:
        if os.path.exists(unmatched_output_file_path):
            with open(unmatched_output_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    existing_unmatched_names.add(line.strip())
    except FileNotFoundError:
        pass # 文件不存在是正常情况，无需报错

    new_unmatched_names = set(unmatched_channels_list)
    
    # 合并现有和新的不匹配名称
    all_unmatched_names = existing_unmatched_names | new_unmatched_names
    
    try:
        with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
            for name in sorted(list(all_unmatched_names)):
                f.write(f"{name}\n")
        logging.warning(f"\n已将不匹配但已检测到的频道名称列表写入到：'{unmatched_output_file_path}'，总计 {len(all_unmatched_names)} 个名称。")
    except IOError as e: # 更具体的异常
        logging.error(f"写入文件 '{unmatched_output_file_path}' 发生 IO 错误：{e}")
    except Exception as e:
        logging.error(f"写入文件 '{unmatched_output_file_path}' 发生未知错误：{e}")

def merge_local_channel_files(source_dir, output_file_name):
    """
    合并本地的频道文件（包括临时文件和配置中指定的分类文件），
    进行去重和排序，并生成最终的 M3U 列表。
    """
    all_channels = {} # 使用字典进行去重：{(name, url): channel_dict}
    
    logging.info(f"正在合并本地文件 '{source_dir}' 中的频道。")
    
    # 1. 首先添加临时文件中的频道
    temp_iptv_file_path = os.path.join(source_dir, TEMP_IPTV_FILE)
    if os.path.exists(temp_iptv_file_path):
        try:
            with open(temp_iptv_file_path, "r", encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',', 1)
                        if len(parts) == 2:
                            name = parts[0].strip()
                            url = clean_url_params(parts[1].strip()) # 清理 URL
                            all_channels[(name, url)] = {"name": name, "url": url}
            logging.info(f"已从临时文件 '{TEMP_IPTV_FILE}' 中加载频道。")
        except FileNotFoundError: # 理论上上面if os.path.exists已经检查了，这里只是防御性编程
            pass 
        except Exception as e:
            logging.error(f"读取临时文件 '{TEMP_IPTV_FILE}' 发生错误: {e}")

    # 2. 然后添加配置中指定的分类文件中的频道
    for category_item in CONFIG['categories']:
        file_name = category_item.get('file')
        if file_name:
            file_path = os.path.join(source_dir, file_name)
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8") as file:
                        for line in file:
                            line = line.strip()
                            # 尝试解析 M3U 格式的频道信息
                            if line.startswith("#EXTINF:-1"):
                                # 提取名称
                                name_match = re.search(r',([^,]+)$', line)
                                if name_match:
                                    name = name_match.group(1).strip()
                                else:
                                    logging.warning(f"无法从 EXTINF 行提取频道名称：{line}")
                                    continue
                                # 下一行通常是 URL
                                try:
                                    url = next(file).strip()
                                    if url:
                                        url = clean_url_params(url)
                                        all_channels[(name, url)] = {"name": name, "url": url}
                                except StopIteration:
                                    logging.warning(f"EXTINF 行 '{line}' 后缺少 URL。")
                                    break # 提前结束，防止无限循环
                            elif line and not line.startswith('#'): # 兼容非M3U格式的 name,url
                                parts = line.split(',', 1)
                                if len(parts) == 2:
                                    name = parts[0].strip()
                                    url = clean_url_params(parts[1].strip())
                                    all_channels[(name, url)] = {"name": name, "url": url}

                    logging.info(f"已从分类文件 '{file_name}' 中加载频道。")
                except FileNotFoundError:
                    logging.warning(f"配置中的本地分类文件 '{file_name}' 未找到，跳过合并。")
                except Exception as e:
                    logging.error(f"读取本地分类文件 '{file_name}' 发生错误: {e}")
            else:
                logging.debug(f"本地分类文件 '{file_name}' 不存在，跳过。")


    final_channels_list = list(all_channels.values())
    logging.info(f"合并所有本地文件后，总计 {len(final_channels_list)} 个频道（已去重）。")
    
    # 排序频道并生成 M3U 内容
    m3u_content = sort_channels_by_category(final_channels_list)

    try:
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.write(m3u_content)
        logging.info(f"已将合并、去重和排序后的频道列表写入到：'{output_file_name}'。")
    except IOError as e:
        logging.error(f"写入文件 '{output_file_name}' 发生 IO 错误：{e}")
    except Exception as e:
        logging.error(f"写入文件 '{output_file_name}' 发生未知错误：{e}")

# --- 主函数 ---
def main():
    start_time = time.time()
    logging.info("IPTV 频道抓取和管理脚本开始运行...")

    # 步骤 1: 加载配置
    load_config()

    # 步骤 2: 获取所有待抓取的 URL
    urls_to_crawl_content, _ = get_github_file_content(URLS_PATH_IN_REPO)
    if not urls_to_crawl_content:
        logging.error(f"无法从 '{URLS_PATH_IN_REPO}' 获取 URL 列表，脚本终止。")
        exit(1)

    urls_config = []
    try:
        urls_config = json.loads(urls_to_crawl_content)
    except json.JSONDecodeError as e:
        logging.error(f"解析 URL 列表文件 '{URLS_PATH_IN_REPO}' 失败: {e}。请检查 JSON 格式。")
        exit(1)

    # 步骤 3: 从所有 URL 中提取频道
    all_extracted_channels = get_channel_urls(urls_config)
    logging.info(f"已从所有配置的 URL 中提取到 {len(all_extracted_channels)} 个频道。")

    # 步骤 4: 多线程检查频道有效性
    valid_channels, unmatched_names = check_channels_multithreaded(all_extracted_channels)

    # 步骤 5: 将所有有效频道写入临时文件 iptv.txt
    try:
        with open(TEMP_IPTV_FILE, 'w', encoding='utf-8') as f:
            for ch in valid_channels:
                f.write(f"{ch['name']},{ch['url']}\n")
        logging.info(f"所有有效频道已写入临时文件 '{TEMP_IPTV_FILE}'，共 {len(valid_channels)} 个。")
    except IOError as e:
        logging.error(f"写入临时文件 '{TEMP_IPTV_FILE}' 发生 IO 错误: {e}")
        # 这里可以选择是否终止脚本，如果临时文件写入失败，后续合并可能会有问题
        exit(1) 

    # 步骤 6: 写入不匹配的频道名称列表
    write_unmatched_channels_to_file(unmatched_names, UNMATCHED_CHANNELS_FILE)

    # 步骤 7: 合并本地的频道文件，生成最终的 iptv_list.txt
    # '.', 'iptv_list.txt' 表示在当前目录下生成 iptv_list.txt
    merge_local_channel_files('.', FINAL_IPTV_LIST_FILE) 

    # 步骤 8: 更新 URL 状态文件到 GitHub
    url_states_sha = get_current_sha(URL_STATES_PATH_IN_REPO)
    new_url_states_content = json.dumps(URL_STATES, indent=4, ensure_ascii=False)
    update_github_file(URL_STATES_PATH_IN_REPO, new_url_states_content, "更新 URL 抓取状态", url_states_sha)

    # 步骤 9: 更新 iptv_list.txt 到 GitHub
    iptv_list_sha = get_current_sha(FINAL_IPTV_LIST_FILE) # 获取本地生成的文件的 SHA
    with open(FINAL_IPTV_LIST_FILE, 'r', encoding='utf-8') as f:
        final_iptv_content = f.read()
    update_github_file(FINAL_IPTV_LIST_FILE, final_iptv_content, "更新 IPTV 频道列表", iptv_list_sha)

    # 步骤 10: 更新 unmatched_channels.txt 到 GitHub
    unmatched_file_sha = get_current_sha(UNMATCHED_CHANNELS_FILE)
    with open(UNMATCHED_CHANNELS_FILE, 'r', encoding='utf-8') as f:
        unmatched_content = f.read()
    update_github_file(UNMATCHED_CHANNELS_FILE, unmatched_content, "更新不匹配频道名称列表", unmatched_file_sha)
    
    # 步骤 11: 清理临时文件
    try:
        if os.path.exists(TEMP_IPTV_FILE):
            os.remove(TEMP_IPTV_FILE)
            logging.debug(f"已删除临时文件 '{TEMP_IPTV_FILE}'。")
        if os.path.exists(TEMP_IPTV_SPEED_FILE): # 如果有测速功能产生此文件
            os.remove(TEMP_IPTV_SPEED_FILE)
            logging.debug(f"已删除临时文件 '{TEMP_IPTV_SPEED_FILE}'。")
    except Exception as e:
        logging.error(f"清理临时文件时发生错误: {e}")

    end_time = time.time()
    duration = end_time - start_time
    logging.info(f"IPTV 频道抓取和管理脚本运行结束。总耗时：{duration:.2f} 秒。")

if __name__ == "__main__":
    main()
