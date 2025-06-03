#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
import dns.resolver  # DNS 解析库，用于检查域名有效性
import aiohttp  # 异步 HTTP 请求库
import asyncio
from collections import defaultdict
from tqdm import tqdm  # 进度条库

# 配置日志，WARNING 级别记录关键信息，DEBUG 记录调试细节
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# DNS 缓存，避免重复解析相同域名
DNS_CACHE = defaultdict(lambda: None)

# 环境变量，从 GitHub Actions 或本地环境读取
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')

# 验证环境变量，确保必要配置存在
for var, name in [(GITHUB_TOKEN, 'BOT'), (REPO_OWNER, 'REPO_OWNER'), (REPO_NAME, 'REPO_NAME'),
                  (CONFIG_PATH_IN_REPO, 'CONFIG_PATH'), (URLS_PATH_IN_REPO, 'URLS_PATH'),
                  (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH')]:
    if not var:
        logging.error(f"错误：环境变量 '{name}' 未设置。")
        exit(1)

# GitHub 相关 URL
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"

def fetch_from_github(file_path_in_repo):
    """从 GitHub 获取文件内容"""
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"从 GitHub 获取 {file_path_in_repo} 发生错误：{e}")
        return None

def get_current_sha(file_path_in_repo):
    """获取 GitHub 文件的 SHA 值，用于更新文件"""
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"获取 {file_path_in_repo} 的 SHA 发生错误（可能不存在）：{e}")
        return None

def save_to_github(file_path_in_repo, content, commit_message):
    """将内容保存到 GitHub 仓库"""
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    sha = get_current_sha(file_path_in_repo)
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }
    import base64
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": "main"
    }
    if sha:
        payload["sha"] = sha
    try:
        response = requests.put(api_url, headers=headers, json=payload)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"将 {file_path_in_repo} 保存到 GitHub 发生错误：{e}")
        return False

def load_config():
    """加载远程 config.yaml 文件，失败时使用默认配置"""
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"错误：远程配置文件 '{CONFIG_PATH_IN_REPO}' 中的 YAML 无效：{e}")
    logging.warning(f"无法加载远程配置文件，使用默认配置")
    return {
        'search_keywords': ['iptv playlist extension:m3u,m3u8 in:file', 'iptv m3u filetype:m3u'],
        'per_page': 100,
        'max_search_pages': 5,
        'github_api_timeout': 20,
        'github_api_retry_wait': 12,
        'channel_fetch_timeout': 15,
        'channel_check_timeout': 10,
        'max_channel_urls_per_group': 200,
        'name_filter_words': ['adult', 'xxx', 'test', 'demo'],
        'url_filter_words': ['login', 'signup', '.lat', '.ml', '.tk'],
        'channel_name_replacements': {'CCTV': '央视', 'HD': '高清'},
        'ordered_categories': ['央视', '卫视', '地方'],
        'url_pre_screening': {
            'allowed_protocols': ['http', 'https', 'rtmp', 'rtp', 'p3p'],
            'invalid_url_patterns': ['.*\\.onion$', '.*\\.local$', '.*\\.lat$']
        },
        'requests_pool_size': 20,
        'requests_retry_total': 3,
        'requests_retry_backoff_factor': 1,
        'channel_check_workers': 20
    }

CONFIG = load_config()

# 配置常量，从 config.yaml 读取
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20)
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 12)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 10)
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200)
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
URL_FILTER_WORDS = CONFIG.get('url_filter_words', [])
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})
ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])
INVALID_TLDS = {'.local', '.invalid', '.test', '.example', '.lat', '.ml', '.tk'}

# 初始化 requests 会话
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
pool_size = CONFIG.get('requests_pool_size', 20)
retry_strategy = Retry(
    total=CONFIG.get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1),
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

def is_valid_domain(domain):
    """检查域名是否可解析，带缓存和重试机制"""
    if DNS_CACHE[domain] is not None:
        return DNS_CACHE[domain]
    for _ in range(2):  # 重试两次
        try:
            dns.resolver.resolve(domain, 'A')
            DNS_CACHE[domain] = True
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            DNS_CACHE[domain] = False
            return False
        except dns.resolver.Timeout:
            time.sleep(1)
    logging.debug(f"DNS 解析超时：{domain}")
    DNS_CACHE[domain] = False
    return False

def read_txt_to_array_local(file_name):
    """读取本地文本文件到数组"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 发生错误：{e}")
        return []

def write_array_to_txt_local(file_name, data_array):
    """将数组写入本地文本文件"""
    try:
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 发生错误：{e}")

def get_url_file_extension(url):
    """获取 URL 文件扩展名"""
    parsed_url = urlparse(url)
    return os.path.splitext(parsed_url.path)[1].lower()

def convert_m3u_to_txt(m3u_content):
    """将 M3U 格式转换为 TXT 格式（频道名,URL）"""
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = ""
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTM3U"):
            continue
        if line.startswith("#EXTINF"):
            match = re.search(r'#EXTINF:.*?\,(.*)', line)
            channel_name = match.group(1).strip() if match else "未知频道"
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = ""
    return '\n'.join(txt_lines)

def clean_url_params(url):
    """清理 URL 参数，保留方案、主机和路径"""
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

def load_url_states_remote():
    """加载远程 URL 状态（ETag、Last-Modified 等）"""
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"解码远程 '{URL_STATES_PATH_IN_REPO}' 的 JSON 错误：{e}")
            return {}
    return {}

def save_url_states_remote(url_states):
    """保存 URL 状态到 GitHub"""
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态")
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH_IN_REPO}' 错误：{e}")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True,
       retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
    """带重试机制获取 URL 内容"""
    parsed_url = urlparse(url)
    if not is_valid_domain(parsed_url.netloc):
        logging.debug(f"跳过无效域名：{url}")
        return None
    headers = {}
    current_state = url_states.get(url, {})
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']
    try:
        response = session.get(url, headers=headers, timeout=CHANNEL_FETCH_TIMEOUT)
        response.raise_for_status()
        if response.status_code == 304:
            return None
        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            return None
        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }
        save_url_states_remote(url_states)
        return content
    except requests.exceptions.RequestException as e:
        logging.error(f"获取 URL {url} 错误：{e}")
        return None

def extract_channels_from_url(url, url_states):
    """从 URL 提取频道信息"""
    extracted_channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states)
        if text is None:
            return []
        if get_url_file_extension(url) in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if "#genre#" not in line and "," in line and "://" in line:
                parts = line.split(',', 1)
                channel_name = parts[0].strip()
                channel_address_raw = parts[1].strip()
                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url:
                            extracted_channels.append((channel_name, channel_url))
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url:
                        extracted_channels.append((channel_name, channel_url))
    except Exception as e:
        logging.error(f"从 {url} 提取频道错误：{e}")
    return extracted_channels

def pre_screen_url(url):
    """预筛选 URL，过滤无效或不合规的链接"""
    if not isinstance(url, str) or not url:
        return False
    parsed_url = urlparse(url)
    if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
        return False
    if not parsed_url.netloc:
        return False
    for tld in INVALID_TLDS:
        if parsed_url.netloc.lower().endswith(tld):
            logging.debug(f"预筛选过滤（无效 TLD）：{url}")
            return False
    if not is_valid_domain(parsed_url.netloc):
        logging.debug(f"预筛选过滤（域名不可解析）：{url}")
        return False
    invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
    for pattern in compiled_patterns:
        if pattern.search(url):
            logging.debug(f"预筛选过滤（无效模式）：{url}")
            return False
    if len(url) < 15:
        return False
    return True

def filter_and_modify_channels(channels):
    """过滤和修改频道信息"""
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        if not pre_screen_url(url):
            continue
        pre_screened_count += 1
        if any(word in url for word in URL_FILTER_WORDS):
            continue
        if any(word.lower() in name.lower() for word in NAME_FILTER_WORDS):
            continue
        for old_str, new_str in CHANNEL_NAME_REPLACEMENTS.items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    logging.warning(f"URL 预筛选后，剩余 {pre_screened_count} 个频道待进一步过滤")
    return filtered_channels

def clear_directory_txt_files(directory):
    """清空目录中的 TXT 文件"""
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
            except Exception as e:
                logging.error(f"删除文件 {file_path} 错误：{e}")

async def check_http_url_async(url, timeout=CHANNEL_CHECK_TIMEOUT):
    """异步检查 HTTP/HTTPS URL，验证是否为有效 IPTV 流"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout, allow_redirects=True) as response:
                if 200 <= response.status < 400:
                    content = await response.text(encoding='utf-8', errors='ignore')
                    if '#EXTM3U' in content[:1024]:
                        return True, "有效 M3U 流"
                    return False, "非 M3U 流"
                return False, f"HTTP {response.status}"
    except aiohttp.ClientError as e:
        return False, f"客户端错误：{str(e)}"
    except asyncio.TimeoutError:
        return False, "超时"
    except Exception as e:
        return False, f"错误：{str(e)}"

def check_rtmp_url(url, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查 RTMP URL，使用 ffprobe"""
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
        cmd = ['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url, '-show_streams', '-print_format', 'json']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        if result.returncode == 0:
            try:
                streams = json.loads(result.stdout).get('streams', [])
                return len(streams) > 0, "有效 RTMP 流"
            except json.JSONDecodeError:
                return False, "无效 ffprobe 输出"
        return False, f"ffprobe 失败：{result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "超时"
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return False, f"ffprobe 错误：{str(e)}"
    except Exception as e:
        return False, f"错误：{str(e)}"

def check_rtp_url(url, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查 RTP URL"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            return False, "无效主机/端口"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True, "有效 RTP 连接"
    except (socket.timeout, socket.error) as e:
        return False, f"套接字错误：{str(e)}"
    except Exception as e:
        return False, f"错误：{str(e)}"

def check_p3p_url(url, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查 P3P URL，降级为 HTTP 检查"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'
        if not host:
            return False, "无效主机"
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return ("P3P" in response or response.startswith("HTTP/1.")), "有效 P3P/HTTP 响应"
    except Exception as e:
        return False, f"错误：{str(e)}"

def check_channel_validity_and_speed(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    """检查频道连通性和速度"""
    start_time = time.time()
    parsed_url = urlparse(url)
    if not is_valid_domain(parsed_url.netloc):
        logging.debug(f"跳过无效域名：{url}")
        return None, False, f"DNS 解析失败：{parsed_url.netloc}"
    try:
        if url.startswith("http"):
            loop = asyncio.get_event_loop()
            is_valid, reason = loop.run_until_complete(check_http_url_async(url, timeout))
        elif url.startswith("rtmp"):
            is_valid, reason = check_rtmp_url(url, timeout)
        elif url.startswith("rtp"):
            is_valid, reason = check_rtp_url(url, timeout)
        elif url.startswith("p3p"):
            is_valid, reason = check_p3p_url(url, timeout)
        else:
            logging.debug(f"频道 {channel_name} 的协议不受支持：{url}")
            return None, False, f"不支持的协议：{urlparse(url).scheme}"
        elapsed_time = (time.time() - start_time) * 1000
        return elapsed_time if is_valid else None, is_valid, reason
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 错误：{e}")
        return None, False, f"常规错误：{str(e)}"

async def process_single_channel_line_async(channel_line, timeout=CHANNEL_CHECK_TIMEOUT):
    """异步处理单条频道行"""
    if "://" not in channel_line:
        return None, None, "无效 URL 格式"
    parts = channel_line.split(',', 1)
    if len(parts) != 2:
        return None, None, "无效频道格式"
    name, url = parts
    url = url.strip()
    elapsed_time, is_valid, reason = check_channel_validity_and_speed(name, url, timeout)
    return elapsed_time, f"{name},{url}" if is_valid else None, reason

async def check_channels_async(channel_lines, timeout=CHANNEL_CHECK_TIMEOUT):
    """异步检查所有频道"""
    results = []
    failure_reasons = defaultdict(int)
    total_channels = len(channel_lines)
    logging.warning(f"开始异步频道有效性和速度检测，总计 {total_channels} 个频道...")
    async with aiohttp.ClientSession() as session:
        tasks = [process_single_channel_line_async(line, timeout) for line in channel_lines]
        for future in tqdm(asyncio.as_completed(tasks), total=total_channels, desc="检查频道"):
            elapsed_time, result_line, reason = await future
            if elapsed_time is not None and result_line is not None:
                results.append((elapsed_time, result_line))
            failure_reasons[reason] += 1
    logging.warning("频道检测完成，失败原因统计：")
    for reason, count in failure_reasons.items():
        logging.warning(f"{reason}: {count} 频道")
    logging.warning(f"有效频道数量：{len(results)}")
    return results

def check_channels_multithreaded(channel_lines, max_workers=CONFIG.get('channel_check_workers', 20)):
    """多线程协调异步检查"""
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    results = loop.run_until_complete(check_channels_async(channel_lines))
    return results

def write_sorted_channels_to_file(file_path, data_list):
    """将排序后的频道写入文件"""
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in sorted(data_list, key=lambda x: x[0]):  # 按响应时间排序
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    """对 CCTV 频道按数字排序"""
    def channel_key(channel_line):
        channel_name = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name)
        return int(match.group()) if match else float('inf')
    return sorted(channels, key=channel_key)

def generate_update_time_header():
    """生成更新时间头部"""
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    """分组并限制每个频道组的 URL 数量"""
    grouped_channels = {}
    for line in lines:
        line = line.strip()
        if line:
            channel_name = line.split(',', 1)[0].strip()
            if channel_name not in grouped_channels:
                grouped_channels[channel_name] = []
            grouped_channels[channel_name].append(line)
    final_lines = []
    for channel_name in grouped_channels:
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            final_lines.append(ch_line + '\n')
    return final_lines

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt"):
    """合并本地频道文件"""
    final_output_lines = generate_update_time_header()
    all_iptv_files = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    files_to_merge = []
    processed_files = set()
    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files and file_name not in processed_files:
            files_to_merge.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)
    for file_name in sorted(all_iptv_files):
        if file_name not in processed_files:
            files_to_merge.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)
    for file_path in files_to_merge:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                continue
            header = lines[0].strip()
            if '#genre#' in header:
                final_output_lines.append(header + '\n')
                final_output_lines.extend(group_and_limit_channels(lines[1:]))
            else:
                logging.warning(f"文件 {file_path} 未以类别标题开头，跳过")
    with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
        iptv_list_file.writelines(final_output_lines)
    logging.warning(f"所有频道文件已合并，输出保存至：{output_file_name}")

def read_txt_to_array_remote(file_path_in_repo):
    """读取远程文本文件到数组"""
    content = fetch_from_github(file_path_in_repo)
    if content:
        return [line.strip() for line in content.split('\n') if line.strip()]
    return []

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message):
    """将数组写入远程文本文件"""
    content = '\n'.join(data_array)
    if save_to_github(file_path_in_repo, content, commit_message):
        logging.warning(f"数据成功写入远程 '{file_path_in_repo}'")
    else:
        logging.error(f"写入远程 '{file_path_in_repo}' 失败")

def auto_discover_github_urls(urls_file_path_remote, github_token):
    """从 GitHub 自动发现 IPTV 源 URL"""
    if not github_token:
        logging.warning("环境变量 'BOT' 未设置，跳过 GitHub URL 发现")
        return
    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }
    logging.warning("开始从 GitHub 自动发现新的 IPTV 源 URL...")
    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if i > 0:
            logging.warning(f"切换到关键词：'{keyword}'，等待 {GITHUB_API_RETRY_WAIT} 秒...")
            time.sleep(GITHUB_API_RETRY_WAIT)
        page = 1
        while page <= MAX_SEARCH_PAGES:
            params = {
                "q": keyword,
                "sort": "indexed",
                "order": "desc",
                "per_page": PER_PAGE,
                "page": page
            }
            try:
                response = session.get(
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                    headers=headers,
                    params=params,
                    timeout=GITHUB_API_TIMEOUT
                )
                response.raise_for_status()
                data = response.json()
                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
                if rate_limit_remaining < 5:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API 接近速率限制（剩余：{rate_limit_remaining}），等待 {wait_seconds:.0f} 秒...")
                    time.sleep(wait_seconds)
                if not data.get('items'):
                    break
                for item in data['items']:
                    html_url = item.get('html_url', '')
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user, repo, branch, path = match.groups()
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
                        cleaned_url = clean_url_params(raw_url)
                        if (cleaned_url.startswith("https://raw.githubusercontent.com/") and
                            cleaned_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and
                            pre_screen_url(cleaned_url)):
                            found_urls.add(cleaned_url)
                logging.warning(f"关键词 '{keyword}' 第 {page} 页发现 {len(data['items'])} 个结果")
                page += 1
                time.sleep(1)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    wait_seconds = max(0, int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制，等待 {wait_seconds:.0f} 秒...")
                    time.sleep(wait_seconds)
                    continue
                else:
                    logging.error(f"GitHub API 请求失败（关键词：{keyword}，页：{page}）：{e}")
                    break
    new_urls_count = len(found_urls - existing_urls)
    if new_urls_count > 0:
        updated_urls = list(existing_urls | found_urls)
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "通过 GitHub 发现新 URL")
        logging.warning(f"发现并添加 {new_urls_count} 个新 IPTV 源 URL，总计：{len(updated_urls)}")
    logging.warning("GitHub URL 自动发现完成")

def main():
    """主函数，协调所有操作"""
    try:
        auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)
        urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
        if not urls:
            logging.warning(f"远程 '{URLS_PATH_IN_REPO}' 未找到 URL，脚本退出")
            return
        url_states = load_url_states_remote()
        logging.warning(f"加载 {len(url_states)} 个历史 URL 状态")
        all_extracted_channels = set()
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls}
            for future in as_completed(future_to_url):
                try:
                    result_channels = future.result()
                    all_extracted_channels.update(result_channels)
                except Exception as e:
                    logging.error(f"处理源 '{future_to_url[future]}' 错误：{e}")
        save_url_states_remote(url_states)
        logging.warning(f"从所有源提取 {len(all_extracted_channels)} 个原始频道")
        filtered_channels = filter_and_modify_channels(list(all_extracted_channels))
        unique_filtered_channels = list(set(filtered_channels))
        unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]
        logging.warning(f"过滤后剩余 {len(unique_filtered_channels_str)} 个唯一频道")
        valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
        logging.warning(f"有效频道数量：{len(valid_channels_with_speed)}")
        iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
        write_sorted_channels_to_file(iptv_speed_file_path, valid_channels_with_speed)
        local_channels_directory = os.path.join(os.getcwd(), '地方频道')
        os.makedirs(local_channels_directory, exist_ok=True)
        clear_directory_txt_files(local_channels_directory)
        template_directory = os.path.join(os.getcwd(), '频道模板')
        os.makedirs(template_directory, exist_ok=True)
        template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]
        channels_for_matching = read_txt_to_array_local(iptv_speed_file_path)
        all_template_channel_names = set()
        for template_file in template_files:
            names = read_txt_to_array_local(os.path.join(template_directory, template_file))
            all_template_channel_names.update(names)
        for template_file in template_files:
            template_channels_names = set(read_txt_to_array_local(os.path.join(template_directory, template_file)))
            template_name = os.path.splitext(template_file)[0]
            matched_channels = [
                channel_line for channel_line in channels_for_matching
                if channel_line.split(',', 1)[0].strip() in template_channels_names
            ]
            if "央视" in template_name or "CCTV" in template_name:
                matched_channels = sort_cctv_channels(matched_channels)
                logging.warning(f"已对 '{template_name}' 频道按数字排序")
            output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(f"{template_name},#genre#\n")
                for channel in matched_channels:
                    f.write(channel + '\n')
            logging.warning(f"频道列表写入：'{template_name}_iptv.txt'，包含 {len(matched_channels)} 个频道")
        final_iptv_list_output_file = "iptv_list.txt"
        merge_local_channel_files(local_channels_directory, final_iptv_list_output_file)
        try:
            with open(final_iptv_list_output_file, "r", encoding="utf-8") as f:
                final_iptv_content = f.read()
            save_to_github(f"output/{final_iptv_list_output_file}", final_iptv_content, "更新最终 IPTV 列表")
            logging.warning(f"已推送 {final_iptv_list_output_file} 到远程仓库")
        except Exception as e:
            logging.error(f"推送 {final_iptv_list_output_file} 到 GitHub 错误：{e}")
        unmatched_channels = [
            channel_line for channel_line in channels_for_matching
            if channel_line.split(',', 1)[0].strip() not in all_template_channel_names
        ]
        unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
        with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
            for channel_line in unmatched_channels:
                f.write(channel_line.split(',')[0].strip() + '\n')
        logging.warning(f"保存未匹配频道到：'{unmatched_output_file_path}'，共 {len(unmatched_channels)} 个")
        for temp_file in ['iptv.txt', 'iptv_speed.txt']:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError as e:
                    logging.warning(f"删除临时文件 {temp_file} 错误：{e}")
    except Exception as e:
        logging.error(f"主程序错误：{e}")
        raise

if __name__ == "__main__":
    main()
