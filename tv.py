import os
import re
import subprocess
import socket
import time
import json
import hashlib
import logging
import base64
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import yaml

# 配置日志，输出到文件和控制台
logging.basicConfig(
    level=logging.INFO,  # 使用 INFO 级别以记录运行进度
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iptv_crawler.log', encoding='utf-8'),
        logging.StreamHandler()  # 同时输出到控制台
    ]
)

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH', 'config/config.yaml')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH', 'config/urls.txt')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH', 'config/url_states.json')

# 验证环境变量
for env_var, name in [
    (GITHUB_TOKEN, 'BOT'),
    (REPO_OWNER, 'REPO_OWNER'),
    (REPO_NAME, 'REPO_NAME'),
    (CONFIG_PATH_IN_REPO, 'CONFIG_PATH'),
    (URLS_PATH_IN_REPO, 'URLS_PATH'),
    (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH')
]:
    if not env_var:
        logging.error(f"错误：环境变量 '{name}' 未设置。")
        exit(1)

# 初始化 Requests 会话
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0.4896.127"
})
retry_strategy = Retry(
    total=3,
    backoff_factor=1.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(
    pool_connections=50,
    pool_maxsize=50,
    max_retries=retry_strategy
)
session.mount("http://", adapter)
session.mount("https://", adapter)

# 加载配置
def load_config(session):
    raw_url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main/{CONFIG_PATH_IN_REPO}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = session.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return yaml.safe_load(response.text)
    except yaml.YAMLError as e:
        logging.error(f"解析 YAML 配置文件 '{CONFIG_PATH_IN_REPO}' 失败：{e}")
        exit(1)
    except requests.exceptions.RequestException as e:
        logging.error(f"获取配置文件 '{CONFIG_PATH_IN_REPO}' 失败：{e}")
        exit(1)

CONFIG = load_config(session)

# 更新会话配置
retry_strategy = Retry(
    total=CONFIG.get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1.5),
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(
    pool_connections=CONFIG.get('requests_pool_size', 50),
    pool_maxsize=CONFIG.get('requests_pool_size', 50),
    max_retries=retry_strategy
)
session.mount("http://", adapter)
session.mount("https://", adapter)

# 配置参数
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 60)
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 60)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 30)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 5)
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 100)
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
URL_FILTER_WORDS = CONFIG.get('url_filter_words', [])
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})
ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])
ENABLE_GITEE_SEARCH = CONFIG.get('enable_gitee_search', True)

# 异步 HTTP 客户端会话
async def create_aiohttp_session(timeout=CHANNEL_CHECK_TIMEOUT):
    return aiohttp.ClientSession(
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0.4896.127"},
        timeout=aiohttp.ClientTimeout(total=timeout)
    )

# 从 GitHub 获取文件内容
def fetch_from_github(file_path_in_repo, session):
    raw_url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = session.get(raw_url, headers=headers, timeout=GITHUB_API_TIMEOUT)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.warning(f"从 GitHub 获取 '{file_path_in_repo}' 失败：{e}")
        return None
    except Exception as e:
        logging.error(f"获取 '{file_path_in_repo}' 时发生未知错误：{e}")
        return None

# 获取文件的 SHA 值
def get_sha(file_path_in_repo, session):
    api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = session.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"获取 '{file_path_in_repo}' 的 SHA 失败（可能不存在）：{e}")
        return None

# 保存文件到 GitHub
def save_to_github(file_path_in_repo, content, commit_message, session):
    api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path_in_repo}"
    sha = get_sha(file_path_in_repo, session)
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
    if sha:
        payload["sha"] = sha
    try:
        response = session.put(api_url, headers=headers, json=payload)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"保存 '{file_path_in_repo}' 到 GitHub 失败：{e}")
        return False

# 动态生成年份关键词
def generate_dynamic_keywords():
    current_year = datetime.now().year
    dynamic_keywords = [
        f"iptv m3u {current_year}",
        f"iptv m3u8 {current_year}",
        f"m3u playlist {current_year}",
        f"IPTV{current_year}",
        f"直播源{current_year}"
    ]
    return SEARCH_KEYWORDS + dynamic_keywords

# 读取本地文本文件
def read_local_txt(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到。")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败：{e}")
        return []

# 写入本地文本文件
def write_local_txt(file_name, data_array):
    try:
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 失败：{e}")

# 获取 URL 文件扩展名
def get_url_extension(url):
    parsed_url = urlparse(url)
    return os.path.splitext(parsed_url.path)[1].lower()

# 转换 M3U 文件为 TXT 格式
def convert_m3u_to_txt(m3u_content):
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

# 清理 URL 参数
def clean_url_params(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

# 加载 URL 状态
def load_url_states(session):
    content = fetch_from_github(URL_STATES_PATH_IN_REPO, session)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"解析 '{URL_STATES_PATH_IN_REPO}' 的 JSON 失败：{e}")
            return {}
    return {}

# 保存 URL 状态
def save_url_states(url_states, session):
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态", session)
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH_IN_REPO}' 失败：{e}")

# 异步获取 URL 内容
@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), retry=retry_if_exception_type(aiohttp.ClientError))
async def fetch_url_content(url, url_states, session):
    headers = {}
    current_state = url_states.get(url, {})
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 304:
                return None
            response.raise_for_status()
            content = await response.text()
            content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
            if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
                return None
            url_states[url] = {
                'etag': response.headers.get('ETag'),
                'last_modified': response.headers.get('Last-Modified'),
                'content_hash': content_hash,
                'last_checked': datetime.now().isoformat()
            }
            return content
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.warning(f"获取 URL {url} 失败：{e}")
        return None

# 从 URL 提取频道
async def extract_channels(url, url_states, session):
    extracted_channels = []
    try:
        text = await fetch_url_content(url, url_states, session)
        if text is None:
            return []
        if get_url_extension(url) in [".m3u", ".m3u8"]:
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
        logging.error(f"从 {url} 提取频道失败：{e}")
    return extracted_channels

# 预筛选 URL
def pre_screen_url(url):
    if not isinstance(url, str) or not url:
        return False
    parsed_url = urlparse(url)
    if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
        return False
    if not parsed_url.netloc:
        return False
    invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    for pattern in [re.compile(p, re.IGNORECASE) for p in invalid_url_patterns]:
        if pattern.search(url):
            logging.debug(f"预筛选过滤（无效模式）：{url}")
            return False
    return len(url) >= 15

# 过滤和修改频道
def filter_channels(channels):
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
    logging.info(f"URL 预筛选后，剩余 {pre_screened_count} 个频道。")
    return filtered_channels

# 清理目录中的文本文件
def clear_txt_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
            except Exception as e:
                logging.error(f"删除文件 {file_path} 失败：{e}")

# 异步检查 HTTP URL
async def check_http_url(url, session):
    try:
        async with session.head(url, allow_redirects=True) as response:
            return 200 <= response.status < 400
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False

# 检查 RTMP URL
def check_rtmp_url(url, timeout):
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("未找到 ffprobe，跳过 RTMP 检查。")
        return False
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} 检查超时")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} 检查失败：{e}")
        return False

# 检查 RTP URL
def check_rtp_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error):
        return False

# 检查 P3P URL
def check_p3p_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or 80
        path = parsed_url.path or '/'
        if not host:
            return False
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception:
        return False

# 异步检查频道有效性和速度
async def check_channel_validity(channel_name, url, session):
    start_time = time.time()
    try:
        if url.startswith("http"):
            is_valid = await check_http_url(url, session)
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, CHANNEL_CHECK_TIMEOUT)
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, CHANNEL_CHECK_TIMEOUT)
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, CHANNEL_CHECK_TIMEOUT)
        else:
            logging.debug(f"频道 {channel_name} 的协议不支持：{url}")
            return None, False
        elapsed_time = (time.time() - start_time) * 1000
        return elapsed_time if is_valid else None, is_valid
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 失败：{e}")
        return None, False

# 多线程处理频道检查
async def check_channels(channels, max_workers=CONFIG.get('channel_check_workers', 50)):
    results = []
    total_channels = len(channels)
    logging.info(f"开始检查 {total_channels} 个频道...")
    async with await create_aiohttp_session() as session:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_channel_validity, line.split(',', 1)[0], line.split(',', 1)[1], session): line
                for line in channels if "://" in line and ',' in line
            }
            checked_count = 0
            for future in as_completed(futures):
                checked_count += 1
                if checked_count % 100 == 0:
                    logging.info(f"已检查 {checked_count}/{total_channels} 个频道...")
                try:
                    elapsed_time, is_valid = future.result()
                    if is_valid:
                        results.append((elapsed_time, futures[future]))
                except Exception as e:
                    logging.warning(f"频道检查失败：{e}")
    return sorted(results, key=lambda x: x[0])

# 写入排序后的频道
def write_sorted_channels(file_path, data_list):
    with open(file_path, 'w', encoding='utf-8') as file:
        for _, line in data_list:
            file.write(line + '\n')

# 按 CCTV 频道编号排序
def sort_cctv_channels(channels):
    def channel_key(line):
        name = line.split(',', 1)[0].strip()
        match = re.search(r'\d+', name)
        return int(match.group()) if match else float('inf')
    return sorted(channels, key=channel_key)

# 生成更新时间头
def generate_update_time_header():
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

# 分组并限制频道数量
def group_and_limit_channels(lines):
    grouped_channels = {}
    for line in lines:
        line = line.strip()
        if line:
            channel_name = line.split(',', 1)[0].strip()
            grouped_channels.setdefault(channel_name, []).append(line)
    final_lines = []
    for channel_name in grouped_channels:
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            final_lines.append(ch_line + '\n')
    return final_lines

# 合并本地频道文件
def merge_channel_files(directory, output_file="iptv_list.txt"):
    final_output_lines = generate_update_time_header()
    all_iptv_files = [f for f in os.listdir(directory) if f.endswith('_iptv.txt')]
    files_to_merge = []
    processed_files = set()
    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files and file_name not in processed_files:
            files_to_merge.append(os.path.join(directory, file_name))
            processed_files.add(file_name)
    for file_name in sorted(all_iptv_files):
        if file_name not in processed_files:
            files_to_merge.append(os.path.join(directory, file_name))
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
                logging.warning(f"文件 {file_path} 未以类别标题开头，跳过。")
    with open(output_file, "w", encoding='utf-8') as file:
        file.writelines(final_output_lines)
    logging.info(f"频道列表已合并，保存到：{output_file}")

# 读取远程文本文件
def read_remote_txt(file_path_in_repo, session):
    content = fetch_from_github(file_path_in_repo, session)
    if content:
        return [line.strip() for line in content.split('\n') if line.strip()]
    return []

# 写入远程文本文件
def write_remote_txt(file_path_in_repo, data_array, commit_message, session):
    content = '\n'.join(data_array)
    if save_to_github(file_path_in_repo, content, commit_message, session):
        logging.info(f"成功写入远程 '{file_path_in_repo}'。")
    else:
        logging.error(f"写入远程 '{file_path_in_repo}' 失败。")

# Gitee API 搜索
@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def search_gitee_urls(keyword, session):
    gitee_api = "https://gitee.com/api/v5/search/repositories"
    headers = {"Accept": "application/json"}
    params = {"q": keyword, "per_page": PER_PAGE, "page": 1}
    found_urls = set()
    try:
        async with session.get(gitee_api, headers=headers, params=params, timeout=30) as response:
            response.raise_for_status()
            data = await response.json()
            for item in data:
                repo = item.get('html_url', '')
                match = re.search(r'https?://gitee\.com/([^/]+)/([^/]+)', repo)
                if match:
                    user, repo_name = match.group(1), match.group(2)
                    raw_url = f"https://gitee.com/{user}/{repo_name}/raw/master/iptv.m3u"
                    if pre_screen_url(raw_url):
                        found_urls.add(raw_url)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.warning(f"Gitee API 请求失败（关键词：{keyword}）：{e}")
    return found_urls

# 自动发现 GitHub 和 Gitee URL
async def auto_discover_urls(urls_file_path, github_token, session):
    if not github_token:
        logging.warning("未设置 GITHUB_TOKEN，跳过 URL 发现。")
        return
    existing_urls = set(read_remote_txt(urls_file_path, session))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }
    dynamic_keywords = generate_dynamic_keywords()
    logging.info("开始从 GitHub 和 Gitee 自动发现新的 IPTV 源 URL...")
    for i, keyword in enumerate(dynamic_keywords):
        if i > 0:
            logging.info(f"切换关键词：'{keyword}'，等待 {GITHUB_API_RETRY_WAIT} 秒...")
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
                if rate_limit_remaining == 0:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制，等待 {wait_seconds:.0f} 秒...")
                    time.sleep(wait_seconds)
                    continue
                for item in data.get('items', []):
                    html_url = item.get('html_url', '')
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user, repo, branch, path = match.groups()
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
                        if raw_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and pre_screen_url(raw_url):
                            found_urls.add(clean_url_params(raw_url))
                if len(data.get('items', [])) < PER_PAGE:
                    break
                page += 1
                time.sleep(2)
            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API 请求失败（关键词：{keyword}，页：{page}）：{e}")
                if response and response.status_code == 403:
                    wait_seconds = max(0, int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制，等待 {wait_seconds:.0f} 秒...")
                    time.sleep(wait_seconds)
                    continue
                break
        if ENABLE_GITEE_SEARCH:
            async with await create_aiohttp_session(timeout=30) as aio_session:
                found_urls.update(await search_gitee_urls(keyword, aio_session))
    new_urls_count = sum(1 for url in found_urls if url not in existing_urls)
    if new_urls_count > 0:
        existing_urls.update(found_urls)
        write_remote_txt(urls_file_path, list(existing_urls), "更新 IPTV 源 URL", session)
        logging.info(f"发现并添加 {new_urls_count} 个新 URL，总计：{len(existing_urls)}")
    else:
        logging.info("未发现新 URL。")
    logging.info("URL 发现完成。")

# 主函数
async def main():
    async with await create_aiohttp_session() as aio_session:
        await auto_discover_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN, session)
        urls = read_remote_txt(URLS_PATH_IN_REPO, session)
        if not urls:
            logging.warning(f"未找到 URL，退出。")
            return
        url_states = load_url_states(session)
        logging.info(f"加载 {len(url_states)} 个 URL 状态。")
        all_channels = set()
        tasks = [extract_channels(url, url_states, aio_session) for url in urls]
        for future in asyncio.as_completed(tasks):
            try:
                all_channels.update(await future)
            except Exception as e:
                logging.error(f"提取频道失败：{e}")
        save_url_states(url_states, session)
        logging.info(f"提取 {len(all_channels)} 个原始频道。")
        filtered_channels = filter_channels(list(all_channels))
        unique_channels = list(set(f"{name},{url}" for name, url in filtered_channels))
        logging.info(f"过滤后剩余 {len(unique_channels)} 个唯一频道。")
        valid_channels = await check_channels(unique_channels)
        logging.info(f"有效频道数量：{len(valid_channels)}")
        iptv_speed_file = os.path.join(os.getcwd(), 'iptv_speed.txt')
        write_sorted_channels(iptv_speed_file, valid_channels)
        local_channels_dir = os.path.join(os.getcwd(), '地方频道')
        os.makedirs(local_channels_dir, exist_ok=True)
        clear_txt_files(local_channels_dir)
        template_dir = os.path.join(os.getcwd(), '频道模板')
        os.makedirs(template_dir, exist_ok=True)
        template_files = [f for f in os.listdir(template_dir) if f.endswith('.txt')]
        channels_for_matching = read_local_txt(iptv_speed_file)
        all_template_names = set()
        for template_file in template_files:
            all_template_names.update(read_local_txt(os.path.join(template_dir, template_file)))
        for template_file in template_files:
            template_names = set(read_local_txt(os.path.join(template_dir, template_file)))
            template_name = os.path.splitext(template_file)[0]
            matched_channels = [
                line for line in channels_for_matching
                if line.split(',', 1)[0].strip() in template_names
            ]
            if "央视" in template_name or "CCTV" in template_name:
                matched_channels = sort_cctv_channels(matched_channels)
                logging.info(f"对 '{template_name}' 频道按数字排序。")
            output_file = os.path.join(local_channels_dir, f"{template_name}_iptv.txt")
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"{template_name},#genre#\n")
                for channel in matched_channels:
                    f.write(channel + '\n')
            logging.info(f"写入 '{template_name}_iptv.txt'，包含 {len(matched_channels)} 个频道。")
        final_output_file = "iptv_list.txt"
        merge_channel_files(local_channels_dir, final_output_file)
        try:
            with open(final_output_file, "r", encoding="utf-8") as f:
                content = f.read()
            save_to_github(f"output/{final_output_file}", content, "更新 IPTV 列表", session)
            logging.info(f"已推送 {final_output_file} 到仓库。")
        except Exception as e:
            logging.error(f"推送 {final_output_file} 失败：{e}")
        unmatched_channels = [
            line for line in channels_for_matching
            if line.split(',', 1)[0].strip() not in all_template_names
        ]
        unmatched_file = os.path.join(os.getcwd(), 'unmatched_channels.txt')
        with open(unmatched_file, 'w', encoding='utf-8') as f:
            for line in unmatched_channels:
                f.write(line.split(',')[0].strip() + '\n')
        logging.info(f"保存 {len(unmatched_channels)} 个未匹配频道到 '{unmatched_file}'。")
        for temp_file in ['iptv.txt', 'iptv_speed.txt']:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError as e:
                    logging.warning(f"删除临时文件 {temp_file} 失败：{e}")

if __name__ == "__main__":
    asyncio.run(main())
