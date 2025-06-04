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
import psutil
import asyncio
import aiohttp
import aiofiles

# 配置日志，仅记录 ERROR 和 WARNING 级别
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')

# 验证环境变量
for var, name in [
    (GITHUB_TOKEN, 'BOT'),
    (REPO_OWNER, 'REPO_OWNER'),
    (REPO_NAME, 'REPO_NAME'),
    (CONFIG_PATH_IN_REPO, 'CONFIG_PATH'),
    (URLS_PATH_IN_REPO, 'URLS_PATH'),
    (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH')
]:
    if not var:
        logging.error(f"错误：环境变量 '{name}' 未设置。")
        exit(1)

GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

def fetch_from_github(file_path_in_repo, headers=None):
    raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}"
    headers = headers or {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"从 GitHub 获取 {file_path_in_repo} 发生错误：{e}")
        return None

def fetch_multiple_from_github(file_paths):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    contents = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_from_github, path, headers): path for path in file_paths}
        for future in as_completed(futures):
            path = futures[future]
            contents[path] = future.result()
    return contents

def get_current_sha(file_path_in_repo):
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
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"错误：远程配置文件 '{CONFIG_PATH_IN_REPO}' 中的 YAML 无效：{e}")
            exit(1)
    logging.error(f"无法从 GitHub 的 '{CONFIG_PATH_IN_REPO}' 加载配置。")
    exit(1)

CONFIG = load_config()

# 配置参数
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 60)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 30)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 5)
CHANNEL_CHECK_TIMEOUT_HTTP = CONFIG.get('channel_check_timeout_http', 3)
CHANNEL_CHECK_WORKERS = min(psutil.cpu_count() * 20, 200)  # 动态调整并发
CHANNEL_CHECK_BATCH_SIZE = 500  # 减小批次大小
SEARCH_CACHE_TTL = 604800  # 缓存1周
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 100)
NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})
ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])
ALLOWED_PROTOCOLS = set(CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []))
STREAM_EXTENSIONS = set(CONFIG.get('url_pre_screening', {}).get('stream_extensions', []))
INVALID_URL_PATTERN = re.compile('|'.join(CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])), re.IGNORECASE)

# 配置 HTTP 会话
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"})
pool_size = CONFIG.get('requests_pool_size', 50)
retry_strategy = Retry(
    total=CONFIG.get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1.5),
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

def read_txt_to_array_local(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到。")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 发生错误：{e}")
        return []

async def write_array_to_txt_local(file_name, data_array):
    try:
        async with aiofiles.open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                await file.write(item + '\n')
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 发生错误：{e}")

def get_url_file_extension(url):
    parsed_url = urlparse(url)
    return os.path.splitext(parsed_url.path)[1].lower()

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

def clean_url_params(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

def load_url_states_local():
    local_path = 'url_states.json'
    if os.path.exists(local_path):
        try:
            with open(local_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"解码本地 '{local_path}' 中的 JSON 发生错误：{e}")
    return load_url_states_remote()

def load_url_states_remote():
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"解码远程 '{URL_STATES_PATH_IN_REPO}' 中的 JSON 发生错误：{e}")
            return {}
    return {}

def save_url_states_local(url_states):
    try:
        with open('url_states.json', 'w', encoding='utf-8') as f:
            json.dump(url_states, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存本地 URL 状态到 'url_states.json' 发生错误：{e}")

def save_url_states_remote(url_states):
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态")
        save_url_states_local(url_states)  # 同步保存到本地
    except Exception as e:
        logging.error(f"将 URL 状态保存到远程 '{URL_STATES_PATH_IN_REPO}' 发生错误：{e}")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
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
        save_url_states_local(url_states)  # 先保存本地
        save_url_states_remote(url_states)
        return content
    except requests.exceptions.RequestException as e:
        logging.error(f"获取 URL (重试后) 发生请求错误：{url} - {e}")
        return None

def extract_channels_from_url(url, url_states):
    state = url_states.get(url, {})
    if state.get('channels') and state.get('content_hash') == state.get('last_content_hash'):
        return state['channels']
    channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states)
        if text is None:
            return []
        if get_url_file_extension(url) in STREAM_EXTENSIONS:
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
                            channels.append((channel_name, channel_url))
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url:
                        channels.append((channel_name, channel_url))
        url_states[url]['channels'] = channels
        url_states[url]['last_content_hash'] = url_states[url].get('content_hash')
        save_url_states_local(url_states)
    except Exception as e:
        logging.error(f"从 {url} 提取频道时发生错误：{e}")
    return channels

def pre_screen_url(url):
    if not isinstance(url, str) or not url or len(url) < 15:
        return False
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ALLOWED_PROTOCOLS or not parsed_url.netloc:
        return False
    if not any(parsed_url.path.lower().endswith(ext) for ext in STREAM_EXTENSIONS):
        return False
    if INVALID_URL_PATTERN.search(url):
        logging.debug(f"预筛选过滤（无效模式）：{url}")
        return False
    return True

def filter_and_modify_channels(channels):
    filtered_channels = set()
    for name, url in channels:
        if not pre_screen_url(url):
            continue
        if any(word.lower() in name.lower() for word in NAME_FILTER_WORDS):
            continue
        for old_str, new_str in CHANNEL_NAME_REPLACEMENTS.items():
            name = re.sub(re.escape(old_str), new_str, name, flags=re.IGNORECASE)
        filtered_channels.add((name, url))
    return list(filtered_channels)

async def check_http_url_async(url, timeout):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.head(url, timeout=timeout, allow_redirects=True) as response:
                return 200 <= response.status < 400
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.debug(f"HTTP URL {url} 检查失败：{e}")
            return False

def check_rtmp_url(url, timeout):
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("未找到 ffprobe 或其无法工作。RTMP 流检查已跳过。")
        return False
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} 检查超时")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} 检查错误：{e}")
        return False

def check_channel_validity_and_speed(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    url_states = load_url_states_local()
    state = url_states.get(url, {})
    last_valid = state.get('last_valid')
    if last_valid and (datetime.now() - datetime.fromisoformat(last_valid)).total_seconds() < 86400:
        return state.get('elapsed_time'), True
    if not url.startswith(("http", "rtmp")):  # 仅检查 HTTP 和 RTMP
        return None, False
    start_time = time.time()
    is_valid = False
    timeout = CHANNEL_CHECK_TIMEOUT_HTTP if url.startswith("http") else CHANNEL_CHECK_TIMEOUT
    try:
        if url.startswith("http"):
            is_valid = check_http_url(url, timeout)
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            url_states[url]['last_valid'] = datetime.now().isoformat()
            url_states[url]['elapsed_time'] = elapsed_time
            save_url_states_local(url_states)
            return elapsed_time, True
        return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 时发生错误：{e}")
        return None, False

async def check_channel_validity_and_speed_async(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    if url.startswith("http"):
        start_time = time.time()
        is_valid = await check_http_url_async(url, timeout)
        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            url_states = load_url_states_local()
            url_states[url]['last_valid'] = datetime.now().isoformat()
            url_states[url]['elapsed_time'] = elapsed_time
            save_url_states_local(url_states)
            return elapsed_time, True
        return None, False
    else:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, check_channel_validity_and_speed, channel_name, url, timeout)

async def check_channels_async(channel_lines, max_concurrent=None):
    max_concurrent = max_concurrent or min(psutil.cpu_count() * 20, 200)
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    async def process_channel(line):
        async with semaphore:
            if "://" not in line:
                return None, None
            parts = line.split(',', 1)
            if len(parts) == 2:
                name, url = parts
                url = url.strip()
                elapsed_time, is_valid = await check_channel_validity_and_speed_async(name, url)
                if is_valid:
                    return elapsed_time, f"{name},{url}"
            return None, None
    tasks = [process_channel(line) for line in channel_lines]
    for future in asyncio.as_completed(tasks):
        elapsed_time, result_line = await future
        if elapsed_time is not None and result_line is not None:
            results.append((elapsed_time, result_line))
    return results

def check_channels_multithreaded(channel_lines, max_workers=None):
    if max_workers is None:
        max_workers = min(psutil.cpu_count() * 20, 200)
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"开始多线程频道有效性和速度检测，总计 {total_channels} 个频道...")
    start_time = time.time()
    for i in range(0, len(channel_lines), CHANNEL_CHECK_BATCH_SIZE):
        batch = channel_lines[i:i + CHANNEL_CHECK_BATCH_SIZE]
        logging.warning(f"处理批次 {i//CHANNEL_CHECK_BATCH_SIZE + 1}，包含 {len(batch)} 个频道...")
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            batch_results = loop.run_until_complete(check_channels_async(batch, max_concurrent=max_workers))
            results.extend(batch_results)
            checked_count += len(batch)
            elapsed = time.time() - start_time
            logging.warning(f"已检查 {checked_count}/{total_channels} 个频道，耗时 {elapsed:.2f} 秒...")
        finally:
            loop.close()
    logging.warning(f"频道检测完成，总耗时 {(time.time() - start_time):.2f} 秒。")
    return results

async def write_sorted_channels_to_file_async(file_path, data_list):
    async with aiofiles.open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            await file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        return int(match.group()) if match else float('inf')
    return sorted(channels, key=channel_key)

def generate_update_time_header():
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    grouped_channels = {}
    for line_content in lines:
        line_content = line_content.strip()
        if line_content:
            channel_name = line_content.split(',', 1)[0].strip()
            if channel_name not in grouped_channels:
                grouped_channels[channel_name] = []
            grouped_channels[channel_name].append(line_content)
    final_grouped_lines = []
    for channel_name in grouped_channels:
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            final_grouped_lines.append(ch_line + '\n')
    return final_grouped_lines

async def merge_local_channel_files_in_memory(channels_by_category, output_file_name="iptv_list.txt"):
    final_output_lines = generate_update_time_header()
    for category in ORDERED_CATEGORIES:
        if category in channels_by_category:
            final_output_lines.append(f"{category},#genre#\n")
            final_output_lines.extend(group_and_limit_channels(channels_by_category[category]))
    async with aiofiles.open(output_file_name, 'w', encoding='utf-8') as f:
        for line in final_output_lines:
            await f.write(line)
    logging.warning(f"所有区域频道列表已合并。输出保存到：{output_file_name}")

def read_txt_to_array_remote(file_path_in_repo):
    content = fetch_from_github(file_path_in_repo)
    if content:
        return [line.strip() for line in content.split('\n') if line.strip()]
    return []

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message):
    content = '\n'.join(data_array)
    if save_to_github(file_path_in_repo, content, commit_message):
        logging.warning(f"成功将数据写入远程 '{file_path_in_repo}'")
    else:
        logging.error(f"将数据写入远程 '{file_path_in_repo}' 失败。")

def check_rate_limit(response):
    remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
    if remaining < 10:
        reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
        wait_seconds = max(0, reset_time - time.time()) + 1
        logging.warning(f"接近速率限制，剩余 {remaining}，等待 {wait_seconds} 秒")
        time.sleep(wait_seconds)

def search_keyword(keyword, headers):
    found_urls = set()
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
            check_rate_limit(response)
            data = response.json()
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
                        any(cleaned_url.lower().endswith(ext) for ext in STREAM_EXTENSIONS) and
                        pre_screen_url(cleaned_url)):
                        found_urls.add(cleaned_url)
            page += 1
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            logging.error(f"关键词 '{keyword}' 搜索失败：{e}")
            break
    return keyword, found_urls

def auto_discover_github_urls(urls_file_path_remote, github_token):
    if not github_token:
        logging.warning("环境变量 'BOT' 未设置。跳过 GitHub URL 自动发现。")
        return
    url_states = load_url_states_local()
    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }
    logging.warning("正在开始从 GitHub 自动发现新的 IPTV 源 URL...")
    for keyword in SEARCH_KEYWORDS:
        keyword_state = url_states.get(f"search:{keyword}", {})
        last_searched = keyword_state.get('last_searched')
        if last_searched and (datetime.now() - datetime.fromisoformat(last_searched)).total_seconds() < SEARCH_CACHE_TTL:
            logging.warning(f"关键词 '{keyword}' 的搜索结果已缓存，跳过...")
            found_urls.update(keyword_state.get('urls', []))
            continue
        keyword, urls = search_keyword(keyword, headers)
        found_urls.update(urls)
        url_states[f"search:{keyword}"] = {
            'last_searched': datetime.now().isoformat(),
            'urls': list(urls)
        }
        save_url_states_local(url_states)
        logging.warning(f"关键词 '{keyword}' 搜索完成，发现 {len(urls)} 个 URL。")
        time.sleep(0.5)
    new_urls_count = len(found_urls - existing_urls)
    if new_urls_count > 0:
        updated_urls = list(existing_urls | found_urls)
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "通过 GitHub 发现的新 URL 更新 urls.txt")
        logging.warning(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URL。总 URL 数：{len(updated_urls)}")
    else:
        logging.warning("未发现新的 GitHub IPTV 源 URL。")
    save_url_states_remote(url_states)

def main():
    # 批量加载 GitHub 文件
    files_to_fetch = [CONFIG_PATH_IN_REPO, URLS_PATH_IN_REPO, URL_STATES_PATH_IN_REPO]
    contents = fetch_multiple_from_github(files_to_fetch)
    if not contents.get(URLS_PATH_IN_REPO):
        logging.warning(f"在远程 '{URLS_PATH_IN_REPO}' 中未找到 URL，脚本将提前退出。")
        return
    urls = [line.strip() for line in contents[URLS_PATH_IN_REPO].split('\n') if line.strip()]
    
    url_states = load_url_states_local()
    logging.warning(f"已加载 {len(url_states)} 个历史 URL 状态。")
    
    all_extracted_channels = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result_channels = future.result()
                all_extracted_channels.update(result_channels)
            except Exception as exc:
                logging.error(f"处理源 '{url}' 时发生异常：{exc}")
    
    save_url_states_remote(url_states)
    logging.warning(f"从所有源提取了 {len(all_extracted_channels)} 个原始频道。")
    
    filtered_channels = filter_and_modify_channels(all_extracted_channels)
    unique_filtered_channels_str = [f"{name},{url}" for name, url in filtered_channels]
    logging.warning(f"过滤和清理后，剩余 {len(unique_filtered_channels_str)} 个唯一频道。")
    
    valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
    logging.warning(f"有效且响应的频道数量：{len(valid_channels_with_speed)}")
    
    asyncio.run(write_sorted_channels_to_file_async('iptv_speed.txt', valid_channels_with_speed))
    
    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    os.makedirs(local_channels_directory, exist_ok=True)
    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True)
    
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]
    channels_for_matching = [line[1] for line in valid_channels_with_speed]
    channels_by_category = {}
    all_template_channel_names = set()
    
    for template_file in template_files:
        names_from_current_template = read_txt_to_array_local(os.path.join(template_directory, template_file))
        all_template_channel_names.update(names_from_current_template)
        template_name = os.path.splitext(template_file)[0]
        channels_by_category[template_name] = []
        for channel_line in channels_for_matching:
            channel_name = channel_line.split(',', 1)[0].strip()
            if channel_name in names_from_current_template:
                channels_by_category[template_name].append(channel_line)
        if "央视" in template_name or "CCTV" in template_name:
            channels_by_category[template_name] = sort_cctv_channels(channels_by_category[template_name])
            logging.warning(f"已按数字对 '{template_name}' 频道进行排序。")
    
    asyncio.run(merge_local_channel_files_in_memory(channels_by_category, 'iptv_list.txt'))
    
    try:
        with open('iptv_list.txt', 'r', encoding='utf-8') as f:
            final_iptv_content = f.read()
        save_to_github('output/iptv_list.txt', final_iptv_content, '更新最终 IPTV 列表')
        logging.warning('已将 iptv_list.txt 推送到远程仓库。')
    except Exception as e:
        logging.error(f'无法将 iptv_list.txt 推送到 GitHub：{e}')
    
    unmatched_channels_list = [line for line in channels_for_matching if line.split(',', 1)[0].strip() not in all_template_channel_names]
    asyncio.run(write_array_to_txt_local('unmatched_channels.txt', [line.split(',')[0].strip() for line in unmatched_channels_list]))
    logging.warning(f"已保存不匹配但已检测到的频道列表到：'unmatched_channels.txt'，总共 {len(unmatched_channels_list)} 个频道。")
    
    for temp_file in ['iptv.txt', 'iptv_speed.txt']:
        if os.path.exists(temp_file):
            os.remove(temp_file)

if __name__ == "__main__":
    main()
