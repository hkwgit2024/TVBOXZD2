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
import shutil

# 设置日志
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
log_file = os.path.join(os.getcwd(), 'iptv_crawler.log')
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(file_handler)

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')
KEYWORD_STATS_PATH_IN_REPO = os.getenv('KEYWORD_STATS_PATH', 'config/keyword_stats.json')

# 环境变量检查
if not GITHUB_TOKEN:
    logging.error("错误：环境变量 'BOT' 未设置。")
    exit(1)
if not REPO_OWNER:
    logging.error("错误：环境变量 'REPO_OWNER' 未设置。")
    exit(1)
if not REPO_NAME:
    logging.error("错误：环境变量 'REPO_NAME' 未设置。")
    exit(1)
if not CONFIG_PATH_IN_REPO:
    logging.error("错误：环境变量 'CONFIG_PATH' 未设置。")
    exit(1)
if not URLS_PATH_IN_REPO:
    logging.error("错误：环境变量 'URLS_PATH' 未设置。")
    exit(1)
if not URL_STATES_PATH_IN_REPO:
    logging.error("错误：环境变量 'URL_STATES_PATH' 未设置。")
    exit(1)

GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"

def fetch_from_github(file_path_in_repo):
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
        except Exception as e:
            logging.error(f"加载远程配置文件 '{CONFIG_PATH_IN_REPO}' 发生错误：{e}")
            exit(1)
    logging.error(f"无法从 GitHub 的 '{CONFIG_PATH_IN_REPO}' 加载配置。")
    exit(1)

CONFIG = load_config()

GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 3)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20)
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 30)
SEARCH_CACHE_TTL = CONFIG.get('search_cache_ttl', 3600)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 6)
CHANNEL_STABILITY_TEST_DURATION = CONFIG.get('channel_stability_test_duration', 10)

MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200)

NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
URL_FILTER_WORDS = CONFIG.get('url_filter_words', [])

CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})

ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"})

pool_size = CONFIG.get('requests_pool_size', 200)
retry_strategy = Retry(
    total=CONFIG.get('requests_retry_total', 3),
    backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1),
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

def load_search_cache():
    content = fetch_from_github(KEYWORD_STATS_PATH_IN_REPO)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"解码远程 '{KEYWORD_STATS_PATH_IN_REPO}' 中的 JSON 发生错误：{e}")
            return {}
    return {}

def save_search_cache(cache):
    try:
        content = json.dumps(cache, indent=4, ensure_ascii=False)
        success = save_to_github(KEYWORD_STATS_PATH_IN_REPO, content, "更新关键词搜索缓存")
        if not success:
            logging.error(f"将关键词统计保存到 '{KEYWORD_STATS_PATH}' 失败。")
            return
        logging.warning(f"成功保存关键词统计到 '{KEYWORD_STATS_PATH}'")
    except Exception as e:
        logging.error(f"将关键词统计保存到远程 '{KEYWORD_STATS_PATH}' 发生错误：{e}")

def read_txt_to_array_local(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines if line.strip()]
            return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到。")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 错误：{e}")
        return []

def get_url_file_extension(url):
    parsed_url = urlparse(url)
    extension = os.path.splitext(parsed_url.path)[1].lower()
    return extension

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
            if match:
                channel_name = match.group(1).strip()
            else:
                channel_name = "未知频道"
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = ""
    return '\n'.join(txt_lines)

def clean_url_params(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

def load_url_states_remote():
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"解码远程 '{URL_STATES_PATH_IN_REPO}' 中的 JSON 发生错误：{e}")
            return {}
    return {}

def save_url_states_remote(url_states):
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        success = save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态")
        if not success:
            logging.error(f"将远程 URL 状态保存到 '{URL_STATES_PATH_IN_REPO}' 发生错误。")
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
        save_url_states_remote(url_states)

        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"获取 URL (重试后) 发生请求错误：{url} - {e}")
        return None
    except Exception as e:
        logging.error(f"获取 URL 发生未知错误：{url} - {e}")
        return None

def extract_channels_from_url(url, url_states):
    extracted_channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states)
        if text is None:
            return []

        if get_url_file_extension(url) in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)

        lines = text.split('\n')
        channel_count = 0
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
                            channel_count += 1
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url:
                        extracted_channels.append((channel_name, channel_url))
                        channel_count += 1
    except Exception as e:
        logging.error(f"从 {url} 提取频道时发生错误：{e}")
    return extracted_channels

def pre_screen_url(url):
    if not isinstance(url, str) or not url:
        return False

    parsed_url = urlparse(url)

    if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
        return False

    if not parsed_url.netloc:
        return False

    invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
    for pattern in compiled_invalid_url_patterns:
        if pattern.search(url):
            logging.debug(f"预筛选过滤（无效模式）：{url}")
            return False

    if len(url) < 15:
        return False

    return True

def filter_and_modify_channels(channels):
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        if not pre_screen_url(url):
            continue
        pre_screened_count += 1

        if any(word in url for word in CONFIG.get('url_filter_words', [])):
            continue

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            continue

        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    return filtered_channels

def check_http_url(url, timeout):
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
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
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} 检查超时")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} 检查错误：{e}")
        return False

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
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL {url} 检查失败：{e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} 检查错误：{e}")
        return False

def check_p3p_url(url, timeout):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'

        if not host:
            return False

        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} 检查失败：{e}")
        return False

def check_stream_quality(url, timeout=10):
    try:
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-show_streams', '-show_format', '-print_format', 'json', url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        if result.returncode != 0:
            logging.debug(f"ffprobe 检查 {url} 失败：{result.stderr.decode()}")
            return None, None, None

        data = json.loads(result.stdout)
        video_stream = None
        for stream in data.get('streams', []):
            if stream.get('codec_type') == 'video':
                video_stream = stream
                break

        if not video_stream:
            return None, None, None

        resolution = f"{video_stream.get('width', 0)}x{video_stream.get('height', 0)}"
        bitrate = data.get('format', {}).get('bit_rate', '0')
        bitrate = int(bitrate) // 1000 if bitrate else 0
        frame_rate = video_stream.get('avg_frame_rate', '0/1')
        frame_rate = eval(frame_rate) if '/' in frame_rate else float(frame_rate)

        return resolution, bitrate, frame_rate
    except Exception as e:
        logging.debug(f"ffprobe 检查 {url} 时发生错误：{e}")
        return None, None, None

def check_stream_stability(url, duration=10):
    try:
        start_time = time.time()
        process = subprocess.Popen(
            ['ffmpeg', '-i', url, '-f', 'null', '-'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(duration)
        process.terminate()
        process.wait(timeout=5)
        return process.returncode == 0
    except Exception as e:
        logging.debug(f"稳定性测试 {url} 失败：{e}")
        return False

def check_channel_validity_and_speed(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    start_time = time.time()
    is_valid = False
    resolution = bitrate = frame_rate = None
    is_stable = False

    try:
        if url.startswith("udp"):
            logging.debug(f"跳过不受支持的 UDP 协议：{url}")
            return None, False, None, None, None, False
        elif url.startswith("http"):
            is_valid = check_http_url(url, timeout)
            if is_valid:
                resolution, bitrate, frame_rate = check_stream_quality(url, timeout)
                is_stable = check_stream_stability(url, CHANNEL_STABILITY_TEST_DURATION)
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, timeout)
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
            if is_valid:
                resolution, bitrate, frame_rate = check_stream_quality(url, timeout)
                is_stable = check_stream_stability(url, CHANNEL_STABILITY_TEST_DURATION)
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, timeout)
        else:
            logging.debug(f"频道 {channel_name} 的协议不受支持：{url}")
            return None, False, None, None, None, False

        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            return elapsed_time, True, resolution, bitrate, frame_rate, is_stable
        return None, False, None, None, None, False
    except (requests.exceptions.RequestException, socket.gaierror) as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 网络错误：{e}")
        return None, False, None, None, None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 未知错误：{e}")
        return None, False, None, None, None, False

def process_single_channel_line(channel_line):
    try:
        if "://" not in channel_line:
            return None, None, None, None, None, None
        parts = channel_line.split(',', 1)
        if len(parts) != 2:
            logging.debug(f"无效的频道行格式：{channel_line}")
            return None, None, None, None, None, None
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid, resolution, bitrate, frame_rate, is_stable = check_channel_validity_and_speed(name, url)
        if is_valid:
            return elapsed_time, f"{name},{url},{elapsed_time:.0f},{resolution or '未知'},{bitrate or 0},{frame_rate or 0},{is_stable}", resolution, bitrate, frame_rate, is_stable
        return None, None, None, None, None, None
    except Exception as e:
        logging.debug(f"处理频道行 {channel_line} 失败：{e}")
        return None, None, None, None, None, None

def check_channels_multithreaded(channel_lines, max_workers=CONFIG.get('channel_check_workers', 50)):
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"开始多线程频道有效性和效果检测，总计 {total_channels} 个频道...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line): line for line in channel_lines}
        for future in as_completed(futures):
            checked_count += 1
            if checked_count % 100 == 0:
                logging.warning(f"已检查 {checked_count}/{total_channels} 个频道...")
            try:
                result = future.result()
                if len(result) != 6:
                    logging.debug(f"频道行 {futures[future]} 返回值无效：{result}")
                    continue
                elapsed_time, result_line, resolution, bitrate, frame_rate, is_stable = result
                if elapsed_time is not None and result_line is not None:
                    if resolution and 'x' in resolution:
                        width, height = map(int, resolution.split('x'))
                        if height >= 720 and is_stable:
                            results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.debug(f"频道行 {futures[future]} 处理异常：{exc}")
    logging.warning(f"完成频道检测，共找到 {len(results)} 个有效高质量频道")
    return results

def match_channel_to_category(channel_name):
    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True)
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]
    
    for template_file in template_files:
        template_channels = read_txt_to_array_local(os.path.join(template_directory, template_file))
        if channel_name in template_channels:
            template_name = os.path.splitext(template_file)[0]
            return template_name
    return "其他频道"

def write_sorted_channels_to_file(file_path, data_list):
    grouped_channels = {cat: [] for cat in ORDERED_CATEGORIES}
    grouped_channels["其他频道"] = []

    for elapsed_time, result_line in data_list:
        channel_name = result_line.split(',')[0].strip()
        category = match_channel_to_category(channel_name)
        grouped_channels[category].append((elapsed_time, result_line))

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write("频道名称,URL,响应时间(ms),分辨率,码率(kbps),帧率(fps),稳定性\n")
        for category in ORDERED_CATEGORIES + ["其他频道"]:
            channels = grouped_channels.get(category, [])
            if channels:
                file.write(f"{category},#genre#\n")
                for elapsed_time, result_line in sorted(channels, key=lambda x: x[0]):
                    file.write(result_line + '\n')

    m3u_path = file_path.replace('.txt', '.m3u')
    with open(m3u_path, 'w', encoding='utf-8') as file:
        file.write('#EXTM3U\n')
        for category in ORDERED_CATEGORIES + ["其他频道"]:
            channels = grouped_channels.get(category, [])
            if channels:
                file.write(f'#EXTINF:-1 tvg-name="{category}",{category}\n#EXTGRP:{category}\nhttp://example.com/placeholder.m3u8\n')
                for elapsed_time, result_line in sorted(channels, key=lambda x: x[0]):
                    name, url, *_ = result_line.split(',')
                    file.write(f'#EXTINF:-1 tvg-name="{name}",{name}\n#EXTGRP:{category}\n{url}\n')

def read_txt_to_array_remote(file_path_in_repo):
    content = fetch_from_github(file_path_in_repo)
    if content:
        lines = content.split('\n')
        return [line.strip() for line in lines if line.strip()]
    return []

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message):
    content = '\n'.join(data_array)
    success = save_to_github(file_path_in_repo, content, commit_message)
    if not success:
        logging.error(f"将数据写入远程 '{file_path_in_repo}' 失败。")

def extract_unavailable_domains_from_log(log_file_path):
    unavailable_domains = set()
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
        # 匹配错误日志中的 URL
        error_patterns = [
            r"检查频道 .*?\((.*?)\) 网络错误：(NameResolutionError|ConnectionResetError|Timeout|RequestException)",
            r"获取 URL .*? 发生请求错误：(.*?)\s+-",
        ]
        for pattern in error_patterns:
            matches = re.finditer(pattern, log_content)
            for match in matches:
                url = match.group(1).strip()
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()
                if domain and domain not in unavailable_domains:
                    # 排除有效域名
                    valid_domains = {'github.com', 'raw.githubusercontent.com'}
                    if domain not in valid_domains:
                        unavailable_domains.add(domain)
        logging.warning(f"从日志中提取到 {len(unavailable_domains)} 个不可用域名")
        return list(unavailable_domains)[:50]  # 限制最大 50 个
    except Exception as e:
        logging.error(f"解析日志提取不可用域名失败：{e}")
        return []

def update_config_with_unavailable_domains(unavailable_domains):
    if not unavailable_domains:
        logging.warning("没有新的不可用域名需要添加到 url_filter_words")
        return
    try:
        config_content = fetch_from_github(CONFIG_PATH_IN_REPO)
        if not config_content:
            logging.error(f"无法获取远程配置文件 {CONFIG_PATH_IN_REPO}")
            return
        config = yaml.safe_load(config_content)
        current_filters = set(config.get('url_filter_words', []))
        new_filters = current_filters.union(unavailable_domains)
        if len(new_filters) == len(current_filters):
            logging.warning("所有不可用域名已存在于 url_filter_words，无需更新")
            return
        config['url_filter_words'] = list(new_filters)
        updated_yaml = yaml.safe_dump(config, allow_unicode=True)
        success = save_to_github(CONFIG_PATH_IN_REPO, updated_yaml, f"自动添加 {len(new_filters) - len(current_filters)} 个不可用域名到 url_filter_words")
        if success:
            logging.warning(f"成功添加 {len(new_filters) - len(current_filters)} 个不可用域名到 {CONFIG_PATH_IN_REPO}")
        else:
            logging.error(f"更新 {CONFIG_PATH_IN_REPO} 失败")
    except Exception as e:
        logging.error(f"更新配置文件添加不可用域名失败：{e}")

def auto_discover_github_urls(urls_file_path_remote, github_token):
    if not github_token:
        logging.warning("环境变量 'BOT' 未设置。跳过 GitHub URL 自动发现。")
        return

    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    search_cache = load_search_cache()
    logging.warning("正在开始从 GitHub 自动发现新的 IPTV 源 URL...")

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if keyword in search_cache and search_cache[keyword].get('timestamp', 0) > time.time() - SEARCH_CACHE_TTL:
            logging.warning(f"关键词 '{keyword}' 的搜索结果缓存有效，复用缓存中的 {len(search_cache[keyword]['urls'])} 个 URL。")
            found_urls.update(search_cache[keyword]['urls'])
            continue

        if i > 0:
            logging.warning(f"切换到下一个关键词：'{keyword}'。等待 {GITHUB_API_RETRY_WAIT} 秒以避免速率限制...")
            time.sleep(GITHUB_API_RETRY_WAIT)

        keyword_urls = set()
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

                if rate_limit_remaining <= CONFIG.get('rate_limit_threshold', 5):
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制接近！剩余请求：{rate_limit_remaining}。等待 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    raw_url = None

                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user = match.group(1)
                        repo = match.group(2)
                        branch = match.group(3)
                        path = match.group(4)
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"

                    if raw_url:
                        cleaned_url = clean_url_params(raw_url)
                        if cleaned_url.startswith("https://raw.githubusercontent.com/") and \
                           cleaned_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and \
                           pre_screen_url(cleaned_url):
                            keyword_urls.add(cleaned_url)
                            logging.debug(f"已发现原始 GitHub URL（通过预筛选）：{cleaned_url}")
                        else:
                            logging.debug(f"正在跳过非原始 GitHub M3U/M3U8/TEXT 链接或未通过预筛选：{raw_url}")
                    else:
                        logging.debug(f"无法从 HTML URL 构造原始 URL：{html_url}")

                if len(data['items']) < PER_PAGE:
                    break

                page += 1
                time.sleep(2)

            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API 请求失败（关键词：{keyword}，页码：{page}）：{e}")
                if 'response' in locals() and response.status_code == 403:
                    rate_limit_reset_time = response.headers.get('X-RateLimit-Reset', 0)
                    wait_seconds = max(0, rate_limit_reset_time - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制已达到！等待时间 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue
                else:
                    break
            except Exception as e:
                logging.error(f"GitHub URL 自动发现期间发生未知错误：{e}")
                break

        search_cache[keyword] = {
            'urls': list(keyword_urls),
            'timestamp': time.time()
        }
        found_urls.update(keyword_urls)

    save_search_cache(search_cache)

    new_urls_count = 0
    for url in found_urls:
        if url not in existing_urls:
            existing_urls.add(url)
            new_urls_count += 1

    if new_urls_count > 0:
        updated_urls = list(existing_urls)
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "通过 GitHub 更新发现的新 URL 更新 urls.txt")
        logging.warning(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URLs 到 {urls_file_path_remote}。总 URL 数：{len(updated_urls)}")
    else:
        logging.warning("未发现新的 GitHub IPTV 源 URL。")

    logging.warning("GitHub URL 自动发现完成。")

def main():
    try:
        auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)

        urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
        if not urls:
            logging.warning(f"在远程 '{URLS_PATH_IN_REPO}' 中未找到 URL，脚本将提前退出。")
            return

        url_states = load_url_states_remote()
        logging.warning(f"已加载到 {len(url_states)} 个历史 URL 状态。")

        all_extracted_channels = set()
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result_channels = future.result()
                    for name, addr in result_channels:
                        all_extracted_channels.add((name, addr))
                except Exception as exc:
                    logging.error(f"处理源 '{url}' 时发生异常：{exc}")

        save_url_states_remote(url_states)

        logging.warning(f"\n从所有源提取了 {len(all_extracted_channels)} 个原始频道。")

        filtered_channels = filter_and_modify_channels(list(all_extracted_channels))
        unique_filtered_channels = list(set(filtered_channels))
        unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]

        logging.warning(f"\n过滤和清理后，剩余 {len(unique_filtered_channels_str)} 个唯一频道。")

        valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
        logging.warning(f"有效且高质量的频道数量：{len(valid_channels_with_speed)}")

        iptv_results_file_path = os.path.join(os.getcwd(), 'output', 'iptv_results.txt')
        os.makedirs(os.path.dirname(iptv_results_file_path), exist_ok=True)
        write_sorted_channels_to_file(iptv_results_file_path, valid_channels_with_speed)
        logging.warning(f"已生成输出文件：{iptv_results_file_path}")
        logging.warning(f"已生成 M3U 文件：{iptv_results_file_path.replace('.txt', '.m3u')}")

        # 复制到本地根目录
        local_txt_path = os.path.join(os.getcwd(), 'iptv_results.txt')
        local_m3u_path = os.path.join(os.getcwd(), 'iptv_results.m3u')
        shutil.copy(iptv_results_file_path, local_txt_path)
        shutil.copy(iptv_results_file_path.replace('.txt', '.m3u'), local_m3u_path)
        logging.warning(f"已在本地根目录生成文件：{local_txt_path}")
        logging.warning(f"已在本地根目录生成 M3U 文件：{local_m3u_path}")

        try:
            with open(iptv_results_file_path, "r", encoding='utf-8') as f:
                iptv_results_content = f.read()
            save_to_github(f"output/iptv_results.txt", iptv_results_content, "更新 IPTV 效果测试结果")
            logging.warning(f"已将 {iptv_results_file_path} 推送到远程仓库。")
            
            with open(iptv_results_file_path.replace('.txt', '.m3u'), "r", encoding='utf-8') as f:
                iptv_results_m3u_content = f.read()
            save_to_github(f"output/iptv_results.m3u", iptv_results_m3u_content, "更新 IPTV M3U 播放列表")
            logging.warning(f"已将 iptv_results.m3u 推送到远程仓库。")
        except Exception as e:
            logging.error(f"无法将文件推送到 GitHub：{e}")

        # 提取不可用域名并更新 config.yaml
        unavailable_domains = extract_unavailable_domains_from_log(log_file)
        update_config_with_unavailable_domains(unavailable_domains)

    except Exception as e:
        logging.error(f"主程序执行失败：{e}")
        raise
    finally:
        logging.getLogger().removeHandler(file_handler)
        file_handler.close()

if __name__ == "__main__":
    main()
