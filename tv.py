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

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')
KEYWORD_STATS_PATH_IN_REPO = os.getenv('KEYWORD_STATS_PATH', 'config/keyword_stats.json')

if not GITHUB_TOKEN:
    logging.error("Error: 'BOT' secret is not set.")
    exit(1)
if not REPO_OWNER:
    logging.error("Error: 'REPO_OWNER' not set.")
    exit(1)
if not REPO_NAME:
    logging.error("Error: 'REPO_NAME' not set.")
    exit(1)
if not CONFIG_PATH_IN_REPO:
    logging.error("Error: 'CONFIG_PATH' not set.")
    exit(1)
if not URLS_PATH_IN_REPO:
    logging.error("Error: 'URLS_PATH' not set.")
    exit(1)
if not URL_STATES_PATH_IN_REPO:
    logging.error("Error: 'URL_STATES_PATH' not set.")
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
        logging.error(f"Error fetching {file_path_in_repo} from GitHub: {e}")
        return None

def get_current_sha(file_path_in_repo):
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error getting SHA for {file_path_in_repo} (may not exist): {e}")
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
        logging.info(f"Successfully saved '{file_path_in_repo}' to GitHub.")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error saving {file_path_in_repo} to GitHub: {e}")
        if response is not None:
             logging.error(f"GitHub API response: {response.text}")
        return False

def load_config():
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"Error: Invalid YAML in remote config '{CONFIG_PATH_IN_REPO}': {e}")
            exit(1)
        except Exception as e:
            logging.error(f"Error loading remote config '{CONFIG_PATH_IN_REPO}': {e}")
            exit(1)
    logging.error(f"Could not load config from GitHub '{CONFIG_PATH_IN_REPO}'.")
    exit(1)

CONFIG = load_config()

log_level_str = CONFIG.get('log_level', 'WARNING').upper()
numeric_log_level = getattr(logging, log_level_str, None)
if isinstance(numeric_log_level, int):
    logging.getLogger().setLevel(numeric_log_level)
    logging.info(f"Log level set to: {log_level_str}")
else:
    logging.warning(f"Invalid log_level '{log_level_str}' in config, using default WARNING.")

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
            logging.error(f"Error decoding JSON from remote '{KEYWORD_STATS_PATH_IN_REPO}': {e}")
            return {}
    return {}

def save_search_cache(cache):
    try:
        content = json.dumps(cache, indent=4, ensure_ascii=False)
        success = save_to_github(KEYWORD_STATS_PATH_IN_REPO, content, "Update keyword search cache")
        if not success:
            logging.error(f"Failed to save keyword search cache to '{KEYWORD_STATS_PATH_IN_REPO}'.")
    except Exception as e:
        logging.error(f"Error saving keyword search cache to remote '{KEYWORD_STATS_PATH_IN_REPO}': {e}")

def load_url_states_remote():
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    if content:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from remote '{URL_STATES_PATH_IN_REPO}': {e}")
            return {}
    return {}

def save_url_states_remote(url_states):
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        success = save_to_github(URL_STATES_PATH_IN_REPO, content, "Update URL states")
        if not success:
            logging.error(f"Failed to save remote URL states to '{URL_STATES_PATH_IN_REPO}'.")
    except Exception as e:
        logging.error(f"Error saving URL states to remote '{URL_STATES_PATH_IN_REPO}': {e}")

def read_txt_to_array_local(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines if line.strip()]
            return lines
    except FileNotFoundError:
        logging.warning(f"File '{file_name}' not found.")
        return []
    except Exception as e:
        logging.error(f"Error reading file '{file_name}': {e}")
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
            logging.debug(f"URL {url} content not modified (304 Not Modified).")
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL {url} content hash matches cache.")
            return None

        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error fetching URL (after retries): {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"Unknown error fetching URL: {url} - {e}")
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
        logging.error(f"Error extracting channels from {url}: {e}")
    return extracted_channels

def pre_screen_url(url):
    if not isinstance(url, str) or not url:
        return False

    parsed_url = urlparse(url)

    if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
        logging.debug(f"Pre-screen filter (protocol not allowed): {url}")
        return False

    if not parsed_url.netloc:
        logging.debug(f"Pre-screen filter (no host): {url}")
        return False

    invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
    for pattern in compiled_invalid_url_patterns:
        if pattern.search(url):
            logging.debug(f"Pre-screen filter (invalid pattern): {url}")
            return False

    if len(url) < 15:
        logging.debug(f"Pre-screen filter (URL too short): {url}")
        return False

    return True

def filter_and_modify_channels(channels):
    filtered_channels = []
    for name, url in channels:
        if not pre_screen_url(url):
            continue

        if any(word in url for word in CONFIG.get('url_filter_words', [])):
            logging.debug(f"URL filter (keyword): {url}")
            continue

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            logging.debug(f"Name filter (keyword): {name}")
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
        logging.debug(f"HTTP URL {url} check failed: {e}")
        return False

def check_rtmp_url(url, timeout):
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("ffprobe not found or not working. RTMP stream check skipped.")
        return False
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} check timed out")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} check error: {e}")
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
        logging.debug(f"RTP URL {url} check failed: {e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} check error: {e}")
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
        logging.debug(f"P3P URL {url} check failed: {e}")
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
            logging.debug(f"ffprobe check {url} failed: {result.stderr.decode()}")
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
        logging.debug(f"Error during ffprobe check for {url}: {e}")
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
        
        stderr_output = process.stderr.read().decode('utf-8', errors='ignore')
        if "error" in stderr_output.lower() or "failed" in stderr_output.lower():
            logging.debug(f"Stability test {url} found errors: {stderr_output}")
            return False
        return process.returncode == 0
    except Exception as e:
        logging.debug(f"Stability test {url} failed: {e}")
        return False

def check_channel_validity_and_speed(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    start_time = time.time()
    is_valid = False
    resolution = bitrate = frame_rate = None
    is_stable = False

    try:
        if url.startswith("http"):
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
            logging.debug(f"Channel {channel_name} has unsupported protocol: {url}")
            return None, False, None, None, None, False

        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            return elapsed_time, True, resolution, bitrate, frame_rate, is_stable
        else:
            return None, False, None, None, None, False
    except Exception as e:
        logging.debug(f"Error checking channel {channel_name} ({url}): {e}")
        return None, False, None, None, None, False

def process_single_channel_line(channel_line):
    if "://" not in channel_line:
        logging.debug(f"Skipping invalid channel line (no protocol): {channel_line}")
        return None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid, resolution, bitrate, frame_rate, is_stable = check_channel_validity_and_speed(name, url)
        if is_valid:
            res_str = resolution if resolution else '未知'
            bit_str = bitrate if bitrate else 0
            frame_str = frame_rate if frame_rate else 0
            stable_bool = "是" if is_stable else "否"
            return (elapsed_time, f"{name},{url},{elapsed_time:.0f},{res_str},{bit_str},{frame_str},{stable_bool}", resolution, is_stable)
    logging.debug(f"Channel line processing failed or invalid: {channel_line}")
    return None

def check_channels_multithreaded(channel_lines, max_workers=CONFIG.get('channel_check_workers', 50)):
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"Starting multi-threaded channel validity and performance detection for {total_channels} channels...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line): line for line in channel_lines}
        for future in as_completed(futures):
            checked_count += 1
            if checked_count % 100 == 0:
                logging.warning(f"Checked {checked_count}/{total_channels} channels...")
            try:
                result_tuple = future.result()
                if result_tuple and len(result_tuple) == 4:
                    elapsed_time, result_line, resolution, is_stable = result_tuple
                    if elapsed_time is not None and result_line is not None:
                        if resolution and 'x' in resolution:
                            try:
                                _, height = map(int, resolution.split('x'))
                                if height >= 720 and is_stable:
                                    results.append((elapsed_time, result_line))
                            except ValueError:
                                logging.debug(f"Invalid resolution format: {resolution}")
                                continue
                else:
                    logging.debug(f"Channel line processing result incomplete or invalid: {result_tuple}")
            except Exception as exc:
                logging.warning(f"Exception during channel line processing: {exc}")

    logging.warning(f"Channel detection complete. Found {len(results)} valid and high-quality channels.")
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

    output_dir = os.path.dirname(file_path)
    os.makedirs(output_dir, exist_ok=True)

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write("频道名称,URL,响应时间(ms),分辨率,码率(kbps),帧率(fps),稳定性\n")
        for category in ORDERED_CATEGORIES + ["其他频道"]:
            channels = grouped_channels.get(category, [])
            if channels:
                file.write(f"\n{category},#genre#\n")
                for elapsed_time, result_line in sorted(channels, key=lambda x: x[0]):
                    file.write(result_line + '\n')
    logging.info(f"TXT file written: {file_path}")

    m3u_path = file_path.replace('.txt', '.m3u')
    with open(m3u_path, 'w', encoding='utf-8') as file:
        file.write('#EXTM3U\n')
        for category in ORDERED_CATEGORIES + ["其他频道"]:
            channels = grouped_channels.get(category, [])
            if channels:
                file.write(f'#EXTINF:-1 tvg-name="{category}" group-title="{category}",{category}\n')
                file.write(f'#EXTGRP:{category}\n')

                for elapsed_time, result_line in sorted(channels, key=lambda x: x[0]):
                    parts = result_line.split(',')
                    name = parts[0].strip()
                    url = parts[1].strip()
                    file.write(f'#EXTINF:-1 tvg-name="{name}" group-title="{category}",{name}\n')
                    file.write(f'{url}\n')
    logging.info(f"M3U file written: {m3u_path}")

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
        logging.error(f"Failed to write data to remote '{file_path_in_repo}'.")

def auto_discover_github_urls(urls_file_path_remote, github_token):
    if not github_token:
        logging.warning("Environment variable 'BOT' not set. Skipping GitHub URL auto-discovery.")
        return

    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    search_cache = load_search_cache()
    logging.warning("Starting automatic discovery of new IPTV source URLs from GitHub...")

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if keyword in search_cache and search_cache[keyword].get('timestamp', 0) > time.time() - SEARCH_CACHE_TTL:
            logging.warning(f"Search results for keyword '{keyword}' are valid from cache, reusing {len(search_cache[keyword]['urls'])} URLs.")
            found_urls.update(search_cache[keyword]['urls'])
            continue

        if i > 0:
            logging.warning(f"Switching to next keyword: '{keyword}'. Waiting {GITHUB_API_RETRY_WAIT} seconds to avoid rate limits...")
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
                    logging.warning(f"GitHub API rate limit close! Remaining requests: {rate_limit_remaining}. Waiting {wait_seconds:.0f} seconds before retrying.")
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
                            logging.debug(f"Discovered raw GitHub URL (pre-screened): {cleaned_url}")
                        else:
                            logging.debug(f"Skipping non-raw GitHub M3U/M3U8/TEXT link or pre-screen failed: {raw_url}")
                    else:
                        logging.debug(f"Could not construct raw URL from HTML URL: {html_url}")

                if len(data['items']) < PER_PAGE:
                    break

                page += 1
                time.sleep(2)

            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API request failed (keyword: {keyword}, page: {page}): {e}")
                if 'response' in locals() and response.status_code == 403:
                    rate_limit_reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_seconds = max(0, rate_limit_reset_time - time.time()) + 5
                    logging.warning(f"GitHub API rate limit hit! Waiting {wait_seconds:.0f} seconds before retrying.")
                    time.sleep(wait_seconds)
                    continue
                else:
                    break
            except Exception as e:
                logging.error(f"Unknown error during GitHub URL auto-discovery: {e}")
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
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "Update urls.txt with new GitHub discovered URLs")
        logging.warning(f"Successfully discovered and added {new_urls_count} new GitHub IPTV source URLs to {urls_file_path_remote}. Total URLs: {len(updated_urls)}")
    else:
        logging.warning("No new GitHub IPTV source URLs discovered.")

    logging.warning("GitHub URL auto-discovery complete.")

def main():
    logging.info("IPTV Channel Update script started.")

    auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)

    urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
    if not urls:
        logging.warning(f"No URLs found in remote '{URLS_PATH_IN_REPO}', script will exit.")
        return

    url_states = load_url_states_remote()
    logging.warning(f"Loaded {len(url_states)} historical URL states.")

    all_extracted_channels = set()
    with ThreadPoolExecutor(max_workers=CONFIG.get('channel_extract_workers', 5)) as executor:
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result_channels = future.result()
                for name, addr in result_channels:
                    all_extracted_channels.add((name, addr))
            except Exception as exc:
                logging.error(f"Exception processing source '{url}': {exc}")

    save_url_states_remote(url_states)
    logging.warning(f"\nExtracted {len(all_extracted_channels)} raw channels from all sources.")

    filtered_channels = filter_and_modify_channels(list(all_extracted_channels))
    unique_filtered_channels = list(set(filtered_channels))
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]

    logging.warning(f"\nAfter filtering and cleaning, {len(unique_filtered_channels_str)} unique channels remain.")

    valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
    logging.warning(f"Number of valid and high-quality channels: {len(valid_channels_with_speed)}")

    output_dir = os.path.join(os.getcwd(), 'output')
    os.makedirs(output_dir, exist_ok=True)

    iptv_results_output_path = os.path.join(output_dir, 'iptv_results.txt')
    iptv_results_m3u_output_path = os.path.join(output_dir, 'iptv_results.m3u')

    write_sorted_channels_to_file(iptv_results_output_path, valid_channels_with_speed)

    logging.warning(f"Generated iptv_results.txt and iptv_results.m3u in '{output_dir}' directory.")

    root_dir = os.getcwd()

    iptv_results_root_path = os.path.join(root_dir, 'iptv_results.txt')
    iptv_results_m3u_root_path = os.path.join(root_dir, 'iptv_results.m3u')

    try:
        with open(iptv_results_output_path, 'r', encoding='utf-8') as f_output_txt:
            root_txt_content = f_output_txt.read()
        with open(iptv_results_root_path, 'w', encoding='utf-8') as f_root_txt:
            f_root_txt.write(root_txt_content)
        logging.warning(f"Copied iptv_results.txt to root directory: '{iptv_results_root_path}'.")

        with open(iptv_results_m3u_output_path, 'r', encoding='utf-8') as f_output_m3u:
            root_m3u_content = f_output_m3u.read()
        with open(iptv_results_m3u_root_path, 'w', encoding='utf-8') as f_root_m3u:
            f_root_m3u.write(root_m3u_content)
        logging.warning(f"Copied iptv_results.m3u to root directory: '{iptv_results_m3u_root_path}'.")

    except Exception as e:
        logging.error(f"Error copying files to root directory: {e}")

    try:
        with open(iptv_results_output_path, "r", encoding='utf-8') as f:
            iptv_results_content = f.read()
        save_to_github(f"output/iptv_results.txt", iptv_results_content, "Update IPTV test results")
        logging.warning(f"Pushed output/iptv_results.txt to remote repository.")
        
        with open(iptv_results_m3u_output_path, "r", encoding='utf-8') as f:
            iptv_results_m3u_content = f.read()
        save_to_github(f"output/iptv_results.m3u", iptv_results_m3u_content, "Update IPTV M3U playlist")
        logging.warning(f"Pushed output/iptv_results.m3u to remote repository.")

    except Exception as e:
        logging.error(f"Failed to push files to GitHub (via API): {e}")

    logging.info("IPTV Channel Update script finished running.")

if __name__ == "__main__":
    main()
