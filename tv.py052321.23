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
import hashlib # Added for content hashing

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants and Configuration ---
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN') # This variable will hold the token passed from GitHub Actions

SEARCH_KEYWORDS = [
    "extension:m3u8 in:file",
  #  "extension:m3u in:file",
  #  "iptv playlist extension:m3u,m3u8 in:file",
  #  "raw.githubusercontent.com path:.m3u8",
  #  "raw.githubusercontent.com path:.m3u",
  #  "tv channels extension:m3u,m3u8 in:file",
  #  "live tv extension:m3u,m3u8 in:file",
  #  "playlist.m3u8 in:file",
  #  "index.m3u8 in:file",
   # "channels.m3u in:file",
   # "iptv links extension:m3u,m3u8 in:file"
]

PER_PAGE = 100
MAX_SEARCH_PAGES = 5
GITHUB_API_TIMEOUT = 20
GITHUB_API_RETRY_WAIT = 10 # seconds between keyword searches or after rate limit
CHANNEL_FETCH_TIMEOUT = 15 # seconds for fetching URL content
CHANNEL_CHECK_TIMEOUT = 6 # seconds for checking channel validity

MAX_CHANNEL_URLS_PER_GROUP = 200 # Limit each channel to a maximum of 200 URLs in merged file

# Filter lists for channel names and URLs
NAME_FILTER_WORDS = ['购物', '理财', '导视', '指南', '测试', '芒果', 'CGTN', '(480p)', '(360p)', '(240p)', '(406p)', ' (540p)', '(600p)', '(576p)', '[Not 24/7]', 'DJ', '音乐', '演唱会', '舞曲', '春晚', '格斗', '粤', '祝', '体育', '广播', '博斯', '神话']
URL_FILTER_WORDS = [] # Currently empty, but kept for consistency

# Channel name cleaning replacements
CHANNEL_NAME_REPLACEMENTS = {
    "FHD": "", "HD": "", "hd": "", "频道": "", "高清": "",
    "超清": "", "20M": "", "-": "", "4k": "", "4K": "", "4kR": ""
}

# Ordered categories for merging
ORDERED_CATEGORIES = ["央视频道", "卫视频道", "湖南频道", "港台频道"]

URL_STATES_FILE = "url_states.json" # File to store URL states for conditional fetching

# Global Requests Session for better performance with retries
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"})

# --- Helper Functions ---

def read_txt_to_array(file_name):
    """Reads content from a TXT file, one element per line."""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines if line.strip()]
            return lines
    except FileNotFoundError:
        logging.warning(f"File '{file_name}' not found. A new one will be created.")
        return []
    except Exception as e:
        logging.error(f"Error reading file '{file_name}': {e}")
        return []

def write_array_to_txt(file_name, data_array):
    """Writes array content to a TXT file, one element per line."""
    try:
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
        logging.info(f"Data successfully written to '{file_name}'.")
    except Exception as e:
        logging.error(f"Error writing file '{file_name}': {e}")

def get_url_file_extension(url):
    """Gets the file extension from a URL."""
    parsed_url = urlparse(url)
    extension = os.path.splitext(parsed_url.path)[1].lower()
    return extension

def convert_m3u_to_txt(m3u_content):
    """Converts m3u/m3u8 content to channel name and address in TXT format."""
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
                channel_name = "Unknown Channel"
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = "" # Reset channel name after finding a URL
    return '\n'.join(txt_lines)

def clean_url_params(url):
    """Cleans query parameters and fragment identifiers from a URL, keeping only the base URL."""
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

def load_url_states(file_path):
    """从 JSON 文件加载 URL 状态。"""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from '{file_path}': {e}. Starting with empty states.")
            return {}
    return {}

def save_url_states(file_path, url_states):
    """将 URL 状态保存到 JSON 文件。"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(url_states, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Error saving URL states to '{file_path}': {e}")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states, url_states_file_path, timeout=CHANNEL_FETCH_TIMEOUT):
    """
    Fetches URL content using requests with retries, supporting conditional requests
    and content hashing for update checks.
    """
    logging.info(f"尝试抓取 URL: {url} (超时: {timeout}s)")
    
    headers = {}
    current_state = url_states.get(url, {})
    
    # Add conditional headers if available
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']

    try:
        response = session.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()

        if response.status_code == 304:
            logging.info(f"URL 内容 {url} 未修改 (304)。跳过下载。")
            return None  # Indicate no new content

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        # Check content hash if ETag/Last-Modified didn't prevent download
        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.info(f"URL 内容 {url} 基于哈希值是相同的。跳过下载。")
            return None # Indicate no new content
        
        # Update state for the URL
        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }
        save_url_states(url_states_file_path, url_states) # Save states after each successful fetch

        logging.info(f"成功获取 URL: {url} 的新内容。内容已更新。")
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"获取 URL 时请求出错 (重试后失败): {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"获取 URL 时发生未知错误: {url} - {e}")
        return None


def extract_channels_from_url(url, url_states, url_states_file_path):
    """Fetches and extracts channel name/URL pairs from a given URL."""
    extracted_channels = []
    try:
        text = fetch_url_content_with_retry(url, url_states, url_states_file_path)
        if text is None: # Content not modified or error
            return [] # Return empty list if no new content or error

        if get_url_file_extension(url) in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)

        lines = text.split('\n')
        channel_count = 0
        for line in lines:
            line = line.strip()
            # Ensure line contains both name and URL, and is not a genre tag
            if "#genre#" not in line and "," in line and "://" in line:
                parts = line.split(',', 1)
                channel_name = parts[0].strip()
                channel_address_raw = parts[1].strip()

                # Handle multiple URLs separated by '#' (though rare in m3u/txt)
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
        logging.info(f"成功从 URL: {url} 中提取到 {channel_count} 个频道。")
    except Exception as e:
        logging.error(f"从 {url} 提取频道时出错: {e}")
    return extracted_channels

def filter_and_modify_channels(channels):
    """Filters and modifies channel names and URLs."""
    filtered_channels = []
    for name, url in channels:
        # Check against URL filter words
        if any(word in url for word in URL_FILTER_WORDS):
            logging.info(f"过滤频道 (URL 匹配): {name},{url}")
            continue

        # Check against name filter words (case-insensitive)
        if any(word.lower() in name.lower() for word in NAME_FILTER_WORDS):
            logging.info(f"过滤频道 (名称匹配): {name},{url}")
            continue

        # Apply channel name replacements
        for old_str, new_str in CHANNEL_NAME_REPLACEMENTS.items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    return filtered_channels

def clear_directory_txt_files(directory):
    """Deletes all TXT files in the specified directory."""
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
                logging.info(f"已删除文件: {file_path}")
            except Exception as e:
                logging.error(f"删除文件 {file_path} 时出错: {e}")

# --- URL Validity Check Functions ---
def check_http_url(url, timeout):
    """Checks if an HTTP/HTTPS URL is active."""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} 检查失败: {e}")
        return False

def check_rtmp_url(url, timeout):
    """Checks if an RTMP stream is available using ffprobe."""
    try:
        # Check if ffprobe is available once
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("未找到 ffprobe 或其无法工作。RTMP 流无法检查。")
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
        logging.debug(f"RTMP URL {url} 检查错误: {e}")
        return False

def check_rtp_url(url, timeout):
    """Checks if an RTP URL is active (UDP protocol)."""
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
            s.recv(1) # Try to receive data
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL {url} 检查失败: {e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} 检查错误: {e}")
        return False

def check_p3p_url(url, timeout):
    """Checks if a P3P URL is active (simulates an HTTP request)."""
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
        logging.debug(f"P3P URL {url} 检查失败: {e}")
        return False

def check_channel_validity_and_speed(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    """Checks the validity of a URL based on its protocol and returns response time."""
    start_time = time.time()
    is_valid = False

    try:
        if url.startswith("http"):
            is_valid = check_http_url(url, timeout)
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, timeout)
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, timeout)
        else:
            logging.debug(f"不支持的协议 {channel_name}: {url}")
            return None, False

        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            return elapsed_time, True
        else:
            return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 时出错: {e}")
        return None, False

def process_single_channel_line(channel_line):
    """Processes a single channel line (name,url) and checks validity."""
    if "://" not in channel_line:
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

def check_channels_multithreaded(channel_lines, max_workers=200):
    """Processes a list of channel lines concurrently for validity checking."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line): line for line in channel_lines}
        for future in as_completed(futures):
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"频道行处理期间发生异常: {exc}")

    results.sort() # Sort by response time
    return results

def write_sorted_channels_to_file(file_path, data_list):
    """Writes a list of (time, channel_line) to a file, only writing channel_line."""
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    """Sorts CCTV channels numerically."""
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        if match:
            return int(match.group())
        return float('inf') # Put channels without numbers at the end

    return sorted(channels, key=channel_key)

def generate_update_time_header():
    """Generates the update time header lines."""
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    """Groups channels by name and limits the number of URLs per group."""
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
        # Limit each channel to a maximum of MAX_CHANNEL_URLS_PER_GROUP URLs
        for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]:
            final_grouped_lines.append(ch_line + '\n')
    return final_grouped_lines


def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt"):
    """Merges all local channel files into a single output file."""
    final_output_lines = []
    final_output_lines.extend(generate_update_time_header())

    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]

    # Create a list of files to merge, prioritizing ordered categories
    files_to_merge_paths = []
    processed_files = set()

    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files_in_dir and file_name not in processed_files:
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    # Add any remaining files, sorted alphabetically
    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    for file_path in files_to_merge_paths:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                continue

            header = lines[0].strip()
            if '#genre#' in header:
                final_output_lines.append(header + '\n')
                final_output_lines.extend(group_and_limit_channels(lines[1:]))
            else:
                logging.warning(f"文件 {file_path} 未以类别头开始。跳过。")

    iptv_list_file_path = output_file_name
    with open(iptv_list_file_path, "w", encoding="utf-8") as iptv_list_file:
        iptv_list_file.writelines(final_output_lines)

    logging.info(f"\n所有区域频道列表文件已合并。输出保存到: {iptv_list_file_path}")

def auto_discover_github_urls(urls_file_path, github_token):
    """
    Automatically searches for public IPTV source URLs on GitHub and updates the urls.txt file.
    """
    if not github_token:
        logging.warning("环境变量 'GITHUB_TOKEN' 未设置。跳过 GitHub URL 自动发现。")
        return

    existing_urls = set(read_txt_to_array(urls_file_path))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.info("开始从 GitHub 自动发现新的 IPTV 源 URL...")

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if i > 0:
            logging.info(f"切换到下一个关键词: '{keyword}'。等待 {GITHUB_API_RETRY_WAIT} 秒以避免速率限制...")
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
                    logging.warning(f"GitHub API 速率限制达到！剩余请求: 0。等待 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    logging.info(f"关键词 '{keyword}' 在第 {page} 页未找到更多结果。")
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
                        if raw_url.startswith("https://raw.githubusercontent.com/") and \
                           raw_url.lower().endswith(('.m3u', '.m3u8', '.txt')):
                            cleaned_url = clean_url_params(raw_url)
                            found_urls.add(cleaned_url)
                            logging.debug(f"发现原始 GitHub URL: {cleaned_url}")
                        else:
                            logging.debug(f"跳过非原始 GitHub M3U/M3U8/TXT 链接: {raw_url}")
                    else:
                        logging.debug(f"无法从 HTML URL 构造原始 URL: {html_url}")

                logging.info(f"关键词 '{keyword}'，第 {page} 页搜索完成。当前找到 {len(found_urls)} 个原始 URL。")

                if len(data['items']) < PER_PAGE:
                    break

                page += 1
                time.sleep(2) # Wait 2 seconds between page requests for the same keyword

            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API 请求失败 (关键词: {keyword}, 页码: {page}): {e}")
                if response.status_code == 403:
                    rate_limit_reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_seconds = max(0, rate_limit_reset_time - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制达到！等待 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue
                else:
                    break
            except Exception as e:
                logging.error(f"GitHub URL 自动发现期间发生未知错误: {e}")
                break

    new_urls_count = 0
    for url in found_urls:
        if url not in existing_urls:
            existing_urls.add(url)
            new_urls_count += 1

    if new_urls_count > 0:
        updated_urls = list(existing_urls)
        write_array_to_txt(urls_file_path, updated_urls)
        logging.info(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URL 到 {urls_file_path}。总 URL 数量: {len(updated_urls)}")
    else:
        logging.info("未发现新的 GitHub IPTV 源 URL。")

    logging.info("GitHub URL 自动发现完成。")


def main():
    config_dir = os.path.join(os.getcwd(), 'config')
    os.makedirs(config_dir, exist_ok=True)
    urls_file_path = os.path.join(config_dir, 'urls.txt')
    url_states_file_path = os.path.join(config_dir, URL_STATES_FILE) # 新增 URL 状态文件路径

    # --- START OF DEBUG LOGGING ---
    if os.getenv('GITHUB_TOKEN'):
        logging.info("环境变量 'GITHUB_TOKEN' 已设置。")
    else:
        logging.error("环境变量 'GITHUB_TOKEN' 未设置！请检查 GitHub Actions 工作流配置。")
    # --- END OF DEBUG LOGGING ---

    # 1. Automatically discover GitHub URLs and update urls.txt
    auto_discover_github_urls(urls_file_path, GITHUB_TOKEN)

    # 2. Read URLs to process from urls.txt (including newly discovered ones)
    urls = read_txt_to_array(urls_file_path)
    if not urls:
        logging.warning(f"在 '{urls_file_path}' 中未找到任何URL，脚本将提前退出。")
        return

    # Load existing URL states
    url_states = load_url_states(url_states_file_path)
    logging.info(f"已加载 {len(url_states)} 个 URL 的历史状态。")

    # 3. Process all channel lists from config/urls.txt
    all_extracted_channels = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Pass url_states and url_states_file_path to extract_channels_from_url
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states, url_states_file_path): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                # future.result() will be an empty list if content was not modified or an error occurred
                result_channels = future.result()
                for name, addr in result_channels:
                    all_extracted_channels.add((name, addr))
            except Exception as exc:
                logging.error(f"处理源 '{url}' 时发生异常: {exc}")

    # Save URL states after all URLs have been processed
    # (This ensures states are saved even if the script is interrupted later)
    save_url_states(url_states_file_path, url_states) 
    
    # Convert set back to list for filtering
    all_extracted_channels_list = list(all_extracted_channels)
    logging.info(f"\n已从所有源中提取到 {len(all_extracted_channels_list)} 个原始频道。")

    # 4. Filter and clean channel names
    filtered_channels = filter_and_modify_channels(all_extracted_channels_list)
    unique_filtered_channels = list(set(filtered_channels)) # Use set to ensure uniqueness again
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]

    logging.info(f"\n经过过滤和清洗后，剩余 {len(unique_filtered_channels_str)} 个独立频道。")

    # 5. Multi-threaded channel validity and speed check
    logging.info("开始多线程频道有效性及速度检测...")
    valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
    logging.info(f"有效且有响应的频道数量: {len(valid_channels_with_speed)}")

    # Write channels with speed to iptv_speed.txt
    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_sorted_channels_to_file(iptv_speed_file_path, valid_channels_with_speed)
    for elapsed_time, result in valid_channels_with_speed:
        channel_name, channel_url = result.split(',', 1)
        logging.debug(f"检查成功: {channel_name},{channel_url} 响应时间: {elapsed_time:.0f} ms") # Changed to DEBUG

    # 6. Process regional channels and templates
    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    os.makedirs(local_channels_directory, exist_ok=True)
    clear_directory_txt_files(local_channels_directory) # Clear existing files

    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True)
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]

    # Read the valid channels from iptv_speed.txt for matching
    channels_for_matching = read_txt_to_array(iptv_speed_file_path)

    all_template_channel_names = set()
    for template_file in template_files:
        names_from_current_template = read_txt_to_array(os.path.join(template_directory, template_file))
        all_template_channel_names.update(names_from_current_template)

    for template_file in template_files:
        template_channels_names = set(read_txt_to_array(os.path.join(template_directory, template_file)))
        template_name = os.path.splitext(template_file)[0]

        current_template_matched_channels = []
        for channel_line in channels_for_matching:
            channel_name = channel_line.split(',', 1)[0].strip()
            if channel_name in template_channels_names:
                current_template_matched_channels.append(channel_line)

        if "央视" in template_name or "CCTV" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.info(f"已按数字顺序排序 '{template_name}' 频道。")

        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.info(f"频道列表已写入: '{template_name}_iptv.txt', 包含 {len(current_template_matched_channels)} 个频道。")

    # 7. Merge all IPTV files
    merge_local_channel_files(local_channels_directory, "iptv_list.txt")

    # 8. Find unmatched channels
    unmatched_channels_list = []
    for channel_line in channels_for_matching:
        channel_name = channel_line.split(',', 1)[0].strip()
        if channel_name not in all_template_channel_names:
            unmatched_channels_list.append(channel_line)

    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels_list:
            f.write(channel_line.split(',')[0].strip() + '\n')
    logging.info(f"\n未匹配但已检测到的频道列表已保存到: '{unmatched_output_file_path}', 共 {len(unmatched_channels_list)} 个频道。")

    # Cleanup temporary files
    try:
        if os.path.exists('iptv.txt'):
            os.remove('iptv.txt')
            logging.info(f"临时文件 'iptv.txt' 已删除。")
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.info(f"临时文件 'iptv_speed.txt' 已删除。")
    except OSError as e:
        logging.warning(f"删除临时文件时出错: {e}")

if __name__ == "__main__":
    main()
