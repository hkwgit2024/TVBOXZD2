
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
import yaml # 导入 yaml 模块

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration Loading ---
# 定义配置文件路径，现在是 config.yaml
CONFIG_FILE = os.path.join(os.getcwd(), 'config', 'config.yaml')

def load_config(file_path):
    """Loads configuration from a YAML file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) # 使用 yaml.safe_load 来加载 YAML 文件
    except FileNotFoundError:
        logging.error(f"Error: Config file '{file_path}' not found. Please create it in the 'config' directory.")
        exit(1)
    except yaml.YAMLError as e: # 捕获 YAML 解析相关的错误
        logging.error(f"Error: Invalid YAML in config file '{file_path}': {e}")
        exit(1)
    except Exception as e:
        logging.error(f"Error loading config file '{file_path}': {e}")
        exit(1)

# Load config early at script startup
CONFIG = load_config(CONFIG_FILE)

# --- Constants and Configuration (Now loaded from CONFIG) ---
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

SEARCH_KEYWORDS = CONFIG.get('search_keywords', [])
PER_PAGE = CONFIG.get('per_page', 100)
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5)
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20)
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 10)
CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15)
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 6)

MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200)

NAME_FILTER_WORDS = CONFIG.get('name_filter_words', [])
URL_FILTER_WORDS = CONFIG.get('url_filter_words', [])

CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {})

ORDERED_CATEGORIES = CONFIG.get('ordered_categories', [])

URL_STATES_FILE = "url_states.json"

# --- URL Pre-screening Configuration (Now loaded from CONFIG) ---
URL_PRE_SCREENING_CONFIG = CONFIG.get('url_pre_screening', {})
ALLOWED_PROTOCOLS = set(URL_PRE_SCREENING_CONFIG.get('allowed_protocols', []))
STREAM_EXTENSIONS = set(URL_PRE_SCREENING_CONFIG.get('stream_extensions', [])) # Set for faster lookup

INVALID_URL_PATTERNS = URL_PRE_SCREENING_CONFIG.get('invalid_url_patterns', [])
COMPILED_INVALID_URL_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in INVALID_URL_PATTERNS]


# Global Requests Session for better performance with retries
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"})

# Configure a larger connection pool using values from config.yaml
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

# --- Helper Functions ---

def read_txt_to_array(file_name):
    """Reads content from a TXT file, one element per line."""
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
    """Loads URL states from a JSON file."""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from '{file_path}': {e}. Starting with empty states.")
            return {}
    return {}

def save_url_states(file_path, url_states):
    """Saves URL states to a JSON file."""
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
    logging.info(f"Attempting to fetch URL: {url} (Timeout: {timeout}s)")

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
            logging.info(f"URL content {url} not modified (304). Skipping download.")
            return None  # Indicate no new content

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        # Check content hash if ETag/Last-Modified didn't prevent download
        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.info(f"URL content {url} is identical based on hash. Skipping download.")
            return None # Indicate no new content

        # Update state for the URL
        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }
        save_url_states(url_states_file_path, url_states) # Save states after each successful fetch

        logging.info(f"Successfully fetched new content for URL: {url}. Content updated.")
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error when fetching URL (after retries): {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"Unknown error when fetching URL: {url} - {e}")
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
        logging.info(f"Successfully extracted {channel_count} channels from URL: {url}.")
    except Exception as e:
        logging.error(f"Error extracting channels from {url}: {e}")
    return extracted_channels

def pre_screen_url(url):
    """
    Pre-screens URLs to exclude obviously invalid or irrelevant links.
    Returns True if the URL passes pre-screening, False otherwise.
    """
    if not isinstance(url, str) or not url:
        return False

    parsed_url = urlparse(url)

    # 1. Protocol check
    if parsed_url.scheme not in ALLOWED_PROTOCOLS:
        # logging.debug(f"Pre-screen filtered (protocol): {url}")
        return False

    # 2. Check if hostname/netloc exists
    if not parsed_url.netloc:
        # logging.debug(f"Pre-screen filtered (no hostname): {url}")
        return False

    # 3. Check for common invalid patterns (regex)
    for pattern in COMPILED_INVALID_URL_PATTERNS:
        if pattern.search(url):
            logging.debug(f"Pre-screen filtered (invalid pattern): {url}")
            return False

    # 4. (Optional) Check file extensions, exclude non-video files.
    #    Commented out by default as it might filter valid streams without extensions.
    # extension = os.path.splitext(parsed_url.path)[1].lower()
    # if extension and extension not in STREAM_EXTENSIONS:
    #     logging.debug(f"Pre-screen filtered (non-stream extension): {url}")
    #     return False

    # 5. Length check (avoiding very short, possibly junk links)
    if len(url) < 15: # e.g., a valid http://a.b/c is at least 10 chars
        # logging.debug(f"Pre-screen filtered (too short): {url}")
        return False

    return True


def filter_and_modify_channels(channels):
    """Filters and modifies channel names and URLs, and performs pre-screening."""
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        # 0. URL Pre-screening: first exclude obviously invalid links
        if not pre_screen_url(url):
            logging.info(f"Filtering channel (pre-screen failed): {name},{url}")
            continue
        pre_screened_count += 1

        # Check against URL filter words
        if any(word in url for word in URL_FILTER_WORDS):
            logging.info(f"Filtering channel (URL matched blacklist): {name},{url}")
            continue

        # Check against name filter words (case-insensitive)
        if any(word.lower() in name.lower() for word in NAME_FILTER_WORDS):
            logging.info(f"Filtering channel (name matched blacklist): {name},{url}")
            continue

        # Apply channel name replacements
        for old_str, new_str in CHANNEL_NAME_REPLACEMENTS.items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    logging.info(f"After URL pre-screening, {pre_screened_count} channels remain for further filtering.")
    return filtered_channels

def clear_directory_txt_files(directory):
    """Deletes all TXT files in the specified directory."""
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
                logging.info(f"Deleted file: {file_path}")
            except Exception as e:
                logging.error(f"Error deleting file {file_path}: {e}")

# --- URL Validity Check Functions ---
def check_http_url(url, timeout):
    """Checks if an HTTP/HTTPS URL is active."""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} check failed: {e}")
        return False

def check_rtmp_url(url, timeout):
    """Checks if an RTMP stream is available using ffprobe."""
    try:
        # Check if ffprobe is available once
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
        logging.debug(f"RTP URL {url} check failed: {e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} check error: {e}")
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
        logging.debug(f"P3P URL {url} check failed: {e}")
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
            logging.debug(f"Unsupported protocol for channel {channel_name}: {url}")
            return None, False

        elapsed_time = (time.time() - start_time) * 1000
        if is_valid:
            return elapsed_time, True
        else:
            return None, False
    except Exception as e:
        logging.debug(f"Error checking channel {channel_name} ({url}): {e}")
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

def check_channels_multithreaded(channel_lines, max_workers=CONFIG.get('channel_check_workers', 200)): # Use config for workers
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
                logging.warning(f"Exception during channel line processing: {exc}")

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
                logging.warning(f"File {file_path} does not start with a category header. Skipping.")

    iptv_list_file_path = output_file_name
    with open(iptv_list_file_path, "w", encoding="utf-8") as iptv_list_file:
        iptv_list_file.writelines(final_output_lines)

    logging.info(f"\nAll regional channel list files merged. Output saved to: {iptv_list_file_path}")

def auto_discover_github_urls(urls_file_path, github_token):
    """
    Automatically searches for public IPTV source URLs on GitHub and updates the urls.txt file.
    """
    if not github_token:
        logging.warning("Environment variable 'GITHUB_TOKEN' is not set. Skipping GitHub URL auto-discovery.")
        return

    existing_urls = set(read_txt_to_array(urls_file_path))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.info("Starting automatic discovery of new IPTV source URLs from GitHub...")

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if i > 0:
            logging.info(f"Switching to next keyword: '{keyword}'. Waiting {GITHUB_API_RETRY_WAIT} seconds to avoid rate limits...")
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
                    logging.warning(f"GitHub API rate limit reached! Remaining requests: 0. Waiting {wait_seconds:.0f} seconds before retrying.")
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    logging.info(f"No more results found for keyword '{keyword}' on page {page}.")
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
                        # Only add raw URLs that pass pre-screening
                        cleaned_url = clean_url_params(raw_url)
                        if cleaned_url.startswith("https://raw.githubusercontent.com/") and \
                           cleaned_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and \
                           pre_screen_url(cleaned_url): # Added pre-screening here
                            found_urls.add(cleaned_url)
                            logging.debug(f"Discovered raw GitHub URL (passed pre-screen): {cleaned_url}")
                        else:
                            logging.debug(f"Skipping non-raw GitHub M3U/M3U8/TXT link or failed pre-screen: {raw_url}")
                    else:
                        logging.debug(f"Could not construct raw URL from HTML URL: {html_url}")

                logging.info(f"Keyword '{keyword}', page {page} search completed. Currently found {len(found_urls)} raw URLs.")

                if len(data['items']) < PER_PAGE:
                    break

                page += 1
                time.sleep(2) # Wait 2 seconds between page requests for the same keyword

            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API request failed (keyword: {keyword}, page: {page}): {e}")
                if response.status_code == 403:
                    rate_limit_reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_seconds = max(0, rate_limit_reset_time - time.time()) + 5
                    logging.warning(f"GitHub API rate limit reached! Waiting {wait_seconds:.0f} seconds before retrying.")
                    time.sleep(wait_seconds)
                    continue
                else:
                    break
            except Exception as e:
                logging.error(f"Unknown error during GitHub URL auto-discovery: {e}")
                break

    new_urls_count = 0
    for url in found_urls:
        if url not in existing_urls:
            existing_urls.add(url)
            new_urls_count += 1

    if new_urls_count > 0:
        updated_urls = list(existing_urls)
        write_array_to_txt(urls_file_path, updated_urls)
        logging.info(f"Successfully discovered and added {new_urls_count} new GitHub IPTV source URLs to {urls_file_path}. Total URLs: {len(updated_urls)}")
    else:
        logging.info("No new GitHub IPTV source URLs discovered.")

    logging.info("GitHub URL auto-discovery completed.")


def main():
    config_dir = os.path.join(os.getcwd(), 'config')
    os.makedirs(config_dir, exist_ok=True)
    urls_file_path = os.path.join(config_dir, 'urls.txt') # urls.txt 依然保持不变，因为它不是配置而是数据
    url_states_file_path = os.path.join(config_dir, URL_STATES_FILE)

    # --- START OF DEBUG LOGGING ---
    if os.getenv('GITHUB_TOKEN'):
        logging.info("Environment variable 'GITHUB_TOKEN' is set.")
    else:
        logging.error("Environment variable 'GITHUB_TOKEN' is NOT set! Please check GitHub Actions workflow configuration.")
    # --- END OF DEBUG LOGGING ---

    # 1. Automatically discover GitHub URLs and update urls.txt
    auto_discover_github_urls(urls_file_path, GITHUB_TOKEN)

    # 2. Read URLs to process from urls.txt (including newly discovered ones)
    urls = read_txt_to_array(urls_file_path)
    if not urls:
        logging.warning(f"No URLs found in '{urls_file_path}', script will exit early.")
        return

    # Load existing URL states
    url_states = load_url_states(url_states_file_path)
    logging.info(f"Loaded {len(url_states)} historical URL states.")

    # 3. Process all channel lists from config/urls.txt
    all_extracted_channels = set()
    with ThreadPoolExecutor(max_workers=5) as executor: # For fetching initial M3U/TXT files
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
                logging.error(f"Exception processing source '{url}': {exc}")

    # Save URL states after all URLs have been processed
    # (This ensures states are saved even if the script is interrupted later)
    save_url_states(url_states_file_path, url_states)

    # Convert set back to list for filtering
    all_extracted_channels_list = list(all_extracted_channels)
    logging.info(f"\nExtracted {len(all_extracted_channels_list)} raw channels from all sources.")

    # 4. Filter and clean channel names
    # This is where the pre-screening for individual channel URLs happens
    filtered_channels = filter_and_modify_channels(all_extracted_channels_list)
    unique_filtered_channels = list(set(filtered_channels)) # Use set to ensure uniqueness again
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]

    logging.info(f"\nAfter filtering and cleaning, {len(unique_filtered_channels_str)} unique channels remain.")

    # 5. Multi-threaded channel validity and speed check
    logging.info("Starting multi-threaded channel validity and speed detection...")
    valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
    logging.info(f"Number of valid and responsive channels: {len(valid_channels_with_speed)}")

    # Write channels with speed to iptv_speed.txt
    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_sorted_channels_to_file(iptv_speed_file_path, valid_channels_with_speed)
    for elapsed_time, result in valid_channels_with_speed:
        channel_name, channel_url = result.split(',', 1)
        logging.debug(f"Check successful: {channel_name},{channel_url} response time: {elapsed_time:.0f} ms")

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
            logging.info(f"Sorted '{template_name}' channels by number.")

        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.info(f"Channel list written to: '{template_name}_iptv.txt', containing {len(current_template_matched_channels)} channels.")

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
    logging.info(f"\nUnmatched but detected channel list saved to: '{unmatched_output_file_path}', total {len(unmatched_channels_list)} channels.")

    # Cleanup temporary files
    try:
        if os.path.exists('iptv.txt'):
            os.remove('iptv.txt')
            logging.info(f"Temporary file 'iptv.txt' deleted.")
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.info(f"Temporary file 'iptv_speed.txt' deleted.")
    except OSError as e:
        logging.warning(f"Error deleting temporary files: {e}")

if __name__ == "__main__":
    main()
