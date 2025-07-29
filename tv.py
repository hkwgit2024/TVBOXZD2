import os
import re
import subprocess
import socket
import time
from datetime import datetime, timedelta
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
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define local configuration and data file paths
CONFIG_FILE_PATH = "config/config.yaml"
URL_STATES_FILE_PATH = "config/url_states.json"
URLS_FILE_PATH = "config/urls.txt"
IPTV_LIST_PATH = "iptv_list.txt"
UNCATEGORIZED_IPTV_PATH = "uncategorized_iptv.txt" # Ensure this is saved to root

# --- Local file operations for config/states/urls ---
def load_config():
    """Load and parse YAML configuration file from local path."""
    try:
        # Ensure the config directory exists
        os.makedirs(os.path.dirname(CONFIG_FILE_PATH), exist_ok=True)
        with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"Error: Config file '{CONFIG_FILE_PATH}' not found. Please create it.")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Error: Invalid YAML in config file '{CONFIG_FILE_PATH}': {e}")
        exit(1)
    except Exception as e:
        logging.error(f"Error loading config file '{CONFIG_FILE_PATH}': {e}")
        exit(1)

def load_url_states_local():
    """Load URL state JSON file from local, and clean up expired states."""
    url_states = {}
    try:
        # Ensure the config directory exists
        os.makedirs(os.path.dirname(URL_STATES_FILE_PATH), exist_ok=True)
        with open(URL_STATES_FILE_PATH, 'r', encoding='utf-8') as file:
            url_states = json.load(file)
    except FileNotFoundError:
        logging.warning(f"URL states file '{URL_STATES_FILE_PATH}' not found. Starting with empty state.")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from '{URL_STATES_FILE_PATH}': {e}. Starting with empty state.")
        return {}
    
    # Clean up expired states
    current_time = datetime.now()
    updated_url_states = {}
    for url, state in url_states.items():
        if 'last_checked' in state:
            try:
                last_checked_datetime = datetime.fromisoformat(state['last_checked'])
                if (current_time - last_checked_datetime).days < CONFIG.get('url_state_expiration_days', 90):
                    updated_url_states[url] = state
                else:
                    logging.debug(f"Removing expired URL state: {url} (last checked on {state['last_checked']})")
            except ValueError:
                logging.warning(f"Could not parse last_checked timestamp for URL {url}: {state['last_checked']}, keeping its state.")
                updated_url_states[url] = state
        else: # If no last_checked, keep it for now or decide based on other criteria
            updated_url_states[url] = state
            
    return updated_url_states

def save_url_states_local(url_states):
    """Save URL states to local JSON file."""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(URL_STATES_FILE_PATH), exist_ok=True)
        with open(URL_STATES_FILE_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
        logging.debug(f"Successfully saved URL states to '{URL_STATES_FILE_PATH}'.")
    except Exception as e:
        logging.error(f"Error saving URL states to local '{URL_STATES_FILE_PATH}': {e}")

def read_txt_to_array_local_urls():
    """Read content from a local TXT file (urls.txt) into an array."""
    try:
        # Ensure the config directory exists
        os.makedirs(os.path.dirname(URLS_FILE_PATH), exist_ok=True)
        with open(URLS_FILE_PATH, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        lines = [line.strip() for line in lines if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"File '{URLS_FILE_PATH}' not found. Returning empty list.")
        return []
    except Exception as e:
        logging.error(f"Error reading file '{URLS_FILE_PATH}': {e}")
        return []

def write_array_to_txt_local_urls(data_array):
    """Write array content to a local TXT file (urls.txt)."""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(URLS_FILE_PATH), exist_ok=True)
        with open(URLS_FILE_PATH, 'w', encoding='utf-8') as file:
            file.write('\n'.join(data_array))
        logging.debug(f"Successfully wrote data to local '{URLS_FILE_PATH}'.")
    except Exception as e:
        logging.error(f"Error writing data to local '{URLS_FILE_PATH}': {e}")


# Load configuration from local config.yaml
CONFIG = load_config()

# Get GITHUB_TOKEN from environment variable (passed by GitHub Actions)
GITHUB_TOKEN = os.getenv('BOT')

# Get other parameters from configuration
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
STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24)
URL_STATE_EXPIRATION_DAYS = CONFIG.get('url_state_expiration_days', 90)

# New configuration parameters for URL and channel cleanup
CHANNEL_FAIL_THRESHOLD = CONFIG.get('channel_fail_threshold', 5)
URL_FAIL_THRESHOLD = CONFIG.get('url_fail_threshold', 5)
URL_RETENTION_HOURS = CONFIG.get('url_retention_hours', 72)

# Configure requests session
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

# --- Local file operations functions (general) ---
def read_txt_to_array_local(file_name):
    """Read content from a local TXT file into an array."""
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

def read_existing_channels(file_path):
    """Read existing channel (name, URL) combinations from a file for deduplication."""
    existing_channels = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ',' in line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        name, url = parts
                        existing_channels.add((name.strip(), url.strip()))
    except FileNotFoundError:
        pass  # Return empty set if file not found
    except Exception as e:
        logging.error(f"Error reading file '{file_path}' for deduplication: {e}")
    return existing_channels

def write_sorted_channels_to_file(file_path, data_list):
    """Append sorted channel data to a file, with deduplication."""
    existing_channels = read_existing_channels(file_path)
    new_channels = set()
    
    for _, line in data_list:
        if ',' in line:
            name, url = line.split(',', 1)
            new_channels.add((name.strip(), url.strip()))
    
    all_channels = existing_channels | new_channels
    
    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            for name, url in all_channels:
                if (name, url) not in existing_channels:
                    file.write(f"{name},{url}\n")
        logging.debug(f"Appended {len(all_channels - existing_channels)} new channels to {file_path}")
    except Exception as e:
        logging.error(f"Error appending to file '{file_path}': {e}")

# --- URL processing and channel extraction functions ---
def get_url_file_extension(url):
    """Get the file extension from a URL."""
    try:
        parsed_url = urlparse(url)
        extension = os.path.splitext(parsed_url.path)[1].lower()
        return extension
    except ValueError as e:
        logging.debug(f"Failed to get URL extension: {url} - {e}")
        return ""

def convert_m3u_to_txt(m3u_content):
    """Convert M3U format content to TXT format (channel name,URL)."""
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

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, url_states):
    """Attempt to fetch URL content with retry mechanism, and use ETag/Last-Modified/Content-Hash to avoid re-download."""
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
            logging.debug(f"URL content {url} not modified (304). Skipping download.")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            logging.debug(f"URL content {url} is same based on hash. Skipping download.")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            return None

        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        }

        logging.debug(f"Successfully fetched new content for URL: {url}. Content updated.")
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error fetching URL (after retries): {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"Unknown error fetching URL: {url} - {e}")
        return None

def extract_channels_from_url(url, url_states):
    """Extract channels from the given URL."""
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
                if len(parts) != 2:
                    logging.debug(f"Skipping invalid channel line (malformed): {line}")
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip()
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    logging.debug(f"Skipping invalid channel URL (no valid protocol): {line}")
                    continue

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                            channel_count += 1
                        else:
                            logging.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}")
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
                        channel_count += 1
                    else:
                        logging.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}")
        logging.debug(f"Successfully extracted {channel_count} channels from URL: {url}.")
    except Exception as e:
        logging.error(f"Error extracting channels from {url}: {e}")
    return extracted_channels

def pre_screen_url(url):
    """Pre-screen URLs based on configuration for protocol, length, and invalid patterns."""
    if not isinstance(url, str) or not url:
        logging.debug(f"Pre-screening filtered (invalid type or empty): {url}")
        return False

    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        logging.debug(f"Pre-screening filtered (no valid protocol): {url}")
        return False

    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        logging.debug(f"Pre-screening filtered (contains illegal characters or spaces): {url}")
        return False

    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
            logging.debug(f"Pre-screening filtered (unsupported protocol): {url}")
            return False

        if not parsed_url.netloc:
            logging.debug(f"Pre-screening filtered (no network location): {url}")
            return False

        invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                logging.debug(f"Pre-screening filtered (invalid pattern): {url}")
                return False

        if len(url) < 15:
            logging.debug(f"Pre-screening filtered (URL too short): {url}")
            return False

        return True
    except ValueError as e:
        logging.debug(f"Pre-screening filtered (URL parse error): {url} - {e}")
        return False

def filter_and_modify_channels(channels):
    """Filter and modify channel names and URLs."""
    filtered_channels = []
    pre_screened_count = 0
    for name, url in channels:
        if not pre_screen_url(url):
            logging.debug(f"Filtering channel (pre-screening failed): {name},{url}")
            continue
        pre_screened_count += 1

        if any(word in url for word in CONFIG.get('url_filter_words', [])):
            logging.debug(f"Filtering channel (URL matches blacklist): {name},{url}")
            continue

        if any(word.lower() in name.lower() for word in CONFIG.get('name_filter_words', [])):
            logging.debug(f"Filtering channel (name matches blacklist): {name},{url}")
            continue

        for old_str, new_str in CONFIG.get('channel_name_replacements', {}).items():
            name = name.replace(old_str, new_str)
        filtered_channels.append((name, url))
    logging.debug(f"After URL pre-screening, {pre_screened_count} channels remain for further filtering.")
    return filtered_channels

# --- Channel validity check functions ---
def check_http_url(url, timeout):
    """Check if HTTP/HTTPS URL is reachable."""
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} check failed: {e}")
        return False

def check_rtmp_url(url, timeout):
    """Check if RTMP URL is reachable (requires ffprobe)."""
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
    """Check if RTP URL is reachable (by attempting UDP connection)."""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.debug(f"RTP URL {url} parse failed: missing host or port.")
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
    """Check if P3P URL is reachable (simple TCP connection and HTTP response header check)."""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'

        if not host:
            logging.debug(f"P3P URL {url} parse failed: missing host.")
            return False

        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} check failed: {e}")
        return False

def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT):
    """Check single channel's validity and speed, and record failure status for skipping."""
    current_time = datetime.now()
    current_url_state = url_states.get(url, {})

    if 'stream_check_failed_at' in current_url_state:
        last_failed_time_str = current_url_state['stream_check_failed_at']
        try:
            last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
            time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600
            if time_since_failed_hours < STREAM_SKIP_FAILED_HOURS:
                logging.debug(f"Skipping channel {channel_name} ({url}) as it failed within cooldown period ({STREAM_SKIP_FAILED_HOURS}h). Last failed at {last_failed_time_str}, {time_since_failed_hours:.2f}h ago.")
                return None, False
        except ValueError:
            logging.warning(f"Could not parse failed timestamp for URL {url}: {last_failed_time_str}")
            pass

    start_time = time.time()
    is_valid = False
    protocol_checked = False

    try:
        if url.startswith("http"):
            is_valid = check_http_url(url, timeout)
            protocol_checked = True
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, timeout)
            protocol_checked = True
        elif url.startswith("rtmp"):
            is_valid = check_rtmp_url(url, timeout)
            protocol_checked = True
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, timeout)
            protocol_checked = True
        else:
            logging.debug(f"Channel {channel_name}'s protocol is not supported: {url}")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat()
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            return None, False

        elapsed_time = (time.time() - start_time) * 1000

        if is_valid:
            if url not in url_states:
                url_states[url] = {}
            url_states[url].pop('stream_check_failed_at', None)
            url_states[url].pop('stream_fail_count', None)
            url_states[url]['last_successful_stream_check'] = current_time.isoformat()
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.debug(f"Channel {channel_name} ({url}) check successful, took {elapsed_time:.0f} ms.")
            return elapsed_time, True
        else:
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['stream_check_failed_at'] = current_time.isoformat()
            url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
            url_states[url]['last_stream_checked'] = current_time.isoformat()
            logging.debug(f"Channel {channel_name} ({url}) check failed.")
            return None, False
    except Exception as e:
        if url not in url_states:
            url_states[url] = {}
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1
        url_states[url]['last_stream_checked'] = current_time.isoformat()
        logging.debug(f"Error checking channel {channel_name} ({url}): {e}")
        return None, False

def process_single_channel_line(channel_line, url_states):
    """Process a single channel line for validity check."""
    if "://" not in channel_line:
        logging.debug(f"Skipping invalid channel line (no protocol): {channel_line}")
        return None, None
    parts = channel_line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG.get('channel_check_workers', 200)):
    """Check channel validity using multithreading."""
    results = []
    checked_count = 0
    total_channels = len(channel_lines)
    logging.warning(f"Starting multithreaded channel validity and speed detection for {total_channels} channels...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines}
        for i, future in enumerate(as_completed(futures)):
            checked_count += 1
            if checked_count % 100 == 0:
                logging.warning(f"Checked {checked_count}/{total_channels} channels...")
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"Exception occurred during channel line processing: {exc}")
    return results

# --- File merge and sort functions ---
def generate_update_time_header():
    """Generate update time information for the top of the file."""
    now = datetime.now()
    return [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]

def group_and_limit_channels(lines):
    """Group channels and limit the number of URLs under each channel name."""
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

def merge_local_channel_files(local_channels_directory, output_file_name="iptv_list.txt", url_states=None):
    """Merge locally generated channel list files, with deduplication and cleanup based on url_states."""
    # Ensure the local_channels_directory exists
    os.makedirs(local_channels_directory, exist_ok=True)
    
    existing_channels_data = [] # To store (name, url) for channels from current iptv_list.txt
    # Read existing iptv_list.txt channels
    if os.path.exists(output_file_name):
        with open(output_file_name, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line and '#genre#' not in line:
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        existing_channels_data.append((parts[0].strip(), parts[1].strip()))

    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    # MODIFICATION: Also include the uncategorized_iptv.txt from the root directory
    uncategorized_file_in_root = UNCATEGORIZED_IPTV_PATH # Use the constant
    if os.path.exists(uncategorized_file_in_root):
        all_iptv_files_in_dir.append(uncategorized_file_in_root)

    files_to_merge_paths = []
    processed_files = set()
    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        # Check both in temp_channels and root (for 'uncategorized')
        temp_path = os.path.join(local_channels_directory, file_name)
        root_path = file_name # For 'uncategorized_iptv.txt'
        
        if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files:
            files_to_merge_paths.append(temp_path)
            processed_files.add(os.path.basename(temp_path))
        elif category == 'uncategorized' and os.path.basename(root_path) in all_iptv_files_in_dir and root_path not in processed_files:
            files_to_merge_paths.append(root_path)
            processed_files.add(os.path.basename(root_path))

    for file_name in sorted(all_iptv_files_in_dir): # Now `all_iptv_files_in_dir` contains full paths or just filenames for root
        if file_name not in processed_files:
            if os.path.basename(file_name) == uncategorized_file_in_root:
                files_to_merge_paths.append(uncategorized_file_in_root)
            else:
                files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    new_channels_from_merged_files = set()
    for file_path in files_to_merge_paths:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                continue
            for line in lines:
                line = line.strip()
                if line and ',' in line and '#genre#' not in line:
                    name, url = line.split(',', 1)
                    new_channels_from_merged_files.add((name.strip(), url.strip()))

    # Combine existing and new channels
    combined_channels = existing_channels_data + list(new_channels_from_merged_files)

    # Deduplicate and filter based on stream_fail_count
    final_channels_for_output = set()
    channels_for_checking = [] # Channels that will be checked for validity

    # First, add all channels (new and existing) to a list for checking
    # We use a set to avoid processing duplicate (name, url) combinations multiple times for checking
    unique_channels_to_check = set()
    for name, url in combined_channels:
        unique_channels_to_check.add((name, url))

    # Convert to list of strings for multithreaded checking
    channels_for_checking_lines = [f"{name},{url}" for name, url in unique_channels_to_check]
    logging.warning(f"Total unique channels to check and filter for {output_file_name}: {len(channels_for_checking_lines)}")

    # Perform validity check on all combined unique channels
    # The check_channels_multithreaded function will update url_states for these URLs
    # and return only the currently valid ones.
    valid_channels_from_check = check_channels_multithreaded(channels_for_checking_lines, url_states)

    # Now, filter based on updated url_states and CHANNEL_FAIL_THRESHOLD
    for elapsed_time, channel_line in valid_channels_from_check:
        name, url = channel_line.split(',', 1)
        url = url.strip()
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        if fail_count <= CHANNEL_FAIL_THRESHOLD:
            final_channels_for_output.add((name, url))
        else:
            logging.info(f"Removing channel '{name},{url}' from {output_file_name} due to excessive failures ({fail_count} > {CHANNEL_FAIL_THRESHOLD}).")

    # Sort all_channels before writing to ensure consistent output
    sorted_final_channels = sorted(list(final_channels_for_output), key=lambda x: x[0])

    # Rewrite the entire file instead of appending, to ensure order and cleanliness
    try:
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(generate_update_time_header())
            for name, url in sorted_final_channels:
                iptv_list_file.write(f"{name},{url}\n")
        logging.warning(f"\nAll regional channel list files merged, deduplicated, and cleaned. Output saved to: {output_file_name}")
    except Exception as e:
        logging.error(f"Error appending write to file '{output_file_name}': {e}")


# --- GitHub URL auto-discovery function ---
def auto_discover_github_urls(github_token):
    """Automatically discover new IPTV source URLs from GitHub, and record URL counts per keyword."""
    if not github_token:
        logging.warning("GitHub token not set in environment variable 'BOT'. Skipping GitHub URL auto-discovery.")
        return

    existing_urls = set(read_txt_to_array_local_urls())
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }
    logging.warning("Starting automatic discovery of new IPTV source URLs from GitHub...")
    keyword_url_counts = {keyword: 0 for keyword in SEARCH_KEYWORDS}

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        keyword_found_urls = set()
        if i > 0:
            logging.warning(f"Switching to next keyword: '{keyword}'. Waiting {GITHUB_API_RETRY_WAIT} seconds to avoid rate limits...")
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
                search_url = f"https://api.github.com/search/code"
                response = requests.get(search_url, headers=headers, params=params, timeout=GITHUB_API_TIMEOUT)
                response.raise_for_status()
                search_results = response.json()

                for item in search_results.get("items", []):
                    try:
                        repo_owner = item['repository']['owner']['login']
                        repo_name = item['repository']['name']
                        file_path = item['path']
                        # Construct the raw content URL
                        raw_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/main/{file_path}"
                        if raw_url not in existing_urls and raw_url not in found_urls:
                            found_urls.add(raw_url)
                            keyword_found_urls.add(raw_url)
                    except KeyError as ke:
                        logging.debug(f"Skipping search result due to missing key: {ke} in item {item}")
                        continue
                
                # Check for rate limit and next page
                if 'Link' in response.headers:
                    links = requests.utils.parse_header_links(response.headers['Link'])
                    next_page = None
                    for link in links:
                        if link['rel'] == 'next':
                            next_page = re.search(r'page=(\d+)', link['url'])
                            if next_page:
                                page = int(next_page.group(1))
                                logging.debug(f"Found next page for keyword '{keyword}': {page}")
                                break
                    if not next_page:
                        logging.debug(f"No next page found for keyword '{keyword}'.")
                        break
                else:
                    break # No Link header, so no more pages

            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API request error for keyword '{keyword}': {e}")
                if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers and int(response.headers['X-RateLimit-Remaining']) == 0:
                    reset_time = int(response.headers['X-RateLimit-Reset'])
                    sleep_time = max(0, reset_time - int(time.time()) + 5) # Add 5 seconds buffer
                    logging.warning(f"GitHub API rate limit exceeded. Sleeping for {sleep_time} seconds until reset.")
                    time.sleep(sleep_time)
                break # Exit loop on error
            except Exception as e:
                logging.error(f"Error processing GitHub search results for keyword '{keyword}': {e}")
                break # Exit loop on error
        
        keyword_url_counts[keyword] = len(keyword_found_urls)
        logging.warning(f"Found {len(keyword_found_urls)} new URLs for keyword '{keyword}'.")

    all_urls = sorted(list(existing_urls | found_urls))
    write_array_to_txt_local_urls(all_urls) # Save the combined URLs to the local urls.txt
    logging.warning(f"Finished GitHub URL auto-discovery. Total unique URLs found: {len(found_urls)}. Total URLs after merge: {len(all_urls)}.")
    logging.warning("Keyword URL counts: " + str(keyword_url_counts))


def cleanup_temp_files():
    """Clean up temporary files created during the process."""
    logging.info("Starting temporary file cleanup...")
    temp_dir = "temp_channels"
    if os.path.exists(temp_dir):
        for f_name in os.listdir(temp_dir):
            if f_name.endswith('_iptv.txt'):
                os.remove(os.path.join(temp_dir, f_name))
                logging.debug(f"Removed temporary channel file '{f_name}'.")
        # Optionally remove the directory if it's empty
        if not os.listdir(temp_dir):
            os.rmdir(temp_dir)
            logging.debug(f"Removed empty directory '{temp_dir}'.")
    
    # Also clean up the 'uncategorized_iptv.txt' from the root if it was created
    if os.path.exists(UNCATEGORIZED_IPTV_PATH):
        os.remove(UNCATEGORIZED_IPTV_PATH)
        logging.debug(f"Removed '{UNCATEGORIZED_IPTV_PATH}' from root directory.")
    logging.info("Temporary file cleanup finished.")


def main():
    logging.info("Starting IPTV channel processing...")

    # Load URL states
    url_states = load_url_states_local()

    # Auto-discover URLs
    auto_discover_github_urls(GITHUB_TOKEN)

    # Read URLs for processing
    urls_to_process = read_txt_to_array_local_urls()

    all_extracted_channels = []
    
    with ThreadPoolExecutor(max_workers=CONFIG.get('url_fetch_workers', 10)) as executor:
        futures = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls_to_process}
        for i, future in enumerate(as_completed(futures)):
            url = futures[future]
            logging.info(f"Processing URL {i+1}/{len(urls_to_process)}: {url}")
            try:
                extracted_channels = future.result()
                all_extracted_channels.extend(extracted_channels)
            except Exception as exc:
                logging.error(f"Error processing URL {url}: {exc}")

    logging.info(f"Extracted {len(all_extracted_channels)} channels from all URLs.")

    # Filter and modify channels
    filtered_channels = filter_and_modify_channels(all_extracted_channels)
    logging.info(f"After filtering, {len(filtered_channels)} channels remain.")

    # Group and limit channels (this will be used to create temp files per category)
    grouped_lines = group_and_limit_channels([f"{name},{url}" for name, url in filtered_channels])

    # Save channels to temporary categorized files
    temp_channels_dir = "temp_channels"
    os.makedirs(temp_channels_dir, exist_ok=True)
    
    categorized_channels = {}
    uncategorized_lines = []

    for line in grouped_lines:
        line = line.strip()
        if not line:
            continue
        name, url = line.split(',', 1)
        name = name.strip()
        url = url.strip()

        found_category = False
        for category in ORDERED_CATEGORIES:
            if category.lower() in name.lower():
                if category not in categorized_channels:
                    categorized_channels[category] = []
                categorized_channels[category].append(f"{name},{url}\n")
                found_category = True
                break
        if not found_category:
            uncategorized_lines.append(f"{name},{url}\n")

    for category, lines in categorized_channels.items():
        file_path = os.path.join(temp_channels_dir, f"{category}_iptv.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        logging.info(f"Saved {len(lines)} channels to {file_path}")

    # Save uncategorized channels to the root directory
    if uncategorized_lines:
        with open(UNCATEGORIZED_IPTV_PATH, "w", encoding="utf-8") as f:
            f.writelines(uncategorized_lines)
        logging.info(f"Saved {len(uncategorized_lines)} uncategorized channels to {UNCATEGORIZED_IPTV_PATH}")


    # Merge and clean up all local channel files into iptv_list.txt
    merge_local_channel_files(temp_channels_dir, IPTV_LIST_PATH, url_states)

    # Save updated URL states
    save_url_states_local(url_states)

    # Clean up temporary files
    cleanup_temp_files()

    logging.info("IPTV channel processing finished.")

if __name__ == "__main__":
    # Ensure GITHUB_TOKEN is available as an environment variable
    if not os.getenv('BOT'):
        logging.error("Error: Environment variable 'BOT' (GitHub Token) not set. It's required for auto-discovery.")
        exit(1)
    main()
