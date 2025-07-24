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

# Get configuration from environment variables
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')
IPTV_LIST_PATH = "iptv_list.txt" # Define the path for iptv_list.txt

# Check if environment variables are set
if not GITHUB_TOKEN:
    logging.error("Error: Environment variable 'BOT' not set.")
    exit(1)
if not REPO_OWNER:
    logging.error("Error: Environment variable 'REPO_OWNER' not set.")
    exit(1)
if not REPO_NAME:
    logging.error("Error: Environment variable 'REPO_NAME' not set.")
    exit(1)
if not CONFIG_PATH_IN_REPO:
    logging.error("Error: Environment variable 'CONFIG_PATH' not set.")
    exit(1)
if not URLS_PATH_IN_REPO:
    logging.error("Error: Environment variable 'URLS_PATH' not set.")
    exit(1)
if not URL_STATES_PATH_IN_REPO:
    logging.error("Error: Environment variable 'URL_STATES_PATH' not set.")
    exit(1)

# GitHub repository base URLs
GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# --- GitHub file operations functions ---
def fetch_from_github(file_path_in_repo):
    """Fetch file content from GitHub repository."""
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
    """Get the current SHA of a file in the GitHub repository."""
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('sha')
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error getting SHA for {file_path_in_repo} (might not exist): {e}")
        return None

def save_to_github(file_path_in_repo, content, commit_message):
    """Save (create or update) content to GitHub repository."""
    api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}"
    sha = get_current_sha(file_path_in_repo)
    
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
        response = requests.put(api_url, headers=headers, json=payload)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error saving {file_path_in_repo} to GitHub: {e}")
        logging.error(f"GitHub API response: {response.text if 'response' in locals() else 'N/A'}")
        return False

def load_config():
    """Load and parse YAML configuration file from GitHub repository."""
    content = fetch_from_github(CONFIG_PATH_IN_REPO)
    if content:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"Error: Invalid YAML in remote config file '{CONFIG_PATH_IN_REPO}': {e}")
            exit(1)
        except Exception as e:
            logging.error(f"Error loading remote config file '{CONFIG_PATH_IN_REPO}': {e}")
            exit(1)
    logging.error(f"Could not load config from '{CONFIG_PATH_IN_REPO}' on GitHub.")
    exit(1)

# Load configuration
CONFIG = load_config()

# Get parameters from configuration
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
CHANNEL_FAIL_THRESHOLD = CONFIG.get('channel_fail_threshold', 5) # Threshold for channel cleanup in iptv_list.txt
URL_FAIL_THRESHOLD = CONFIG.get('url_fail_threshold', 5) # Threshold for URL cleanup in urls.txt
URL_RETENTION_HOURS = CONFIG.get('url_retention_hours', 72) # Hours to retain failed URLs in urls.txt

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

# --- Local file operations functions ---
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

def clean_url_params(url):
    """Clean URL parameters, keeping only scheme, netloc, and path."""
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    except ValueError as e:
        logging.debug(f"Failed to clean URL parameters: {url} - {e}")
        return url

# --- URL state management functions ---
def load_url_states_remote():
    """Load URL state JSON file from remote, and clean up expired states."""
    content = fetch_from_github(URL_STATES_PATH_IN_REPO)
    url_states = {}
    if content:
        try:
            url_states = json.loads(content)
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from remote '{URL_STATES_PATH_IN_REPO}': {e}. Starting with empty state.")
            return {}
    
    # Clean up expired states
    current_time = datetime.now()
    updated_url_states = {}
    for url, state in url_states.items():
        if 'last_checked' in state:
            try:
                last_checked_datetime = datetime.fromisoformat(state['last_checked'])
                if (current_time - last_checked_datetime).days < URL_STATE_EXPIRATION_DAYS:
                    updated_url_states[url] = state
                else:
                    logging.debug(f"Removing expired URL state: {url} (last checked on {state['last_checked']})")
            except ValueError:
                logging.warning(f"Could not parse last_checked timestamp for URL {url}: {state['last_checked']}, keeping its state.")
                updated_url_states[url] = state
        else: # If no last_checked, keep it for now or decide based on other criteria
            updated_url_states[url] = state
            
    return updated_url_states

def save_url_states_remote(url_states):
    """Save URL states to remote JSON file."""
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        success = save_to_github(URL_STATES_PATH_IN_REPO, content, "Update URL states")
        if not success:
            logging.error(f"Error saving remote URL states to '{URL_STATES_PATH_IN_REPO}'.")
    except Exception as e:
        logging.error(f"Error saving URL states to remote '{URL_STATES_PATH_IN_REPO}': {e}")

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
        for future in as_completed(futures):
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
    os.makedirs(local_channels_directory, exist_ok=True) # Added this line to fix FileNotFoundError

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
    files_to_merge_paths = []
    processed_files = set()

    for category in ORDERED_CATEGORIES:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files_in_dir and file_name not in processed_files:
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
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

# --- Remote TXT file operations functions ---
def read_txt_to_array_remote(file_path_in_repo):
    """Read content from a remote GitHub repository TXT file into an array."""
    content = fetch_from_github(file_path_in_repo)
    if content:
        lines = content.split('\n')
        return [line.strip() for line in lines if line.strip()]
    return []

def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message):
    """Write array content to a remote GitHub repository TXT file."""
    content = '\n'.join(data_array)
    success = save_to_github(file_path_in_repo, content, commit_message)
    if not success:
        logging.error(f"Failed to write data to remote '{file_path_in_repo}'.")

# --- GitHub URL auto-discovery function ---
def auto_discover_github_urls(urls_file_path_remote, github_token):
    """Automatically discover new IPTV source URLs from GitHub, and record URL counts per keyword."""
    if not github_token:
        logging.warning("Environment variable 'BOT' not set. Skipping GitHub URL auto-discovery.")
        return

    existing_urls = set(read_txt_to_array_remote(urls_file_path_remote))
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
                    logging.debug(f"No more results found on page {page} for keyword '{keyword}'.")
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    raw_url = None
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user = match.group(1)
                        repo = match.group(2)
                        branch = match.group(3)
                        file_path = match.group(4)
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}"
                    else:
                        logging.debug(f"Could not parse raw URL from html_url: {html_url}")
                        continue

                    if raw_url and raw_url not in existing_urls and raw_url not in found_urls:
                        # Check content for .m3u or .m3u8 patterns
                        content_check_success = False
                        try:
                            content_response = session.get(raw_url, timeout=5)
                            content_response.raise_for_status()
                            content = content_response.text
                            if re.search(r'#EXTM3U', content, re.IGNORECASE) or re.search(r'\.(m3u8|m3u)$', raw_url, re.IGNORECASE):
                                found_urls.add(raw_url)
                                keyword_found_urls.add(raw_url)
                                logging.debug(f"Found new IPTV source URL: {raw_url}")
                                content_check_success = True
                            else:
                                logging.debug(f"URL {raw_url} does not contain M3U content and is not an M3U file extension. Skipping.")
                        except requests.exceptions.RequestException as req_e:
                            logging.debug(f"Error fetching raw content for {raw_url}: {req_e}")
                        except Exception as exc:
                            logging.debug(f"Unexpected error during content check for {raw_url}: {exc}")
                
                logging.debug(f"Finished page {page} for keyword '{keyword}'. Found {len(keyword_found_urls)} new URLs.")
                page += 1

            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                    logging.error(f"GitHub API rate limit exceeded or access forbidden for keyword '{keyword}'. Error: {e}")
                    # Attempt to parse rate limit headers to wait if possible
                    rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                    rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
                    if rate_limit_remaining == 0:
                        wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                        logging.warning(f"Rate limit hit for keyword '{keyword}'. Waiting {wait_seconds:.0f} seconds.")
                        time.sleep(wait_seconds)
                        continue # Retry current page after wait
                else:
                    logging.error(f"Error searching GitHub for keyword '{keyword}': {e}")
                break # Exit loop for current keyword on other errors
            except Exception as e:
                logging.error(f"An unexpected error occurred during GitHub search for keyword '{keyword}': {e}")
                break # Exit loop for current keyword on unexpected errors
        
        keyword_url_counts[keyword] = len(keyword_found_urls) # Record count for current keyword
    
    # Save newly found URLs to the remote urls.txt file
    if found_urls:
        updated_urls = sorted(list(existing_urls | found_urls))
        logging.warning(f"Discovered {len(found_urls)} new unique URLs. Total URLs to save: {len(updated_urls)}.")
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "Add new discovered IPTV URLs")
    else:
        logging.warning("No new IPTV source URLs discovered.")
    
    for keyword, count in keyword_url_counts.items():
        logging.warning(f"Keyword '{keyword}' discovered {count} new URLs.")

# --- URL cleanup function ---
def cleanup_urls_remote(urls_file_path_remote, url_states):
    """Clean up invalid/failed URLs from the remote urls.txt based on URL_FAIL_THRESHOLD and URL_RETENTION_HOURS."""
    all_urls = read_txt_to_array_remote(urls_file_path_remote)
    
    current_time = datetime.now()
    urls_to_keep = []
    removed_count = 0

    for url in all_urls:
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        last_failed_time_str = state.get('stream_check_failed_at')

        remove_url = False
        if fail_count > URL_FAIL_THRESHOLD:
            if last_failed_time_str:
                try:
                    last_failed_datetime = datetime.fromisoformat(last_failed_time_str)
                    if (current_time - last_failed_datetime).total_seconds() / 3600 > URL_RETENTION_HOURS:
                        remove_url = True
                        logging.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) and retention period ({URL_RETENTION_HOURS}h) exceeded.")
                except ValueError:
                    logging.warning(f"Could not parse last_failed timestamp for URL {url}: {last_failed_time_str}, keeping it for now.")
            else: # If fail_count is high but no last_failed_time, remove immediately
                remove_url = True
                logging.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) with no last_failed_at timestamp.")

        if not remove_url:
            urls_to_keep.append(url)
        else:
            removed_count += 1
            url_states.pop(url, None) # Also remove from states if cleaned up from urls.txt

    if removed_count > 0:
        logging.warning(f"Cleaned up {removed_count} URLs from {urls_file_path_remote}.")
        write_array_to_txt_remote(urls_file_path_remote, urls_to_keep, f"Cleaned up {removed_count} failed URLs")
    else:
        logging.warning("No URLs needed cleanup from urls.txt.")

# --- Main logic ---
def main():
    logging.warning("Starting IPTV processing script...")
    
    # Step 1: Load URL states (includes cleanup of expired states)
    url_states = load_url_states_remote()
    logging.warning("URL states loaded and expired states cleaned.")

    # Step 2: Auto-discover new URLs from GitHub (only if BOT token is set)
    # This function internally handles reading existing URLs and writing updated ones
    auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)
    logging.warning("Auto-discovery of GitHub URLs completed.")

    # Step 3: Cleanup urls.txt based on failure thresholds and retention
    cleanup_urls_remote(URLS_PATH_IN_REPO, url_states)
    logging.warning("Remote URLs cleaned up based on failure thresholds.")

    # Step 4: Get all URLs from the remote urls.txt after discovery and cleanup
    all_urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
    logging.warning(f"Total URLs to process: {len(all_urls)}")

    # Step 5: Process all URLs and extract channels in parallel
    raw_channels = []
    urls_to_process_for_extraction = []
    # Filter URLs that haven't been checked for content recently or whose content_hash changed
    # The fetch_url_content_with_retry will handle 304/content_hash skipping
    
    # Create temp_channels directory if it doesn't exist
    os.makedirs("temp_channels", exist_ok=True) # Ensure this directory exists before writing to it.

    logging.warning("Starting multithreaded URL content fetching and channel extraction...")
    with ThreadPoolExecutor(max_workers=CONFIG.get('url_fetch_workers', 10)) as executor:
        futures = {executor.submit(extract_channels_from_url, url, url_states): url for url in all_urls}
        for i, future in enumerate(as_completed(futures)):
            if i % 10 == 0:
                logging.warning(f"Processed {i}/{len(all_urls)} URLs for channel extraction...")
            try:
                channels = future.result()
                if channels:
                    raw_channels.extend(channels)
            except Exception as exc:
                logging.error(f"Error processing URL for channel extraction: {exc}")
    logging.warning(f"Finished URL content fetching and channel extraction. Total raw channels extracted: {len(raw_channels)}.")

    # Step 6: Filter and modify channels based on configuration
    filtered_channels = filter_and_modify_channels(raw_channels)
    logging.warning(f"Channels filtered and modified. Remaining channels: {len(filtered_channels)}.")

    # Step 7: Write channels to categorized _iptv.txt files in temp_channels directory
    categorized_channels = {category: [] for category in ORDERED_CATEGORIES + ['其他']}
    for name, url in filtered_channels:
        assigned_category = '其他'
        for category in ORDERED_CATEGORIES:
            if category.lower() in name.lower():
                assigned_category = category
                break
        categorized_channels[assigned_category].append((name, url))

    for category, channels in categorized_channels.items():
        if channels:
            file_path = os.path.join("temp_channels", f"{category}_iptv.txt")
            sorted_channels = sorted(list(set(channels)), key=lambda x: x[0]) # Deduplicate and sort
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(generate_update_time_header())
                for name, url in sorted_channels:
                    f.write(f"{name},{url}\n")
            logging.debug(f"Saved {len(sorted_channels)} channels to {file_path}")
    logging.warning("Categorized channels saved to temporary files.")

    # Step 8: Merge and validate channels into iptv_list.txt (existing logic)
    logging.warning(f"Starting to merge and validate channels into {IPTV_LIST_PATH}...")
    merge_local_channel_files("temp_channels", IPTV_LIST_PATH, url_states)

    # Step 9: Save all channel check states again after iptv_list.txt processing
    save_url_states_remote(url_states)
    logging.warning("Final channel check states saved to remote.")

    # Step 10: Clean up temporary files (existing logic)
    try:
        if os.path.exists('iptv.txt'): # This file is not generated in the current script, might be legacy
            os.remove('iptv.txt')
            logging.debug(f"Removed temporary file 'iptv.txt'.")
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.debug(f"Removed temporary file 'iptv_speed.txt'.")
        # Clean up _iptv.txt files in temp_channels directory
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
    except Exception as e:
        logging.error(f"Error during temporary file cleanup: {e}")
    logging.warning("Temporary files cleanup completed.")
    logging.warning("Script finished.")

if __name__ == "__main__":
    main()
