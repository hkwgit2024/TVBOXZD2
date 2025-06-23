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
from tenacity import retry, stop_after_attempt, wait_fixed, wait_exponential, retry_if_exception_type
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
import base64

# Configure logging with DEBUG level for detailed diagnostics
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Get configuration from environment variables
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')
IPTV_LIST_PATH = "iptv_list.txt"

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
        pass
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
        else:
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
        if response.status_code == 404:
            logging.error(f"URL {url} returned 404 Not Found. Marking as failed.")
            if url not in url_states:
                url_states[url] = {}
            url_states[url]['last_checked'] = datetime.now().isoformat()
            url_states[url]['fetch_fail_count'] = current_state.get('fetch_fail_count', 0) + 1
            return None
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
            'last_checked': datetime.now().isoformat(),
            'fetch_fail_count': 0
        }

        logging.debug(f"Successfully fetched new content for URL: {url}. Content updated.")
        return content

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error fetching URL (after retries): {url} - {e}")
        if url not in url_states:
            url_states[url] = {}
        url_states[url]['last_checked'] = datetime.now().isoformat()
        url_states[url]['fetch_fail_count'] = current_state.get('fetch_fail_count', 0) + 1
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
            logging.debug(f"No content fetched from {url}, skipping channel extraction.")
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
        logging.debug(f"Extracted {channel_count} channels from URL: {url}.")
        return extracted_channels
    except Exception as e:
        logging.error(f"Error extracting channels from {url}: {e}")
        return []

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
    if not os.path.exists(local_channels_directory):
        os.makedirs(local_channels_directory)
        logging.warning(f"Created directory '{local_channels_directory}' as it did not exist.")
    
    existing_channels_data = []
    if os.path.exists(output_file_name):
        with open(output_file_name, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line and '#genre#' not in line:
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        existing_channels_data.append((parts[0].strip(), parts[1].strip()))

    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    
    if not all_iptv_files_in_dir:
        logging.warning(f"No '_iptv.txt' files found in '{local_channels_directory}'. Writing existing channels to {output_file_name}.")
        try:
            with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
                iptv_list_file.writelines(generate_update_time_header())
                for name, url in sorted(existing_channels_data, key=lambda x: x[0]):
                    iptv_list_file.write(f"{name},{url}\n")
            logging.warning(f"Output saved to {output_file_name} with {len(existing_channels_data)} existing channels.")
        except Exception as e:
            logging.error(f"Error writing to file '{output_file_name}': {e}")
        return

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

    combined_channels = existing_channels_data + list(new_channels_from_merged_files)
    
    unique_channels_to_check = set()
    for name, url in combined_channels:
        unique_channels_to_check.add((name, url))

    channels_for_checking_lines = [f"{name},{url}" for name, url in unique_channels_to_check]

    logging.warning(f"Total unique channels to check and filter for {output_file_name}: {len(channels_for_checking_lines)}")
    
    valid_channels_from_check = check_channels_multithreaded(channels_for_checking_lines, url_states)

    final_channels_for_output = set()
    for elapsed_time, channel_line in valid_channels_from_check:
        name, url = channel_line.split(',', 1)
        url = url.strip()
        state = url_states.get(url, {})
        fail_count = state.get('stream_fail_count', 0)
        
        if fail_count <= CHANNEL_FAIL_THRESHOLD:
            final_channels_for_output.add((name, url))
        else:
            logging.info(f"Removing channel '{name},{url}' from {output_file_name} due to excessive failures ({fail_count} > {CHANNEL_FAIL_THRESHOLD}).")

    sorted_final_channels = sorted(list(final_channels_for_output), key=lambda x: x[0])

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
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=60))
def fetch_github_search_page(url, headers, params, timeout):
    """Fetch GitHub search page with retry mechanism."""
    response = session.get(url, headers=headers, params=params, timeout=timeout)
    response.raise_for_status()
    return response

def auto_discover_github_urls(urls_file_path_remote, github_token):
    """Automatically discover new IPTV source URLs from GitHub."""
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
                response = fetch_github_search_page(
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                    headers=headers,
                    params=params,
                    timeout=GITHUB_API_TIMEOUT
                )
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
                        path = match.group(4)
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
                    if raw_url:
                        cleaned_url = clean_url_params(raw_url)
                        if cleaned_url.startswith("https://raw.githubusercontent.com/") and \
                           cleaned_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and \
                           pre_screen_url(cleaned_url):
                            found_urls.add(cleaned_url)
                            keyword_found_urls.add(cleaned_url)
                            logging.debug(f"Discovered raw GitHub URL (pre-screened): {cleaned_url}")
                        else:
                            logging.debug(f"Skipping non-raw GitHub M3U/M3U8/TXT link or failed pre-screening: {raw_url}")
                    else:
                        logging.debug(f"Could not construct raw URL from HTML URL: {html_url}")
                if len(data['items']) < PER_PAGE:
                    break
                page += 1
                time.sleep(2)
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
        keyword_url_counts[keyword] = len(keyword_found_urls)
        logging.warning(f"Keyword '{keyword}' found {keyword_url_counts[keyword]} valid URLs.")

    logging.warning("\n=== Keyword Search Results Summary ===")
    low_result_threshold = 5
    low_or_no_result_keywords = []
    for keyword, count in keyword_url_counts.items():
        logging.warning(f"Keyword '{keyword}': {count} URLs")
        if count <= low_result_threshold:
            low_or_no_result_keywords.append((keyword, count))

    if low_or_no_result_keywords:
        logging.warning(f"\nConsider removing the following keywords from config.yaml's search_keywords due to low or no results (≤{low_result_threshold}):")
        for keyword, count in low_or_no_result_keywords:
            logging.warning(f" - '{keyword}' (found {count} URLs)")
    else:
        logging.warning("All keywords have a reasonable number of search results, no removal suggested.")

    new_urls_count = 0
    for url in found_urls:
        if url not in existing_urls:
            existing_urls.add(url)
            new_urls_count += 1
    
    if new_urls_count > 0:
        updated_urls = list(existing_urls)
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "Update urls.txt with new URLs from GitHub discovery")
        logging.warning(f"Successfully discovered and added {new_urls_count} new GitHub IPTV source URLs to {urls_file_path_remote}. Total URLs: {len(updated_urls)}")
    else:
        logging.warning("No new GitHub IPTV source URLs discovered.")
    logging.warning("GitHub URL auto-discovery completed.")

def clean_urls_file_remote(urls_file_path_remote, url_states):
    """Cleans the remote urls.txt file by removing URLs that have consistently failed."""
    logging.warning(f"Starting cleanup of remote URLs file: {urls_file_path_remote}")
    current_urls = read_txt_to_array_remote(urls_file_path_remote)
    
    urls_to_keep = []
    current_time = datetime.now()
    removed_count = 0

    for url in current_urls:
        state = url_states.get(url, {})
        fetch_fail_count = state.get('fetch_fail_count', 0)
        stream_fail_count = state.get('stream_fail_count', 0)
        last_checked_time_str = state.get('last_stream_checked') or state.get('stream_check_failed_at') or state.get('last_checked')

        should_remove = False
        if fetch_fail_count > URL_FAIL_THRESHOLD or stream_fail_count > URL_FAIL_THRESHOLD:
            if last_checked_time_str:
                try:
                    last_checked_datetime = datetime.fromisoformat(last_checked_time_str)
                    time_since_checked_hours = (current_time - last_checked_datetime).total_seconds() / 3600
                    if time_since_checked_hours > URL_RETENTION_HOURS:
                        should_remove = True
                        logging.info(f"Removing URL '{url}' from {urls_file_path_remote} due to fetch failures ({fetch_fail_count}) or stream failures ({stream_fail_count}) and last check {time_since_checked_hours:.2f} hours ago (>{URL_RETENTION_HOURS}h retention).")
                except ValueError:
                    logging.warning(f"Could not parse last_checked time for URL '{url}', keeping it for now.")
            else:
                should_remove = True
                logging.info(f"Removing URL '{url}' from {urls_file_path_remote} due to {fetch_fail_count} fetch failures or {stream_fail_count} stream failures and no recent check time.")
        
        if not should_remove:
            urls_to_keep.append(url)
        else:
            removed_count += 1
            if url in url_states:
                del url_states[url]

    if removed_count > 0:
        write_array_to_txt_remote(urls_file_path_remote, urls_to_keep, f"Cleaned up {removed_count} failed URLs from urls.txt")
        logging.warning(f"Removed {removed_count} invalid URLs from {urls_file_path_remote}. Remaining URLs: {len(urls_to_keep)}")
    else:
        logging.warning(f"No invalid URLs found to remove from {urls_file_path_remote}.")
    logging.warning(f"Cleanup of remote URLs file: {urls_file_path_remote} completed.")

# --- Main program logic ---
def main():
    # Step 1: Automatically discover new GitHub URLs
    auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)

    # Step 2: Load historical URL states
    url_states = load_url_states_remote()
    logging.warning(f"Loaded {len(url_states)} historical URL states.")

    # Step 3: Clean up remote urls.txt
    clean_urls_file_remote(URLS_PATH_IN_REPO, url_states)
    urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
    valid_urls = [url for url in urls if pre_screen_url(url)]
    if not valid_urls:
        logging.warning(f"No valid URLs found in remote '{URLS_PATH_IN_REPO}' after cleanup and validation, script will exit.")
        return
    logging.debug(f"Processing {len(valid_urls)} valid URLs from {URLS_PATH_IN_REPO}")

    # Step 4: Extract channels from all sources, and update URL content state
    temp_dir = "temp_channels"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
        logging.warning(f"Created directory '{temp_dir}' for temporary channel files.")

    all_extracted_channels = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in valid_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result_channels = future.result()
                if result_channels:
                    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
                    output_file = os.path.join(temp_dir, f"{url_hash}_iptv.txt")
                    with open(output_file, "w", encoding="utf-8") as f:
                        for name, addr in result_channels:
                            f.write(f"{name},{addr}\n")
                            all_extracted_channels.add((name, addr))
                    logging.debug(f"Saved {len(result_channels)} channels from {url} to {output_file}")
                else:
                    logging.debug(f"No channels extracted from {url}")
            except Exception as exc:
                logging.error(f"Exception occurred while processing source '{url}': {exc}")

    # Step 5: Save updated URL content states
    save_url_states_remote(url_states)
    logging.warning("Channel content fetch states saved to remote.")

    # Step 6: Filter and clean channels
    filtered_channels = []
    for channel in all_extracted_channels:
        try:
            filtered = filter_and_modify_channels([channel])
            filtered_channels.extend(filtered)
        except Exception as e:
            name, url = channel
            logging.error(f"Error filtering channel {name},{url}: {e}, skipping this channel.")
            continue
    unique_filtered_channels = list(set(filtered_channels))
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]
    logging.warning(f"\nAfter filtering and cleaning, {len(unique_filtered_channels_str)} unique channels remain.")

    # Step 7: Merge and validate channels
    logging.warning(f"Proceeding to merge and validate channels into {IPTV_LIST_PATH}...")
    merge_local_channel_files(temp_dir, IPTV_LIST_PATH, url_states)

    # Step 8: Save final channel check states
    save_url_states_remote(url_states)
    logging.warning("Final channel check states saved to remote.")

    # Step 9: Clean up temporary files
    try:
        if os.path.exists('iptv.txt'):
            os.remove('iptv.txt')
            logging.debug(f"Removed temporary file 'iptv.txt'.")
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.debug(f"Removed temporary file 'iptv_speed.txt'.")
        if os.path.exists(temp_dir):
            for f_name in os.listdir(temp_dir):
                if f_name.endswith('_iptv.txt'):
                    os.remove(os.path.join(temp_dir, f_name))
                    logging.debug(f"Removed temporary channel file '{f_name}'.")
            if not os.listdir(temp_dir):
                os.rmdir(temp_dir)
                logging.debug(f"Removed empty temporary directory '{temp_dir}'.")
    except OSError as e:
        logging.warning(f"Error during temporary file cleanup: {e}")

if __name__ == "__main__":
    main()
