import os
import re
import subprocess
import socket
import time
import logging
import requests
import yaml
import json
import base64
import hashlib
import traceback
from datetime import datetime, timedelta
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging.handlers

# Constants
[cite_start]M3U_EXTENSIONS = {".m3u", ".m3u8"} [cite: 1]
[cite_start]DEFAULT_CHANNEL_NAME = "未知频道" [cite: 1]
[cite_start]UNCATEGORIZED_CATEGORY = "未分类" [cite: 1]
[cite_start]IPTV_LIST_PATH = "iptv_list.txt" [cite: 1]
# 修改 UNCATEGORIZED_CHANNELS_PATH 以确保其指向当前目录，这通常就是“根目录”
# 如果你需要在更具体意义上的“根目录”（例如文件系统的根），你需要提供绝对路径
[cite_start]UNCATEGORIZED_CHANNELS_PATH = "uncategorized_channels.txt" # [cite: 1]
[cite_start]TEMP_CHANNELS_DIR = "temp_channels" [cite: 1]
[cite_start]LOG_FILE_PATH = "iptv_script.log" [cite: 1]
[cite_start]URL_CHECK_COOLDOWN_HOURS = 1 [cite: 1]
[cite_start]MAX_WORKERS_DEFAULT = 50 [cite: 1]
[cite_start]MIN_WORKERS = 10 [cite: 1]
[cite_start]MAX_WORKERS = 200 [cite: 1]
[cite_start]MIN_RETRY_WAIT = 5  # Minimum wait time for retries (seconds) [cite: 1]
[cite_start]MAX_RETRY_WAIT = 60  # Maximum wait time for retries (seconds) [cite: 1]

# Configure logging with file output
[cite_start]logger = logging.getLogger() [cite: 1]
[cite_start]logger.setLevel(logging.INFO) [cite: 1]
[cite_start]formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s') [cite: 1]
[cite_start]console_handler = logging.StreamHandler() [cite: 1]
[cite_start]console_handler.setFormatter(formatter) [cite: 1]
[cite_start]logger.addHandler(console_handler) [cite: 1]
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE_PATH, maxBytes=10*1024*1024, backupCount=5
[cite_start]) [cite: 2]
[cite_start]file_handler.setFormatter(formatter) [cite: 2]
[cite_start]logger.addHandler(file_handler) [cite: 2]

# Get configuration from environment variables
[cite_start]GITHUB_TOKEN = os.getenv('BOT') [cite: 2]
[cite_start]REPO_OWNER = os.getenv('REPO_OWNER') [cite: 2]
[cite_start]REPO_NAME = os.getenv('REPO_NAME') [cite: 2]
[cite_start]CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH') [cite: 2]
[cite_start]URLS_PATH_IN_REPO = os.getenv('URLS_PATH') [cite: 2]
[cite_start]URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH') [cite: 2]

# Check if environment variables are set
if not GITHUB_TOKEN:
    [cite_start]logger.error("Error: Environment variable 'BOT' not set.") [cite: 2]
    [cite_start]exit(1) [cite: 2]
if not REPO_OWNER:
    [cite_start]logger.error("Error: Environment variable 'REPO_OWNER' not set.") [cite: 2]
    [cite_start]exit(1) [cite: 2]
if not REPO_NAME:
    [cite_start]logger.error("Error: Environment variable 'REPO_NAME' not set.") [cite: 2]
    [cite_start]exit(1) [cite: 2]
if not CONFIG_PATH_IN_REPO:
    [cite_start]logger.error("Error: Environment variable 'CONFIG_PATH' not set.") [cite: 2]
    [cite_start]exit(1) [cite: 2]
if not URLS_PATH_IN_REPO:
    [cite_start]logger.error("Error: Environment variable 'URLS_PATH' not set.") [cite: 2]
    [cite_start]exit(1) [cite: 3]
if not URL_STATES_PATH_IN_REPO:
    [cite_start]logger.error("Error: Environment variable 'URL_STATES_PATH' not set.") [cite: 3]
    [cite_start]exit(1) [cite: 3]

# GitHub repository base URLs
[cite_start]GITHUB_RAW_CONTENT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main" [cite: 3]
[cite_start]GITHUB_API_CONTENTS_BASE_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents" [cite: 3]
[cite_start]GITHUB_API_BASE_URL = "https://api.github.com" [cite: 3]
[cite_start]SEARCH_CODE_ENDPOINT = "/search/code" [cite: 3]

# Configure requests session
[cite_start]session = requests.Session() [cite: 3]
[cite_start]session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"}) [cite: 3, 4]

# --- GitHub file operations functions ---
def fetch_from_github(file_path_in_repo):
    """Fetch file content from GitHub repository."""
    [cite_start]raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}" [cite: 4]
    [cite_start]headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 4]
    try:
        [cite_start]response = requests.get(raw_url, headers=headers, timeout=10) [cite: 4]
        [cite_start]response.raise_for_status() [cite: 4]
        [cite_start]return response.text [cite: 4]
    except requests.exceptions.RequestException as e:
        [cite_start]logger.error(f"Error fetching {file_path_in_repo} from GitHub: {e}\n{traceback.format_exc()}") [cite: 4]
        [cite_start]return None [cite: 4]

def get_current_sha(file_path_in_repo):
    """Get the current SHA of a file in the GitHub repository."""
    [cite_start]api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 5]
    [cite_start]headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 5]
    try:
        [cite_start]response = requests.get(api_url, headers=headers, timeout=10) [cite: 5]
        [cite_start]response.raise_for_status() [cite: 5]
        [cite_start]return response.json().get('sha') [cite: 5]
    except requests.exceptions.RequestException as e:
        [cite_start]logger.debug(f"Error getting SHA for {file_path_in_repo} (might not exist): {e}") [cite: 5]
        [cite_start]return None [cite: 5]

def save_to_github(file_path_in_repo, content, commit_message):
    [cite_start]"""Save (create or update) content to GitHub repository.""" [cite: 6]
    [cite_start]api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 6]
    [cite_start]sha = get_current_sha(file_path_in_repo) [cite: 6]
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    [cite_start]} [cite: 6]
    
    [cite_start]encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8') [cite: 6]

    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": "main"
    [cite_start]} [cite: 6]
 
    [cite_start]if sha: [cite: 7]
        [cite_start]payload["sha"] = sha [cite: 7]
    
    try:
        [cite_start]response = requests.put(api_url, headers=headers, json=payload) [cite: 7]
        [cite_start]response.raise_for_status() [cite: 7]
        [cite_start]return True [cite: 7]
    except requests.exceptions.RequestException as e:
        [cite_start]logger.error(f"Error saving {file_path_in_repo} to GitHub: {e}\n{traceback.format_exc()}") [cite: 7]
        [cite_start]logger.error(f"GitHub API response: {response.text if 'response' in locals() else 'N/A'}") [cite: 7]
        [cite_start]return False [cite: 8]

def load_config():
    """Load and parse YAML configuration file from GitHub repository."""
    [cite_start]content = fetch_from_github(CONFIG_PATH_IN_REPO) [cite: 8]
    [cite_start]if content: [cite: 8]
        try:
            [cite_start]return yaml.safe_load(content) [cite: 8]
        except yaml.YAMLError as e:
            [cite_start]logger.error(f"Error: Invalid YAML in remote config file '{CONFIG_PATH_IN_REPO}': {e}\n{traceback.format_exc()}") [cite: 8]
            [cite_start]exit(1) [cite: 8]
        [cite_start]except Exception as e: [cite: 8, 9]
            [cite_start]logger.error(f"Error loading remote config file '{CONFIG_PATH_IN_REPO}': {e}\n{traceback.format_exc()}") [cite: 9]
            [cite_start]exit(1) [cite: 9]
    [cite_start]logger.error(f"Could not load config from '{CONFIG_PATH_IN_REPO}' on GitHub.") [cite: 9]
    [cite_start]exit(1) [cite: 9]

# Load configuration
[cite_start]CONFIG = load_config() [cite: 9]

# Get parameters from configuration
[cite_start]SEARCH_KEYWORDS = CONFIG.get('search_keywords', []) [cite: 9]
[cite_start]PER_PAGE = CONFIG.get('per_page', 30)  # Reduced to avoid rate limits [cite: 9]
[cite_start]MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 3)  # Reduced to avoid rate limits [cite: 9]
[cite_start]GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 20) [cite: 9]
[cite_start]GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 30) [cite: 9]
[cite_start]CHANNEL_FETCH_TIMEOUT = CONFIG.get('channel_fetch_timeout', 15) [cite: 9]
[cite_start]CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 6) [cite: 9]
[cite_start]MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 200) [cite: 9]
[cite_start]NAME_FILTER_WORDS = CONFIG.get('name_filter_words', []) [cite: 9]
[cite_start]URL_FILTER_WORDS = CONFIG.get('url_filter_words', []) [cite: 9]
[cite_start]CHANNEL_NAME_REPLACEMENTS = CONFIG.get('channel_name_replacements', {}) [cite: 9, 10]
[cite_start]ORDERED_CATEGORIES = CONFIG.get('ordered_categories', []) [cite: 10]
[cite_start]STREAM_SKIP_FAILED_HOURS = CONFIG.get('stream_skip_failed_hours', 24) [cite: 10]
[cite_start]URL_STATE_EXPIRATION_DAYS = CONFIG.get('url_state_expiration_days', 90) [cite: 10]
[cite_start]CHANNEL_FAIL_THRESHOLD = CONFIG.get('channel_fail_threshold', 5) [cite: 10]
[cite_start]URL_FAIL_THRESHOLD = CONFIG.get('url_fail_threshold', 5) [cite: 10]
[cite_start]URL_RETENTION_HOURS = CONFIG.get('url_retention_hours', 72) [cite: 10]

# Configure requests session with retry strategy
[cite_start]pool_size = CONFIG.get('requests_pool_size', 200) [cite: 10]
retry_strategy = Retry(
    [cite_start]total=CONFIG.get('requests_retry_total', 3), [cite: 10]
    [cite_start]backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1), [cite: 10]
    [cite_start]status_forcelist=[429, 500, 502, 503, 504], [cite: 10]
    [cite_start]allowed_methods=["HEAD", "GET", "OPTIONS"] [cite: 10]
)
[cite_start]adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry_strategy) [cite: 10]
[cite_start]session.mount("http://", adapter) [cite: 10]
[cite_start]session.mount("https://", adapter) [cite: 10]

# --- Local file operations functions ---
def read_txt_to_array_local(file_name):
    """Read content from a local TXT file into an array."""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            [cite_start]lines = file.readlines() [cite: 11]
        [cite_start]lines = [line.strip() for line in lines if line.strip()] [cite: 11]
        [cite_start]return lines [cite: 11]
    except FileNotFoundError:
        [cite_start]logger.warning(f"File '{file_name}' not found.") [cite: 11]
        [cite_start]return [] [cite: 11]
    except Exception as e:
        [cite_start]logger.error(f"Error reading file '{file_name}': {e}\n{traceback.format_exc()}") [cite: 11]
        [cite_start]return [] [cite: 11]

def read_existing_channels(file_path):
    [cite_start]"""Read existing channel (name, URL) combinations from a file for deduplication.""" [cite: 12]
    [cite_start]existing_channels = set() [cite: 12]
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                [cite_start]line = line.strip() [cite: 12]
                [cite_start]if line and ',' in line and not line.startswith('#'): [cite: 12]
                    [cite_start]parts = line.split(',', 1) [cite: 13]
                    [cite_start]if len(parts) == 2: [cite: 13]
                        [cite_start]name, url = parts [cite: 13]
                        [cite_start]existing_channels.add((name.strip(), url.strip())) [cite: 13]
    except FileNotFoundError:
        [cite_start]pass [cite: 13]
    [cite_start]except Exception as e: [cite: 14]
        [cite_start]logger.error(f"Error reading file '{file_path}' for deduplication: {e}\n{traceback.format_exc()}") [cite: 14]
    [cite_start]return existing_channels [cite: 14]

def write_sorted_channels_to_file(file_path, data_list):
    """Append sorted channel data to a file, with deduplication."""
    [cite_start]existing_channels = read_existing_channels(file_path) [cite: 14]
    [cite_start]new_channels = set() [cite: 14]
    
    [cite_start]for _, line in data_list: [cite: 14]
        [cite_start]if ',' in line: [cite: 14]
            [cite_start]name, url = line.split(',', 1) [cite: 14]
            [cite_start]new_channels.add((name.strip(), url.strip())) [cite: 15]
  
    [cite_start]all_channels = existing_channels | new_channels [cite: 16]
    
    try:
        [cite_start]with open(file_path, 'a', encoding='utf-8') as file: [cite: 16]
            [cite_start]for name, url in all_channels: [cite: 16]
                [cite_start]if (name, url) not in existing_channels: [cite: 16]
                    [cite_start]file.write(f"{name},{url}\n") [cite: 16]
        [cite_start]logger.debug(f"Appended {len(all_channels - existing_channels)} new channels to {file_path}") [cite: 16]
    [cite_start]except Exception as e: [cite: 17]
        [cite_start]logger.error(f"Error appending to file '{file_path}': {e}\n{traceback.format_exc()}") [cite: 17]

# --- URL processing and channel extraction functions ---
def get_url_file_extension(url):
    """Get the file extension from a URL."""
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 17]
        [cite_start]extension = os.path.splitext(parsed_url.path)[1].lower() [cite: 17]
        [cite_start]return extension [cite: 17]
    except ValueError as e:
        [cite_start]logger.debug(f"Failed to get URL extension: {url} - {e}") [cite: 17]
        [cite_start]return "" [cite: 17]

def convert_m3u_to_txt(m3u_content):
    [cite_start]"""Convert M3U format content to TXT format (channel name,URL).""" [cite: 18]
    [cite_start]lines = m3u_content.split('\n') [cite: 18]
    [cite_start]txt_lines = [] [cite: 18]
    [cite_start]channel_name = "" [cite: 18]
    [cite_start]for line in lines: [cite: 18]
        [cite_start]line = line.strip() [cite: 18]
        [cite_start]if line.startswith("#EXTM3U"): [cite: 18]
            [cite_start]continue [cite: 18]
        [cite_start]if line.startswith("#EXTINF"): [cite: 18]
            [cite_start]match = re.search(r'#EXTINF:.*?\,(.*)', line) [cite: 18]
            [cite_start]if match: [cite: 19]
                [cite_start]channel_name = match.group(1).strip() [cite: 19]
            else:
                [cite_start]channel_name = DEFAULT_CHANNEL_NAME [cite: 19]
        [cite_start]elif line and not line.startswith('#'): [cite: 19]
            [cite_start]if channel_name: [cite: 19]
                [cite_start]txt_lines.append(f"{channel_name},{line}") [cite: 19]
            [cite_start]channel_name = "" [cite: 20]
    [cite_start]return '\n'.join(txt_lines) [cite: 20]

def clean_url_params(url):
    """Clean URL parameters, keeping only scheme, netloc, and path."""
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 20]
        [cite_start]return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path [cite: 20]
    except ValueError as e:
        [cite_start]logger.debug(f"Failed to clean URL parameters: {url} - {e}") [cite: 21]
        [cite_start]return url [cite: 21]

# --- URL state management functions ---
def load_url_states_remote():
    [cite_start]"""Load URL state JSON file from remote, and clean up expired states.""" [cite: 21]
    [cite_start]content = fetch_from_github(URL_STATES_PATH_IN_REPO) [cite: 21]
    [cite_start]url_states = {} [cite: 21]
    [cite_start]if content: [cite: 21]
        try:
            [cite_start]url_states = json.loads(content) [cite: 21]
        except json.JSONDecodeError as e:
            [cite_start]logger.error(f"Error decoding JSON from remote '{URL_STATES_PATH_IN_REPO}': {e}\n{traceback.format_exc()}") [cite: 21]
            [cite_start]return {} [cite: 21]
    
    [cite_start]current_time = datetime.now() [cite: 21]
    [cite_start]updated_url_states = {} [cite: 22]
    [cite_start]for url, state in url_states.items(): [cite: 22]
        [cite_start]if 'last_checked' in state: [cite: 22]
            try:
                [cite_start]last_checked_datetime = datetime.fromisoformat(state['last_checked']) [cite: 22]
                [cite_start]if (current_time - last_checked_datetime).days < URL_STATE_EXPIRATION_DAYS: [cite: 22]
                    [cite_start]updated_url_states[url] = state [cite: 22]
                [cite_start]else: [cite: 23]
                    [cite_start]logger.debug(f"Removing expired URL state: {url} (last checked on {state['last_checked']})") [cite: 23]
            except ValueError:
                [cite_start]logger.warning(f"Could not parse last_checked timestamp for URL {url}: {state['last_checked']}, keeping its state.") [cite: 23]
                [cite_start]updated_url_states[url] = state [cite: 23]
        [cite_start]else: [cite: 24]
            [cite_start]updated_url_states[url] = state [cite: 24]
            
    [cite_start]logger.info("URL states loaded and expired states cleaned.") [cite: 24]
    [cite_start]return updated_url_states [cite: 24]

def save_url_states_remote(url_states):
    """Save URL states to remote JSON file."""
    try:
        [cite_start]content = json.dumps(url_states, indent=4, ensure_ascii=False) [cite: 24]
        [cite_start]success = save_to_github(URL_STATES_PATH_IN_REPO, content, "Update URL states") [cite: 24]
        [cite_start]if not success: [cite: 24]
            [cite_start]logger.error(f"Error saving remote URL states to '{URL_STATES_PATH_IN_REPO}'.") [cite: 25]
    except Exception as e:
        [cite_start]logger.error(f"Error saving URL states to remote '{URL_STATES_PATH_IN_REPO}': {e}\n{traceback.format_exc()}") [cite: 25]

@retry(
    [cite_start]stop=stop_after_attempt(3), [cite: 25]
    [cite_start]wait=wait_exponential(multiplier=1, min=MIN_RETRY_WAIT, max=MAX_RETRY_WAIT), [cite: 25]
    [cite_start]reraise=True, [cite: 25]
    [cite_start]retry=retry_if_exception_type(requests.exceptions.RequestException) [cite: 25]
)
def fetch_url_content_with_retry(url, url_states):
    """Attempt to fetch URL content with retry mechanism, and use ETag/Last-Modified/Content-Hash to avoid re-download."""
    [cite_start]headers = {} [cite: 25]
    [cite_start]current_state = url_states.get(url, {}) [cite: 25]

    [cite_start]if 'etag' in current_state: [cite: 25]
        [cite_start]headers['If-None-Match'] = current_state['etag'] [cite: 26]
    [cite_start]if 'last_modified' in current_state: [cite: 26]
        [cite_start]headers['If-Modified-Since'] = current_state['last_modified'] [cite: 26]

    try:
        [cite_start]response = session.get(url, headers=headers, timeout=CHANNEL_FETCH_TIMEOUT) [cite: 26]
        [cite_start]response.raise_for_status() [cite: 26]

        [cite_start]if response.status_code == 304: [cite: 26]
            [cite_start]logger.debug(f"URL content {url} not modified (304). Skipping download.") [cite: 27]
            [cite_start]if url not in url_states: [cite: 27]
                [cite_start]url_states[url] = {} [cite: 27]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 27]
            [cite_start]return None [cite: 27]

        [cite_start]content = response.text [cite: 27]
        [cite_start]content_hash = hashlib.md5(content.encode('utf-8')).hexdigest() [cite: 27]

        [cite_start]if 'content_hash' in current_state and current_state['content_hash'] == content_hash: [cite: 27, 28]
            [cite_start]logger.debug(f"URL content {url} is same based on hash. Skipping download.") [cite: 28]
            [cite_start]if url not in url_states: [cite: 28]
                [cite_start]url_states[url] = {} [cite: 28]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 28]
            [cite_start]return None [cite: 28]

        url_states[url] = {
            [cite_start]'etag': response.headers.get('ETag'), [cite: 29]
            [cite_start]'last_modified': response.headers.get('Last-Modified'), [cite: 29]
            [cite_start]'content_hash': content_hash, [cite: 29]
            [cite_start]'last_checked': datetime.now().isoformat() [cite: 29]
        [cite_start]} [cite: 29]

        [cite_start]logger.debug(f"Successfully fetched new content for URL: {url}. Content updated.") [cite: 29, 30]
        [cite_start]return content [cite: 30]

    except requests.exceptions.RequestException as e:
        [cite_start]logger.error(f"Request error fetching URL (after retries): {url} - {e}\n{traceback.format_exc()}") [cite: 30]
        [cite_start]return None [cite: 30]
    except Exception as e:
        [cite_start]logger.error(f"Unknown error fetching URL: {url} - {e}\n{traceback.format_exc()}") [cite: 30]
        [cite_start]return None [cite: 30]

def extract_channels_from_url(url, url_states):
    """Extract channels from the given URL."""
    [cite_start]extracted_channels = [] [cite: 31]
    try:
        [cite_start]text = fetch_url_content_with_retry(url, url_states) [cite: 31]
        [cite_start]if text is None: [cite: 31]
            [cite_start]return [] [cite: 31]

        [cite_start]if get_url_file_extension(url) in M3U_EXTENSIONS: [cite: 31]
            [cite_start]text = convert_m3u_to_txt(text) [cite: 31]

        [cite_start]lines = text.split('\n') [cite: 31]
        [cite_start]channel_count = 0 [cite: 31]
        [cite_start]for line in lines: [cite: 31]
            [cite_start]line = line.strip() [cite: 32]
            [cite_start]if "#genre#" not in line and "," in line and "://" in line: [cite: 32]
                [cite_start]parts = line.split(',', 1) [cite: 32]
                [cite_start]if len(parts) != 2: [cite: 32]
                    [cite_start]logger.debug(f"Skipping invalid channel line (malformed): {line}") [cite: 32]
                    [cite_start]continue [cite: 33]
                [cite_start]channel_name, channel_address_raw = parts [cite: 33]
                [cite_start]channel_name = channel_name.strip() [cite: 33]
                [cite_start]channel_address_raw = channel_address_raw.strip() [cite: 33]

                [cite_start]if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw): [cite: 33]
                    [cite_start]logger.debug(f"Skipping invalid channel URL (no valid protocol): {line}") [cite: 34]
                    [cite_start]continue [cite: 34]

                [cite_start]if '#' in channel_address_raw: [cite: 34]
                    [cite_start]url_list = channel_address_raw.split('#') [cite: 34]
                    [cite_start]for channel_url in url_list: [cite: 34, 35]
                        [cite_start]channel_url = clean_url_params(channel_url.strip()) [cite: 35]
                        [cite_start]if channel_url and pre_screen_url(channel_url): [cite: 35]
                            [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 35]
                            [cite_start]channel_count += 1 [cite: 36]
                        else:
                            [cite_start]logger.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}") [cite: 36]
                else:
                    [cite_start]channel_url = clean_url_params(channel_address_raw) [cite: 36]
                    [cite_start]if channel_url and pre_screen_url(channel_url): [cite: 37]
                        [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 37]
                        [cite_start]channel_count += 1 [cite: 37]
                    else:
                        [cite_start]logger.debug(f"Skipping invalid or pre-screened channel URL: {channel_url}") [cite: 38]
        [cite_start]logger.debug(f"Successfully extracted {channel_count} channels from URL: {url}.") [cite: 38]
    except Exception as e:
        [cite_start]logger.error(f"Error extracting channels from {url}: {e}\n{traceback.format_exc()}") [cite: 38]
    [cite_start]return extracted_channels [cite: 38]

def pre_screen_url(url):
    """Pre-screen URLs based on configuration for protocol, length, and invalid patterns."""
    [cite_start]if not isinstance(url, str) or not url: [cite: 38]
        [cite_start]logger.debug(f"Pre-screening filtered (invalid type or empty): {url}") [cite: 39]
        [cite_start]return False [cite: 39]

    [cite_start]if not re.match(r'^[a-zA-Z0-9+.-]+://', url): [cite: 39]
        [cite_start]logger.debug(f"Pre-screening filtered (no valid protocol): {url}") [cite: 39]
        [cite_start]return False [cite: 39]

    [cite_start]if re.search(r'[^\x00-\x7F]', url) or ' ' in url: [cite: 39]
        [cite_start]logger.debug(f"Pre-screening filtered (contains illegal characters or spaces): {url}") [cite: 39]
        [cite_start]return False [cite: 39]

    try:
        [cite_start]parsed_url = urlparse(url) [cite: 39]
        [cite_start]if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []): [cite: 39, 40]
            [cite_start]logger.debug(f"Pre-screening filtered (unsupported protocol): {url}") [cite: 40]
            [cite_start]return False [cite: 40]

        [cite_start]if not parsed_url.netloc: [cite: 40]
            [cite_start]logger.debug(f"Pre-screening filtered (no network location): {url}") [cite: 40]
            [cite_start]return False [cite: 40]

        [cite_start]invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', []) [cite: 40]
        [cite_start]compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns] [cite: 40]
        [cite_start]for pattern in compiled_invalid_url_patterns: [cite: 41]
            [cite_start]if pattern.search(url): [cite: 41]
                [cite_start]logger.debug(f"Pre-screening filtered (invalid pattern): {url}") [cite: 41]
                [cite_start]return False [cite: 41]

        [cite_start]if len(url) < 15: [cite: 41]
            [cite_start]logger.debug(f"Pre-screening filtered (URL too short): {url}") [cite: 41]
            [cite_start]return False [cite: 42]

        [cite_start]return True [cite: 42]
    except ValueError as e:
        [cite_start]logger.debug(f"Pre-screening filtered (URL parse error): {url} - {e}") [cite: 42]
        [cite_start]return False [cite: 42]

def filter_and_modify_channels(channels):
    """Filter and modify channel names and URLs."""
    [cite_start]filtered_channels = [] [cite: 42]
    [cite_start]pre_screened_count = 0 [cite: 42]
    [cite_start]for name, url in channels: [cite: 42]
        [cite_start]if not pre_screen_url(url): [cite: 42]
            [cite_start]logger.debug(f"Filtering channel (pre-screening failed): {name},{url}") [cite: 42]
            [cite_start]continue [cite: 43]
        [cite_start]pre_screened_count += 1 [cite: 43]

        [cite_start]if any(word in url for word in URL_FILTER_WORDS): [cite: 43]
            [cite_start]logger.debug(f"Filtering channel (URL matches blacklist): {name},{url}") [cite: 43]
            [cite_start]continue [cite: 43]

        [cite_start]if any(word.lower() in name.lower() for word in NAME_FILTER_WORDS): [cite: 43]
            [cite_start]logger.debug(f"Filtering channel (name matches blacklist): {name},{url}") [cite: 43]
            [cite_start]continue [cite: 44]

        [cite_start]for old_str, new_str in CHANNEL_NAME_REPLACEMENTS.items(): [cite: 44]
            [cite_start]name = name.replace(old_str, new_str) [cite: 44]
        [cite_start]filtered_channels.append((name, url)) [cite: 44]
    [cite_start]logger.debug(f"After URL pre-screening, {pre_screened_count} channels remain for further filtering.") [cite: 44]
    [cite_start]return filtered_channels [cite: 44]

# --- Channel validity check functions ---
def check_http_url(url, timeout):
    """Check if HTTP/HTTPS URL is reachable."""
    try:
        [cite_start]response = session.head(url, timeout=timeout, allow_redirects=True) [cite: 44, 45]
        [cite_start]return 200 <= response.status_code < 400 [cite: 45]
    except requests.exceptions.RequestException as e:
        [cite_start]logger.debug(f"HTTP URL {url} check failed: {e}") [cite: 45]
        [cite_start]return False [cite: 45]

def check_rtmp_url(url, timeout):
    """Check if RTMP URL is reachable (requires ffprobe)."""
    try:
        [cite_start]subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2) [cite: 45]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        [cite_start]logger.warning("ffprobe not found or not working. RTMP stream check skipped.") [cite: 45, 46]
        [cite_start]return False [cite: 46]
    try:
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                               stdout=subprocess.PIPE,
                               [cite_start]stderr=subprocess.PIPE, timeout=timeout) [cite: 46]
        [cite_start]return result.returncode == 0 [cite: 47]
    except subprocess.TimeoutExpired:
        [cite_start]logger.debug(f"RTMP URL {url} check timed out") [cite: 47]
        [cite_start]return False [cite: 47]
    except Exception as e:
        [cite_start]logger.debug(f"RTMP URL {url} check error: {e}") [cite: 47]
        [cite_start]return False [cite: 47]

def check_rtp_url(url, timeout):
    """Check if RTP URL is reachable (by attempting UDP connection)."""
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 47, 48]
        [cite_start]host = parsed_url.hostname [cite: 48]
        [cite_start]port = parsed_url.port [cite: 48]
        [cite_start]if not host or not port: [cite: 48]
            [cite_start]logger.debug(f"RTP URL {url} parse failed: missing host or port.") [cite: 48]
            [cite_start]return False [cite: 48]

        [cite_start]with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: [cite: 48]
            [cite_start]s.settimeout(timeout) [cite: 49]
            [cite_start]s.connect((host, port)) [cite: 49]
            [cite_start]s.sendto(b'', (host, port)) [cite: 49]
            [cite_start]s.recv(1) [cite: 49]
        [cite_start]return True [cite: 49]
    except (socket.timeout, socket.error) as e:
        [cite_start]logger.debug(f"RTP URL {url} check failed: {e}") [cite: 49]
        [cite_start]return False [cite: 49]
    except Exception as e:
        [cite_start]logger.debug(f"RTP URL {url} check error: {e}") [cite: 49]
        [cite_start]return False [cite: 49]

def check_p3p_url(url, timeout):
    [cite_start]"""Check if P3P URL is reachable (simple TCP connection and HTTP response header check).""" [cite: 49, 50]
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 50]
        [cite_start]host = parsed_url.hostname [cite: 50]
        [cite_start]port = parsed_url.port if parsed_url.port else 80 [cite: 50]
        [cite_start]path = parsed_url.path if parsed_url.path else '/' [cite: 50]

        [cite_start]if not host: [cite: 50]
            [cite_start]logger.debug(f"P3P URL {url} parse failed: missing host.") [cite: 50]
            [cite_start]return False [cite: 51]

        [cite_start]with socket.create_connection((host, port), timeout=timeout) as s: [cite: 51]
            [cite_start]request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n" [cite: 51]
            [cite_start]s.sendall(request.encode()) [cite: 51]
            [cite_start]response = s.recv(1024).decode('utf-8', errors='ignore') [cite: 51]
            [cite_start]return "P3P" in response or response.startswith("HTTP/1.") [cite: 51]
    except Exception as e:
        [cite_start]logger.debug(f"P3P URL {url} check failed: {e}") [cite: 51]
        [cite_start]return False [cite: 52]

def check_channel_validity_and_speed(channel_name, url, url_states, timeout=CHANNEL_CHECK_TIMEOUT):
    """Check single channel's validity and speed, and record failure status for skipping."""
    [cite_start]current_time = datetime.now() [cite: 52]
    [cite_start]current_url_state = url_states.get(url, {}) [cite: 52]

    [cite_start]if 'stream_check_failed_at' in current_url_state: [cite: 52]
        [cite_start]last_failed_time_str = current_url_state['stream_check_failed_at'] [cite: 52]
        try:
            [cite_start]last_failed_datetime = datetime.fromisoformat(last_failed_time_str) [cite: 52]
            [cite_start]time_since_failed_hours = (current_time - last_failed_datetime).total_seconds() / 3600 [cite: 52]
            [cite_start]if time_since_failed_hours < STREAM_SKIP_FAILED_HOURS: [cite: 53]
                [cite_start]logger.debug(f"Skipping channel {channel_name} ({url}) as it failed within cooldown period ({STREAM_SKIP_FAILED_HOURS}h). Last failed at {last_failed_time_str}, {time_since_failed_hours:.2f}h ago.") [cite: 53, 54]
                [cite_start]return None, False [cite: 54]
        except ValueError:
            [cite_start]logger.warning(f"Could not parse failed timestamp for URL {url}: {last_failed_time_str}") [cite: 54]
            [cite_start]pass [cite: 54]

    [cite_start]start_time = time.time() [cite: 54]
    [cite_start]is_valid = False [cite: 54]
    [cite_start]protocol_checked = False [cite: 54]

    try:
        [cite_start]if url.startswith("http"): [cite: 54, 55]
            [cite_start]is_valid = check_http_url(url, timeout) [cite: 55]
            [cite_start]protocol_checked = True [cite: 55]
        [cite_start]elif url.startswith("p3p"): [cite: 55]
            [cite_start]is_valid = check_p3p_url(url, timeout) [cite: 55]
            [cite_start]protocol_checked = True [cite: 55]
        [cite_start]elif url.startswith("rtmp"): [cite: 55]
            [cite_start]is_valid = check_rtmp_url(url, timeout) [cite: 55]
            [cite_start]protocol_checked = True [cite: 56]
        [cite_start]elif url.startswith("rtp"): [cite: 56]
            [cite_start]is_valid = check_rtp_url(url, timeout) [cite: 56]
            [cite_start]protocol_checked = True [cite: 56]
        else:
            [cite_start]logger.debug(f"Channel {channel_name}'s protocol is not supported: {url}") [cite: 56]
            [cite_start]if url not in url_states: [cite: 56]
                [cite_start]url_states[url] = {} [cite: 57]
            [cite_start]url_states[url]['last_checked_protocol_unsupported'] = current_time.isoformat() [cite: 57]
            [cite_start]url_states[url].pop('stream_check_failed_at', None) [cite: 57]
            [cite_start]url_states[url].pop('stream_fail_count', None) [cite: 57]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 57]
            [cite_start]return None, False [cite: 57]

        [cite_start]elapsed_time = (time.time() - start_time) * 1000 [cite: 57]

        [cite_start]if is_valid: [cite: 57]
            [cite_start]if url not in url_states: [cite: 58]
                [cite_start]url_states[url] = {} [cite: 58]
            [cite_start]url_states[url].pop('stream_check_failed_at', None) [cite: 58]
            [cite_start]url_states[url].pop('stream_fail_count', None) [cite: 58]
            [cite_start]url_states[url]['last_successful_stream_check'] = current_time.isoformat() [cite: 58]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 58]
            [cite_start]logger.debug(f"Channel {channel_name} ({url}) check successful, took {elapsed_time:.0f} ms.") [cite: 58, 59]
            [cite_start]return elapsed_time, True [cite: 59]
        else:
            [cite_start]if url not in url_states: [cite: 59]
                [cite_start]url_states[url] = {} [cite: 59]
            [cite_start]url_states[url]['stream_check_failed_at'] = current_time.isoformat() [cite: 59]
            [cite_start]url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 [cite: 59, 60]
            [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 60]
            [cite_start]logger.debug(f"Channel {channel_name} ({url}) check failed.") [cite: 60]
            [cite_start]return None, False [cite: 60]
    except Exception as e:
        [cite_start]if url not in url_states: [cite: 60]
            [cite_start]url_states[url] = {} [cite: 61]
        [cite_start]url_states[url]['stream_check_failed_at'] = current_time.isoformat() [cite: 61]
        [cite_start]url_states[url]['stream_fail_count'] = current_url_state.get('stream_fail_count', 0) + 1 [cite: 61]
        [cite_start]url_states[url]['last_stream_checked'] = current_time.isoformat() [cite: 61]
        [cite_start]logger.debug(f"Error checking channel {channel_name} ({url}): {e}\n{traceback.format_exc()}") [cite: 61]
        [cite_start]return None, False [cite: 61]

def process_single_channel_line(channel_line, url_states):
    """Process a single channel line for validity check."""
    [cite_start]if "://" not in channel_line: [cite: 61]
        [cite_start]logger.debug(f"Skipping invalid channel line (no protocol): {channel_line}") [cite: 62]
        [cite_start]return None, None [cite: 62]
    [cite_start]parts = channel_line.split(',', 1) [cite: 62]
    [cite_start]if len(parts) == 2: [cite: 62]
        [cite_start]name, url = parts [cite: 62]
        [cite_start]url = url.strip() [cite: 62]
        [cite_start]elapsed_time, is_valid = check_channel_validity_and_speed(name, url, url_states) [cite: 62]
        [cite_start]if is_valid: [cite: 62]
            [cite_start]return elapsed_time, f"{name},{url}" [cite: 62]
    [cite_start]return None, None [cite: 62]

def check_channels_multithreaded(channel_lines, url_states, max_workers=CONFIG.get('channel_check_workers', MAX_WORKERS_DEFAULT)):
    """Check channel validity using multithreading."""
    [cite_start]results = [] [cite: 62]
    [cite_start]checked_count = 0 [cite: 62]
    [cite_start]total_channels = len(channel_lines) [cite: 62]
    [cite_start]logger.info(f"Starting multithreaded channel validity and speed detection for {total_channels} channels...") [cite: 62]
    [cite_start]with ThreadPoolExecutor(max_workers=max(min(max_workers, MAX_WORKERS), MIN_WORKERS)) as executor: [cite: 62, 63]
        [cite_start]futures = {executor.submit(process_single_channel_line, line, url_states): line for line in channel_lines} [cite: 63]
        [cite_start]for future in as_completed(futures): [cite: 63]
            [cite_start]checked_count += 1 [cite: 63]
            [cite_start]if checked_count % 100 == 0: [cite: 63]
                [cite_start]logger.info(f"Checked {checked_count}/{total_channels} channels...") [cite: 63]
            try:
                [cite_start]elapsed_time, result_line = future.result() [cite: 64]
                [cite_start]if elapsed_time is not None and result_line is not None: [cite: 64]
                    [cite_start]results.append((elapsed_time, result_line)) [cite: 64]
            except Exception as exc:
                [cite_start]logger.warning(f"Exception occurred during channel line processing: {exc}\n{traceback.format_exc()}") [cite: 64]
    [cite_start]logger.info(f"Completed channel validity check. Valid channels: {len(results)}") [cite: 64, 65]
    [cite_start]return results [cite: 65]

# --- File merge and sort functions ---
def generate_update_time_header():
    """Generate update time information for the top of the file."""
    [cite_start]now = datetime.now() [cite: 65]
    return [
        [cite_start]f"更新时间,#genre#\n", [cite: 65]
        [cite_start]f"{now.strftime('%Y-%m-%d')},url\n", [cite: 65]
        [cite_start]f"{now.strftime('%H:%M:%S')},url\n" [cite: 65]
    ]

def group_and_limit_channels(lines):
    """Group channels and limit the number of URLs under each channel name."""
    [cite_start]grouped_channels = {} [cite: 65]
    [cite_start]for line_content in lines: [cite: 65]
        [cite_start]line_content = line_content.strip() [cite: 66]
        [cite_start]if line_content: [cite: 66]
            [cite_start]channel_name = line_content.split(',', 1)[0].strip() [cite: 66]
            [cite_start]if channel_name not in grouped_channels: [cite: 66]
                [cite_start]grouped_channels[channel_name] = [] [cite: 66]
            [cite_start]grouped_channels[channel_name].append(line_content) [cite: 66]
    
    [cite_start]final_grouped_lines = [] [cite: 66]
    [cite_start]for channel_name in grouped_channels: [cite: 67]
        [cite_start]for ch_line in grouped_channels[channel_name][:MAX_CHANNEL_URLS_PER_GROUP]: [cite: 67]
            [cite_start]final_grouped_lines.append(ch_line + '\n') [cite: 67]
    [cite_start]return final_grouped_lines [cite: 67]

def merge_local_channel_files(local_channels_directory, output_file_name=IPTV_LIST_PATH, url_states=None):
    """Merge locally generated channel list files, with deduplication and cleanup based on url_states."""
    [cite_start]os.makedirs(local_channels_directory, exist_ok=True) [cite: 67]

    [cite_start]existing_channels_data = [] [cite: 67]
    [cite_start]if os.path.exists(output_file_name): [cite: 67]
        [cite_start]with open(output_file_name, 'r', encoding='utf-8') as f: [cite: 67]
            for line in f:
                [cite_start]line = line.strip() [cite: 68]
                [cite_start]if line and ',' in line and '#genre#' not in line: [cite: 68]
                    [cite_start]parts = line.split(',', 1) [cite: 68]
                    [cite_start]if len(parts) == 2: [cite: 69]
                        [cite_start]existing_channels_data.append((parts[0].strip(), parts[1].strip())) [cite: 69]

    [cite_start]all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')] [cite: 69]
    [cite_start]files_to_merge_paths = [] [cite: 69]
    [cite_start]processed_files = set() [cite: 69]

    [cite_start]for category in ORDERED_CATEGORIES: [cite: 69]
        [cite_start]file_name = f"{category}_iptv.txt" [cite: 69]
        [cite_start]if file_name in all_iptv_files_in_dir and file_name not in processed_files: [cite: 69]
            [cite_start]files_to_merge_paths.append(os.path.join(local_channels_directory, file_name)) [cite: 69]
            [cite_start]processed_files.add(file_name) [cite: 69]

    [cite_start]for file_name in sorted(all_iptv_files_in_dir): [cite: 69]
        [cite_start]if file_name not in processed_files: [cite: 70]
            [cite_start]files_to_merge_paths.append(os.path.join(local_channels_directory, file_name)) [cite: 70]
            [cite_start]processed_files.add(file_name) [cite: 70]

    [cite_start]new_channels_from_merged_files = set() [cite: 70]
    [cite_start]for file_path in files_to_merge_paths: [cite: 70]
        [cite_start]with open(file_path, "r", encoding="utf-8") as file: [cite: 70]
            [cite_start]lines = file.readlines() [cite: 70]
            [cite_start]if not lines: [cite: 70]
                [cite_start]continue [cite: 70]
            [cite_start]for line in lines: [cite: 71]
                [cite_start]line = line.strip() [cite: 71]
                [cite_start]if line and ',' in line and '#genre#' not in line: [cite: 71]
                    [cite_start]name, url = line.split(',', 1) [cite: 71]
                    [cite_start]new_channels_from_merged_files.add((name.strip(), url.strip())) [cite: 72]

    [cite_start]combined_channels = existing_channels_data + list(new_channels_from_merged_files) [cite: 72]
    [cite_start]unique_channels_to_check = set() [cite: 72]
    [cite_start]for name, url in combined_channels: [cite: 72]
        [cite_start]unique_channels_to_check.add((name, url)) [cite: 72]

    [cite_start]channels_for_checking_lines = [f"{name},{url}" for name, url in unique_channels_to_check] [cite: 72]
    [cite_start]logger.info(f"Total unique channels to check and filter for {output_file_name}: {len(channels_for_checking_lines)}") [cite: 72]

    [cite_start]valid_channels_from_check = check_channels_multithreaded(channels_for_checking_lines, url_states) [cite: 73]

    [cite_start]final_channels_for_output = set() [cite: 73]
    [cite_start]for elapsed_time, channel_line in valid_channels_from_check: [cite: 73]
        [cite_start]name, url = channel_line.split(',', 1) [cite: 73]
        [cite_start]url = url.strip() [cite: 73]
        [cite_start]state = url_states.get(url, {}) [cite: 73]
        [cite_start]fail_count = state.get('stream_fail_count', 0) [cite: 73]
        [cite_start]if fail_count <= CHANNEL_FAIL_THRESHOLD: [cite: 73]
            [cite_start]final_channels_for_output.add((name, url)) [cite: 73]
        else:
            [cite_start]logger.info(f"Removing channel '{name},{url}' from {output_file_name} due to excessive failures ({fail_count} > {CHANNEL_FAIL_THRESHOLD}).") [cite: 73]

    [cite_start]sorted_final_channels = sorted(list(final_channels_for_output), key=lambda x: x[0]) [cite: 73]

    try:
        [cite_start]with open(output_file_name, "w", encoding='utf-8') as iptv_list_file: [cite: 73, 74]
            [cite_start]iptv_list_file.writelines(generate_update_time_header()) [cite: 74]
            [cite_start]for name, url in sorted_final_channels: [cite: 74]
                [cite_start]iptv_list_file.write(f"{name},{url}\n") [cite: 74]
        [cite_start]logger.info(f"All regional channel list files merged, deduplicated, and cleaned. Output saved to: {output_file_name}") [cite: 74, 75]
    except Exception as e:
        [cite_start]logger.error(f"Error writing to file '{output_file_name}': {e}\n{traceback.format_exc()}") [cite: 75]

# --- Remote TXT file operations functions ---
def read_txt_to_array_remote(file_path_in_repo):
    """Read content from a remote GitHub repository TXT file into an array."""
    [cite_start]content = fetch_from_github(file_path_in_repo) [cite: 75]
    [cite_start]if content: [cite: 75]
        [cite_start]lines = content.split('\n') [cite: 76]
        [cite_start]return [line.strip() for line in lines if line.strip()] [cite: 76]
    [cite_start]logger.warning(f"No content fetched from remote '{file_path_in_repo}'. Returning empty list.") [cite: 76]
    [cite_start]return [] [cite: 76]

[cite_start]def write_array_to_txt_remote(file_path_in_repo, data_array, commit_message): [cite: 76]
    """Write array content to a remote GitHub repository TXT file."""
    [cite_start]content = '\n'.join(data_array) [cite: 76]
    [cite_start]success = save_to_github(file_path_in_repo, content, commit_message) [cite: 76]
    [cite_start]if not success: [cite: 76]
        [cite_start]logger.error(f"Failed to write data to remote '{file_path_in_repo}'.") [cite: 76]

# --- GitHub URL auto-discovery function ---
@retry(
    [cite_start]stop=stop_after_attempt(3), [cite: 77]
    [cite_start]wait=wait_exponential(multiplier=1, min=MIN_RETRY_WAIT, max=MAX_RETRY_WAIT), [cite: 77]
    [cite_start]reraise=True, [cite: 77]
    [cite_start]retry=retry_if_exception_type(requests.exceptions.RequestException) [cite: 77]
)
def github_api_search(params, headers):
    """Perform GitHub API search with retry for rate limits."""
    response = session.get(
        [cite_start]f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}", [cite: 77]
        [cite_start]headers=headers, [cite: 77]
        [cite_start]params=params, [cite: 77]
        timeout=GITHUB_API_TIMEOUT
    [cite_start]) [cite: 77]
    [cite_start]response.raise_for_status() [cite: 77]
    [cite_start]return response [cite: 77]

def auto_discover_github_urls(urls_file_path_remote, github_token):
    """Automatically discover new IPTV source URLs from GitHub."""
    [cite_start]if not github_token: [cite: 77]
        [cite_start]logger.warning("Environment variable 'BOT' not set. Skipping GitHub URL auto-discovery.") [cite: 78]
        [cite_start]return [cite: 78]

    [cite_start]existing_urls = set(read_txt_to_array_remote(urls_file_path_remote)) [cite: 78]
    [cite_start]found_urls = set() [cite: 78]
    headers = {
        [cite_start]"Accept": "application/vnd.github.v3.text-match+json", [cite: 78]
        [cite_start]"Authorization": f"token {github_token}" [cite: 78]
    [cite_start]} [cite: 78]

    [cite_start]logger.info("Starting automatic discovery of new IPTV source URLs from GitHub...") [cite: 79]
    [cite_start]keyword_url_counts = {keyword: 0 for keyword in SEARCH_KEYWORDS} [cite: 79]
    [cite_start]url_to_keyword = {}  # Track which keyword discovered each URL [cite: 79]

    [cite_start]for i, keyword in enumerate(SEARCH_KEYWORDS): [cite: 79]
        [cite_start]keyword_found_urls = set() [cite: 79]
        [cite_start]if i > 0: [cite: 79]
            [cite_start]logger.info(f"Switching to next keyword: '{keyword}'. Waiting {GITHUB_API_RETRY_WAIT} seconds...") [cite: 79]
            [cite_start]time.sleep(GITHUB_API_RETRY_WAIT) [cite: 79]

        [cite_start]page = 1 [cite: 79]
        [cite_start]while page <= MAX_SEARCH_PAGES: [cite: 79]
            params = {
                [cite_start]"q": f"{keyword} from:{REPO_OWNER}/{REPO_NAME}",  # Restrict to specific repo [cite: 80]
                [cite_start]"sort": "indexed", [cite: 80]
                [cite_start]"order": "desc", [cite: 80]
                [cite_start]"per_page": PER_PAGE, [cite: 80]
                [cite_start]"page": page [cite: 81]
            [cite_start]} [cite: 81]
            try:
                [cite_start]response = github_api_search(params, headers) [cite: 81]
                [cite_start]data = response.json() [cite: 81]

                [cite_start]rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0)) [cite: 81]
                [cite_start]rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0)) [cite: 81]

                [cite_start]if rate_limit_remaining <= 5:  # Preemptive wait if close to limit [cite: 82]
                    [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 [cite: 82]
                    [cite_start]logger.warning(f"GitHub API rate limit low ({rate_limit_remaining} remaining). Waiting {wait_seconds:.0f} seconds.") [cite: 82, 83]
                    [cite_start]time.sleep(wait_seconds) [cite: 83]
                    [cite_start]continue [cite: 83]

                [cite_start]if not data.get('items'): [cite: 83]
                    [cite_start]logger.debug(f"No more results found on page {page} for keyword '{keyword}'.") [cite: 83]
                    [cite_start]break [cite: 84]

                [cite_start]for item in data['items']: [cite: 84]
                    [cite_start]html_url = item.get('html_url', '') [cite: 84]
                    [cite_start]raw_url = None [cite: 84]
                    [cite_start]match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url) [cite: 84]
                    [cite_start]if match: [cite: 85]
                        [cite_start]user, repo, branch, file_path = match.groups() [cite: 85]
                        [cite_start]if not any(file_path.lower().endswith(ext) for ext in M3U_EXTENSIONS): [cite: 85]
                            [cite_start]logger.debug(f"Skipping non-M3U file: {file_path} (from {html_url})") [cite: 86]
                            [cite_start]continue [cite: 86]
                        [cite_start]raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}" [cite: 86]
                    else:
                        [cite_start]logger.debug(f"Could not parse raw URL from html_url: {html_url}") [cite: 87]
                        [cite_start]continue [cite: 87]

                    [cite_start]if raw_url and raw_url not in existing_urls and raw_url not in found_urls: [cite: 87]
                        try:
                            [cite_start]content_response = fetch_url_content_with_retry(raw_url, {}) [cite: 88]
                            if content_response and (
                                [cite_start]re.search(r'#EXTM3U', content_response, re.IGNORECASE) or [cite: 88]
                                [cite_start]any(raw_url.lower().endswith(ext) for ext in M3U_EXTENSIONS) [cite: 89]
                            [cite_start]): [cite: 89]
                                [cite_start]found_urls.add(raw_url) [cite: 89]
                                [cite_start]if raw_url not in url_to_keyword: [cite: 90]
                                    [cite_start]url_to_keyword[raw_url] = keyword [cite: 90]
                                    [cite_start]keyword_found_urls.add(raw_url) [cite: 90]
                                [cite_start]logger.debug(f"Found new IPTV source URL: {raw_url} (keyword: {keyword})") [cite: 91]
                            else:
                                [cite_start]logger.debug(f"URL {raw_url} does not contain M3U content or valid extension. Skipping.") [cite: 91, 92]
                        except Exception as e:
                            [cite_start]logger.warning(f"Error fetching content for {raw_url}: {e}\n{traceback.format_exc()}") [cite: 92]
                
                [cite_start]logger.debug(f"Finished page {page} for keyword '{keyword}'. Found {len(keyword_found_urls)} new URLs.") [cite: 93]
                [cite_start]page += 1 [cite: 93]

            except requests.exceptions.HTTPError as e:
                [cite_start]if e.response.status_code == 403: [cite: 93]
                    [cite_start]rate_limit_reset = int(e.response.headers.get('X-RateLimit-Reset', 0)) [cite: 94]
                    [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 [cite: 94]
                    [cite_start]logger.warning(f"GitHub API rate limit or access forbidden for keyword '{keyword}': {e}\n{traceback.format_exc()}") [cite: 94]
                    [cite_start]logger.info(f"Rate limit hit for keyword '{keyword}'. Waiting {wait_seconds:.0f} seconds.") [cite: 94]
                    [cite_start]time.sleep(wait_seconds) [cite: 94]
                    [cite_start]continue [cite: 95]
                else:
                    [cite_start]logger.error(f"Error searching GitHub for keyword '{keyword}': {e}\n{traceback.format_exc()}") [cite: 95]
                    [cite_start]break [cite: 95]
            except Exception as e:
                [cite_start]logger.error(f"Unexpected error during GitHub search for keyword '{keyword}': {e}\n{traceback.format_exc()}") [cite: 96]
                [cite_start]break [cite: 96]
        
        [cite_start]keyword_url_counts[keyword] = len(keyword_found_urls) [cite: 97]
        [cite_start]logger.info(f"Completed search for keyword '{keyword}'. Found {len(keyword_found_urls)} new URLs.") [cite: 97]
    
    [cite_start]if found_urls: [cite: 97]
        [cite_start]updated_urls = sorted(list(existing_urls | found_urls)) [cite: 97]
        [cite_start]logger.info(f"Discovered {len(found_urls)} new unique URLs. Total URLs to save: {len(updated_urls)}.") [cite: 97]
        [cite_start]write_array_to_txt_remote(urls_file_path_remote, updated_urls, "Add new discovered IPTV URLs") [cite: 97]
    else:
        [cite_start]logger.info("No new IPTV source URLs discovered.") [cite: 97]
    
    [cite_start]for keyword, count in keyword_url_counts.items(): [cite: 97]
        [cite_start]logger.info(f"Keyword '{keyword}' discovered {count} new URLs.") [cite: 98]
    [cite_start]logger.info("Auto-discovery of GitHub URLs completed.") [cite: 98]

# --- URL cleanup function ---
def cleanup_urls_remote(urls_file_path_remote, url_states):
    """Clean up invalid/failed URLs from the remote urls.txt based on URL_FAIL_THRESHOLD and URL_RETENTION_HOURS."""
    [cite_start]all_urls = read_txt_to_array_remote(urls_file_path_remote) [cite: 98]
    
    [cite_start]current_time = datetime.now() [cite: 98]
    [cite_start]urls_to_keep = [] [cite: 98]
    [cite_start]removed_count = 0 [cite: 98]

    [cite_start]for url in all_urls: [cite: 98]
        [cite_start]state = url_states.get(url, {}) [cite: 99]
        [cite_start]fail_count = state.get('stream_fail_count', 0) [cite: 99]
        [cite_start]last_failed_time_str = state.get('stream_check_failed_at') [cite: 99]

        [cite_start]remove_url = False [cite: 99]
        [cite_start]if fail_count > URL_FAIL_THRESHOLD: [cite: 99]
            [cite_start]if last_failed_time_str: [cite: 99]
                try:
                    [cite_start]last_failed_datetime = datetime.fromisoformat(last_failed_time_str) [cite: 99]
                    [cite_start]if (current_time - last_failed_datetime).total_seconds() / 3600 > URL_RETENTION_HOURS: [cite: 99, 100]
                        [cite_start]remove_url = True [cite: 100]
                        [cite_start]logger.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) and retention period ({URL_RETENTION_HOURS}h) exceeded.") [cite: 100]
                except ValueError:
                    [cite_start]logger.warning(f"Could not parse last_failed timestamp for URL {url}: {last_failed_time_str}, keeping it for now.") [cite: 100, 101]
            else:
                [cite_start]remove_url = True [cite: 101]
                [cite_start]logger.info(f"Removing URL '{url}' due to excessive failures ({fail_count}) with no last_failed_at timestamp.") [cite: 101]

        [cite_start]if not remove_url: [cite: 101]
            [cite_start]urls_to_keep.append(url) [cite: 101]
        else:
            [cite_start]removed_count += 1 [cite: 102]
            [cite_start]url_states.pop(url, None) [cite: 102]

    [cite_start]if removed_count > 0: [cite: 102]
        [cite_start]logger.info(f"Cleaned up {removed_count} URLs from {urls_file_path_remote}.") [cite: 102]
        [cite_start]write_array_to_txt_remote(urls_file_path_remote, urls_to_keep, f"Cleaned up {removed_count} failed URLs") [cite: 102]
    else:
        [cite_start]logger.info("No URLs needed cleanup from urls.txt.") [cite: 102]

# --- Main logic ---
def main():
    [cite_start]logger.info("Starting IPTV processing script...") [cite: 103]
    
    [cite_start]url_states = load_url_states_remote() [cite: 103]
    
    [cite_start]auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN) [cite: 103]
    
    [cite_start]cleanup_urls_remote(URLS_PATH_IN_REPO, url_states) [cite: 103]
    [cite_start]logger.info("Remote URLs cleaned up based on failure thresholds.") [cite: 103]

    [cite_start]all_urls = read_txt_to_array_remote(URLS_PATH_IN_REPO) [cite: 103]
    [cite_start]if not all_urls: [cite: 103]
        [cite_start]logger.warning(f"No URLs found in {URLS_PATH_IN_REPO}. Skipping channel extraction and merging.") [cite: 104]
        [cite_start]return [cite: 104]
    [cite_start]logger.info(f"Total URLs to process: {len(all_urls)}") [cite: 104]

    [cite_start]os.makedirs(TEMP_CHANNELS_DIR, exist_ok=True) [cite: 104]
    [cite_start]logger.info("Starting multithreaded URL content fetching and channel extraction...") [cite: 104]
    [cite_start]raw_channels = [] [cite: 104]
    [cite_start]with ThreadPoolExecutor(max_workers=CONFIG.get('url_fetch_workers', 10)) as executor: [cite: 104]
        [cite_start]futures = {executor.submit(extract_channels_from_url, url, url_states): url for url in all_urls} [cite: 105]
        [cite_start]for i, future in enumerate(as_completed(futures)): [cite: 105]
            [cite_start]if i % 10 == 0: [cite: 105]
                [cite_start]logger.info(f"Processed {i}/{len(all_urls)} URLs for channel extraction...") [cite: 105]
            try:
                [cite_start]channels = future.result() [cite: 105]
                [cite_start]if channels: [cite: 105]
                    [cite_start]raw_channels.extend(channels) [cite: 105]
            except Exception as exc:
                [cite_start]logger.error(f"Error processing URL for channel extraction: {exc}\n{traceback.format_exc()}") [cite: 106]
    [cite_start]logger.info(f"Finished URL content fetching and channel extraction. Total raw channels extracted: {len(raw_channels)}.") [cite: 106, 107]

    [cite_start]filtered_channels = filter_and_modify_channels(raw_channels) [cite: 107]
    [cite_start]logger.info(f"Channels filtered and modified. Remaining channels: {len(filtered_channels)}.") [cite: 107]

    [cite_start]categorized_channels = {category: [] for category in ORDERED_CATEGORIES + [UNCATEGORIZED_CATEGORY]} [cite: 107]
    [cite_start]for name, url in filtered_channels: [cite: 107]
        [cite_start]assigned_category = UNCATEGORIZED_CATEGORY [cite: 107]
        [cite_start]for category in ORDERED_CATEGORIES: [cite: 107]
            [cite_start]if category.lower() in name.lower(): [cite: 108]
                [cite_start]assigned_category = category [cite: 108]
                [cite_start]break [cite: 108]
        [cite_start]categorized_channels[assigned_category].append((name, url)) [cite: 108]

    [cite_start]for category, channels in categorized_channels.items(): [cite: 108]
        [cite_start]if channels: [cite: 108]
            # 为未分类频道直接写入到根目录 (即当前工作目录)
            if category == UNCATEGORIZED_CATEGORY:
                file_path = UNCATEGORIZED_CHANNELS_PATH # 直接使用 UNCATEGORIZED_CHANNELS_PATH
            else:
                [cite_start]file_name = f"{category}_iptv.txt" [cite: 108]
                [cite_start]file_path = os.path.join(TEMP_CHANNELS_DIR, file_name) [cite: 109]
            [cite_start]sorted_channels = sorted(list(set(channels)), key=lambda x: x[0]) [cite: 109]
            try:
                [cite_start]with open(file_path, 'w', encoding='utf-8') as f: [cite: 109]
                    [cite_start]f.writelines(generate_update_time_header()) [cite: 109]
                    [cite_start]for name, url in sorted_channels: [cite: 109]
                        [cite_start]f.write(f"{name},{url}\n") [cite: 109]
                [cite_start]logger.debug(f"Saved {len(sorted_channels)} channels to {file_path}") [cite: 110]
            except Exception as e:
                [cite_start]logger.error(f"Error writing to {file_path}: {e}\n{traceback.format_exc()}") [cite: 110]
    [cite_start]logger.info("Categorized channels saved to temporary files.") [cite: 110]

    [cite_start]logger.info(f"Starting to merge and validate channels into {IPTV_LIST_PATH}...") [cite: 110]
    [cite_start]merge_local_channel_files(TEMP_CHANNELS_DIR, IPTV_LIST_PATH, url_states) [cite: 110]

    [cite_start]save_url_states_remote(url_states) [cite: 110]
    [cite_start]logger.info("Final channel check states saved to remote.") [cite: 110]

    try:
        [cite_start]if os.path.exists('iptv.txt'): [cite: 110]
            [cite_start]os.remove('iptv.txt') [cite: 111]
            [cite_start]logger.debug(f"Removed temporary file 'iptv.txt'.") [cite: 111]
        [cite_start]if os.path.exists('iptv_speed.txt'): [cite: 111]
            [cite_start]os.remove('iptv_speed.txt') [cite: 111]
            [cite_start]logger.debug(f"Removed temporary file 'iptv_speed.txt'.") [cite: 111]
        [cite_start]temp_dir = TEMP_CHANNELS_DIR [cite: 111]
        [cite_start]if os.path.exists(temp_dir): [cite: 111]
            [cite_start]for f_name in os.listdir(temp_dir): [cite: 112]
                # 修改：不再删除 uncategorized_iptv.txt，因为它现在直接写入到根目录
                if f_name.endswith('_iptv.txt') and f_name != "uncategorized_iptv.txt":
                    [cite_start]os.remove(os.path.join(temp_dir, f_name)) [cite: 112]
                    [cite_start]logger.debug(f"Removed temporary channel file '{f_name}'.") [cite: 112]
            [cite_start]if not os.listdir(temp_dir): [cite: 112]
                [cite_start]os.rmdir(temp_dir) [cite: 112]
                [cite_start]logger.debug(f"Removed empty directory '{temp_dir}'.") [cite: 113]
    except Exception as e:
        [cite_start]logger.error(f"Error during temporary file cleanup: {e}\n{traceback.format_exc()}") [cite: 113]
    [cite_start]logger.info("Temporary files cleanup completed.") [cite: 113]
    [cite_start]logger.info("Script finished.") [cite: 113]

if __name__ == "__main__":
    main()
