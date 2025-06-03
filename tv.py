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
import dns.resolver  # 新增 DNS 解析库

# 配置日志，减少 DEBUG 输出
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')

# 验证环境变量
for var, name in [(GITHUB_TOKEN, 'BOT'), (REPO_OWNER, 'REPO_OWNER'), (REPO_NAME, 'REPO_NAME'),
                  (CONFIG_PATH_IN_REPO, 'CONFIG_PATH'), (URLS_PATH_IN_REPO, 'URLS_PATH'),
                  (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH')]:
    if not var:
        logging.error(f"错误：环境变量 '{name}' 未设置。")
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
    logging.error(f"无法从 GitHub 的 '{CONFIG_PATH_IN_REPO}' 加载配置。")
    exit(1)

CONFIG = load_config()

GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
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

# 新增：常见无效 TLD 列表
INVALID_TLDS = {'.local', '.invalid', '.test', '.example', '.lat', '.ml', '.tk'}

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
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

def is_valid_domain(domain):
    """检查域名是否可解析"""
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return False

def pre_screen_url(url):
    if not isinstance(url, str) or not url:
        return False
    parsed_url = urlparse(url)
    if parsed_url.scheme not in CONFIG.get('url_pre_screening', {}).get('allowed_protocols', []):
        return False
    if not parsed_url.netloc:
        return False
    # 检查无效 TLD
    for tld in INVALID_TLDS:
        if parsed_url.netloc.lower().endswith(tld):
            logging.debug(f"预筛选过滤（无效 TLD）：{url}")
            return False
    # DNS 解析检查
    if not is_valid_domain(parsed_url.netloc):
        logging.debug(f"预筛选过滤（域名不可解析）：{url}")
        return False
    invalid_url_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    for pattern in [re.compile(p, re.IGNORECASE) for p in invalid_url_patterns]:
        if pattern.search(url):
            logging.debug(f"预筛选过滤（无效模式）：{url}")
            return False
    if len(url) < 15:
        return False
    return True

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
        logging.error(f"获取 URL {url} 发生请求错误：{e}")
        return None

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
    logging.warning("正在开始从 GitHub 自动发现新的 IPTV 源 URL...")
    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if i > 0:
            logging.warning(f"切换到下一个关键词：'{keyword}'。等待 {GITHUB_API_RETRY_WAIT} 秒...")
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
                if rate_limit_remaining < 5:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API 接近速率限制（剩余：{rate_limit_remaining}）。等待 {wait_seconds:.0f} 秒...")
                    time.sleep(wait_seconds)
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
                            cleaned_url.lower().endswith(('.m3u', '.m3u8', '.txt')) and
                            pre_screen_url(cleaned_url)):
                            found_urls.add(cleaned_url)
                page += 1
                time.sleep(1)  # 减少每页请求间隔
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    wait_seconds = max(0, int(response.headers.get('X-RateLimit-Reset', 0)) - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制已达到！等待 {wait_seconds:.0f} 秒...")
                    time.sleep(wait_seconds)
                    continue
                else:
                    logging.error(f"GitHub API 请求失败（关键词：{keyword}，页码：{page}）：{e}")
                    break
    new_urls_count = len(found_urls - existing_urls)
    if new_urls_count > 0:
        updated_urls = list(existing_urls | found_urls)
        write_array_to_txt_remote(urls_file_path_remote, updated_urls, "通过 GitHub 发现的新 URL 更新 urls.txt")
        logging.warning(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URL。总 URL 数：{len(updated_urls)}")
    logging.warning("GitHub URL 自动发现完成。")

def check_channel_validity_and_speed(channel_name, url, timeout=CHANNEL_CHECK_TIMEOUT):
    start_time = time.time()
    parsed_url = urlparse(url)
    if not is_valid_domain(parsed_url.netloc):
        logging.debug(f"跳过无效域名：{url}")
        return None, False
    try:
        if url.startswith("http"):
            response = session.head(url, timeout=timeout, allow_redirects=True)
            is_valid = 200 <= response.status_code < 400
        elif url.startswith("rtmp"):
            try:
                subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
                result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
                is_valid = result.returncode == 0
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                is_valid = False
        elif url.startswith("rtp"):
            host, port = parsed_url.hostname, parsed_url.port
            if host and port:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.connect((host, port))
                    s.sendto(b'', (host, port))
                    s.recv(1)
                    is_valid = True
            else:
                is_valid = False
        else:
            is_valid = False
        if is_valid:
            return (time.time() - start_time) * 1000, True
        return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 失败：{e}")
        return None, False

def main():
    auto_discover_github_urls(URLS_PATH_IN_REPO, GITHUB_TOKEN)
    urls = read_txt_to_array_remote(URLS_PATH_IN_REPO)
    if not urls:
        logging.warning(f"在远程 '{URLS_PATH_IN_REPO}' 中未找到 URL，脚本将提前退出。")
        return
    url_states = load_url_states_remote()
    logging.warning(f"已加载 {len(url_states)} 个历史 URL 状态。")
    all_extracted_channels = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(extract_channels_from_url, url, url_states): url for url in urls}
        for future in as_completed(future_to_url):
            try:
                result_channels = future.result()
                all_extracted_channels.update(result_channels)
            except Exception as exc:
                logging.error(f"处理源 '{future_to_url[future]}' 时发生异常：{exc}")
    save_url_states_remote(url_states)
    logging.warning(f"从所有源提取了 {len(all_extracted_channels)} 个原始频道。")
    filtered_channels = filter_and_modify_channels(list(all_extracted_channels))
    unique_filtered_channels = list(set(filtered_channels))
    unique_filtered_channels_str = [f"{name},{url}" for name, url in unique_filtered_channels]
    logging.warning(f"过滤和清理后，剩余 {len(unique_filtered_channels_str)} 个唯一频道。")
    valid_channels_with_speed = check_channels_multithreaded(unique_filtered_channels_str)
    logging.warning(f"有效且响应的频道数量：{len(valid_channels_with_speed)}")
    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_sorted_channels_to_file(iptv_speed_file_path, valid_channels_with_speed)
    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    os.makedirs(local_channels_directory, exist_ok=True)
    clear_directory_txt_files(local_channels_directory)
    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True)
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]
    channels_for_matching = read_txt_to_array_local(iptv_speed_file_path)
    all_template_channel_names = set()
    for template_file in template_files:
        names_from_current_template = read_txt_to_array_local(os.path.join(template_directory, template_file))
        all_template_channel_names.update(names_from_current_template)
    for template_file in template_files:
        template_channels_names = set(read_txt_to_array_local(os.path.join(template_directory, template_file)))
        template_name = os.path.splitext(template_file)[0]
        current_template_matched_channels = [
            channel_line for channel_line in channels_for_matching
            if channel_line.split(',', 1)[0].strip() in template_channels_names
        ]
        if "央视" in template_name or "CCTV" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.warning(f"已按数字对 '{template_name}' 频道进行排序。")
        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.warning(f"频道列表已写入：'{template_name}_iptv.txt'，包含 {len(current_template_matched_channels)} 个频道。")
    final_iptv_list_output_file = "iptv_list.txt"
    merge_local_channel_files(local_channels_directory, final_iptv_list_output_file)
    try:
        with open(final_iptv_list_output_file, "r", encoding="utf-8") as f:
            final_iptv_content = f.read()
        save_to_github(f"output/{final_iptv_list_output_file}", final_iptv_content, "更新最终 IPTV 列表")
        logging.warning(f"已将 {final_iptv_list_output_file} 推送到远程仓库。")
    except Exception as e:
        logging.error(f"无法将 {final_iptv_list_output_file} 推送到 GitHub：{e}")
    unmatched_channels_list = [
        channel_line for channel_line in channels_for_matching
        if channel_line.split(',', 1)[0].strip() not in all_template_channel_names
    ]
    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels_list:
            f.write(channel_line.split(',')[0].strip() + '\n')
    logging.warning(f"已保存不匹配但已检测到的频道列表到：'{unmatched_output_file_path}'，总共 {len(unmatched_channels_list)} 个频道。")
    for temp_file in ['iptv.txt', 'iptv_speed.txt']:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError as e:
                logging.warning(f"删除临时文件 {temp_file} 时发生错误：{e}")

if __name__ == "__main__":
    main()
