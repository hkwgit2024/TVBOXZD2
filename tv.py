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

# 配置日志，调整为 INFO 级别，以便追踪更多信息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH'),
]:
    if not var:
        logging.error(f"环境变量 '{name}' 未设置。请检查您的配置。")
        exit(1)

# 定义常量
# 默认请求头
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Accept': '*/*'
}
# GitHub API 地址
GITHUB_API_BASE_URL = "https://api.github.com"
# 本地文件路径
LOCAL_CONFIG_PATH = "config.yaml"
LOCAL_URLS_PATH = "urls.txt"
LOCAL_URL_STATES_PATH = "url_states.json"
LOCAL_TEMPLATE_FILE = "template.txt"
LOCAL_SOURCE_FILE = "source.txt"
LOCAL_GITHUB_M3U_FILE = "github_m3u_channels.txt"
LOCAL_IPTV_LIST_FILE = "iptv_list.txt"

# 线程池最大工作线程数，根据系统资源和网络情况调整
MAX_WORKERS = 20 # 适当增加并发，但避免过高导致资源耗尽
# URL 请求超时时间（秒）
URL_REQUEST_TIMEOUT = 10 # 增加超时时间

# 全局会话，用于重用连接
session = requests.Session()
retry_strategy = Retry(
    total=3, # 总共重试3次
    backoff_factor=1, # 重试间隔因子
    status_forcelist=[429, 500, 502, 503, 504], # 针对这些状态码进行重试
    allowed_methods=["HEAD", "GET", "OPTIONS"] # 只对这些方法进行重试
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)
session.headers.update(DEFAULT_HEADERS)

def create_requests_session():
    """创建并配置 Requests 会话，支持重试和超时。"""
    s = requests.Session()
    retry_strategy = Retry(
        total=5, # 增加重试次数
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update(DEFAULT_HEADERS)
    return s

# 使用全局会话
global_session = create_requests_session()

def get_github_headers():
    """获取 GitHub API 请求头。"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    return headers

def check_github_api_rate_limit():
    """检查 GitHub API 速率限制。"""
    logging.info("检查 GitHub API 速率限制...")
    url = f"{GITHUB_API_BASE_URL}/rate_limit"
    try:
        response = global_session.get(url, headers=get_github_headers(), timeout=5)
        response.raise_for_status()
        rate_limit_data = response.json()
        core_limit = rate_limit_data.get('resources', {}).get('core', {})
        logging.info(f"GitHub API 速率限制：总数 {core_limit.get('limit')}, 剩余 {core_limit.get('remaining')}, 重置时间 {datetime.fromtimestamp(core_limit.get('reset'))}")
        if core_limit.get('remaining') < 50: # 如果剩余请求次数过少，等待一段时间
            reset_time = core_limit.get('reset')
            current_time = datetime.now().timestamp()
            wait_time = max(0, reset_time - current_time + 5) # 额外等待5秒
            logging.warning(f"GitHub API 剩余请求次数过少 ({core_limit.get('remaining')})，等待 {wait_time:.0f} 秒直到速率限制重置。")
            time.sleep(wait_time)
            check_github_api_rate_limit() # 再次检查确保限制已重置
    except requests.exceptions.RequestException as e:
        logging.error(f"检查 GitHub API 速率限制失败: {e}")

def get_file_from_github(repo_owner, repo_name, file_path, branch="main"):
    """
    从 GitHub 仓库获取文件内容。
    """
    url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{branch}/{file_path}"
    logging.info(f"尝试从 GitHub 获取文件: {url}")
    try:
        response = global_session.get(url, headers=DEFAULT_HEADERS, timeout=URL_REQUEST_TIMEOUT)
        response.raise_for_status()
        logging.info(f"成功获取文件: {file_path}")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"从 GitHub 获取文件 {file_path} 失败: {e}")
        return None

def save_to_github(file_path, content, commit_message):
    """
    将内容保存到 GitHub 仓库中的指定文件。
    """
    logging.info(f"准备将文件 {file_path} 推送到 GitHub...")
    url = f"{GITHUB_API_BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}"
    headers = get_github_headers()
    headers["Content-Type"] = "application/json"

    try:
        # 尝试获取当前文件 SHA，如果文件不存在则不传 SHA
        get_response = global_session.get(url, headers=headers, timeout=10)
        sha = None
        if get_response.status_code == 200:
            sha = get_response.json().get("sha")
            logging.info(f"获取到文件 {file_path} 的 SHA: {sha}")
        elif get_response.status_code == 404:
            logging.info(f"文件 {file_path} 在仓库中不存在，将创建新文件。")
        else:
            get_response.raise_for_status() # 如果是其他错误，抛出异常

        data = {
            "message": commit_message,
            "content": content.encode("utf-8").decode("base64"),
            "branch": "main"
        }
        if sha:
            data["sha"] = sha

        response = global_session.put(url, headers=headers, data=json.dumps(data), timeout=10)
        response.raise_for_status()
        logging.info(f"成功将 {file_path} 推送到 GitHub。")
    except requests.exceptions.RequestException as e:
        logging.error(f"无法将 {file_path} 推送到 GitHub：{e}")
    except Exception as e:
        logging.error(f"保存到 GitHub 时发生意外错误: {e}")


def load_config():
    """
    加载配置文件。
    """
    config_content = get_file_from_github(REPO_OWNER, REPO_NAME, CONFIG_PATH_IN_REPO)
    if config_content:
        try:
            config = yaml.safe_load(config_content)
            logging.info("成功加载配置文件。")
            return config
        except yaml.YAMLError as e:
            logging.error(f"解析 config.yaml 失败: {e}")
            return None
    return None

def load_urls():
    """
    加载 urls.txt。
    """
    urls_content = get_file_from_github(REPO_OWNER, REPO_NAME, URLS_PATH_IN_REPO)
    if urls_content:
        urls = [url.strip() for url in urls_content.splitlines() if url.strip()]
        logging.info(f"加载 {len(urls)} 个 URL。")
        return urls
    return []

def load_url_states():
    """
    加载 url_states.json。
    """
    states_content = get_file_from_github(REPO_OWNER, REPO_NAME, URL_STATES_PATH_IN_REPO)
    if states_content:
        try:
            states = json.loads(states_content)
            logging.info("成功加载 URL 状态。")
            return states
        except json.JSONDecodeError as e:
            logging.error(f"解析 url_states.json 失败: {e}")
            return {}
    return {}

def save_url_states(url_states):
    """
    保存 url_states.json 到 GitHub。
    """
    logging.info("保存 URL 状态到 GitHub...")
    content = json.dumps(url_states, indent=4, ensure_ascii=False)
    save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态")

def get_file_sha(file_path):
    """获取文件的 SHA 值以便更新 GitHub 文件。"""
    try:
        response = global_session.get(
            f"{GITHUB_API_BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}",
            headers=get_github_headers(),
            timeout=10
        )
        response.raise_for_status()
        return response.json().get("sha")
    except requests.exceptions.RequestException as e:
        logging.warning(f"无法获取 {file_path} 的 SHA 值: {e}")
        return None

def fetch_github_search_results(config):
    """
    根据配置中的关键词从 GitHub 搜索 M3U/M3U8 文件。
    """
    logging.info("开始从 GitHub 搜索 M3U/M3U8 文件...")
    check_github_api_rate_limit() # 搜索前检查速率限制

    search_keywords = config.get("search_keywords", [])
    headers = get_github_headers()
    all_results = []
    
    for keyword in search_keywords:
        logging.info(f"搜索关键词: {keyword}")
        page = 1
        while True:
            search_url = f"{GITHUB_API_BASE_URL}/search/code?q={keyword}&page={page}&per_page=100"
            try:
                response = global_session.get(search_url, headers=headers, timeout=URL_REQUEST_TIMEOUT)
                response.raise_for_status()
                search_data = response.json()
                items = search_data.get("items", [])
                all_results.extend(items)
                logging.info(f"关键词 '{keyword}' 发现 {len(items)} 个结果 (总数: {search_data.get('total_count')})")

                # 检查是否还有下一页
                if len(items) < 100 or page >= 10: # 限制最多获取10页，避免过度请求
                    break
                page += 1
                time.sleep(1) # 避免触发速率限制，每次请求间隔1秒
            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub 搜索关键词 '{keyword}' 失败: {e}")
                break
    
    logging.info(f"GitHub 搜索完成，共找到 {len(all_results)} 个潜在文件。")
    return all_results

def extract_raw_url(item):
    """
    从 GitHub 搜索结果中提取原始文件 URL。
    """
    html_url = item.get("html_url")
    if html_url:
        # 将 https://github.com/owner/repo/blob/branch/path/to/file 转换为
        # https://raw.githubusercontent.com/owner/repo/branch/path/to/file
        raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        return raw_url
    return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_file_content(url):
    """
    获取原始文件内容。使用 tenacity 库进行重试。
    """
    logging.info(f"尝试获取文件内容: {url}")
    try:
        response = global_session.get(url, stream=True, timeout=URL_REQUEST_TIMEOUT)
        response.raise_for_status()
        content = response.text
        logging.info(f"成功获取文件内容: {url} (大小: {len(content)} 字节)")
        return content
    except requests.exceptions.Timeout:
        logging.warning(f"获取文件内容超时: {url}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"获取文件内容失败: {url} - {e}")
        return None

def is_m3u_or_m3u8(content):
    """
    简单检查内容是否为 M3U/M3U8 格式。
    """
    if not content:
        return False
    return "#EXTM3U" in content or "#EXTINF" in content

def filter_invalid_urls(urls, config):
    """
    根据配置文件中的黑名单过滤无效 URL。
    """
    logging.info("开始过滤无效 URL...")
    blacklist_patterns = config.get("blacklist_patterns", [])
    valid_urls = []
    
    for url in urls:
        is_invalid = False
        for pattern in blacklist_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                logging.debug(f"URL '{url}' 匹配黑名单模式 '{pattern}'，已过滤。")
                is_invalid = True
                break
        if not is_invalid:
            valid_urls.append(url)
    logging.info(f"过滤后剩余 {len(valid_urls)} 个有效 URL。")
    return valid_urls

async def async_check_url_validity(url, timeout=3):
    """
    异步检查 M3U8 URL 的有效性（仅检查响应状态码和内容类型）。
    """
    logging.debug(f"异步检查 URL: {url}")
    try:
        # 使用 aiohttp 替代 requests 进行异步请求
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.head(url, allow_redirects=True) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/vnd.apple.mpegurl' in content_type or 'audio/mpegurl' in content_type or 'application/x-mpegurl' in content_type or 'video/mp2t' in content_type:
                        logging.debug(f"URL 有效 (状态码: {response.status}, Content-Type: {content_type}): {url}")
                        return True
                    else:
                        logging.debug(f"URL 内容类型不匹配 (状态码: {response.status}, Content-Type: {content_type}): {url}")
                        return False
                else:
                    logging.debug(f"URL 无效 (状态码: {response.status}): {url}")
                    return False
    except aiohttp.ClientError as e:
        logging.debug(f"异步检查 URL 失败 ({e}): {url}")
        return False
    except Exception as e:
        logging.debug(f"异步检查 URL 发生未知错误 ({e}): {url}")
        return False

async def run_async_checks(urls, max_concurrent_tasks=50):
    """
    并发运行异步 URL 检查。
    """
    logging.info(f"开始异步并发检查 {len(urls)} 个 URL 的有效性 (并发数: {max_concurrent_tasks})...")
    tasks = []
    for url in urls:
        tasks.append(async_check_url_validity(url))

    results = []
    # 控制并发量
    semaphore = asyncio.Semaphore(max_concurrent_tasks)
    async def limited_task(task):
        async with semaphore:
            return await task

    for f in asyncio.as_completed([limited_task(task) for task in tasks]):
        results.append(await f)
        
    logging.info("异步 URL 检查完成。")
    return results

def get_channel_name_from_line(line):
    """
    从 M3U/M3U8 播放列表行中提取频道名称。
    """
    match = re.search(r'#EXTINF:-1,(.*?)\s*$', line)
    if match:
        return match.group(1).strip()
    return None

def process_m3u_content(content, template_channels):
    """
    处理 M3U/M3U8 内容，提取频道和 URL，并与模板匹配。
    """
    lines = content.splitlines()
    processed_channels = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("#EXTINF"):
            channel_name = get_channel_name_from_line(line)
            if channel_name:
                # 查找下一个非空行作为 URL
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines):
                    url = lines[j].strip()
                    # 检查频道名称是否在模板中（忽略大小写和空格）
                    if channel_name.lower().replace(" ", "") in [t.lower().replace(" ", "") for t in template_channels]:
                        processed_channels.append((channel_name, url))
                    else:
                        logging.debug(f"频道 '{channel_name}' 不在模板中，跳过。")
                i = j # 更新索引到 URL 之后
            else:
                i += 1
        else:
            i += 1
    return processed_channels

def update_channels_from_url(url, template_channels, matched_channels, url_states):
    """
    从单个 URL 获取并更新频道列表。
    """
    logging.info(f"处理 URL: {url}")
    
    # 检查 URL 是否在上次运行时已失效，如果是，则跳过
    if url_states.get(url) == 'invalid' and (datetime.now() - datetime.fromisoformat(url_states.get(f"{url}_last_check_time", '2000-01-01T00:00:00'))).total_seconds() < 3600 * 24: # 24小时内不重复检查失效URL
        logging.info(f"URL {url} 24小时内已标记为无效，跳过。")
        return

    try:
        content = fetch_file_content(url)
        if content and is_m3u_or_m3u8(content):
            channels_from_url = process_m3u_content(content, template_channels)
            valid_channels_count = 0
            for name, stream_url in channels_from_url:
                # 检查 stream_url 是否有效 (同步检查，可以考虑异步)
                if asyncio.run(async_check_url_validity(stream_url)): # 直接调用异步检查函数
                    matched_channels[name] = stream_url
                    valid_channels_count += 1
                else:
                    logging.debug(f"流 URL 无效，跳过: {stream_url}")
            
            if valid_channels_count > 0:
                logging.info(f"从 {url} 找到 {valid_channels_count} 个有效频道。")
                url_states[url] = 'valid'
            else:
                logging.info(f"从 {url} 未找到有效频道。")
                url_states[url] = 'no_valid_channels'

        else:
            logging.info(f"URL {url} 内容不是有效的 M3U/M3U8 格式或获取失败。")
            url_states[url] = 'invalid'
    except Exception as e:
        logging.error(f"处理 URL {url} 时发生错误: {e}")
        url_states[url] = 'error'
    finally:
        url_states[f"{url}_last_check_time"] = datetime.now().isoformat()

def merge_local_channel_files(directory, output_file):
    """
    合并指定目录下的所有频道文件到一个输出文件。
    """
    logging.info(f"开始合并本地频道文件到 {output_file}...")
    all_channels = set()
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        all_channels.add(line.strip())
            except Exception as e:
                logging.error(f"读取本地文件 {filepath} 失败: {e}")
    
    with open(output_file, "w", encoding="utf-8") as f:
        for channel_line in sorted(list(all_channels)):
            f.write(channel_line + "\n")
    logging.info(f"成功合并 {len(all_channels)} 个频道到 {output_file}。")

def main():
    start_time = datetime.now()
    logging.info("脚本开始执行。")

    # 1. 加载配置、URL 和状态
    config = load_config()
    if not config:
        logging.error("无法加载配置，脚本退出。")
        return

    existing_urls = load_urls()
    url_states = load_url_states()

    local_channels_directory = "output"
    os.makedirs(local_channels_directory, exist_ok=True)

    # 2. 从 template.txt 加载模板频道
    template_content = get_file_from_github(REPO_OWNER, REPO_NAME, LOCAL_TEMPLATE_FILE)
    if not template_content:
        logging.error("无法加载模板文件 template.txt，脚本退出。")
        return
    template_channels = [line.split(',', 1)[0].strip() for line in template_content.splitlines() if line.strip()]
    logging.info(f"加载 {len(template_channels)} 个模板频道。")
    all_template_channel_names = set(template_channels) # 用于快速查找

    # 3. 从 source.txt 加载待匹配频道
    source_content = get_file_from_github(REPO_OWNER, REPO_NAME, LOCAL_SOURCE_FILE)
    channels_for_matching = []
    if source_content:
        channels_for_matching = [line.strip() for line in source_content.splitlines() if line.strip()]
    else:
        logging.warning("无法加载 source.txt，将不会有额外的频道进行匹配。")
    
    # 4. 获取 GitHub 搜索结果
    github_search_items = fetch_github_search_results(config)
    github_raw_urls = [extract_raw_url(item) for item in github_search_items if extract_raw_url(item)]
    github_raw_urls = filter_invalid_urls(list(set(github_raw_urls)), config) # 去重并过滤黑名单

    all_urls_to_check = list(set(existing_urls + github_raw_urls))
    logging.info(f"总计 {len(all_urls_to_check)} 个 URL 需要检查。")

    # 5. 并发处理 URL，获取有效频道
    current_template_matched_channels = {} # 存储当前运行周期匹配到的频道

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(update_channels_from_url, url, template_channels, current_template_matched_channels, url_states): url for url in all_urls_to_check}
        for future in as_completed(futures):
            url = futures[future]
            try:
                future.result() # 获取结果，如果出现异常会在这里抛出
            except Exception as exc:
                logging.error(f'URL {url} 生成了异常: {exc}')

    logging.info(f"已匹配到 {len(current_template_matched_channels)} 个频道。")

    # 6. 保存所有匹配到的频道到 output/github_m3u_channels.txt
    github_matched_output_path = os.path.join(local_channels_directory, LOCAL_GITHUB_M3U_FILE)
    with open(github_matched_output_path, "w", encoding="utf-8") as f:
        for channel_name, url in current_template_matched_channels.items():
            f.write(f"{channel_name},{url}\n")
    logging.info(f"已将 {len(current_template_matched_channels)} 个匹配到的频道保存到 {github_matched_output_path}。")
    save_to_github(f"output/{LOCAL_GITHUB_M3U_FILE}", '\n'.join([f"{name},{url}" for name, url in current_template_matched_channels.items()]), "更新 GitHub M3U 频道列表")

    # 7. 合并所有本地频道文件并推送到 GitHub
    final_iptv_list_output_file = LOCAL_IPTV_LIST_FILE
    merge_local_channel_files(local_channels_directory, final_iptv_list_output_file)
    try:
        with open(final_iptv_list_output_file, "r", encoding="utf-8") as f:
            final_iptv_content = f.read()
        save_to_github(f"output/{final_iptv_list_output_file}", final_iptv_content, "更新最终 IPTV 列表")
        logging.info(f"已将 {final_iptv_list_output_file} 推送到远程仓库。")
    except Exception as e:
        logging.error(f"无法将 {final_iptv_list_output_file} 推送到 GitHub：{e}")

    # 8. 找出未匹配的频道并保存
    unmatched_channels_list = []
    for channel_line in channels_for_matching:
        channel_name = channel_line.split(',', 1)[0].strip()
        if channel_name not in all_template_channel_names: # 检查是否在模板中，而不是当前匹配到的
            unmatched_channels_list.append(channel_line)
    
    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels_list:
            f.write(channel_line.split(',')[0] + "\n") # 只写入频道名
    logging.info(f"已将 {len(unmatched_channels_list)} 个未匹配频道保存到 {unmatched_output_file_path}。")

    # 9. 保存 URL 状态
    save_url_states(url_states)

    end_time = datetime.now()
    logging.info(f"脚本执行完毕，总耗时: {end_time - start_time}")

if __name__ == "__main__":
    main()
