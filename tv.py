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
import base64 # 导入base64模块用于解码文件内容

# --- 配置日志 ---
# 将日志级别从 ERROR 提升到 INFO，以便输出更详细的运行过程信息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 环境变量定义与验证 ---
GITHUB_TOKEN = os.getenv('BOT')
REPO_OWNER = os.getenv('REPO_OWNER')
REPO_NAME = os.getenv('REPO_NAME')
CONFIG_PATH_IN_REPO = os.getenv('CONFIG_PATH')
URLS_PATH_IN_REPO = os.getenv('URLS_PATH')
URL_STATES_PATH_IN_REPO = os.getenv('URL_STATES_PATH')
# 增加一个环境变量来指定仓库的分支，默认为 'main'
GITHUB_REPO_BRANCH = os.getenv('GITHUB_REPO_BRANCH', 'main')

# 验证所有必需的环境变量是否已设置
for var, name in [
    (GITHUB_TOKEN, 'BOT'),
    (REPO_OWNER, 'REPO_OWNER'),
    (REPO_NAME, 'REPO_NAME'),
    (CONFIG_PATH_IN_REPO, 'CONFIG_PATH'),
    (URLS_PATH_IN_REPO, 'URLS_PATH'),
    (URL_STATES_PATH_IN_REPO, 'URL_STATES_PATH'),
]:
    if not var:
        logging.error(f"环境变量 '{name}' 未设置。请检查您的配置。脚本将退出。")
        exit(1)

# --- 常量定义 ---
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Accept': '*/*'
}
GITHUB_API_BASE_URL = "https://api.github.com"

# 本地文件路径，用于中间操作和最终输出
LOCAL_CONFIG_PATH = "config.yaml" # 这个是历史遗留，实际上不会用到本地路径
LOCAL_URLS_PATH = "urls.txt"      # 同上
LOCAL_URL_STATES_PATH = "url_states.json" # 同上
LOCAL_TEMPLATE_FILE = "template.txt"
LOCAL_SOURCE_FILE = "source.txt"
LOCAL_GITHUB_M3U_FILE = "github_m3u_channels.txt"
LOCAL_IPTV_LIST_FILE = "iptv_list.txt"

# 线程池最大工作线程数，用于并发处理URL
MAX_WORKERS = 50 
# URL 请求超时时间（秒），避免无限等待
URL_REQUEST_TIMEOUT = 10 
# 异步URL检查的超时时间，通常会更短
ASYNC_URL_CHECK_TIMEOUT = 5

# --- 全局 Requests 会话配置 ---
global_session = requests.Session()
retry_strategy = Retry(
    total=5,  # 总共重试次数，包括第一次请求
    backoff_factor=1,  # 重试间隔因子，第一次1s，第二次2s，以此类推
    status_forcelist=[429, 500, 502, 503, 504],  # 对这些HTTP状态码进行重试
    allowed_methods=["HEAD", "GET", "OPTIONS"]  # 只对这些HTTP方法进行重试
)
adapter = HTTPAdapter(max_retries=retry_strategy)
global_session.mount("http://", adapter)
global_session.mount("https://", adapter)
global_session.headers.update(DEFAULT_HEADERS)

# --- GitHub API 相关函数 ---
def get_github_headers():
    """生成 GitHub API 请求所需的认证头。"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    return headers

def check_github_api_rate_limit():
    """
    检查 GitHub API 速率限制。如果剩余请求次数过少，则等待直到重置时间。
    这对于避免被GitHub临时限制非常重要。
    """
    logging.info("检查 GitHub API 速率限制...")
    url = f"{GITHUB_API_BASE_URL}/rate_limit"
    try:
        response = global_session.get(url, headers=get_github_headers(), timeout=5)
        response.raise_for_status() 
        rate_limit_data = response.json()
        core_limit = rate_limit_data.get('resources', {}).get('core', {})
        remaining = core_limit.get('remaining', 0)
        reset_time_timestamp = core_limit.get('reset', 0)
        
        reset_datetime = datetime.fromtimestamp(reset_time_timestamp)
        logging.info(f"GitHub API 速率限制：总数 {core_limit.get('limit')}, 剩余 {remaining}, 重置时间 {reset_datetime}")

        if remaining < 100: # 设置一个阈值，例如低于100次就等待
            current_time = datetime.now().timestamp()
            wait_time = max(0, reset_time_timestamp - current_time + 5) # 额外等待5秒作为缓冲
            logging.warning(f"GitHub API 剩余请求次数过少 ({remaining})，等待 {wait_time:.0f} 秒直到速率限制重置。")
            time.sleep(wait_time)
            # 等待后可以再次检查，确保万无一失
            check_github_api_rate_limit() 
    except requests.exceptions.RequestException as e:
        logging.error(f"检查 GitHub API 速率限制失败: {e}")
    except Exception as e:
        logging.error(f"检查 GitHub API 速率限制时发生意外错误: {e}")


def get_file_from_github(repo_owner, repo_name, file_path, branch="main"):
    """
    从 GitHub 仓库获取文件内容。
    对于私有仓库，使用 GitHub Contents API 获取文件内容，该内容是 Base64 编码的。
    """
    url = f"{GITHUB_API_BASE_URL}/repos/{repo_owner}/{repo_name}/contents/{file_path}?ref={branch}"
    logging.info(f"尝试从 GitHub API 获取文件: {url}")
    try:
        response = global_session.get(url, headers=get_github_headers(), timeout=URL_REQUEST_TIMEOUT)
        response.raise_for_status() # 如果状态码不是2xx，抛出HTTPError

        file_data = response.json()
        if 'content' in file_data:
            # 文件内容是Base64编码的，需要解码
            decoded_content = base64.b64decode(file_data['content']).decode('utf-8')
            logging.info(f"成功从 GitHub API 获取并解码文件: {file_path}")
            return decoded_content
        else:
            logging.error(f"从 GitHub API 获取文件 {file_path} 成功，但未找到 'content' 字段。")
            return None
    except requests.exceptions.HTTPError as e:
        logging.error(f"从 GitHub API 获取文件 {file_path} 失败: HTTP错误 {e.response.status_code} - {e.response.text}")
        if e.response.status_code == 404:
            logging.error(f"请检查文件路径 '{file_path}' 或分支名 '{branch}' 是否正确。")
        elif e.response.status_code == 401 or e.response.status_code == 403:
            logging.error(f"GitHub API 认证失败或无权限访问私有仓库。请检查 BOT 令牌的权限。")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"从 GitHub API 获取文件 {file_path} 失败: 网络或请求错误 - {e}")
        return None
    except Exception as e:
        logging.error(f"获取 GitHub 文件时发生意外错误 {file_path}: {e}")
        return None


def save_to_github(file_path, content, commit_message):
    """
    将内容保存到 GitHub 仓库中的指定文件。
    会先尝试获取文件的SHA值，如果文件存在则更新，不存在则创建。
    """
    logging.info(f"准备将文件 {file_path} 推送到 GitHub...")
    url = f"{GITHUB_API_BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}"
    headers = get_github_headers()
    headers["Content-Type"] = "application/json"

    try:
        # 尝试获取当前文件 SHA，如果文件不存在则不传 SHA
        get_response = global_session.get(url, headers=headers, timeout=URL_REQUEST_TIMEOUT)
        sha = None
        if get_response.status_code == 200:
            sha = get_response.json().get("sha")
            logging.info(f"获取到文件 {file_path} 的 SHA: {sha}")
        elif get_response.status_code == 404:
            logging.info(f"文件 {file_path} 在仓库中不存在，将创建新文件。")
        else:
            get_response.raise_for_status() # 如果是其他错误，抛出异常

        # Base64编码内容
        encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")

        data = {
            "message": commit_message,
            "content": encoded_content,
            "branch": GITHUB_REPO_BRANCH # 使用环境变量指定的分支
        }
        if sha:
            data["sha"] = sha # 如果是更新操作，需要提供SHA值

        response = global_session.put(url, headers=headers, data=json.dumps(data), timeout=URL_REQUEST_TIMEOUT)
        response.raise_for_status() # 检查响应状态
        logging.info(f"成功将 {file_path} 推送到 GitHub。")
    except requests.exceptions.RequestException as e:
        logging.error(f"无法将 {file_path} 推送到 GitHub：网络或API错误 - {e}")
    except json.JSONEncodeError as e:
        logging.error(f"无法将 {file_path} 推送到 GitHub：JSON编码错误 - {e}")
    except Exception as e:
        logging.error(f"保存到 GitHub 时发生意外错误 for {file_path}: {e}")

# --- 文件加载/保存函数 ---
def load_config(branch="main"):
    """加载远程 GitHub 仓库中的配置文件。"""
    config_content = get_file_from_github(REPO_OWNER, REPO_NAME, CONFIG_PATH_IN_REPO, branch=branch)
    if config_content:
        try:
            config = yaml.safe_load(config_content)
            logging.info("成功加载配置文件。")
            return config
        except yaml.YAMLError as e:
            logging.error(f"解析 config.yaml 失败: {e}")
            return None
    logging.error("未能从 GitHub 加载 config.yaml 内容。")
    return None

def load_urls(branch="main"):
    """加载远程 GitHub 仓库中的 urls.txt 文件。"""
    urls_content = get_file_from_github(REPO_OWNER, REPO_NAME, URLS_PATH_IN_REPO, branch=branch)
    if urls_content:
        urls = [url.strip() for url in urls_content.splitlines() if url.strip()]
        logging.info(f"加载 {len(urls)} 个 URL。")
        return urls
    logging.warning("未能从 GitHub 加载 urls.txt 内容，将使用空列表。")
    return []

def load_url_states(branch="main"):
    """加载远程 GitHub 仓库中的 url_states.json 文件，用于记录URL状态。"""
    states_content = get_file_from_github(REPO_OWNER, REPO_NAME, URL_STATES_PATH_IN_REPO, branch=branch)
    if states_content:
        try:
            states = json.loads(states_content)
            logging.info("成功加载 URL 状态。")
            return states
        except json.JSONDecodeError as e:
            logging.error(f"解析 url_states.json 失败: {e}。将返回空状态。")
            return {}
    logging.warning("未能从 GitHub 加载 url_states.json 内容，将返回空状态。")
    return {}

def save_url_states(url_states):
    """保存 URL 状态到 GitHub 的 url_states.json 文件。"""
    logging.info("保存 URL 状态到 GitHub...")
    # indent=4 使JSON格式更易读，ensure_ascii=False 允许非ASCII字符（如中文）直接写入
    content = json.dumps(url_states, indent=4, ensure_ascii=False)
    save_to_github(URL_STATES_PATH_IN_REPO, content, "更新 URL 状态")

# --- GitHub 搜索和 URL 处理 ---
def fetch_github_search_results(config):
    """
    根据配置中的关键词从 GitHub 搜索 M3U/M3U8 文件。
    实现了分页获取和速率限制检查。
    """
    logging.info("开始从 GitHub 搜索 M3U/M3U8 文件...")
    check_github_api_rate_limit() # 在搜索前检查速率限制

    search_keywords = config.get("search_keywords", [])
    headers = get_github_headers()
    all_results = []
    
    for keyword in search_keywords:
        logging.info(f"搜索关键词: {keyword}")
        page = 1
        while True:
            # GitHub API 搜索代码
            search_url = f"{GITHUB_API_BASE_URL}/search/code?q={keyword}&page={page}&per_page=100"
            try:
                response = global_session.get(search_url, headers=headers, timeout=URL_REQUEST_TIMEOUT)
                response.raise_for_status()
                search_data = response.json()
                items = search_data.get("items", [])
                all_results.extend(items)
                logging.info(f"关键词 '{keyword}' 在第 {page} 页发现 {len(items)} 个结果 (总数: {search_data.get('total_count')})")

                # 如果当前页结果少于 per_page，或达到最大页数限制，则停止分页
                # 限制最多获取10页，避免过度请求和长时间运行
                if len(items) < 100 or page >= 10: 
                    break
                page += 1
                time.sleep(1) # 每次请求间隔1秒，避免触发速率限制
            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub 搜索关键词 '{keyword}' (页码 {page}) 失败: {e}")
                break
            except Exception as e:
                logging.error(f"GitHub 搜索关键词 '{keyword}' (页码 {page}) 发生意外错误: {e}")
                break
    
    logging.info(f"GitHub 搜索完成，共找到 {len(all_results)} 个潜在文件。")
    return all_results

def extract_raw_url(item):
    """
    从 GitHub 搜索结果中提取原始文件 URL (raw.githubusercontent.com 链接)。
    注意：GitHub 搜索 API 提供的文件链接通常是公开的 `raw.githubusercontent.com` 链接。
    对于M3U8的流媒体文件，通常是公开的，所以这里保留这个逻辑。
    """
    html_url = item.get("html_url")
    if html_url:
        raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        return raw_url
    return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_file_content(url):
    """
    获取原始文件内容。使用 tenacity 库进行重试，处理临时的网络问题。
    此函数主要用于处理M3U8文件本身的URL，这些通常是公开的。
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
        raise # 重新抛出异常，让 tenacity 捕获并重试
    except requests.exceptions.RequestException as e:
        logging.warning(f"获取文件内容失败（重试中）: {url} - {e}")
        raise # 重新抛出异常，让 tenacity 捕获并重试
    except Exception as e:
        logging.error(f"获取文件内容时发生意外错误: {url} - {e}")
        return None # 对于非 Requests 异常，直接返回None

def is_m3u_or_m3u8(content):
    """
    简单检查内容是否为 M3U/M3U8 格式。
    """
    if not content:
        return False
    # 检查M3U文件的典型标识
    return "#EXTM3U" in content or "#EXTINF" in content

def filter_invalid_urls(urls, config):
    """
    根据配置文件中的黑名单过滤无效 URL。
    """
    logging.info("开始过滤黑名单中的 URL...")
    blacklist_patterns = config.get("blacklist_patterns", [])
    valid_urls = []
    
    for url in urls:
        is_invalid = False
        for pattern in blacklist_patterns:
            # re.IGNORECASE 使匹配不区分大小写
            if re.search(pattern, url, re.IGNORECASE):
                logging.debug(f"URL '{url}' 匹配黑名单模式 '{pattern}'，已过滤。")
                is_invalid = True
                break
        if not is_invalid:
            valid_urls.append(url)
    logging.info(f"过滤黑名单后剩余 {len(valid_urls)} 个 URL。")
    return valid_urls

async def async_check_url_validity(url, timeout=ASYNC_URL_CHECK_TIMEOUT):
    """
    异步检查 M3U8 URL 的有效性。
    仅发送 HEAD 请求，检查响应状态码和内容类型，不下载实际内容。
    这比下载完整内容快很多。
    """
    # 确保 URL 是绝对的，否则 aiohttp 可能无法正确处理
    if not urlparse(url).scheme:
        logging.debug(f"URL 缺少 scheme，无法检查: {url}")
        return False

    logging.debug(f"异步检查 URL: {url}")
    try:
        # 使用 aiohttp.ClientSession 进行异步请求，设置连接超时
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            # 发送 HEAD 请求，只获取响应头，allow_redirects=True 处理重定向
            async with session.head(url, allow_redirects=True, headers=DEFAULT_HEADERS) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    # 检查M3U8或相关流媒体的Content-Type
                    if 'application/vnd.apple.mpegurl' in content_type or \
                       'audio/mpegurl' in content_type or \
                       'application/x-mpegurl' in content_type or \
                       'video/mp2t' in content_type or \
                       'application/octet-stream' in content_type: # 有时M3U8可能以通用二进制流返回
                        logging.debug(f"URL 有效 (状态码: {response.status}, Content-Type: {content_type}): {url}")
                        return True
                    else:
                        logging.debug(f"URL 内容类型不匹配 (状态码: {response.status}, Content-Type: {content_type}): {url}")
                        return False
                else:
                    logging.debug(f"URL 无效 (状态码: {response.status}): {url}")
                    return False
    except aiohttp.ClientError as e:
        # 捕获 aiohttp 客户端请求过程中的各种错误（连接、DNS、超时等）
        logging.debug(f"异步检查 URL 失败 ({e}): {url}")
        return False
    except Exception as e:
        # 捕获其他未知错误
        logging.debug(f"异步检查 URL 发生未知错误 ({e}): {url}")
        return False

async def run_async_checks(urls, max_concurrent_tasks=100):
    """
    并发运行异步 URL 检查。
    使用 asyncio.Semaphore 控制并发量，避免一次性开启过多连接。
    """
    logging.info(f"开始异步并发检查 {len(urls)} 个 URL 的有效性 (最大并发数: {max_concurrent_tasks})...")
    tasks = []
    # 使用 Semaphore 限制并发任务数量
    semaphore = asyncio.Semaphore(max_concurrent_tasks)

    async def semaphored_check(url):
        async with semaphore:
            return await async_check_url_validity(url)

    for url in urls:
        tasks.append(semaphored_check(url))

    # 使用 asyncio.gather 并发运行所有任务并收集结果
    results = await asyncio.gather(*tasks, return_exceptions=True) # return_exceptions=True 防止一个任务失败导致所有任务停止
    
    # 将结果与原始URL关联起来
    valid_urls = [url for url, is_valid in zip(urls, results) if is_valid is True]
    
    logging.info(f"异步 URL 检查完成。发现 {len(valid_urls)} 个有效 URL。")
    return valid_urls


def get_channel_name_from_line(line):
    """
    从 M3U/M3U8 播放列表行中提取频道名称。
    例如: #EXTINF:-1,CCTV1 -> CCTV1
    """
    match = re.search(r'#EXTINF:-1,(.*?)\s*$', line)
    if match:
        return match.group(1).strip()
    return None

def process_m3u_content(content, template_channel_names):
    """
    处理 M3U/M3U8 内容，提取频道和 URL，并与模板匹配。
    template_channel_names 是一个集合，用于快速查找。
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
                    # 检查频道名称是否在模板中（忽略大小写和空格进行比较）
                    # 将模板名称也处理成同样的格式进行比较
                    cleaned_channel_name = channel_name.lower().replace(" ", "")
                    if cleaned_channel_name in template_channel_names:
                        processed_channels.append((channel_name, url))
                    else:
                        logging.debug(f"频道 '{channel_name}' 不在模板中，跳过。")
                i = j # 更新索引到 URL 之后
            else:
                i += 1 # 如果没有提取到频道名，也前进一行
        else:
            i += 1 # 如果不是 #EXTINF 行，前进一行
    return processed_channels

def update_channels_from_url(url, template_channel_names, matched_channels, url_states):
    """
    从单个 M3U/M3U8 URL 获取并更新频道列表。
    此函数将在 ThreadPoolExecutor 中并发运行。
    """
    logging.info(f"开始处理 URL: {url}")
    
    # 检查 URL 上次检查状态和时间，避免频繁检查失效URL
    last_check_time_str = url_states.get(f"{url}_last_check_time")
    last_status = url_states.get(url)

    if last_check_time_str:
        last_check_time = datetime.fromisoformat(last_check_time_str)
        # 如果上次检查时间在过去24小时内且状态为 'invalid' 或 'no_valid_channels'，则跳过
        if (datetime.now() - last_check_time).total_seconds() < 3600 * 24 and \
           (last_status == 'invalid' or last_status == 'no_valid_channels'):
            logging.info(f"URL {url} 在过去24小时内已标记为 '{last_status}'，跳过本次检查。")
            return

    try:
        content = fetch_file_content(url)
        if content and is_m3u_or_m3u8(content):
            channels_from_url = process_m3u_content(content, template_channel_names)
            
            valid_channels_count = 0
            
            stream_urls_to_check = [stream_url for _, stream_url in channels_from_url]
            # 对从当前M3U/M3U8文件中提取出的所有流URL进行批量异步有效性检查
            valid_stream_urls = asyncio.run(run_async_checks(stream_urls_to_check, max_concurrent_tasks=50))
            valid_stream_urls_set = set(valid_stream_urls) # 转换为集合用于快速查找

            for name, stream_url in channels_from_url:
                # 检查流URL是否在有效列表中
                if stream_url in valid_stream_urls_set:
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
        # 无论成功失败，都记录最后检查时间
        url_states[f"{url}_last_check_time"] = datetime.now().isoformat()

def merge_local_channel_files(directory, output_file):
    """
    合并指定目录下的所有频道文件到一个输出文件。
    会去重并按字母顺序排序。
    """
    logging.info(f"开始合并本地频道文件到 {output_file}...")
    all_channels = set() # 使用集合自动去重
    # 确保 directory 存在
    if not os.path.exists(directory):
        logging.warning(f"本地目录 '{directory}' 不存在，跳过文件合并。")
        return
        
    for filename in os.listdir(directory):
        # 只处理 .txt 文件，并且跳过一些已知的文件名，如 ip.txt
        if filename.endswith(".txt") and filename not in ["ip.txt", "ipv6.txt"]: 
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        stripped_line = line.strip()
                        if stripped_line: # 避免添加空行
                            all_channels.add(stripped_line)
            except Exception as e:
                logging.error(f"读取本地文件 {filepath} 失败: {e}")
    
    with open(output_file, "w", encoding="utf-8") as f:
        # 将所有频道行排序后写入文件
        for channel_line in sorted(list(all_channels)):
            f.write(channel_line + "\n")
    logging.info(f"成功合并 {len(all_channels)} 个频道到 {output_file}。")


# --- 主程序逻辑 ---
def main():
    start_time = datetime.now()
    logging.info("脚本开始执行。")

    # 1. 加载配置、URL 和状态
    # 传入 GITHUB_REPO_BRANCH 环境变量作为分支参数
    config = load_config(branch=GITHUB_REPO_BRANCH)
    if not config:
        logging.error("无法加载配置，脚本退出。")
        return

    existing_urls = load_urls(branch=GITHUB_REPO_BRANCH)
    url_states = load_url_states(branch=GITHUB_REPO_BRANCH)

    # 确保本地输出目录存在
    local_channels_directory = "output"
    os.makedirs(local_channels_directory, exist_ok=True)
    logging.info(f"确保本地输出目录 '{local_channels_directory}' 存在。")

    # 2. 从 template.txt 加载模板频道
    template_content = get_file_from_github(REPO_OWNER, REPO_NAME, LOCAL_TEMPLATE_FILE, branch=GITHUB_REPO_BRANCH)
    if not template_content:
        logging.error(f"无法加载模板文件 {LOCAL_TEMPLATE_FILE}，脚本退出。")
        return
    # 提取模板频道名称，并进行标准化处理（小写，移除空格）以便快速查找
    template_channels_raw = [line.split(',', 1)[0].strip() for line in template_content.splitlines() if line.strip()]
    all_template_channel_names_processed = set(c.lower().replace(" ", "") for c in template_channels_raw)
    logging.info(f"加载 {len(template_channels_raw)} 个模板频道。")

    # 3. 从 source.txt 加载待匹配频道
    source_content = get_file_from_github(REPO_OWNER, REPO_NAME, LOCAL_SOURCE_FILE, branch=GITHUB_REPO_BRANCH)
    channels_for_matching = []
    if source_content:
        channels_for_matching = [line.strip() for line in source_content.splitlines() if line.strip()]
        logging.info(f"加载 {len(channels_for_matching)} 个待匹配频道源。")
    else:
        logging.warning(f"无法加载 {LOCAL_SOURCE_FILE}，将不会有额外的频道进行匹配。")
    
    # 4. 获取 GitHub 搜索结果
    # 注意：GitHub 搜索 API 只能搜索公开仓库的代码。
    # 如果您需要搜索私有仓库中的文件，需要使用其他方式（例如GitHub Actions的checkout操作后，在本地文件系统搜索）
    # 但根据您原始脚本的 intent，这里仍然是针对公开搜索。
    github_search_items = fetch_github_search_results(config)
    github_raw_urls = [extract_raw_url(item) for item in github_search_items if extract_raw_url(item)]
    # 去重并过滤黑名单中的 URL
    github_raw_urls = filter_invalid_urls(list(set(github_raw_urls)), config)

    # 合并所有需要检查的 URL (现有URL + GitHub搜索到的URL)
    all_urls_to_check = list(set(existing_urls + github_raw_urls))
    logging.info(f"总计 {len(all_urls_to_check)} 个 URL 需要进行有效性检查和频道匹配。")

    # 5. 并发处理 URL，获取有效频道
    current_template_matched_channels = {} 

    # 使用 ThreadPoolExecutor 进行并发 URL 处理
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(update_channels_from_url, url, all_template_channel_names_processed, current_template_matched_channels, url_states): url for url in all_urls_to_check}
        
        for future in as_completed(futures):
            url = futures[future]
            try:
                future.result() 
            except Exception as exc:
                logging.error(f'处理 URL {url} 时发生异常: {exc}')

    logging.info(f"已从所有来源和搜索结果中匹配到 {len(current_template_matched_channels)} 个频道。")

    # 6. 保存所有匹配到的频道到 output/github_m3u_channels.txt
    github_matched_output_path = os.path.join(local_channels_directory, LOCAL_GITHUB_M3U_FILE)
    # 按照频道名称排序后写入文件
    sorted_matched_channels_lines = sorted([f"{name},{url}" for name, url in current_template_matched_channels.items()])
    
    with open(github_matched_output_path, "w", encoding="utf-8") as f:
        for line in sorted_matched_channels_lines:
            f.write(f"{line}\n")
    logging.info(f"已将 {len(current_template_matched_channels)} 个匹配到的频道保存到本地 {github_matched_output_path}。")
    
    # 推送到 GitHub 远程仓库
    save_to_github(f"output/{LOCAL_GITHUB_M3U_FILE}", '\n'.join(sorted_matched_channels_lines), "更新 GitHub M3U 频道列表")

    # 7. 合并所有本地频道文件并推送到 GitHub (原始脚本中是将 source 目录中的文件合并)
    # 假设这里是合并 output 目录下的文件，并生成 iptv_list.txt
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
        channel_name_raw = channel_line.split(',', 1)[0].strip()
        cleaned_channel_name = channel_name_raw.lower().replace(" ", "")
        if cleaned_channel_name not in all_template_channel_names_processed:
            unmatched_channels_list.append(channel_line)
    
    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    with open(unmatched_output_file_path, 'w', encoding='utf-8') as f:
        for channel_line in unmatched_channels_list:
            f.write(channel_line.split(',')[0].strip() + "\n") 
    logging.info(f"已将 {len(unmatched_channels_list)} 个未匹配频道保存到本地 {unmatched_output_file_path}。")

    # 9. 保存 URL 状态到 GitHub
    save_url_states(url_states)

    end_time = datetime.now()
    logging.info(f"脚本执行完毕，总耗时: {end_time - start_time}")

if __name__ == "__main__":
    main()
