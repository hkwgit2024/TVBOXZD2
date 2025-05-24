import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import aiohttp
import asyncio
import json
import psutil  # 新增，用于动态调整线程数

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler('iptv_crawler.log', encoding='utf-8'),  # 保存日志到文件
    logging.StreamHandler()  # 输出到控制台
])

# --- 全局配置 ---
CONFIG_DIR = os.path.join(os.getcwd(), 'config')
LAST_MODIFIED_FILE = os.path.join(CONFIG_DIR, "last_modified_urls.txt")
DEFAULT_LAST_MODIFIED = "Thu, 01 Jan 1970 00:00:00 GMT"  # Unix Epoch，用于初始比较
URLS_FILE_PATH = os.path.join(CONFIG_DIR, 'urls.txt')
SEARCH_CONFIG_FILE = os.path.join(CONFIG_DIR, 'search_keywords.json')  # 新增配置文件

# --- GitHub API 配置 ---
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # 从环境变量获取 GitHub Token

# --- 优化后的搜索关键词 ---
def load_search_keywords():
    """从配置文件加载搜索关键词，若无配置文件则使用默认关键词"""
    default_keywords = [
        "extension:m3u8 in:file",
        "extension:m3u in:file",
        "iptv playlist extension:m3u,m3u8 in:file",
        "raw.githubusercontent.com path:.m3u8",
        "raw.githubusercontent.com path:.m3u",
        "tv channels extension:m3u,m3u8 in:file",
        "live tv extension:m3u,m3u8 in:file",
        "playlist.m3u8 in:file",
        "index.m3u8 in:file",
        "channels.m3u in:file",
        "iptv links extension:m3u,m3u8 in:file",
        "\"#EXTM3U\" filename:playlist",
        "\"#EXTINF\" in:file language:m3u",
        "filename:m3u8 path:public",
        "filename:m3u path:public",
        "extension:txt iptv list",
        "raw.githubusercontent.com m3u",
        "raw.githubusercontent.com m3u8",
        "site:github.com intitle:m3u8 live",
        "site:github.com inurl:m3u iptv",
        "\"IPTV\" m3u country:cn",  # 中国地区 IPTV
        "\"直播源\" filetype:m3u",  # 中文直播源
        "\"EPG\" m3u",  # 结合 EPG
        "\"电视直播\" filetype:m3u,m3u8",
        "\"playlist.m3u\" in:path",
        # --- 新增关键词 ---
        "extension:m3u8 inurl:live",
        "extension:m3u inurl:iptv",
        "filename:iptv_list filetype:txt",
        "\"HLS stream\" extension:m3u8",
        "site:github.com inurl:tv",
        "\"香港 IPTV\" filetype:m3u,m3u8",  # 香港地区
        "\"台湾 IPTV\" filetype:m3u,m3u8",  # 台湾地区
        "\"日本 IPTV\" filetype:m3u,m3u8",  # 日本地区
        "\"韩国 IPTV\" filetype:m3u,m3u8",  # 韩国地区
        "inurl:cdn filetype:m3u8",  # 搜索 CDN 源
        "\"#EXTM3U\" inurl:public",  # 公共文件
        "filename:channels_list filetype:txt",  # 其他可能的列表文件
        "inurl:stream filetype:m3u,m3u8",  # 流媒体相关
        "site:*.edu inurl:iptv filetype:m3u,m3u8",  # 教育机构源
        "site:*.org inurl:iptv filetype:m3u,m3u8",  # 非营利组织源
    ]
    try:
        if os.path.exists(SEARCH_CONFIG_FILE):
            with open(SEARCH_CONFIG_FILE, 'r', encoding='utf-8') as f:
                custom_keywords = json.load(f).get('keywords', [])
                logging.info(f"从 {SEARCH_CONFIG_FILE} 加载了 {len(custom_keywords)} 个自定义关键词")
                return custom_keywords + default_keywords
        else:
            logging.info("未找到搜索关键词配置文件，使用默认关键词")
            return default_keywords
    except Exception as e:
        logging.error(f"加载搜索关键词配置文件出错: {e}")
        return default_keywords

SEARCH_KEYWORDS = load_search_keywords()
PER_PAGE = 100
MAX_SEARCH_PAGES = 5

# --- 辅助函数 ---

def read_txt_to_array(file_name):
    """从 TXT 文件读取内容，每行一个元素。"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            return [line.strip() for line in lines if line.strip()]
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到，将创建一个新文件")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 时出错: {e}")
        return []

def write_array_to_txt(file_name, data_array):
    """将数组内容写入 TXT 文件，每行一个元素。"""
    try:
        os.makedirs(os.path.dirname(file_name), exist_ok=True)
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
        logging.info(f"数据已成功写入 '{file_name}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 时出错: {e}")

def append_to_txt(file_name, data_array):
    """将数组内容追加到 TXT 文件，每行一个元素，避免重复。"""
    existing_content = set(read_txt_to_array(file_name))
    new_content_to_add = [item for item in data_array if item not in existing_content]
    
    if new_content_to_add:
        try:
            os.makedirs(os.path.dirname(file_name), exist_ok=True)
            with open(file_name, 'a', encoding='utf-8') as file:
                for item in new_content_to_add:
                    file.write(item + '\n')
            logging.info(f"已追加 {len(new_content_to_add)} 条新记录到 '{file_name}'")
        except Exception as e:
            logging.error(f"追加写入文件 '{file_name}' 时出错: {e}")
    else:
        logging.info(f"没有新数据需要追加到 '{file_name}'")

def get_url_file_extension(url):
    """获取 URL 的文件扩展名。"""
    parsed_url = urlparse(url)
    return os.path.splitext(parsed_url.path)[1].lower()

def convert_m3u_to_txt(m3u_content):
    """将 m3u/m3u8 内容转换为频道名称和地址的 TXT 格式。"""
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = ""
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTM3U"):
            continue
        if line.startswith("#EXTINF"):
            match = re.search(r'#EXTINF:.*?\,(.*)', line)
            channel_name = match.group(1).strip() if match else "Unknown Channel"
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = ""
    return '\n'.join(txt_lines)

def clean_url_params(url):
    """清理 URL 的查询参数和片段标识符，只保留基础 URL。"""
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

async def fetch_url_content_async(url, session, timeout=15):
    """异步抓取 URL 内容，带重试机制。"""
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, 
           retry=retry_if_exception_type(aiohttp.ClientError))
    async def _fetch():
        async with session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            text = await response.text()
            last_modified = response.headers.get('Last-Modified')
            return text, last_modified

    try:
        return await _fetch()
    except Exception as e:
        logging.error(f"异步抓取 URL {url} 失败: {e}")
        return None, None

async def fetch_url_headers_async(url, session, timeout=10):
    """异步抓取 URL 的头部信息，带重试机制。"""
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, 
           retry=retry_if_exception_type(aiohttp.ClientError))
    async def _fetch():
        async with session.head(url, timeout=timeout, allow_redirects=True) as response:
            response.raise_for_status()
            return response.headers.get('Last-Modified')

    try:
        return await _fetch()
    except Exception as e:
        logging.debug(f"异步获取 URL {url} 头部信息失败: {e}")
        return None

async def process_url_async(url, last_modified_cache, session):
    """异步处理单个 URL，提取频道名称和地址。"""
    cleaned_url = clean_url_params(url)
    cached_last_modified = last_modified_cache.get(cleaned_url, DEFAULT_LAST_MODIFIED)

    try:
        current_last_modified = await fetch_url_headers_async(cleaned_url, session)
        if current_last_modified == cached_last_modified and current_last_modified != DEFAULT_LAST_MODIFIED:
            logging.info(f"URL '{cleaned_url}' 未更新，跳过处理")
            return [], cached_last_modified
    except Exception as e:
        logging.warning(f"获取 URL '{cleaned_url}' 头部信息失败，将尝试抓取内容: {e}")
        current_last_modified = None

    try:
        text, fetched_last_modified = await fetch_url_content_async(cleaned_url, session)
        if not text:
            return [], current_last_modified

        last_modified_cache[cleaned_url] = fetched_last_modified or current_last_modified or datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")

        if get_url_file_extension(cleaned_url) in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)

        lines = text.split('\n')
        channel_list = []
        channel_count = 0
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
                            channel_list.append((channel_name, channel_url))
                            channel_count += 1
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url:
                        channel_list.append((channel_name, channel_url))
                        channel_count += 1
        logging.info(f"成功读取 URL: {cleaned_url}，获取到 {channel_count} 个频道")
        return channel_list, last_modified_cache[cleaned_url]
    except Exception as e:
        logging.error(f"处理 URL {cleaned_url} 时出错: {e}")
        return [], last_modified_cache.get(cleaned_url)

def filter_and_modify_sources(corrections):
    """过滤和修改频道名称和 URL。"""
    filtered_corrections = []
    name_dict = ['购物', '理财', '导视', '指南', '测试', '芒果', 'CGTN', '(480p)', '(360p)', '(240p)', 
                 '(406p)', '(540p)', '(600p)', '(576p)', '[Not 24/7]', 'DJ', '音乐', '演唱会', '舞曲', 
                 '春晚', '格斗', '粤', '祝', '体育', '广播', '博斯', '神话', '测试频道']
    url_dict = ['.m3u8?auth_key=', 'token=']

    for name, url in corrections:
        if any(word.lower() in name.lower() for word in name_dict) or any(word in url for word in url_dict):
            logging.info(f"过滤频道: {name},{url}")
        else:
            name = re.sub(r'(FHD|HD|hd|频道|高清|超清|20M|-|4k|4K|4kR)\s*', '', name).strip()
            filtered_corrections.append((name, url))
    return filtered_corrections

def clear_txt_files(directory):
    """删除指定目录下所有 TXT 文件。"""
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
                logging.info(f"已删除文件: {file_path}")
            except Exception as e:
                logging.error(f"删除文件 {file_path} 时出错: {e}")

async def check_url_async(url, channel_name, session, timeout=6):
    """异步检查 URL 的有效性。"""
    start_time = time.time()
    try:
        if url.startswith("http"):
            async with session.get(url, timeout=timeout, allow_redirects=True) as response:
                return (time.time() - start_time) * 1000, 200 <= response.status_code < 400
        elif url.startswith("rtmp"):
            return await check_rtmp_url_async(url, timeout)
        elif url.startswith("rtp"):
            return await check_rtp_url_async(url, timeout)
        elif url.startswith("p3p"):
            return await check_p3p_url_async(url, timeout)
        else:
            logging.debug(f"不支持的协议: {channel_name}: {url}")
            return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 时出错: {e}")
        return None, False

async def check_rtmp_url_async(url, timeout):
    """异步检查 RTMP 流是否可用。"""
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
        result = await asyncio.create_subprocess_exec(
            'ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024
        )
        await asyncio.wait_for(result.communicate(), timeout=timeout)
        return 0, result.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError, asyncio.TimeoutError) as e:
        logging.debug(f"RTMP URL {url} 检查失败: {e}")
        return None, False

async def check_rtp_url_async(url, timeout):
    """异步检查 RTP URL 是否活跃。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.debug(f"RTP URL {url} 无效的主机或端口")
            return None, False

        loop = asyncio.get_event_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            await loop.sock_connect(s, (host, port))
            await loop.sock_sendto(s, b'', (host, port))
            await loop.sock_recv(s, 1)
        return 0, True
    except Exception as e:
        logging.debug(f"RTP URL {url} 检查失败: {e}")
        return None, False

async def check_p3p_url_async(url, timeout):
    """异步检查 P3P URL 是否活跃。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or 80
        path = parsed_url.path or '/'

        if not host:
            logging.debug(f"P3P URL {url} 无效的主机")
            return None, False

        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{host}:{port}{path}", timeout=timeout) as response:
                text = await response.text(errors='ignore')
                return 0, "P3P" in text or text.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} 检查失败: {e}")
        return None, False

async def process_lines_async(lines, max_workers=None):
    """异步处理 URL 列表以检查有效性。"""
    if max_workers is None:
        max_workers = min(psutil.cpu_count() * 2, 200)  # 动态调整线程数
    results = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for line in lines:
            if "://" not in line:
                continue
            parts = line.split(',', 1)
            if len(parts) == 2:
                name, url = parts
                tasks.append(check_url_async(url.strip(), name.strip(), session))
        
        for future in asyncio.as_completed(tasks):
            elapsed_time, is_valid = await future
            if is_valid and elapsed_time is not None:
                results.append((elapsed_time, f"{name},{url}"))
    
    return sorted(results)

def write_list(file_path, data_list):
    """将数据列表写入文件。"""
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    """按数字顺序排序 CCTV 频道。"""
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        return int(match.group()) if match else float('inf')
    return sorted(channels, key=channel_key)

def merge_iptv_files(local_channels_directory):
    """将所有本地频道文件合并到 iptv_list.txt。"""
    final_output_lines = []
    now = datetime.now()
    final_output_lines.extend([
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ])

    ordered_categories = ["央视频道", "卫视频道", "湖南频道", "港台频道"]
    all_iptv_files = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    files_to_merge = []

    for category in ordered_categories:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files:
            files_to_merge.append(os.path.join(local_channels_directory, file_name))

    for file_name in sorted(all_iptv_files):
        if file_name not in [f"{cat}_iptv.txt" for cat in ordered_categories]:
            files_to_merge.append(os.path.join(local_channels_directory, file_name))

    for file_path in files_to_merge:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                continue
            header = lines[0].strip()
            if '#genre#' in header:
                final_output_lines.append(header + '\n')
                grouped_channels = {}
                for line in lines[1:]:
                    line = line.strip()
                    if line and "," in line and "://" in line:
                        channel_name = line.split(',', 1)[0].strip()
                        grouped_channels.setdefault(channel_name, []).append(line)
                
                for channel_name in grouped_channels:
                    for ch_line in grouped_channels[channel_name][:200]:
                        final_output_lines.append(ch_line + '\n')
            else:
                logging.warning(f"文件 {file_path} 没有以类别标题开头，跳过")

    iptv_list_file_path = "iptv_list.txt"
    with open(iptv_list_file_path, "w", encoding="utf-8") as iptv_list_file:
        iptv_list_file.writelines(final_output_lines)

    for temp_file in ['iptv.txt', 'iptv_speed.txt']:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
                logging.info(f"临时文件 {temp_file} 已删除")
            except OSError as e:
                logging.warning(f"删除临时文件 {temp_file} 时出错: {e}")

    logging.info(f"所有地方频道列表文件已合并，输出保存到: {iptv_list_file_path}")

async def auto_discover_github_urls_async(urls_file_path, github_token):
    """异步从 GitHub 搜索公共 IPTV 源 URL 并更新 urls.txt 文件。"""
    if not github_token:
        logging.warning("未设置 GITHUB_TOKEN 环境变量，跳过 GitHub URL 自动发现")
        return

    existing_urls = set(read_txt_to_array(urls_file_path))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    async with aiohttp.ClientSession() as session:
        for i, keyword in enumerate(SEARCH_KEYWORDS):
            if i > 0:
                logging.info(f"切换到下一个关键词: '{keyword}'，等待 10 秒...")
                await asyncio.sleep(10)

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
                    async with session.get(
                        f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                        headers=headers,
                        params=params,
                        timeout=20
                    ) as response:
                        response.raise_for_status()
                        data = await response.json()

                        rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                        rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

                        if rate_limit_remaining == 0:
                            wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                            logging.warning(f"GitHub API 速率限制已达到！等待 {wait_seconds:.0f} 秒")
                            await asyncio.sleep(wait_seconds)
                            continue

                        if not data.get('items'):
                            logging.info(f"关键词 '{keyword}' 在第 {page} 页没有找到更多结果")
                            break

                        for item in data['items']:
                            html_url = item.get('html_url', '')
                            match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                            if match:
                                user, repo, branch, path = match.groups()
                                raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
                                if raw_url.lower().endswith(('.m3u', '.m3u8', '.txt')):
                                    cleaned_url = clean_url_params(raw_url)
                                    found_urls.add(cleaned_url)
                                    logging.debug(f"发现 GitHub 相关 URL: {cleaned_url}")

                        logging.info(f"关键词 '{keyword}'，第 {page} 页搜索完成，当前找到 {len(found_urls)} 个 URL")
                        if len(data['items']) < PER_PAGE:
                            break
                        page += 1
                        await asyncio.sleep(2)

                except aiohttp.ClientResponseError as e:
                    if e.status == 403:
                        wait_seconds = int(response.headers.get('X-RateLimit-Reset', 0)) - time.time() + 5
                        logging.warning(f"GitHub API 速率限制，等待 {wait_seconds:.0f} 秒")
                        await asyncio.sleep(wait_seconds)
                        continue
                    else:
                        logging.error(f"GitHub API 请求失败 (关键词: {keyword}, 页码: {page}): {e}")
                        break
                except Exception as e:
                    logging.error(f"GitHub URL 自动发现出错: {e}")
                    break

    new_urls = [url for url in found_urls if url not in existing_urls]
    if new_urls:
        append_to_txt(urls_file_path, new_urls)
        logging.info(f"添加了 {len(new_urls)} 个新 URL 到 {urls_file_path}")
    else:
        logging.info("没有发现新的 GitHub IPTV 源 URL")

def load_last_modified_cache(file_path):
    """从文件中加载 Last-Modified 缓存。"""
    cache = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',', 1)
                if len(parts) == 2:
                    cache[parts[0]] = parts[1]
    except FileNotFoundError:
        logging.info(f"未找到 '{file_path}'，将创建新缓存")
    except Exception as e:
        logging.error(f"加载 '{file_path}' 缓存出错: {e}")
    return cache

def save_last_modified_cache(file_path, cache):
    """将 Last-Modified 缓存保存到文件。"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            for url, timestamp in cache.items():
                f.write(f"{url},{timestamp}\n")
        logging.info(f"Last-Modified 缓存已保存到 '{file_path}'")
    except Exception as e:
        logging.error(f"保存 '{file_path}' 缓存出错: {e}")

async def main():
    """主函数，协调整个 IPTV 爬取流程"""
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # 检查 GITHUB_TOKEN
    if not GITHUB_TOKEN:
        logging.error("未设置 GITHUB_TOKEN 环境变量")
        return

    # 1. 自动发现 GitHub URL
    await auto_discover_github_urls_async(URLS_FILE_PATH, GITHUB_TOKEN)

    # 2. 读取要处理的 URL
    urls_to_process = read_txt_to_array(URLS_FILE_PATH)
    if not urls_to_process:
        logging.warning(f"{URLS_FILE_PATH} 中未找到 URL，脚本退出")
        return

    # 3. 加载 Last-Modified 缓存
    last_modified_cache = load_last_modified_cache(LAST_MODIFIED_FILE)

    # 4. 异步处理所有 URL
    all_channels = []
    updated_urls = set()
    async with aiohttp.ClientSession() as session:
        tasks = [process_url_async(url, last_modified_cache, session) for url in urls_to_process]
        for channels, last_modified in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(channels, list) and channels:
                all_channels.extend(channels)
                updated_urls.add(clean_url_params(url))

    # 更新缓存
    new_cache = {url: last_modified_cache[url] for url in updated_urls if url in last_modified_cache}
    for url in last_modified_cache:
        if url not in updated_urls and url in urls_to_process:
            new_cache[url] = last_modified_cache[url]
    save_last_modified_cache(LAST_MODIFIED_FILE, new_cache)

    # 5. 过滤和清理频道
    filtered_channels = filter_and_modify_sources(all_channels)
    unique_channels = list(set(filtered_channels))
    unique_channels_str = [f"{name},{url}" for name, url in unique_channels]

    iptv_file_path = os.path.join(os.getcwd(), 'iptv.txt')
    write_array_to_txt(iptv_file_path, unique_channels_str)
    logging.info(f"所有频道已保存到: {iptv_file_path}，共 {len(unique_channels_str)} 个频道")

    # 6. 异步检查频道有效性
    logging.info("开始异步频道有效性检查...")
    results = await process_lines_async(unique_channels_str)
    logging.info(f"有效频道数量: {len(results)}")

    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_list(iptv_speed_file_path, results)
    for elapsed_time, result in results:
        channel_name, channel_url = result.split(',', 1)
        logging.info(f"频道 {channel_name},{channel_url} 检查成功，响应时间: {elapsed_time:.0f} ms")

    # 7. 处理地方频道
    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    os.makedirs(local_channels_directory, exist_ok=True)
    clear_txt_files(local_channels_directory)

    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True)
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]

    iptv_speed_channels = read_txt_to_array(iptv_speed_file_path)
    all_template_channel_names = set()
    for template_file in template_files:
        names = read_txt_to_array(os.path.join(template_directory, template_file))
        all_template_channel_names.update(names)

    for template_file in template_files:
        template_channels_names = read_txt_to_array(os.path.join(template_directory, template_file))
        template_name = os.path.splitext(template_file)[0]
        current_template_matched_channels = [
            line for line in iptv_speed_channels 
            if line.split(',', 1)[0].strip() in template_channels_names
        ]

        if "央视" in template_name or "CCTV" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.info(f"已对 {template_name} 频道进行数字排序")

        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.info(f"频道列表已写入: {output_file_path}，包含 {len(current_template_matched_channels)} 个频道")

    # 8. 合并所有 IPTV 文件
    merge_iptv_files(local_channels_directory)

    # 9. 保存未匹配的频道
    unmatched_channels = [
        line for line in iptv_speed_channels 
        if line.split(',', 1)[0].strip() not in all_template_channel_names
    ]
    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    unmatched_channel_names_only = [line.split(',')[0].strip() for line in unmatched_channels]
    append_to_txt(unmatched_output_file_path, unmatched_channel_names_only)
    logging.info(f"未匹配频道列表已保存到: {unmatched_output_file_path}，共 {len(unmatched_channels)} 个频道")

if __name__ == "__main__":
    asyncio.run(main())
