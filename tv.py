import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import requests
import aiohttp
import asyncio
import json
import psutil
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iptv_crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- 全局配置 ---
CONFIG_DIR = os.path.join(os.getcwd(), 'config')
LAST_MODIFIED_FILE = os.path.join(CONFIG_DIR, "last_modified_urls.txt")
DEFAULT_LAST_MODIFIED = "Thu, 01 Jan 1970 00:00:00 GMT"
URLS_FILE_PATH = os.path.join(CONFIG_DIR, 'urls.txt')
SEARCH_CONFIG_FILE = os.path.join(CONFIG_DIR, 'search_keywords.json')
BLACKLIST_FILE = os.path.join(CONFIG_DIR, 'blacklist.txt')  # 新增黑名单文件

# --- GitHub API 配置 ---
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

# --- 加载搜索关键词 ---
def load_search_keywords():
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
        "\"IPTV\" m3u country:cn",
        "\"直播源\" filetype:m3u",
        "\"EPG\" m3u",
        "\"电视直播\" filetype:m3u,m3u8",
        "\"playlist.m3u\" in:path",
        "extension:m3u8 inurl:live",
        "extension:m3u inurl:iptv",
        "filename:iptv_list filetype:txt",
        "\"HLS stream\" extension:m3u8",
        "site:github.com inurl:tv",
        "\"香港 IPTV\" filetype:m3u,m3u8",
        "\"台湾 IPTV\" filetype:m3u,m3u8",
        "\"日本 IPTV\" filetype:m3u,m3u8",
        "\"韩国 IPTV\" filetype:m3u,m3u8",
        "inurl:cdn filetype:m3u8",
        "\"#EXTM3U\" inurl:public",
        "filename:channels_list filetype:txt",
        "inurl:stream filetype:m3u,m3u8",
        "site:*.edu inurl:iptv filetype:m3u,m3u8",
        "site:*.org inurl:iptv filetype:m3u,m3u8",
    ]
    try:
        if os.path.exists(SEARCH_CONFIG_FILE):
            with open(SEARCH_CONFIG_FILE, 'r', encoding='utf-8') as f:
                custom_keywords = json.load(f).get('keywords', [])
                logging.info(f"从 {SEARCH_CONFIG_FILE} 加载了 {len(custom_keywords)} 个自定义关键词")
                return custom_keywords + default_keywords
        return default_keywords
    except Exception as e:
        logging.error(f"加载搜索关键词配置文件出错: {e}")
        return default_keywords

SEARCH_KEYWORDS = load_search_keywords()
PER_PAGE = 100
MAX_SEARCH_PAGES = 5

# --- 黑名单管理 ---
def load_blacklist():
    """加载黑名单域名"""
    blacklist = set()
    try:
        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
                blacklist = {line.strip() for line in f if line.strip()}
        return blacklist
    except Exception as e:
        logging.error(f"加载黑名单文件出错: {e}")
        return set()

def add_to_blacklist(domains):
    """将域名添加到黑名单"""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        logging.info(f"已添加 {len(domains)} 个域名到黑名单")
    except Exception as e:
        logging.error(f"添加黑名单出错: {e}")

# --- 辅助函数 ---
def read_txt_to_array(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 时出错: {e}")
        return []

def write_array_to_txt(file_name, data_array):
    try:
        os.makedirs(os.path.dirname(file_name), exist_ok=True)
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
        logging.info(f"数据已写入 '{file_name}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 时出错: {e}")

def append_to_txt(file_name, data_array):
    existing_content = set(read_txt_to_array(file_name))
    new_content = [item for item in data_array if item not in existing_content]
    if new_content:
        try:
            os.makedirs(os.path.dirname(file_name), exist_ok=True)
            with open(file_name, 'a', encoding='utf-8') as file:
                for item in new_content:
                    file.write(item + '\n')
            logging.info(f"已追加 {len(new_content)} 条记录到 '{file_name}'")
        except Exception as e:
            logging.error(f"追加写入文件 '{file_name}' 时出错: {e}")

def get_url_file_extension(url):
    parsed_url = urlparse(url)
    return os.path.splitext(parsed_url.path)[1].lower()

def convert_m3u_to_txt(m3u_content):
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
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

async def fetch_url_content_async(url, session, timeout=3):  # 缩短超时时间
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(2), reraise=True, 
           retry=retry_if_exception_type(aiohttp.ClientError))
    async def _fetch():
        async with session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            text = await response.text()
            return text, response.headers.get('Last-Modified')
    try:
        return await _fetch()
    except Exception as e:
        logging.error(f"异步抓取 URL {url} 失败: {e}")
        return None, None

async def fetch_url_headers_async(url, session, timeout=2):
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(2), reraise=True, 
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

async def check_stream_quality(url, session, timeout=5, min_bitrate=1000):
    """检查流的质量（响应时间和比特率）"""
    try:
        start_time = time.time()
        async with session.get(url, timeout=timeout) as response:
            if response.status != 200:
                return None, False
            
            # 下载前几个 TS 分段，估算速度
            content = b""
            async for chunk in response.content.iter_chunked(1024 * 1024):  # 每次读取 1MB
                content += chunk
                if len(content) >= 2 * 1024 * 1024:  # 限制下载 2MB
                    break
            
            elapsed_time = (time.time() - start_time) * 1000  # 毫秒
            download_speed = (len(content) * 8 / 1024) / (elapsed_time / 1000)  # Mbps
            
            # 使用 ffprobe 检查比特率（仅对 HLS 流）
            if url.endswith(('.m3u8', '.m3u')):
                try:
                    result = await asyncio.create_subprocess_exec(
                        'ffprobe', '-v', 'error', '-show_streams', '-print_format', 'json', url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(result.communicate(), timeout=timeout)
                    stream_info = json.loads(stdout)
                    bitrate = stream_info.get('streams', [{}])[0].get('bit_rate', 0)
                    if bitrate and int(bitrate) / 1000 < min_bitrate:  # 转换为 kbps
                        logging.debug(f"URL {url} 比特率 {bitrate/1000:.0f}kbps 低于阈值 {min_bitrate}kbps")
                        return None, False
                except Exception as e:
                    logging.debug(f"检查 URL {url} 比特率失败: {e}")
                    return None, False
            
            return elapsed_time, download_speed > 1  # 要求下载速度 > 1Mbps
    except Exception as e:
        logging.debug(f"检查 URL {url} 流质量失败: {e}")
        return None, False

async def process_url_async(url, last_modified_cache, session, blacklist):
    cleaned_url = clean_url_params(url)
    if any(domain in cleaned_url for domain in blacklist):
        logging.info(f"URL {cleaned_url} 在黑名单中，跳过")
        return [], last_modified_cache.get(cleaned_url)

    cached_last_modified = last_modified_cache.get(cleaned_url, DEFAULT_LAST_MODIFIED)
    try:
        current_last_modified = await fetch_url_headers_async(cleaned_url, session)
        if current_last_modified == cached_last_modified and current_last_modified != DEFAULT_LAST_MODIFIED:
            logging.info(f"URL '{cleaned_url}' 未更新，跳过")
            return [], cached_last_modified
    except Exception:
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
                        if channel_url and not any(domain in channel_url for domain in blacklist):
                            channel_list.append((channel_name, channel_url))
                            channel_count += 1
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and not any(domain in channel_url for domain in blacklist):
                        channel_list.append((channel_name, channel_url))
                        channel_count += 1
        logging.info(f"成功读取 URL: {cleaned_url}，获取到 {channel_count} 个频道")
        return channel_list, last_modified_cache[cleaned_url]
    except Exception as e:
        logging.error(f"处理 URL {cleaned_url} 时出错: {e}")
        return [], last_modified_cache.get(cleaned_url)

def filter_and_modify_sources(corrections):
    name_dict = ['购物', '理财', '导视', '指南', '测试', '芒果', 'CGTN', '(480p)', '(360p)', '(240p)', 
                 '(406p)', '(540p)', '(600p)', '(576p)', '[Not 24/7]', 'DJ', '音乐', '演唱会', '舞曲', 
                 '春晚', '格斗', '粤', '祝', '体育', '广播', '博斯', '神话', '测试频道']
    url_dict = ['.m3u8?auth_key=', 'token=']
    filtered_corrections = []
    for name, url in corrections:
        if any(word.lower() in name.lower() for word in name_dict) or any(word in url for word in url_dict):
            logging.info(f"过滤频道: {name},{url}")
        else:
            name = re.sub(r'(FHD|HD|hd|频道|高清|超清|20M|-|4k|4K|4kR)\s*', '', name).strip()
            filtered_corrections.append((name, url))
    return filtered_corrections

def clear_txt_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
                logging.info(f"已删除文件: {file_path}")
            except Exception as e:
                logging.error(f"删除文件 {file_path} 时出错: {e}")

async def check_url_async(url, channel_name, session, timeout=3):
    start_time = time.time()
    try:
        if url.startswith("http"):
            elapsed_time, is_valid = await check_stream_quality(url, session, timeout, min_bitrate=1000)
            return elapsed_time, is_valid
        elif url.startswith("rtmp"):
            try:
                result = await asyncio.create_subprocess_exec(
                    'ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(result.communicate(), timeout=timeout)
                return (time.time() - start_time) * 1000, result.returncode == 0
            except Exception as e:
                logging.debug(f"RTMP URL {url} 检查失败: {e}")
                return None, False
        elif url.startswith("rtp"):
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port
            if not host or not port:
                return None, False
            try:
                loop = asyncio.get_event_loop()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    await loop.sock_connect(s, (host, port))
                    await loop.sock_sendto(s, b'', (host, port))
                    await loop.sock_recv(s, 1)
                return (time.time() - start_time) * 1000, True
            except Exception as e:
                logging.debug(f"RTP URL {url} 检查失败: {e}")
                return None, False
        elif url.startswith("p3p"):
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or 80
            path = parsed_url.path or '/'
            if not host:
                return None, False
            try:
                async with session.get(f"http://{host}:{port}{path}", timeout=timeout) as response:
                    text = await response.text(errors='ignore')
                    return (time.time() - start_time) * 1000, "P3P" in text or text.startswith("HTTP/1.")
            except Exception as e:
                logging.debug(f"P3P URL {url} 检查失败: {e}")
                return None, False
        else:
            logging.debug(f"不支持的协议: {channel_name}: {url}")
            return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 时出错: {e}")
        return None, False

async def process_lines_async(lines, max_workers=None):
    if max_workers is None:
        max_workers = min(psutil.cpu_count() * 2, 100)  # 降低最大并发数
    results = []
    blacklist = load_blacklist()
    async with aiohttp.ClientSession() as session:
        tasks = []
        for line in lines:
            if "://" not in line:
                continue
            parts = line.split(',', 1)
            if len(parts) == 2:
                name, url = parts
                url = url.strip()
                if not any(domain in url for domain in blacklist):
                    tasks.append(check_url_async(url, name.strip(), session))
        
        for future in asyncio.as_completed(tasks):
            elapsed_time, is_valid = await future
            if is_valid and elapsed_time is not None:
                results.append((elapsed_time, f"{name},{url}"))
    
    return sorted(results)

def write_list(file_path, data_list):
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        return int(match.group()) if match else float('inf')
    return sorted(channels, key=channel_key)

def merge_iptv_files(local_channels_directory):
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
                    for ch_line in grouped_channels[channel_name][:50]:  # 限制每个频道最多 50 个 URL
                        final_output_lines.append(ch_line + '\n')
            else:
                logging.warning(f"文件 {file_path} 没有以类别标题开头，跳过")

    iptv_list_file_path = "iptv_list.txt"
    with open(iptv_list_file_path, "w", encoding=" TURBO模式：提高并发效率和播放流畅度

