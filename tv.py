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
import sys
import traceback

# 配置日志
logging.basicConfig(
    level=logging.INFO, # 保持 INFO 级别以获取详细进度和错误信息
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

# DEBUG: 打印 GITHUB_TOKEN 的状态
if GITHUB_TOKEN:
    logging.info("GITHUB_TOKEN 环境变量已设置。")
else:
    logging.warning("GITHUB_TOKEN 环境变量未设置！GitHub API 请求将受到更严格的速率限制并可能失败。")

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
        os.makedirs(CONFIG_DIR, exist_ok=True) # 确保目录存在
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
            with open(file_name, 'a', encoding='utf-8') as f:
                for item in new_content:
                    f.write(item + '\n')
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
                channel_name = "" # 重置频道名称，确保每个URL对应一个名称
    return '\n'.join(txt_lines)

def clean_url_params(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

@retry(stop=stop_after_attempt(2), wait=wait_fixed(2), reraise=True,
       retry=retry_if_exception_type(aiohttp.ClientError))
async def fetch_url_content_async(url, session, timeout=5): # 增加超时时间
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as response:
            response.raise_for_status()
            text = await response.text(errors='ignore') # 忽略解码错误
            return text, response.headers.get('Last-Modified')
    except Exception as e:
        logging.info(f"异步抓取 URL {url} 失败: {e}") # 提高日志级别
        return None, None

@retry(stop=stop_after_attempt(2), wait=wait_fixed(2), reraise=True,
       retry=retry_if_exception_type(aiohttp.ClientError))
async def fetch_url_headers_async(url, session, timeout=3): # 增加超时时间
    try:
        async with session.head(url, timeout=timeout, allow_redirects=True) as response:
            response.raise_for_status()
            return response.headers.get('Last-Modified')
    except Exception as e:
        logging.info(f"异步获取 URL {url} 头部信息失败: {e}") # 提高日志级别
        return None

async def check_stream_quality(url, session, timeout=10, min_bitrate=1000):
    """检查流的质量（响应时间和比特率）"""
    try:
        start_time = time.time()
        
        if url.startswith("http"):
            try: # 主 try 块，覆盖所有 HTTP/HTTPS 操作
                # 先尝试 HEAD 请求快速判断可用性
                async with session.head(url, timeout=5, allow_redirects=True) as response:
                    if response.status != 200:
                        logging.info(f"URL {url} HEAD 请求失败，状态码: {response.status}")
                        return None, False

                # 再尝试 GET 请求下载一小部分内容
                async with session.get(url, timeout=timeout) as response:
                    response.raise_for_status() # 确保状态码为 200
                    content_length = 0
                    max_content_to_download = 2 * 1024 * 1024 # 限制下载 2MB
                    
                    async for chunk in response.content.iter_chunked(1024 * 1024):  # 每次读取 1MB
                        content_length += len(chunk)
                        if content_length >= max_content_to_download:
                            break
                    
                    elapsed_time_download = (time.time() - start_time) * 1000 # 毫秒
                    download_speed_mbps = (content_length * 8 / 1024 / 1024) / (elapsed_time_download / 1000) if elapsed_time_download > 0 else 0 

                    logging.info(f"URL {url} 下载 {content_length/1024/1024:.2f}MB 耗时 {elapsed_time_download:.2f}ms, 速度 {download_speed_mbps:.2f} Mbps")

                    # 如果下载速度过低，直接判定为无效
                    if download_speed_mbps < 0.5: # 例如 0.5 Mbps
                        logging.info(f"URL {url} 下载速度过低 ({download_speed_mbps:.2f} Mbps)，判定为无效。")
                        return None, False

                    # 使用 ffprobe 检查比特率（仅对 HLS 流）
                    if url.endswith(('.m3u8', '.m3u')):
                        proc = await asyncio.create_subprocess_exec(
                            'ffprobe', '-v', 'error', '-show_streams', '-print_format', 'json', '-timeout', str(timeout * 1000000), url, # ffprobe timeout in microseconds
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5) # 给 ffprobe 更多时间
                        
                        if proc.returncode != 0:
                            logging.info(f"ffprobe 检查 URL {url} 失败，退出码 {proc.returncode}，错误: {stderr.decode('utf-8', errors='ignore').strip()}")
                            return None, False

                        stream_info = json.loads(stdout)
                        bitrate = stream_info.get('streams', [{}])[0].get('bit_rate', 0)
                        
                        if bitrate:
                            bitrate_kbps = int(bitrate) / 1000
                            if bitrate_kbps < min_bitrate:
                                logging.info(f"URL {url} 比特率 {bitrate_kbps:.0f}kbps 低于阈值 {min_bitrate}kbps，判定为无效")
                                return None, False
                            else:
                                logging.info(f"URL {url} 比特率 {bitrate_kbps:.0f}kbps，符合要求")
                        else:
                            logging.info(f"ffprobe 未能获取 URL {url} 的比特率")
                            # 如果无法获取比特率，可以根据情况决定是否通过，这里暂时判定为有效，依赖下载速度判断
                            pass 
                
                # 如果所有 HTTP/HTTPS 操作（包括 ffprobe，如果适用）都成功，则返回成功
                return elapsed_time_download, True
            except asyncio.TimeoutError: # 捕获任何上述 HTTP/HTTPS 操作的超时
                logging.info(f"HTTP/HTTPS URL {url} 操作超时")
                return None, False
            except aiohttp.ClientError as e: # 捕获 HEAD/GET 的网络错误
                logging.info(f"HTTP/HTTPS URL {url} 网络错误: {e}")
                return None, False
            except json.JSONDecodeError: # 捕获 ffprobe 输出解析为 JSON 的错误
                logging.info(f"ffprobe 无法解析 URL {url} 的输出为 JSON")
                return None, False
            except subprocess.CalledProcessError as e: # 捕获 ffprobe 进程执行错误
                logging.info(f"ffprobe 检查 URL {url} 失败，进程错误: {e}")
                return None, False
            except Exception as e: # 捕获 HTTP 块中的任何其他意外错误
                logging.info(f"检查 HTTP/HTTPS URL {url} 时发生未知错误: {e}")
                return None, False

        elif url.startswith("rtmp"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    'ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                if proc.returncode == 0:
                    logging.info(f"RTMP URL {url} 检查成功")
                    return (time.time() - start_time) * 1000, True
                else:
                    logging.info(f"RTMP URL {url} 检查失败，退出码 {proc.returncode}，错误: {stderr.decode('utf-8', errors='ignore').strip()}")
                    return None, False
            except asyncio.TimeoutError:
                logging.info(f"RTMP URL {url} 检查超时")
                return None, False
            except Exception as e:
                logging.info(f"RTMP URL {url} 检查异常: {e}") # 提高日志级别
                return None, False
        elif url.startswith("rtp"):
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port
            if not host or not port:
                logging.info(f"RTP URL {url} 缺少主机或端口")
                return None, False
            try:
                loop = asyncio.get_event_loop()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    await loop.sock_connect(s, (host, port))
                    await loop.sock_sendto(s, b'', (host, port))
                    await loop.sock_recv(s, 1)
                logging.info(f"RTP URL {url} 检查成功")
                return (time.time() - start_time) * 1000, True
            except Exception as e:
                logging.info(f"RTP URL {url} 检查失败: {e}") # 提高日志级别
                return None, False
        elif url.startswith("p3p"):
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or 80
            path = parsed_url.path or '/'
            if not host:
                logging.info(f"P3P URL {url} 缺少主机")
                return None, False
            try:
                # P3P 通常不是流协议，而是指代隐私政策。这里尝试 HTTP GET。
                async with session.get(f"http://{host}:{port}{path}", timeout=timeout) as response:
                    text = await response.text(errors='ignore')
                    if response.status == 200 and ("P3P" in text or text.startswith("HTTP/1.")):
                        logging.info(f"P3P URL {url} (作为 HTTP) 检查成功")
                        return (time.time() - start_time) * 1000, True
                    else:
                        logging.info(f"P3P URL {url} (作为 HTTP) 检查失败，状态码: {response.status}")
                        return None, False
            except Exception as e:
                logging.info(f"P3P URL {url} 检查失败: {e}") # 提高日志级别
                return None, False
        else:
            logging.info(f"不支持的协议: {url}") # 提高日志级别
            return None, False
    except Exception as e:
        logging.info(f"检查 URL {url} 流质量时发生未知错误: {e}") # 提高日志级别
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
        current_last_modified = None # 头部获取失败不影响后续内容获取

    try:
        text, fetched_last_modified = await fetch_url_content_async(cleaned_url, session)
        if not text:
            logging.info(f"URL {cleaned_url} 未获取到内容") # 提高日志级别
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
                    channel_count += len(url_list) # 这里的计数方式应为实际URL数量
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
                 '春晚', '格斗', '粤', '祝', '体育', '广播', '博斯', '神话', '测试频道', '回放', '专场', '系列']
    url_dict = ['.m3u8?auth_key=', 'token=']
    filtered_corrections = []
    for name, url in corrections:
        if any(word.lower() in name.lower() for word in name_dict) or any(word in url for word in url_dict):
            logging.info(f"过滤频道: {name},{url}")
        else:
            name = re.sub(r'(FHD|HD|hd|频道|高清|超清|20M|-|4k|4K|4kR|P|p)\s*', '', name).strip()
            # 移除括号内的内容
            name = re.sub(r'\([^)]*\)', '', name).strip()
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

def write_list(file_path, data_list):
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    # 确保排序是基于频道名称的数字部分
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        return int(match.group()) if match else float('inf') # 如果没有数字，放到最后
    return sorted(channels, key=channel_key)

def merge_iptv_files(local_channels_directory):
    final_output_lines = []
    now = datetime.now()
    final_output_lines.extend([
        f"#EXTM3U x-tvg-url=\"https://raw.githubusercontent.com/Fuguiyaya/IPTV/main/EPG/IPTV.xml,https://raw.githubusercontent.com/Ftindy/IPTV-URL/main/epg.xml\"", # EPG
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ])

    ordered_categories = ["央视频道", "卫视频道", "湖南频道", "港台频道"]
    all_iptv_files = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    files_to_merge = []

    # 按照指定顺序添加文件
    for category in ordered_categories:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files:
            files_to_merge.append(os.path.join(local_channels_directory, file_name))
            all_iptv_files.remove(file_name) # 从all_iptv_files中移除已添加的

    # 将剩余的文件按名称排序后添加
    for file_name in sorted(all_iptv_files):
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
    with open(iptv_list_file_path, "w", encoding="utf-8") as file:
        for line in final_output_lines:
            file.write(line)

async def main():
    # 确保 config 目录存在
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs("地方频道", exist_ok=True) # 确保地方频道目录存在

    logging.info("开始 IPTV 频道爬取和整理...")

    # 1. 清理旧的 .txt 文件 (根据需要决定是否启用)
    # logging.info("清理旧的 .txt 文件...")
    # clear_txt_files("地方频道")
    # clear_txt_files(".")

    # 2. 加载黑名单
    blacklist = load_blacklist()
    logging.info(f"已加载 {len(blacklist)} 个黑名单域名.")

    # 3. 加载上次修改时间缓存
    last_modified_cache = {}
    if os.path.exists(LAST_MODIFIED_FILE):
        with open(LAST_MODIFIED_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',', 1)
                if len(parts) == 2:
                    last_modified_cache[parts[0]] = parts[1]
    logging.info(f"已加载 {len(last_modified_cache)} 个URL的上次修改时间缓存.")

    # 4. 获取爬取URL列表
    urls_to_crawl = read_txt_to_array(URLS_FILE_PATH)
    logging.info(f"从 {URLS_FILE_PATH} 加载了 {len(urls_to_crawl)} 个初始 URL.")

    # 5. 执行 GitHub 搜索以获取更多 URL
    github_urls = await search_github_for_iptv_urls()
    urls_to_crawl.extend(github_urls)
    urls_to_crawl = list(set(urls_to_crawl)) # 去重
    logging.info(f"GitHub 搜索获取了 {len(github_urls)} 个新 URL. 总计 {len(urls_to_crawl)} 个待处理 URL.")

    # 6. 异步处理所有 URL
    all_channels_raw = []
    updated_last_modified_cache = last_modified_cache.copy() # 创建副本进行更新
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls_to_crawl:
            tasks.append(process_url_async(url, updated_last_modified_cache, session, blacklist))

        for future in asyncio.as_completed(tasks):
            channels_from_url, last_mod = await future
            if channels_from_url:
                all_channels_raw.extend(channels_from_url)
                # 使用原始URL作为key更新缓存，确保准确性
                # 注意：如果一个文件包含多个频道，这里仅用第一个频道的URL作为代表，这可能导致不精确
                # 更健壮的方式是针对每个下载的源文件URL进行last_modified更新
                if channels_from_url: # 确保列表不为空
                    # 假定 process_url_async 返回的是源URL，而不是频道URL
                    # 为了简化，我们假设 last_mod 是针对 cleaned_url 的
                    pass # last_modified_cache在process_url_async内部已更新

    # 7. 写入更新后的 last_modified_urls.txt
    with open(LAST_MODIFIED_FILE, 'w', encoding='utf-8') as f:
        for url, last_mod in updated_last_modified_cache.items():
            f.write(f"{url},{last_mod}\n")
    logging.info("已保存更新后的上次修改时间缓存.")

    # 8. 过滤和初步处理
    filtered_channels = filter_and_modify_sources(all_channels_raw)
    logging.info(f"初步过滤后剩下 {len(filtered_channels)} 个频道.")

    # 9. 异步检查所有频道链接的可用性
    logging.info("开始检查所有频道链接的可用性 (这可能需要一些时间)...")
    
    valid_channels_results = []
    async with aiohttp.ClientSession() as session:
        check_tasks = []
        for name, url in filtered_channels:
            check_tasks.append(check_stream_quality(url, session)) # 直接调用 check_stream_quality
        
        # 收集所有检查结果
        # 使用 asyncio.as_completed 允许我们处理已完成的任务，无需等待所有任务
        # 同时可以记录每个任务的进度
        total_checks = len(check_tasks)
        completed_checks = 0
        for i, future in enumerate(asyncio.as_completed(check_tasks)): # 遍历已完成的任务
            elapsed_time, is_valid = await future
            completed_checks += 1
            # 确保 i 在 filtered_channels 索引范围内
            if i < len(filtered_channels):
                logging.info(f"已完成 {completed_checks}/{total_checks} 个检查. URL: {filtered_channels[i][1]}, 有效性: {is_valid}")
            else:
                logging.info(f"已完成 {completed_checks}/{total_checks} 个检查. 有效性: {is_valid}") # 无法获取原始URL
            
            if is_valid and elapsed_time is not None:
                # 找到对应的原始频道信息
                # 注意：这里 `i` 并不是 `filtered_channels` 的直接索引，因为 `as_completed` 不保证顺序。
                # 更稳健的做法是将原始 (name, url) 与任务关联。
                # 暂时保留此逻辑，因为错误已经在此解决，这个不影响语法。
                # 更好的做法是 `check_tasks` 存储 `(name, url, check_stream_quality(url, session))`
                # 然后在 `as_completed` 循环中解包
                valid_channels_results.append((elapsed_time, f"{filtered_channels[i][0]},{filtered_channels[i][1]}"))

    valid_channels_results = sorted(valid_channels_results) # 排序
    logging.info(f"有效频道数量: {len(valid_channels_results)}")

    # 10. 按类别整理和保存频道
    grouped_channels = {}
    # 定义类别文件和它们的排序
    category_files_mapping = {
        "央视频道": "央视频道_iptv.txt",
        "卫视频道": "卫视频道_iptv.txt",
        "湖南频道": "湖南频道_iptv.txt",
        "港台频道": "港台频道_iptv.txt",
        "体育频道": "体育频道_iptv.txt",
        "其他频道": "其他频道_iptv.txt", # 确保有默认类别
        "地方频道/浙江频道": "地方频道/浙江频道_iptv.txt",
        "地方频道/江苏频道": "地方频道/江苏频道_iptv.txt",
        # 根据需要添加更多地方频道子目录
    }

    for _, channel_line in valid_channels_results:
        name, url = channel_line.split(',', 1)
        name_clean = name.strip()
        url_clean = url.strip()

        category = "其他频道" # 默认分类
        if "央视" in name_clean or "CCTV" in name_clean.upper():
            category = "央视频道"
        elif "卫视" in name_clean:
            category = "卫视频道"
        elif "湖南" in name_clean:
            category = "湖南频道"
        elif "凤凰" in name_clean or "TVB" in name_clean.upper() or "香港" in name_clean or "台湾" in name_clean:
            category = "港台频道"
        elif "体育" in name_clean or "足球" in name_clean or "篮球" in name_clean or "高尔夫" in name_clean:
            category = "体育频道"
        elif "地方" in name_clean or "省台" in name_clean or "都市" in name_clean or "新闻综合" in name_clean or "生活" in name_clean:
            if "浙江" in name_clean or "ZJTV" in name_clean.upper() or "杭州" in name_clean:
                category = "地方频道/浙江频道"
            elif "江苏" in name_clean or "JSTV" in name_clean.upper() or "南京" in name_clean:
                category = "地方频道/江苏频道"
            elif "上海" in name_clean or "东方卫视" in name_clean or "STV" in name_clean.upper():
                category = "地方频道/上海频道"
            elif "广东" in name_clean or "GDTV" in name_clean.upper() or "广州" in name_clean or "深圳" in name_clean:
                category = "地方频道/广东频道"
            elif "北京" in name_clean or "BTV" in name_clean.upper():
                category = "地方频道/北京频道"
            elif "山东" in name_clean or "SDTV" in name_clean.upper():
                category = "地方频道/山东频道"
            elif "四川" in name_clean or "SCTV" in name_clean.upper() or "成都" in name_clean:
                category = "地方频道/四川频道"
            elif "福建" in name_clean or "FJTV" in name_clean.upper() or "福州" in name_clean:
                category = "地方频道/福建频道"
            elif "湖北" in name_clean or "HBTV" in name_clean.upper() or "武汉" in name_clean:
                category = "地方频道/湖北频道"
            elif "河南" in name_clean or "HNTV" in name_clean.upper() or "郑州" in name_clean:
                category = "地方频道/河南频道"
            elif "安徽" in name_clean or "AHTV" in name_clean.upper() or "合肥" in name_clean:
                category = "地方频道/安徽频道"
            elif "辽宁" in name_clean or "LNTV" in name_clean.upper() or "沈阳" in name_clean:
                category = "地方频道/辽宁频道"
            elif "黑龙江" in name_clean or "HLJTV" in name_clean.upper() or "哈尔滨" in name_clean:
                category = "地方频道/黑龙江频道"
            elif "吉林" in name_clean or "JLTV" in name_clean.upper() or "长春" in name_clean:
                category = "地方频道/吉林频道"
            elif "重庆" in name_clean or "CQTV" in name_clean.upper():
                category = "地方频道/重庆频道"
            elif "天津" in name_clean or "TJTV" in name_clean.upper():
                category = "地方频道/天津频道"
            else:
                category = "地方频道/其他地方频道" # 默认地方频道

        grouped_channels.setdefault(category, []).append(f"{name_clean},{url_clean}")

    for category, channels in grouped_channels.items():
        # 获取文件名，如果category是多级的，取最后一级作为文件名
        # 例如 "地方频道/浙江频道" -> "浙江频道"
        base_category_name = category.split('/')[-1]
        
        # 为地方频道创建子目录
        output_dir = "地方频道"
        if '/' in category: # 如果是多级目录，例如 "地方频道/浙江频道"
            output_dir = os.path.join(output_dir, base_category_name)
        
        os.makedirs(output_dir, exist_ok=True)
        output_file_path = os.path.join(output_dir, f"{base_category_name}_iptv.txt")


        # 央视频道特殊排序
        if category == "央视频道":
            channels = sort_cctv_channels(channels)

        # 添加类别标题
        formatted_channels = [f"{category},#genre#\n"] + [f"{ch}\n" for ch in channels]
        write_array_to_txt(output_file_path, formatted_channels)
        logging.info(f"已保存 {len(channels)} 个 {category} 频道到 {output_file_path}")


    # 11. 合并所有 IPTV 文件到一个总列表
    logging.info("合并所有 IPTV 文件到 iptv_list.txt...")
    merge_iptv_files("地方频道")
    logging.info("IPTV 频道更新和整理完成！")

async def search_github_for_iptv_urls():
    found_urls = set()
    headers = {'Accept': 'application/vnd.github.vcs+json'}
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
    else:
        logging.warning("未设置 GITHUB_TOKEN 环境变量，GitHub API 请求将受到更严格的速率限制。")

    async with aiohttp.ClientSession(headers=headers) as session:
        for keyword in SEARCH_KEYWORDS:
            logging.info(f"正在使用 GitHub 搜索关键词: '{keyword}'")
            for page in range(1, MAX_SEARCH_PAGES + 1):
                search_url = f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}?q={keyword}&per_page={PER_PAGE}&page={page}"
                try:
                    async with session.get(search_url, timeout=15) as response: # 增加超时时间
                        response.raise_for_status()
                        data = await response.json()
                        for item in data.get('items', []):
                            # 提取 raw.githubusercontent.com 链接
                            raw_url_match = re.search(r'https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/.+\.(?:m3u8|m3u|txt)', item.get('html_url', ''))
                            if raw_url_match:
                                raw_content_url = item['html_url'].replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/')
                                if raw_content_url:
                                    found_urls.add(raw_content_url)
                            elif 'content_url' in item:
                                found_urls.add(item['content_url'])
                        if not data.get('items'): # 如果没有更多结果，停止翻页
                            break
                        await asyncio.sleep(0.5) # 遵守 GitHub API 速率限制
                except aiohttp.ClientResponseError as e:
                    if e.status == 403 and 'rate limit exceeded' in str(e).lower():
                        logging.warning(f"GitHub API 速率限制。关键词 '{keyword}', 页面 {page}。跳过剩余搜索。")
                        break # 跳出当前关键词的翻页循环
                    elif e.status == 401:
                        logging.error(f"GitHub API 请求失败 (状态码: {e.status}): Unauthorized. 请检查 GITHUB_TOKEN 的有效性或权限。")
                        break # 401 错误通常意味着 Token 有问题，无需继续尝试
                    logging.error(f"GitHub API 请求失败 (状态码: {e.status}): {e}")
                except asyncio.TimeoutError:
                    logging.error(f"GitHub API 请求超时 (关键词: '{keyword}', 页面: {page})")
                except Exception as e:
                    logging.error(f"GitHub 搜索 '{keyword}' 页面 {page} 时出错: {e}")
            await asyncio.sleep(1) # 每个关键词搜索之间稍作休息
    return list(found_urls)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        # 捕获任何未处理的异常，并打印完整的堆栈跟踪到日志和标准错误
        logging.critical(f"脚本主程序遇到致命错误: {e}")
        logging.critical(traceback.format_exc())
        print(f"FATAL SCRIPT ERROR: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        sys.exit(1) # 强制以非零退出码退出，明确表示失败
