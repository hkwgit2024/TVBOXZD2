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
BLACKLIST_FILE = os.path.join(CONFIG_DIR, 'blacklist.txt')

# --- GitHub API 配置 ---
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

if GITHUB_TOKEN:
    logging.info("GITHUB_TOKEN 环境变量已设置。")
else:
    logging.warning("GITHUB_TOKEN 环境变量未设置！GitHub API 请求将受到更严格的速率限制并可能失败。")

# --- 加载搜索关键词 ---
def load_search_keywords():
    default_keywords = [
        # 高质量、高针对性关键词
        "\"raw.githubusercontent.com\" path:.m3u8",
        "\"raw.githubusercontent.com\" path:.m3u",
        "\"raw.githubusercontent.com\" path:.txt \"#EXTM3U\"",
        # 精确文件名搜索
        "filename:playlist.m3u8 in:file",
        "filename:index.m3u8 in:file",
        "filename:channels.m3u in:file",
        "filename:tv.m3u8 OR filename:tv.m3u in:file",
        "filename:live.m3u8 OR filename:live.m3u in:file",
        "filename:iptv.m3u OR filename:iptv.m3u8 OR filename:iptv.txt in:file \"#EXTM3U\"",
        # 扩展名搜索
        "extension:m3u8 in:file",
        "extension:m3u in:file",
        # IPTV 特定短语 + 文件类型
        "\"iptv playlist\" (extension:m3u OR extension:m3u8) in:file",
        "\"live tv\" (extension:m3u OR extension:m3u8) in:file",
        "\"tv channels\" (extension:m3u OR extension:m3u8) in:file",
        # M3U 内容特征
        "\"#EXTM3U\" \"#EXTINF\" \"tvg-logo\" (extension:m3u OR extension:m3u8)",
        # 中文关键词
        "\"直播源\" (filetype:m3u OR filetype:m3u8 OR filetype:txt)",
        "\"电视直播\" (filetype:m3u OR filetype:m3u8 OR filetype:txt)",
        "\"酒店源\" (filetype:m3u OR filetype:m3u8 OR filetype:txt)",
        "\"源\" \"更新\" (filetype:m3u OR filetype:m3u8 OR filetype:txt)",
        # 区域性关键词 (示例)
        "\"香港 IPTV\" (filetype:m3u OR filetype:m3u8)",
        "\"台湾 IPTV\" (filetype:m3u OR filetype:m3u8)",
        # 综合搜索
        "language:\"m3u\" \"#EXTINF\"", # 搜索 M3U 语言文件中的特征
        "path:.m3u OR path:.m3u8 OR path:.txt \"#EXTM3U\" site:raw.githubusercontent.com" # 极具针对性
    ]
    try:
        if os.path.exists(SEARCH_CONFIG_FILE):
            with open(SEARCH_CONFIG_FILE, 'r', encoding='utf-8') as f:
                custom_keywords = json.load(f).get('keywords', [])
                logging.info(f"从 {SEARCH_CONFIG_FILE} 加载了 {len(custom_keywords)} 个自定义关键词")
                # 用户自定义关键词优先，可以覆盖或补充默认关键词
                return custom_keywords + [kw for kw in default_keywords if kw not in custom_keywords]
        return default_keywords
    except Exception as e:
        logging.error(f"加载搜索关键词配置文件出错: {e}")
        return default_keywords

SEARCH_KEYWORDS = load_search_keywords()
PER_PAGE = 100  # GitHub API 每页最多返回100条
MAX_SEARCH_PAGES = 1  # 每个关键词搜索的最大页数，减少以降低API请求频率
GITHUB_KEYWORD_SLEEP = 10 # 不同关键词之间的休眠时间（秒）
GITHUB_PAGE_SLEEP = 3     # 同一关键词不同页面之间的休眠时间（秒）

# --- 黑名单管理 ---
def load_blacklist():
    """加载黑名单域名"""
    blacklist = set()
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
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
                channel_name = "" # Reset for next entry
    return '\n'.join(txt_lines)

def clean_url_params(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

@retry(stop=stop_after_attempt(5), wait=wait_fixed(8), reraise=True, retry=retry_if_exception_type(aiohttp.ClientError))
async def fetch_url_content_async(url, session, timeout=38):
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as response:
            response.raise_for_status()
            text = await response.text(errors='ignore')
            return text, response.headers.get('Last-Modified')
    except Exception as e:
        logging.debug(f"异步抓取 URL {url} 失败: {e}") # Changed to debug for less noise on retry
        raise # Reraise for tenacity

@retry(stop=stop_after_attempt(8), wait=wait_fixed(28), reraise=True, retry=retry_if_exception_type(aiohttp.ClientError))
async def fetch_url_headers_async(url, session, timeout=48):
    try:
        async with session.head(url, timeout=timeout, allow_redirects=True) as response:
            response.raise_for_status()
            return response.headers.get('Last-Modified')
    except Exception as e:
        logging.debug(f"异步获取 URL {url} 头部信息失败: {e}") # Changed to debug
        raise # Reraise for tenacity

async def check_stream_quality(url, session, timeout=185, min_bitrate=1000):
    """检查流的质量（响应时间和比特率）"""
    try:
        start_time = time.time()
        if url.startswith("http"):
            try:
                # Quick HEAD request to check basic reachability and status
                async with session.head(url, timeout=10, allow_redirects=True) as response: # Increased HEAD timeout slightly
                    if response.status != 200:
                        logging.info(f"URL {url} HEAD 请求失败，状态码: {response.status}")
                        return None, False

                # Download a portion to check speed
                async with session.get(url, timeout=timeout) as response: # Main GET request
                    response.raise_for_status()
                    content_length = 0
                    max_content_to_download = 2 * 1024 * 1024 # 2MB
                    download_start_time = time.time()
                    async for chunk in response.content.iter_chunked(1024 * 1024): # 1MB chunks
                        content_length += len(chunk)
                        if content_length >= max_content_to_download:
                            break
                    elapsed_time_download_sec = time.time() - download_start_time
                    
                    if elapsed_time_download_sec <= 0: # Avoid division by zero
                        download_speed_mbps = 0
                    else:
                        download_speed_mbps = (content_length * 8 / (1024 * 1024)) / elapsed_time_download_sec
                    
                    logging.info(f"URL {url} 下载 {content_length/(1024*1024):.2f}MB 耗时 {elapsed_time_download_sec*1000:.2f}ms, 速度 {download_speed_mbps:.2f} Mbps")

                    if download_speed_mbps < 0.5: # 0.5 Mbps threshold
                        logging.info(f"URL {url} 下载速度过低 ({download_speed_mbps:.2f} Mbps)，判定为无效。")
                        return None, False

                    # ffprobe check for m3u/m3u8
                    if url.endswith(('.m3u8', '.m3u')):
                        # Use a longer timeout for ffprobe as it might need to resolve segments
                        ffprobe_timeout_s = timeout + 10 # seconds for ffprobe process
                        proc = await asyncio.create_subprocess_exec(
                            'ffprobe', '-v', 'error', '-show_streams', '-print_format', 'json', 
                            '-timeout', str(ffprobe_timeout_s * 1000000), # ffprobe timeout in microseconds
                            url,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        try:
                            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=ffprobe_timeout_s + 5)
                        except asyncio.TimeoutError:
                            logging.info(f"ffprobe 检查 URL {url} 超时 (进程超时)")
                            try:
                                proc.kill()
                                await proc.wait()
                            except ProcessLookupError:
                                pass # Process already terminated
                            return None, False

                        if proc.returncode != 0:
                            logging.info(f"ffprobe 检查 URL {url} 失败，退出码 {proc.returncode}，错误: {stderr.decode('utf-8', errors='ignore').strip()}")
                            return None, False
                        
                        stream_info_str = stdout.decode('utf-8', errors='ignore')
                        if not stream_info_str.strip():
                             logging.info(f"ffprobe for URL {url} returned empty stdout.")
                             return None, False # No usable output

                        stream_info = json.loads(stream_info_str)
                        bitrate = 0
                        if stream_info.get('streams'):
                            for s in stream_info['streams']: # Check all streams for a bitrate
                                if 'bit_rate' in s:
                                    bitrate = max(bitrate, int(s['bit_rate'])) # Take the max if multiple streams
                        
                        if bitrate:
                            bitrate_kbps = bitrate / 1000
                            if bitrate_kbps < min_bitrate:
                                logging.info(f"URL {url} 比特率 {bitrate_kbps:.0f}kbps 低于阈值 {min_bitrate}kbps，判定为无效")
                                return None, False
                            else:
                                logging.info(f"URL {url} 比特率 {bitrate_kbps:.0f}kbps，符合要求")
                        else:
                            logging.info(f"ffprobe 未能获取 URL {url} 的比特率 (可能是纯音频或数据流)")
                            # For M3U/M3U8, if no bitrate, but downloaded okay, consider it valid if it's not empty.
                            # This part can be stricter if needed.
                    
                total_elapsed_ms = (time.time() - start_time) * 1000
                return total_elapsed_ms, True

            except asyncio.TimeoutError:
                logging.info(f"HTTP/HTTPS URL {url} 操作超时")
                return None, False
            except aiohttp.ClientError as e:
                logging.info(f"HTTP/HTTPS URL {url} 网络错误: {e}")
                return None, False
            except json.JSONDecodeError:
                logging.info(f"ffprobe 无法解析 URL {url} 的输出为 JSON")
                return None, False
            except subprocess.CalledProcessError as e: # Should be caught by returncode check
                logging.info(f"ffprobe 检查 URL {url} 失败，进程错误: {e}")
                return None, False
            except Exception as e:
                logging.warning(f"检查 HTTP/HTTPS URL {url} 时发生未知错误: {e}\n{traceback.format_exc()}")
                return None, False

        elif url.startswith("rtmp"):
            try:
                rtmp_timeout_s = timeout // 4 # RTMP checks are usually faster if they work
                proc = await asyncio.create_subprocess_exec(
                    'ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url, '-show_streams', '-print_format', 'json',
                    '-timeout', str(rtmp_timeout_s * 1000000),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=rtmp_timeout_s + 5)
                except asyncio.TimeoutError:
                    logging.info(f"ffprobe for RTMP URL {url} 超时 (进程超时)")
                    try:
                        proc.kill()
                        await proc.wait()
                    except ProcessLookupError:
                        pass
                    return None, False
                
                if proc.returncode == 0:
                    logging.info(f"RTMP URL {url} 检查成功 (ffprobe)")
                    return (time.time() - start_time) * 1000, True
                else:
                    logging.info(f"RTMP URL {url} 检查失败 (ffprobe)，退出码 {proc.returncode}，错误: {stderr.decode('utf-8', errors='ignore').strip()}")
                    return None, False
            except Exception as e:
                logging.warning(f"RTMP URL {url} 检查异常: {e}")
                return None, False
        
        # RTP and P3P checks are less common and harder to verify robustly without specific players/tools.
        # Kept original logic for these, but they might need more sophisticated checks.
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
                    s.settimeout(5) # Short timeout for RTP check
                    await loop.sock_connect(s, (host, port))
                    # Sending a dummy byte might not be enough for all RTP servers
                    await loop.sock_sendto(s, b'\x00', (host, port)) 
                    await loop.sock_recv(s, 1) # Attempt to receive something
                logging.info(f"RTP URL {url} 检查似乎成功 (socket test)")
                return (time.time() - start_time) * 1000, True
            except Exception as e:
                logging.info(f"RTP URL {url} 检查失败: {e}")
                return None, False

        else:
            logging.info(f"不支持的协议或检查方式: {url}")
            return None, False
    except Exception as e:
        logging.error(f"检查 URL {url} 流质量时发生最外层未知错误: {e}\n{traceback.format_exc()}")
        return None, False

async def process_url_async(url, last_modified_cache, session, blacklist, semaphore):
    async with semaphore:
        cleaned_url = clean_url_params(url)
        if any(domain in cleaned_url for domain in blacklist):
            logging.info(f"URL {cleaned_url} 在黑名单中，跳过")
            return [], last_modified_cache.get(cleaned_url)

        cached_last_modified = last_modified_cache.get(cleaned_url, DEFAULT_LAST_MODIFIED)
        current_last_modified = None # Initialize
        try:
            current_last_modified = await fetch_url_headers_async(cleaned_url, session)
            if current_last_modified == cached_last_modified and current_last_modified != DEFAULT_LAST_MODIFIED:
                logging.info(f"URL '{cleaned_url}' 未更新 (Last-Modified 相同)，跳过内容抓取")
                return [], cached_last_modified # Return empty list, but update last_modified correctly
        except Exception as e:
            logging.info(f"获取 '{cleaned_url}' Header 失败或无 Last-Modified: {e}，将尝试抓取内容。")
            # Proceed to fetch content if headers fail or no Last-Modified

        try:
            text, fetched_last_modified_from_content = await fetch_url_content_async(cleaned_url, session)
            if not text:
                logging.info(f"URL {cleaned_url} 未获取到内容")
                # Even if no content, update last_modified_cache with current_last_modified if available
                # to prevent re-checking a known-bad URL too soon if it had a Last-Modified header
                if current_last_modified:
                     last_modified_cache[cleaned_url] = current_last_modified
                return [], current_last_modified

            # Use Last-Modified from content fetch if available, else from header fetch, else now.
            final_last_modified = fetched_last_modified_from_content or current_last_modified or datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
            last_modified_cache[cleaned_url] = final_last_modified

            if get_url_file_extension(cleaned_url) in [".m3u", ".m3u8"]:
                text = convert_m3u_to_txt(text)

            lines = text.split('\n')
            channel_list = []
            channel_count = 0
            for line in lines:
                line = line.strip()
                if "#genre#" not in line.lower() and "," in line and "://" in line: # Make #genre# check case-insensitive
                    parts = line.split(',', 1)
                    channel_name = parts[0].strip()
                    channel_address_raw = parts[1].strip()

                    if '#' in channel_address_raw: # Handle multiple URLs for one channel name
                        url_list_for_channel = channel_address_raw.split('#')
                        for single_channel_url in url_list_for_channel:
                            single_channel_url = clean_url_params(single_channel_url.strip())
                            if single_channel_url and not any(domain in single_channel_url for domain in blacklist):
                                channel_list.append((channel_name, single_channel_url))
                                channel_count += 1
                    else:
                        single_channel_url = clean_url_params(channel_address_raw)
                        if single_channel_url and not any(domain in single_channel_url for domain in blacklist):
                            channel_list.append((channel_name, single_channel_url))
                            channel_count += 1
            
            if channel_count > 0:
                logging.info(f"成功读取 URL: {cleaned_url}，获取到 {channel_count} 个频道条目")
            else:
                logging.info(f"URL: {cleaned_url} 内容已读取，但未解析到有效频道条目")
            return channel_list, final_last_modified

        except Exception as e:
            logging.error(f"处理 URL {cleaned_url} 时出错: {e}\n{traceback.format_exc()}")
            # Update last_modified_cache even on error to avoid retrying too soon if headers were fetched
            if current_last_modified:
                 last_modified_cache[cleaned_url] = current_last_modified
            return [], current_last_modified


def filter_and_modify_sources(corrections):
    name_dict = ['购物', '理财', '导视', '指南', '测试', '芒果', 'CGTN', 
                 '[Not 24/7]', 'DJ', '音乐', '演唱会', '舞曲', '广播',
                 '春晚', '格斗', '粤', '祝', '体育', '博斯', '神话', '测试频道', 
                 '回放', '专场', '系列', ' CCTV', 'CCTV-', '卫视'] # Added CCTV/卫视 to avoid generic names like "CCTV1" being stripped to "1"
    
    # More aggressive resolution/quality suffix removal
    resolution_suffixes = [
        '(480p)', '(360p)', '(240p)', '(1080p)', '(720p)', '(4k)',
        '(406p)', '(540p)', '(600p)', '(576p)',
        'FHD', 'HD', 'SD', '高清', '超清', '标清', '流畅', 
        '20M', '4K', '4KR', '8K',
        ' P', ' p', ' 清晰', '原画'
    ]
    
    url_dict = ['.m3u8?auth_key=', 'token=', 'auth=', '.ts?'] # Added .ts? as it's often part of temporary/restricted links

    filtered_corrections = []
    unique_check = set() # To avoid duplicate (name, url) pairs after cleaning

    for name, url in corrections:
        original_name = name
        if any(word.lower() in name.lower() for word in name_dict) or \
           any(word in url for word in url_dict):
            logging.debug(f"过滤频道 (关键词或URL过滤): {name},{url}")
            continue

        # Remove resolution/quality suffixes and extra spaces
        for suffix in resolution_suffixes:
            name = re.sub(r'\s*' + re.escape(suffix) + r'\s*', ' ', name, flags=re.IGNORECASE)
        
        name = re.sub(r'\([^)]*\)', '', name) # Remove content in parentheses
        name = re.sub(r'\[[^\]]*\]', '', name) # Remove content in square brackets
        name = name.replace('-', '').replace('_', ' ').replace('+', ' ') # Replace common separators with space
        name = re.sub(r'\s+', ' ', name).strip() # Normalize spaces

        if not name: # If name becomes empty after cleaning, skip
            logging.debug(f"过滤频道 (名称清理后为空): {original_name} -> {name},{url}")
            continue
        
        if (name.lower(), url.lower()) not in unique_check:
            filtered_corrections.append((name, url))
            unique_check.add((name.lower(), url.lower()))
        else:
            logging.debug(f"过滤频道 (重复项): {name},{url}")

    return filtered_corrections


def clear_txt_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.txt'): # Only iptv.txt or also general .txt? Assuming all .txt in this dir.
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
                logging.info(f"已删除文件: {file_path}")
            except Exception as e:
                logging.error(f"删除文件 {file_path} 时出错: {e}")

# This function seems unused, if it's for a specific output format, it can be integrated elsewhere.
# def write_list(file_path, data_list):
#     with open(file_path, 'w', encoding='utf-8') as file:
#         for item in data_list:
#             file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        # Try to extract a number, then primary name, then any sub-channel indicator
        num_match = re.search(r'(\d+)', channel_name_full)
        num_val = int(num_match.group(1)) if num_match else float('inf')
        
        name_part = re.sub(r'\d+', '', channel_name_full).strip() # Remove numbers to get base name
        
        # Try to find common sub-channel names like "高清", "综合" for secondary sort
        sub_channel_indicator = ""
        if "高清" in channel_name_full: sub_channel_indicator = "高清"
        elif "超清" in channel_name_full: sub_channel_indicator = "超清"
        elif "标清" in channel_name_full: sub_channel_indicator = "标清"
        elif "综合" in channel_name_full: sub_channel_indicator = "综合"
        # Add more indicators if needed

        return (num_val, name_part, sub_channel_indicator, channel_name_full) # Sort by number, then name, then indicator

    return sorted(channels, key=channel_key)

def merge_iptv_files(local_channels_base_directory): # Renamed for clarity
    final_output_lines = []
    now = datetime.now()
    final_output_lines.extend([
        f"#EXTM3U x-tvg-url=\"https://raw.githubusercontent.com/Fuguiyaya/IPTV/main/EPG/IPTV.xml,https://raw.githubusercontent.com/Ftindy/IPTV-URL/main/epg.xml\"",
        f"更新时间,#genre#", # \n will be added when writing
        f"{now.strftime('%Y-%m-%d')},url",
        f"{now.strftime('%H:%M:%S')},url"
    ])

    ordered_main_categories = ["央视频道", "卫视频道", "湖南频道", "港台频道", "体育频道"] # Main categories to appear first
    
    all_found_iptv_files = []
    # Scan the base directory and its subdirectories (like '地方频道/浙江频道')
    for root, _, files in os.walk(local_channels_base_directory):
        for f_name in files:
            if f_name.endswith('_iptv.txt'):
                full_path = os.path.join(root, f_name)
                # Determine category name from file path for sorting
                relative_path = os.path.relpath(full_path, local_channels_base_directory)
                category_name_from_path = relative_path.replace('_iptv.txt', '').replace(os.path.sep, '/')
                all_found_iptv_files.append({'path': full_path, 'category': category_name_from_path})
    
    # Sort files: first by ordered_main_categories, then alphabetically for others
    def sort_key_for_files(file_info):
        cat = file_info['category']
        if cat in ordered_main_categories:
            return (ordered_main_categories.index(cat), cat)
        return (len(ordered_main_categories), cat) # Put others after, then sort alphabetically

    sorted_iptv_files_info = sorted(all_found_iptv_files, key=sort_key_for_files)

    for file_info in sorted_iptv_files_info:
        file_path = file_info['path']
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
                if not lines:
                    logging.warning(f"文件 {file_path} 为空，跳过。")
                    continue
                
                header = lines[0].strip()
                if '#genre#' in header.lower(): # Case-insensitive check for #genre#
                    final_output_lines.append(header) # Keep original header line
                    
                    # Group channels by name to limit duplicates, take top N per name
                    grouped_channels_in_file = {}
                    for line in lines[1:]:
                        line = line.strip()
                        if line and "," in line and "://" in line:
                            channel_name_part = line.split(',', 1)[0].strip()
                            grouped_channels_in_file.setdefault(channel_name_part, []).append(line)
                    
                    for channel_name_key in sorted(grouped_channels_in_file.keys()): # Sort by channel name within category
                        # Limit to 5 sources per unique channel name within this category file
                        for ch_line in grouped_channels_in_file[channel_name_key][:5]: 
                            final_output_lines.append(ch_line)
                else:
                    logging.warning(f"文件 {file_path} 没有以类别标题 (#genre#) 开头，将尝试逐行添加（无分组限制）。")
                    # Fallback: if no genre header, add all valid lines
                    for line in lines:
                        line = line.strip()
                        if line and "," in line and "://" in line:
                             final_output_lines.append(line)

        except Exception as e:
            logging.error(f"合并文件 {file_path} 时出错: {e}")

    iptv_list_file_path = "iptv_list.txt" # Output to root
    with open(iptv_list_file_path, "w", encoding="utf-8") as file:
        for line in final_output_lines:
            file.write(line.strip() + '\n') # Ensure clean lines
    logging.info(f"所有频道已合并到 {iptv_list_file_path}")


async def main():
    start_time_main = time.time()
    os.makedirs(CONFIG_DIR, exist_ok=True)
    # Base directory for categorized channel files
    local_channels_output_dir = "频道文件" 
    os.makedirs(local_channels_output_dir, exist_ok=True)
    # Subdirectory for regional channels
    os.makedirs(os.path.join(local_channels_output_dir, "地方频道"), exist_ok=True)


    logging.info("开始 IPTV 频道爬取和整理...")

    blacklist = load_blacklist()
    logging.info(f"已加载 {len(blacklist)} 个黑名单域名.")

    last_modified_cache = {}
    if os.path.exists(LAST_MODIFIED_FILE):
        with open(LAST_MODIFIED_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',', 1)
                if len(parts) == 2:
                    last_modified_cache[parts[0]] = parts[1]
    logging.info(f"已加载 {len(last_modified_cache)} 个URL的上次修改时间缓存.")

    urls_to_crawl = read_txt_to_array(URLS_FILE_PATH)
    logging.info(f"从 {URLS_FILE_PATH} 加载了 {len(urls_to_crawl)} 个初始 URL.")

    if GITHUB_TOKEN: # Only search GitHub if token is available
        github_urls = await search_github_for_iptv_urls()
        if github_urls: # Only extend if new URLs were found
            urls_to_crawl.extend(github_urls)
            urls_to_crawl = sorted(list(set(urls_to_crawl))) # Sort and unique
            logging.info(f"GitHub 搜索获取了 {len(github_urls)} 个新 URL.")
    else:
        logging.warning("未设置 GITHUB_TOKEN，跳过 GitHub 搜索。")
    
    logging.info(f"总计 {len(urls_to_crawl)} 个待处理 URL.")


    all_channels_raw = []
    updated_last_modified_cache = last_modified_cache.copy()
    # Semaphore for controlling concurrency of fetching content from various URLs
    fetch_semaphore = asyncio.Semaphore(20) # Increased semaphore for fetching URLs
    
    conn = aiohttp.TCPConnector(limit_per_host=10, limit=100, ssl=False) # Custom connector for aiohttp
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [process_url_async(url, updated_last_modified_cache, session, blacklist, fetch_semaphore) for url in urls_to_crawl]
        for i, future in enumerate(asyncio.as_completed(tasks)):
            try:
                channels_from_url, _ = await future # last_mod is handled by updated_last_modified_cache directly
                if channels_from_url:
                    all_channels_raw.extend(channels_from_url)
                logging.info(f"已处理 {i+1}/{len(tasks)} 个源URL.")
            except Exception as e:
                logging.error(f"处理源URL任务时发生错误: {e}")


    with open(LAST_MODIFIED_FILE, 'w', encoding='utf-8') as f:
        for url, last_mod_val in updated_last_modified_cache.items():
            f.write(f"{url},{last_mod_val}\n")
    logging.info("已保存更新后的上次修改时间缓存.")

    logging.info(f"从所有源共获取到 {len(all_channels_raw)} 个原始频道条目。")
    filtered_channels = filter_and_modify_sources(all_channels_raw)
    logging.info(f"初步过滤和名称清理后剩下 {len(filtered_channels)} 个频道条目。")

    if not filtered_channels:
        logging.info("没有有效的频道进行下一步处理。脚本结束。")
        return

    logging.info("开始检查所有频道链接的可用性和质量 (这可能需要较长时间)...")
    valid_channels_results = []
    
    # Semaphore for controlling concurrency of stream quality checks (ffprobe can be CPU intensive)
    check_semaphore = asyncio.Semaphore(os.cpu_count() or 4) # Limit to number of CPU cores or 4

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as check_session: # New session for checks
        check_tasks_with_names = []
        for name, url in filtered_channels:
             check_tasks_with_names.append(
                 (name, url, check_stream_quality(url, check_session, timeout=60)) # timeout for check_stream_quality
             )
        
        total_checks = len(check_tasks_with_names)
        completed_checks = 0
        
        for name, url, task in check_tasks_with_names:
            async with check_semaphore: # Acquire semaphore before awaiting task
                try:
                    elapsed_time, is_valid = await task
                    completed_checks += 1
                    logging.info(f"检查进度: {completed_checks}/{total_checks}. URL: {url}, 有效性: {is_valid}, 耗时: {elapsed_time if elapsed_time else 'N/A'}ms")
                    if is_valid and elapsed_time is not None:
                        valid_channels_results.append((elapsed_time, f"{name},{url}"))
                except Exception as e:
                    completed_checks += 1
                    logging.error(f"检查URL {url} 时发生错误 (in main loop): {e}")


    valid_channels_results = sorted(valid_channels_results) # Sort by elapsed_time (fastest first)
    logging.info(f"有效频道数量: {len(valid_channels_results)}")

    if not valid_channels_results:
        logging.info("没有检测到有效可用的频道。脚本结束。")
        return

    # Clear old categorized files before writing new ones
    logging.info(f"清空旧的频道文件于目录: {local_channels_output_dir}")
    # Be careful with this if there are other important .txt files.
    # For now, it will clear from local_channels_output_dir and its subdirectories like '地方频道'
    for root_dir, _, _ in os.walk(local_channels_output_dir):
        clear_txt_files(root_dir)


    grouped_channels = {}
    # Category mapping: keywords in channel name -> (category_name, sub_directory_if_any)
    # Order of this dict matters for categorization if a channel matches multiple keywords.
    category_map = {
        ("央视", "CCTV"): ("央视频道", None),
        ("卫视",): ("卫视频道", None),
        ("湖南",): ("湖南频道", None),
        ("凤凰", "TVB", "香港", "台湾", "星空", "翡翠", "明珠", "本港", "亞洲"): ("港台频道", None),
        ("CHC", "影院", "电影", "剧场"): ("影视频道", None),
        ("体育", "足球", "篮球", "高尔夫", "赛事", "Sports", "ESPN"): ("体育频道", None),
        ("新闻", "财经", "资讯"): ("新闻财经", None),
        ("纪实", "地理", "探索", "Discovery", "History"): ("纪实频道", None),
        ("卡通", "动画", "动漫", "少儿", "Kids"): ("少儿动画", None),
        ("音乐", "Music", "MTV"): ("音乐戏曲", None),
        # 地方频道 (more specific matches should come before generic "地方")
        ("浙江", "ZJTV", "杭州"): ("浙江频道", "地方频道"),
        ("江苏", "JSTV", "南京"): ("江苏频道", "地方频道"),
        ("上海", "东方卫视", "STV", "SMEG"): ("上海频道", "地方频道"),
        ("广东", "GDTV", "广州", "深圳", "珠江", "南方"): ("广东频道", "地方频道"),
        ("北京", "BTV"): ("北京频道", "地方频道"),
        ("山东", "SDTV", "齐鲁", "济南"): ("山东频道", "地方频道"),
        ("四川", "SCTV", "成都"): ("四川频道", "地方频道"),
        ("福建", "FJTV", "厦门", "福州"): ("福建频道", "地方频道"),
        ("湖北", "HBTV", "武汉"): ("湖北频道", "地方频道"),
        ("河南", "HNTV", "郑州"): ("河南频道", "地方频道"),
        ("安徽", "AHTV", "合肥"): ("安徽频道", "地方频道"),
        ("辽宁", "LNTV", "沈阳"): ("辽宁频道", "地方频道"),
        ("黑龙江", "HLJTV", "哈尔滨"): ("黑龙江频道", "地方频道"),
        ("吉林", "JLTV", "长春"): ("吉林频道", "地方频道"),
        ("重庆", "CQTV"): ("重庆频道", "地方频道"),
        ("天津", "TJTV"): ("天津频道", "地方频道"),
        ("河北", "HEBTV", "石家庄"): ("河北频道", "地方频道"),
        ("山西", "SXTV", "太原"): ("山西频道", "地方频道"),
        ("内蒙古", "NMGTV", "呼和浩特"): ("内蒙古频道", "地方频道"),
        ("江西", "JXTV", "南昌"): ("江西频道", "地方频道"),
        ("广西", "G bañoXTV", "南宁"): ("广西频道", "地方频道"), # Fixed typo GXTV
        ("海南", "HNWTV", "旅游卫视", "海口"): ("海南频道", "地方频道"),
        ("陕西", "SNTV", "西安"): ("陕西频道", "地方频道"),
        ("甘肃", "GSTV", "兰州"): ("甘肃频道", "地方频道"),
        ("宁夏", "NXTV", "银川"): ("宁夏频道", "地方频道"),
        ("青海", "QHTV", "西宁"): ("青海频道", "地方频道"),
        ("新疆", "XJTV", "乌鲁木齐"): ("新疆频道", "地方频道"),
        ("西藏", "XZTV", "拉萨"): ("西藏频道", "地方频道"),
        ("云南", "YNTV", "昆明"): ("云南频道", "地方频道"),
        ("贵州", "GZTV", "贵阳"): ("贵州频道", "地方频道"),
        # More generic local channel identifiers (should be checked after specific provinces)
        ("省台", "地方", "市台", "县台", "都市", "公共", "生活", "经济", "文体", "教育", "农业", "交通"): ("其他地方", "地方频道"),
    }

    for _, channel_line in valid_channels_results:
        name, url = channel_line.split(',', 1)
        name_clean = name.strip()
        url_clean = url.strip()
        
        assigned_category = "其他频道" # Default category
        assigned_subdir = None

        for keywords, (cat_name, subdir) in category_map.items():
            if any(kw.lower() in name_clean.lower() for kw in keywords):
                assigned_category = cat_name
                assigned_subdir = subdir
                break # First match wins

        full_category_path = assigned_category
        if assigned_subdir:
            full_category_path = os.path.join(assigned_subdir, assigned_category)
        
        grouped_channels.setdefault(full_category_path, []).append(f"{name_clean},{url_clean}")

    for category_path_key, channels in grouped_channels.items():
        # Determine output directory and filename
        path_parts = category_path_key.split(os.path.sep)
        base_category_name = path_parts[-1]
        
        current_output_dir = local_channels_output_dir
        if len(path_parts) > 1: # Has subdirectory
            # Create subdirectory like "频道文件/地方频道"
            current_output_dir = os.path.join(local_channels_output_dir, *path_parts[:-1])
        
        os.makedirs(current_output_dir, exist_ok=True)
        output_file_path = os.path.join(current_output_dir, f"{base_category_name}_iptv.txt")

        if base_category_name == "央视频道": # Specific sorting for CCTV
            channels = sort_cctv_channels(channels)

        # Write with genre header
        # The genre for the file is derived from its path/name for clarity
        genre_header_name = category_path_key.replace(os.path.sep, ' - ') # e.g., "地方频道 - 浙江频道"
        formatted_channels = [f"{genre_header_name},#genre#"] + channels # Add \n during write
        
        # Use write_array_to_txt which handles adding newline characters
        write_array_to_txt(output_file_path, formatted_channels)
        logging.info(f"已保存 {len(channels)} 个 {genre_header_name} 频道到 {output_file_path}")

    logging.info("合并所有 IPTV 文件到 iptv_list.txt...")
    merge_iptv_files(local_channels_output_dir) # Pass the base directory of categorized files
    
    end_time_main = time.time()
    logging.info(f"IPTV 频道更新和整理完成！总耗时: {end_time_main - start_time_main:.2f} 秒。")

async def search_github_for_iptv_urls():
    found_urls = set()
    headers = {'Accept': 'application/vnd.github.v3+json'} # Corrected Accept header
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
    else:
        # This case should be handled by the caller, search_github_for_iptv_urls won't be called.
        # But defensive return.
        return [] 

    async with aiohttp.ClientSession(headers=headers) as session:
        for keyword_idx, keyword in enumerate(SEARCH_KEYWORDS):
            logging.info(f"GitHub 搜索 ({keyword_idx+1}/{len(SEARCH_KEYWORDS)}) 使用关键词: '{keyword}'")
            for page in range(1, MAX_SEARCH_PAGES + 1):
                search_url = f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}?q={keyword}&per_page={PER_PAGE}&page={page}"
                try:
                    async with session.get(search_url, timeout=60) as response: # Increased timeout for API call
                        response.raise_for_status()
                        data = await response.json()
                        
                        items = data.get('items', [])
                        if not items and page == 1: # No results for this keyword
                            logging.info(f"关键词 '{keyword}' 未找到结果。")
                            break # Go to next keyword

                        for item in items:
                            raw_url = item.get('download_url')
                            file_name = item.get('name', '').lower()

                            if raw_url and any(raw_url.endswith(ext) for ext in ['.m3u', '.m3u8', '.txt']):
                                found_urls.add(raw_url)
                                logging.debug(f"GitHub URL (from download_url): {raw_url}")
                            elif any(file_name.endswith(ext) for ext in ['.m3u', '.m3u8', '.txt']):
                                html_url = item.get('html_url', '')
                                if html_url.startswith('https://github.com/') and '/blob/' in html_url:
                                    constructed_url = html_url.replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/')
                                    found_urls.add(constructed_url)
                                    logging.debug(f"GitHub URL (constructed): {constructed_url}")
                        
                        if not items or len(items) < PER_PAGE: # No more items or last page
                            break # Go to next keyword if this was the last page for current keyword
                        
                        if MAX_SEARCH_PAGES > 1 and page < MAX_SEARCH_PAGES:
                             logging.info(f"关键词 '{keyword}' 第 {page} 页处理完毕，休眠 {GITHUB_PAGE_SLEEP} 秒...")
                             await asyncio.sleep(GITHUB_PAGE_SLEEP)

                except aiohttp.ClientResponseError as e:
                    if e.status == 403:
                        if 'rate limit exceeded' in str(e.message).lower(): # Check e.message for rate limit string
                            logging.warning(f"GitHub API 速率限制。关键词 '{keyword}', 页面 {page}。将增加等待时间并跳过此关键词的剩余页面。")
                            await asyncio.sleep(60) # Wait longer if rate limited
                            break # Break page loop for this keyword
                        else:
                            logging.error(f"GitHub API 禁止访问 (403 Forbidden)！关键词 '{keyword}', 页面 {page}。可能是触发了滥用检测。将中止 GitHub 搜索。详情: {e}")
                            return list(found_urls) # Abort all GitHub searching
                    elif e.status == 401:
                        logging.error(f"GitHub API 请求失败 (状态码: {e.status}): Unauthorized. 请检查 GITHUB_TOKEN 的有效性或权限。将中止 GitHub 搜索。")
                        return list(found_urls) # Abort all GitHub searching
                    elif e.status == 422: # Unprocessable Entity - often due to complex query
                        logging.warning(f"GitHub API 请求处理失败 (422). 关键词 '{keyword}' 可能过于复杂或无效。跳过此关键词。")
                        break # Break page loop (effectively skipping keyword)
                    else:
                        logging.error(f"GitHub API 请求失败 (状态码: {e.status}) 关键词 '{keyword}', 页面 {page}: {e}")
                        # For other client errors, break page loop and try next keyword after sleep
                        break
                except asyncio.TimeoutError:
                    logging.error(f"GitHub API 请求超时 (关键词: '{keyword}', 页面: {page})")
                    break # Break page loop, try next keyword
                except Exception as e:
                    logging.error(f"GitHub 搜索 '{keyword}' 页面 {page} 时发生未知错误: {e}\n{traceback.format_exc()}")
                    break # Break page loop

            # Sleep between keywords
            if keyword_idx < len(SEARCH_KEYWORDS) - 1: # Don't sleep after the last keyword
                logging.info(f"关键词 '{keyword}' 处理完毕，休眠 {GITHUB_KEYWORD_SLEEP} 秒...")
                await asyncio.sleep(GITHUB_KEYWORD_SLEEP)
            
    return list(found_urls)

if __name__ == "__main__":
    try:
        # Windows event loop policy for ProactorEventLoop for subprocesses if needed
        if sys.platform == "win32" and sys.version_info >= (3, 8):
             asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        asyncio.run(main())

    except KeyboardInterrupt:
        logging.info("脚本被用户中断。")
    except Exception as e:
        logging.critical(f"脚本主程序遇到致命错误: {e}")
        logging.critical(traceback.format_exc())
        print(f"FATAL SCRIPT ERROR: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        sys.exit(1)
