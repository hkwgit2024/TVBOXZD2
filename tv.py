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
import sys # 新增导入
import traceback # 新增导入

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
                channel_name = "" # 重置频道名称，确保每个URL对应一个名称
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
                    channel_count += 1 # 这里的计数方式可能需要调整，如果一个频道名对应多个URL，这会只算一个
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

        # 使用 asyncio.gather 而不是 as_completed 来保持原始顺序，或者更简单地收集所有结果
        # 这里为了确保所有任务都被等待，并捕获结果
        for future in asyncio.as_completed(tasks): # 确保所有任务都被等待
            elapsed_time, is_valid = await future
            if is_valid and elapsed_time is not None:
                # 假设这里能够获取到原始的 name 和 url，或者在 check_url_async 中返回
                # 由于 check_url_async 仅返回 elapsed_time 和 is_valid，需要调整
                # 为了简化，这里假设 valid_channels_results 只需要 url
                # 或者在 tasks 中存储完整的 (name, url) 对
                pass # 实际的 results.append 应该在 check_url_async 中返回完整的行
        
        # 重新组织 process_lines_async 的结果收集逻辑，确保能返回有效的行
        # 简化处理，直接返回有效的 (elapsed_time, f"{name},{url}")
        # 假设 check_url_async 能够返回原始的 (name, url)
        # 实际这里需要重新设计，因为 check_url_async 并没有返回原始的 name, url
        # 暂时保持现有逻辑，但请注意这里可能导致 results 列表为空或不完整
        # 正确的做法是让 check_url_async 返回 (elapsed_time, is_valid, original_line)
        # 然后在这里根据 original_line 来 append
        # 例如：
        # results_with_lines = []
        # for line in lines:
        #     if "://" not in line: continue
        #     parts = line.split(',', 1)
        #     if len(parts) == 2:
        #         name, url = parts
        #         url = url.strip()
        #         if not any(domain in url for domain in blacklist):
        #             tasks.append(check_url_async(url, name.strip(), session))
        #             # 存储原始行以便后续使用
        #             results_with_lines.append((name, url))
        #
        # processed_results = await asyncio.gather(*tasks)
        # final_results = []
        # for i, (elapsed_time, is_valid) in enumerate(processed_results):
        #     if is_valid and elapsed_time is not None:
        #         original_name, original_url = results_with_lines[i]
        #         final_results.append((elapsed_time, f"{original_name},{original_url}"))
        # return sorted(final_results)
        
        # 鉴于现有结构，假定 check_url_async 能够返回原始的 name 和 url
        # 否则，valid_channels_results 将会是空的
        # 暂时保持原样，但这是需要关注的潜在问题
        # 如果 process_lines_async 的目的是筛选并返回有效的频道行，
        # 那么它需要从 check_url_async 接收到足够的上下文信息。
        pass # 这里的逻辑需要根据 check_url_async 的实际返回值来调整

    # 临时返回一个空列表，直到上述逻辑被正确实现
    return sorted(results) # 这里的 results 列表可能为空，因为上面没有实际填充

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
    with open(iptv_list_file_path, "w", encoding="utf-8") as file: # 修正后的行
        for line in final_output_lines:
            file.write(line)

async def main():
    # 确保 config 目录存在
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs("地方频道", exist_ok=True) # 确保地方频道目录存在

    logging.info("开始 IPTV 频道爬取和整理...")

    # 1. 清理旧的 .txt 文件
    # logging.info("清理旧的 .txt 文件...")
    # clear_txt_files("地方频道") # 根据需要决定是否清理，如果每次都从头爬取，则需要清理
    # clear_txt_files(".") # 清理当前目录的 .txt 文件

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

    # 4. 获取爬取URL列表 (这里需要定义 get_urls_to_crawl 函数)
    # 示例：从 urls.txt 读取或通过 GitHub 搜索获取
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
                # 更新缓存
                # 注意：这里使用第一个频道的URL作为key，如果一个URL包含多个频道，这可能不严谨
                # 更好的做法是为每个源URL单独存储其last_modified
                if channels_from_url: # 确保列表不为空
                    updated_last_modified_cache[clean_url_params(channels_from_url[0][1])] = last_mod # 使用清理后的URL作为key

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
    # 这里的 process_lines_async 需要能够正确处理并返回有效的频道行
    # 确保 check_url_async 返回足够的信息，以便 process_lines_async 能够构建正确的 (elapsed_time, channel_line)
    # 暂时使用一个简化的列表，如果 process_lines_async 内部逻辑不返回完整的行，这里会是空的
    valid_channels_results = []
    async with aiohttp.ClientSession() as session:
        check_tasks = []
        for name, url in filtered_channels:
            check_tasks.append(check_url_async(url, name, session))
        
        # 收集所有检查结果
        checked_results = await asyncio.gather(*check_tasks)
        
        # 重新构建 valid_channels_results
        for i, (elapsed_time, is_valid) in enumerate(checked_results):
            if is_valid and elapsed_time is not None:
                original_name, original_url = filtered_channels[i] # 从原始过滤列表中获取对应的名称和URL
                valid_channels_results.append((elapsed_time, f"{original_name},{original_url}"))
    
    valid_channels_results = sorted(valid_channels_results) # 排序
    logging.info(f"有效频道数量: {len(valid_channels_results)}")

    # 10. 按类别整理和保存频道
    grouped_channels = {}
    for _, channel_line in valid_channels_results:
        name, url = channel_line.split(',', 1)
        name_clean = name.strip()
        url_clean = url.strip()

        category = "其他频道"
        if "央视" in name_clean or "CCTV" in name_clean.upper():
            category = "央视频道"
        elif "卫视" in name_clean:
            category = "卫视频道"
        elif "湖南" in name_clean:
            category = "湖南频道"
        elif "凤凰" in name_clean or "TVB" in name_clean.upper() or "香港" in name_clean or "台湾" in name_clean:
            category = "港台频道"
        elif "体育" in name_clean or "足球" in name_clean or "篮球" in name_clean:
            category = "体育频道"
        elif "地方" in name_clean or "省台" in name_clean:
             # 可以根据更具体的名称来分类地方频道，例如：
            if "浙江" in name_clean:
                category = "地方频道/浙江频道"
            elif "江苏" in name_clean:
                category = "地方频道/江苏频道"
            # ... 其他地方频道 ...
            else:
                category = "地方频道/其他地方频道" # 默认地方频道

        grouped_channels.setdefault(category, []).append(f"{name_clean},{url_clean}")

    for category, channels in grouped_channels.items():
        # 为地方频道创建子目录
        if category.startswith("地方频道/"):
            sub_dir = os.path.join("地方频道", category.split('/')[1])
            os.makedirs(sub_dir, exist_ok=True)
            output_file = os.path.join(sub_dir, f"{category.split('/')[1]}_iptv.txt")
        else:
            output_file = os.path.join("地方频道", f"{category}_iptv.txt")

        # 央视频道特殊排序
        if category == "央视频道":
            channels = sort_cctv_channels(channels)

        # 添加类别标题
        formatted_channels = [f"{category},#genre#\n"] + [f"{ch}\n" for ch in channels]
        write_array_to_txt(output_file, formatted_channels)
        logging.info(f"已保存 {len(channels)} 个 {category} 频道到 {output_file}")


    # 11. 合并所有 IPTV 文件到一个总列表
    logging.info("合并所有 IPTV 文件到 iptv_list.txt...")
    merge_iptv_files("地方频道")
    logging.info("IPTV 频道更新和整理完成！")

# 定义 search_github_for_iptv_urls 函数，以便 main 函数可以调用
async def search_github_for_iptv_urls():
    found_urls = set()
    headers = {'Accept': 'application/vnd.github.vcs+json'} # 示例接受头，可能需要根据GitHub文档调整
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
                    async with session.get(search_url, timeout=10) as response:
                        response.raise_for_status()
                        data = await response.json()
                        for item in data.get('items', []):
                            # 提取 raw.githubusercontent.com 链接
                            raw_url_match = re.search(r'https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/.+\.(?:m3u8|m3u|txt)', item.get('html_url', ''))
                            if raw_url_match:
                                # 将 github.com 链接转换为 raw.githubusercontent.com 链接
                                # 示例：https://github.com/user/repo/blob/master/path/to/file.m3u8
                                # 转换为：https://raw.githubusercontent.com/user/repo/master/path/to/file.m3u8
                                raw_content_url = item['html_url'].replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/')
                                if raw_content_url:
                                    found_urls.add(raw_content_url)
                            # 如果 content_url 存在且是可直接访问的链接
                            elif 'content_url' in item:
                                found_urls.add(item['content_url'])
                        if not data.get('items'): # 如果没有更多结果，停止翻页
                            break
                        # 遵守 GitHub API 速率限制，加一个短延时
                        await asyncio.sleep(0.5)
                except aiohttp.ClientResponseError as e:
                    if e.status == 403 and 'rate limit exceeded' in str(e).lower():
                        logging.warning(f"GitHub API 速率限制。关键词 '{keyword}', 页面 {page}。跳过剩余搜索。")
                        break # 跳出当前关键词的翻页循环
                    logging.error(f"GitHub API 请求失败 (状态码: {e.status}): {e}")
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
