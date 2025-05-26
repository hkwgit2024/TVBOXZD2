import aiohttp
import asyncio
import json
import logging
import os
import re
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed
import yaml
from urllib.parse import urlparse
import socket

# 加载配置文件
CONFIG_PATH = os.getenv('CONFIG_PATH', 'config/config.yaml')
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    CONFIG = yaml.safe_load(f)

# 配置日志
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='iptv_crawler.log',
    filemode='a'
)

# 配置参数
QUALITY_CHECK_TIMEOUT = CONFIG.get('quality_check_timeout', 10)  # 质量检查超时（秒）
MIN_RESOLUTION = CONFIG.get('min_resolution', [1280, 720])  # 最低分辨率（720p）
MIN_BITRATE = CONFIG.get('min_bitrate', 1000000)  # 最低码率（1000 kbps）
MAX_RESPONSE_TIME = CONFIG.get('max_response_time', 5)  # 最大响应时间（秒）
STABILITY_DURATION = CONFIG.get('stability_duration', 10)  # 稳定性测试时长（秒）
CHANNEL_CHECK_TIMEOUT = CONFIG.get('channel_check_timeout', 5)  # 频道检查超时（秒）
MAX_CHANNEL_URLS_PER_GROUP = CONFIG.get('max_channel_urls_per_group', 100)  # 每组最大 URL 数
REQUESTS_POOL_SIZE = CONFIG.get('requests_pool_size', 50)  # 请求连接池大小
PER_PAGE = CONFIG.get('per_page', 100)  # 每页结果数
MAX_SEARCH_PAGES = CONFIG.get('max_search_pages', 5)  # 最大搜索页数
GITHUB_API_TIMEOUT = CONFIG.get('github_api_timeout', 60)  # GitHub API 超时（秒）
GITHUB_API_RETRY_WAIT = CONFIG.get('github_api_retry_wait', 60)  # API 限制等待时间（秒）

async def create_aiohttp_session():
    """创建 aiohttp 会话"""
    connector = aiohttp.TCPConnector(limit=REQUESTS_POOL_SIZE)
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=CHANNEL_CHECK_TIMEOUT)
    )

@retry(stop=stop_after_attempt(3), wait=wait_fixed(1.5))
async def search_github(keyword, session):
    """搜索 GitHub 上的 IPTV 源"""
    results = []
    headers = {'Accept': 'application/vnd.github.v3+json'}
    bot_token = os.getenv('BOT')
    if bot_token:
        headers['Authorization'] = f'token {bot_token}'
    
    for page in range(1, MAX_SEARCH_PAGES + 1):
        url = f'https://api.github.com/search/code?q={keyword}&per_page={PER_PAGE}&page={page}'
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 403:
                    logging.warning(f"GitHub API 速率限制，等待 {GITHUB_API_RETRY_WAIT}秒")
                    await asyncio.sleep(GITHUB_API_RETRY_WAIT)
                    continue
                response.raise_for_status()
                data = await response.json()
                results.extend(data.get('items', []))
        except aiohttp.ClientError as e:
            logging.error(f"搜索 GitHub 失败（关键词：{keyword}）：{e}")
    return results

async def fetch_file_content(url, session):
    """获取文件内容"""
    try:
        async with session.get(url, timeout=CONFIG.get('channel_fetch_timeout', 30)) as response:
            response.raise_for_status()
            return await response.text()
    except aiohttp.ClientError as e:
        logging.debug(f"获取内容失败（{url}）：{e}")
        return None

def is_valid_url(url):
    """验证 URL 是否有效"""
    invalid_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    allowed_protocols = CONFIG.get('url_pre_screening', {}).get('allowed_protocols', [])
    stream_extensions = CONFIG.get('url_pre_screening', {}).get('stream_extensions', [])
    
    if not any(url.startswith(p + '://') for p in allowed_protocols):
        return False
    if not any(url.lower().endswith(ext) for ext in stream_extensions):
        parsed = urlparse(url)
        if not parsed.path or parsed.path == '/':
            return False
    return not any(re.search(pattern, url, re.IGNORECASE) for pattern in invalid_patterns)

def check_rtmp_url(url, timeout):
    """检查 RTMP URL"""
    try:
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logging.debug(f"RTMP 检查失败（{url}）：{e}")
        return False

def check_rtp_url(url, timeout):
    """检查 RTP URL"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port))
            s.recv(1)
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP 检查失败（{url}）：{e}")
        return False

def check_p3p_url(url, timeout):
    """检查 P3P URL"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or 80
        path = parsed_url.path or '/'
        if not host:
            return False
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P 检查失败（{url}）：{e}")
        return False

async def check_channel_validity(channel_name, url, session):
    """检查频道有效性、画质和稳定性"""
    start_time = time.time()
    try:
        if url.startswith(("http", "https")):
            # HTTP/HTTPS 检查
            async with session.get(url, timeout=MAX_RESPONSE_TIME) as response:
                if response.status != 200:
                    return None, False
                await response.content.read(1024)
            response_time_ms = (time.time() - start_time) * 1000
            if response_time_ms > MAX_RESPONSE_TIME * 1000:
                logging.debug(f"频道 {channel_name} 响应时间过长：{response_time_ms}ms")
                return None, False

            # 检查画质
            try:
                result = subprocess.run(
                    ['ffprobe', '-v', 'error', '-show_streams', '-print_format', 'json', url],
                    capture_output=True,
                    text=True,
                    timeout=QUALITY_CHECK_TIMEOUT
                )
                if result.returncode != 0:
                    logging.debug(f"频道 {channel_name} ffprobe 失败：{result.stderr}")
                    return None, False
                info = json.loads(result.stdout)
                video_stream = next((s for s in info.get('streams', []) if s.get('codec_type') == 'video'), None)
                if not video_stream:
                    logging.debug(f"频道 {channel_name} 无视频流")
                    return None, False
                width = int(video_stream.get('width', 0))
                height = int(video_stream.get('height', 0))
                bitrate = int(video_stream.get('bit_rate', 0) or 0)
                if width < MIN_RESOLUTION[0] or height < MIN_RESOLUTION[1] or bitrate < MIN_BITRATE:
                    logging.debug(f"频道 {channel_name} 画质不达标：{width}x{height}, {bitrate}bps")
                    return None, False
            except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
                logging.debug(f"频道 {channel_name} ffprobe 错误：{e}")
                return None, False

            # 检查稳定性
            try:
                result = subprocess.run(
                    ['ffmpeg', '-t', str(STABILITY_DURATION), '-i', url, '-f', 'null', '-'],
                    capture_output=True,
                    text=True,
                    timeout=STABILITY_DURATION + 5
                )
                if result.returncode != 0:
                    logging.debug(f"频道 {channel_name} 稳定性测试失败：{result.stderr}")
                    return None, False
            except subprocess.SubprocessError as e:
                logging.debug(f"频道 {channel_name} 稳定性测试错误：{e}")
                return None, False

            return response_time_ms, True

        elif url.startswith("rtmp"):
            # RTMP 检查
            try:
                result = subprocess.run(
                    ['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=CHANNEL_CHECK_TIMEOUT,
                    text=True
                )
                response_time_ms = (time.time() - start_time) * 1000
                if result.returncode != 0:
                    logging.debug(f"频道 {channel_name} RTMP 检查失败：{result.stderr}")
                    return None, False
                # 检查画质
                result = subprocess.run(
                    ['ffprobe', '-v', 'error', '-show_streams', '-print_format', 'json', url],
                    capture_output=True,
                    text=True,
                    timeout=QUALITY_CHECK_TIMEOUT
                )
                if result.returncode != 0:
                    logging.debug(f"频道 {channel_name} RTMP ffprobe 失败：{result.stderr}")
                    return None, False
                info = json.loads(result.stdout)
                video_stream = next((s for s in info.get('streams', []) if s.get('codec_type') == 'video'), None)
                if not video_stream:
                    logging.debug(f"频道 {channel_name} RTMP 无视频流")
                    return None, False
                width = int(video_stream.get('width', 0))
                height = int(video_stream.get('height', 0))
                bitrate = int(video_stream.get('bit_rate', 0) or 0)
                if width < MIN_RESOLUTION[0] or height < MIN_RESOLUTION[1] or bitrate < MIN_BITRATE:
                    logging.debug(f"频道 {channel_name} RTMP 画质不达标：{width}x{height}, {bitrate}bps")
                    return None, False
                # 检查稳定性
                result = subprocess.run(
                    ['ffmpeg', '-t', str(STABILITY_DURATION), '-i', url, '-f', 'null', '-'],
                    capture_output=True,
                    text=True,
                    timeout=STABILITY_DURATION + 5
                )
                if result.returncode != 0:
                    logging.debug(f"频道 {channel_name} RTMP 稳定性测试失败：{result.stderr}")
                    return None, False
                return response_time_ms, True
            except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
                logging.debug(f"频道 {channel_name} RTMP 错误：{e}")
                return None, False
        elif url.startswith("rtp"):
            is_valid = check_rtp_url(url, CHANNEL_CHECK_TIMEOUT)
            response_time_ms = (time.time() - start_time) * 1000
            return response_time_ms, is_valid
        elif url.startswith("p3p"):
            is_valid = check_p3p_url(url, CHANNEL_CHECK_TIMEOUT)
            response_time_ms = (time.time() - start_time) * 1000
            return response_time_ms, is_valid
        else:
            logging.debug(f"频道 {channel_name} 协议不支持：{url}")
            return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 失败：{e}")
        return None, False

async def check_channels(channels, max_workers=CONFIG.get('channel_check_workers', 50)):
    """检查频道列表有效性"""
    results = []
    total_channels = len(channels)
    logging.info(f"开始检查 {total_channels} 个频道...")
    async with await create_aiohttp_session() as session:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_channel_validity, line.split(',', 1)[0], line.split(',', 1)[1], session): line
                for line in channels if "://" in line and ',' in line
            }
            checked_count = 0
            for future in as_completed(futures):
                checked_count += 1
                if checked_count % 100 == 0:
                    logging.info(f"已检查 {checked_count}/{total_channels} 个频道")
                response_time_ms, is_valid = future.result()
                if is_valid:
                    results.append(futures[future])
    logging.info(f"找到有效频道：{len(results)} 个")
    return results

async def process_file_content(content, session):
    """从文件内容中提取频道"""
    channels = []
    lines = content.splitlines()
    current_name = None
    for line in lines:
        line = line.strip()
        if line.startswith('#EXTINF'):
            match = re.search(r'tvg-name="([^"]+)"', line) or re.search(r',(.+)$', line)
            if match:
                current_name = match.group(1).strip()
        elif line.startswith(('http', 'rtmp', 'rtp', 'p3p')):
            if current_name and is_valid_url(line):
                channels.append(f"{current_name},{line}")
                current_name = None
    return channels

async def crawl_iptv():
    """主爬取逻辑"""
    async with await create_aiohttp_session() as session:
        all_channels = []
        for keyword in CONFIG.get('search_keywords', []):
            logging.info(f"搜索关键词：{keyword}")
            items = await search_github(keyword, session)
            for item in items:
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                content = await fetch_file_content(raw_url, session)
                if content:
                    channels = await process_file_content(content, session)
                    all_channels.extend(channels)

        # 去重和过滤
        unique_channels = list(set(all_channels))
        valid_channels = await check_channels(unique_channels)

        # 按分类组织
        categories = defaultdict(list)
        name_replacements = CONFIG.get('channel_name_replacements', {})
        name_filter_words = CONFIG.get('name_filter_words', [])
        ordered_categories = CONFIG.get('ordered_categories', [])

        for channel in valid_channels:
            name, url = channel.split(',', 1)
            for old, new in name_replacements.items():
                name = name.replace(old, new)
            name = name.strip()
            if any(word in name.lower() for word in name_filter_words):
                continue
            category = '其他频道'
            for cat in ordered_categories:
                if cat in name or any(kw in name for kw in CONFIG.get('search_keywords', []) if cat in kw):
                    category = cat
                    break
            categories[category].append((name, url))

        # 生成输出
        with open('iptv_list.txt', 'w', encoding='utf-8') as f:
            f.write("更新时间,#genre#\n")
            f.write(f"{time.strftime('%Y-%m-%d')},url\n")
            f.write(f"{time.strftime('%H:%M:%S')},url\n")
            for category in ordered_categories:
                if category in categories:
                    f.write(f"{category},#genre#\n")
                    for name, url in categories[category][:MAX_CHANNEL_URLS_PER_GROUP]:
                        f.write(f"{name},{url}\n")
                    del categories[category]
            if categories:
                f.write("其他频道,#genre#\n")
                for category, channels in categories.items():
                    for name, url in channels[:MAX_CHANNEL_URLS_PER_GROUP]:
                        f.write(f"{name},{url}\n")

if __name__ == "__main__":
    asyncio.run(crawl_iptv())
