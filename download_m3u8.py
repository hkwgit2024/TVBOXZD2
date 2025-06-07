import requests
import re
import os
import time
import logging
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import asyncio
from aiohttp import ClientSession, TCPConnector
import subprocess
import json

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义常量和配置
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive'
}
TIMEOUT = 10  # 超时时间（秒）
MAX_RETRIES = 3 # 最大重试次数
RETRY_DELAY = 1 # 重试间隔（秒）
MAX_CONCURRENT_REQUESTS = 50 # 并发请求数
MAX_PLAYLISTS_TO_FETCH = 100 # 限制每次运行获取的播放列表数量，防止处理过多导致超时

DATA_DIR = 'data'
VALID_URLS_FILE = os.path.join(DATA_DIR, 'valid_urls.txt')
FAILED_CACHE_FILE = os.path.join(DATA_DIR, 'failed_cache.json')
LAST_RUN_INFO_FILE = os.path.join(DATA_DIR, 'last_run_info.txt')

# 定义跳过验证的URL模式或文件扩展名
SKIP_VALIDATION_PATTERNS = [
    re.compile(r'\.mpd($|\?)'), # DASH manifest
    re.compile(r'\.ts($|\?)'),  # MPEG transport stream segments (UDP often)
    re.compile(r'udp://'),     # UDP streams
    re.compile(r'rtp://'),     # RTP streams
    re.compile(r'rtsp://'),    # RTSP streams
    re.compile(r'acestream://') # AceStream
]

# 用于存储已失效URL的缓存
failed_cache = {}

async def fetch_url_content(session, url, retries=MAX_RETRIES, delay=RETRY_DELAY):
    """
    异步获取URL内容，支持重试。
    """
    for attempt in range(retries):
        try:
            async with session.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT) as response:
                response.raise_for_status()
                return await response.text()
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching {url} on attempt {attempt + 1}/{retries}")
        except ClientSession.TooManyRedirects:
            logger.warning(f"Too many redirects for {url} on attempt {attempt + 1}/{retries}")
            break # 太多重定向，不再重试
        except Exception as e:
            logger.warning(f"Error fetching {url} on attempt {attempt + 1}/{retries}: {e}")
        await asyncio.sleep(delay)
    return None

def extract_m3u_channels(m3u_content):
    """
    从M3U内容中提取频道信息。
    """
    channels = []
    lines = m3u_content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('#EXTINF:'):
            match = re.search(r'tvg-name="([^"]*)"', line)
            name = match.group(1).strip() if match else f"Channel {len(channels) + 1}"
            match = re.search(r'group-title="([^"]*)"', line)
            group_title = match.group(1).strip() if match else "Unknown"

            if i + 1 < len(lines):
                url = lines[i+1].strip()
                if url and not url.startswith('#'):
                    channels.append((name, url, group_title))
                i += 1
        i += 1
    return channels

def is_url_in_failed_cache(url, cache):
    """
    检查URL是否在失效缓存中，并且未过期。
    """
    if url in cache:
        fail_time = cache[url]
        # 假设缓存有效期为 24 小时
        if (time.time() - fail_time) < 24 * 3600:
            return True
    return False

def add_to_failed_cache(url, cache):
    """
    将URL添加到失效缓存。
    """
    cache[url] = time.time()

def load_failed_cache():
    """
    加载失效URL缓存。
    """
    if os.path.exists(FAILED_CACHE_FILE):
        try:
            with open(FAILED_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Error loading failed cache: {e}. Starting with empty cache.")
            return {}
    return {}

def save_failed_cache(cache):
    """
    保存失效URL缓存。
    """
    with open(FAILED_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=4)

async def validate_url_with_ffprobe(url):
    """
    使用 ffprobe 异步验证 M3U8 URL。
    如果链接是 .m3u8 结尾，使用 ffprobe 检查流信息。
    """
    if not url.endswith('.m3u8') and not url.endswith('.m3u'):
        # 对于非M3U8/M3U链接，我们可以尝试简单的 HEAD 请求
        try:
            async with ClientSession(connector=TCPConnector(limit=MAX_CONCURRENT_REQUESTS)) as session:
                async with session.head(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT) as response:
                    return 200 <= response.status < 400
        except Exception as e:
            logger.warning(f"HEAD request failed for non-m3u8 URL {url}: {e}")
            return False

    command = [
        'ffprobe',
        '-v', 'error',
        '-select_streams', 'v:0', # 只选择视频流
        '-show_entries', 'stream=codec_name',
        '-of', 'json',
        '-i', url
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=TIMEOUT)

        if process.returncode == 0:
            try:
                ffprobe_output = json.loads(stdout.decode('utf-8'))
                if 'streams' in ffprobe_output and len(ffprobe_output['streams']) > 0:
                    # 找到了视频流，认为有效
                    return True
                else:
                    logger.warning(f"FFprobe found no video streams for {url}")
                    return False
            except json.JSONDecodeError:
                logger.warning(f"FFprobe output is not valid JSON for {url}")
                return False
        else:
            stderr_str = stderr.decode('utf-8').strip()
            logger.warning(f"FFprobe failed for {url} with exit code {process.returncode}: {stderr_str}")
            return False
    except FileNotFoundError:
        logger.error("FFprobe not found. Please ensure FFmpeg is installed and in your PATH.")
        return False
    except asyncio.TimeoutError:
        logger.warning(f"FFprobe command timed out for {url}")
        return False
    except Exception as e:
        logger.warning(f"Error running FFprobe for {url}: {e}")
        return False

async def process_channel_validation(unique_channels, failed_cache_ref, max_workers=MAX_CONCURRENT_REQUESTS):
    """
    并发验证频道URL。
    """
    tasks = []
    # 使用Semaphore控制并发数量
    semaphore = asyncio.Semaphore(max_workers)

    async def _validate_single_channel(channel, failed_cache_ref):
        name, url, group_title = channel
        async with semaphore:
            if is_url_in_failed_cache(url, failed_cache_ref):
                logger.debug(f"Skipping {url} (in failed cache)")
                return (name, url, group_title, False)

            # 检查是否是需要跳过验证的类型
            for pattern in SKIP_VALIDATION_PATTERNS:
                if pattern.search(url):
                    logger.debug(f"Skipping validation for {url} due to pattern match.")
                    return (name, url, group_title, True) # 标记为True，因为我们无法直接验证这些，但它们可能是有效的

            is_valid = await validate_url_with_ffprobe(url)
            if not is_valid:
                add_to_failed_cache(url, failed_cache_ref)
            return (name, url, group_title, is_valid)

    for channel in unique_channels:
        tasks.append(_validate_single_channel(channel, failed_cache_ref))

    return await asyncio.gather(*tasks)

def classify_channel(name, group_title, url):
    """
    根据频道名称和分组标题分类频道。
    可以根据需要扩展分类逻辑。
    """
    name_lower = name.lower()
    group_lower = group_title.lower()

    if "卫视" in name or "卫星" in name or "地方" in group_lower or "省级" in group_lower:
        return "卫视频道"
    elif "央视" in name or "CCTV" in name_lower or "中央" in name:
        return "央视频道"
    elif "国外" in group_lower or "境外" in group_lower or "国际" in group_lower or "foreign" in group_lower:
        return "国外频道"
    elif "体育" in name or "sport" in group_lower or "体育" in group_lower:
        return "体育频道"
    elif "电影" in name or "movie" in group_lower or "影院" in group_lower:
        return "电影频道"
    elif "少儿" in name or "卡通" in name or "儿童" in group_lower:
        return "少儿频道"
    elif "新闻" in name or "news" in group_lower:
        return "新闻频道"
    else:
        return "其他频道"

def write_channels_to_txt(classified_channels, output_file):
    """
    将分类后的频道写入TXT文件，使用指定格式。
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        # 写入更新时间
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        f.write(f"更新时间,#genre#\n")
        f.write(f"{current_time},url\n")
        f.write(f"\n") # 空一行

        # 按照分类写入频道
        sorted_categories = sorted(classified_channels.keys())
        for category in sorted_categories:
            f.write(f"{category},#genre#\n")
            # 内部按名称排序，便于查找
            sorted_channels = sorted(classified_channels[category], key=lambda x: x[0])
            for name, url in sorted_channels:
                # 移除 URL 中的多余参数，例如 &m=... 或 &_t=...，只保留协议、域名、路径和必要查询参数
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                # 过滤掉常见的追踪参数或时间戳参数
                filtered_query_params = {k: v for k, v in query_params.items() if not k.startswith(('_t', 'm', 'timestamp', 'token'))}
                filtered_query = urlencode(filtered_query_params, doseq=True)

                cleaned_url = urlunparse(parsed_url._replace(query=filtered_query))
                f.write(f"{name},{cleaned_url}\n")
        logger.info(f"Successfully wrote channels to {output_file}")


async def main():
    start_time = time.time()
    logger.info("Starting M3U8 URL download and validation script...")

    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created data directory: {DATA_DIR}")

    # 获取urls.txt中的M3U播放列表URL
    github_token = os.getenv('BOT') # 使用 BOT 环境变量作为 GitHub Token
    if not github_token:
        logger.error("GitHub token (BOT) not found. Please set the BOT environment variable.")
        return

    repo_url_raw = os.getenv('REPO_URL') # 使用 REPO_URL 环境变量作为原始仓库URL
    if not repo_url_raw:
        logger.error("Repository URL (REPO_URL) not found. Please set the REPO_URL environment variable.")
        return

    # 从 REPO_URL 中提取 owner, repo, branch, path
    # 示例: https://raw.githubusercontent.com/qjlxg/362/refs/heads/main/config/urls.txt
    parts = repo_url_raw.split('/')
    if len(parts) >= 7 and parts[2] == 'raw.githubusercontent.com':
        repo_owner = parts[3]
        repo_name = parts[4]
        # branch 可能是 'refs/heads/main' 或直接是 'main'
        if parts[5] == 'refs' and parts[6] == 'heads':
            repo_branch = parts[7]
            path_segments = parts[8:]
        else:
            repo_branch = parts[5]
            path_segments = parts[6:]
        config_path = '/'.join(path_segments)
        logger.info(f"Resolved GitHub Repo: {repo_owner}/{repo_name}, Branch: {repo_branch}, Config Path: {config_path}")
    else:
        logger.error(f"Invalid REPO_URL format: {repo_url_raw}")
        return

    urls_txt_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{repo_branch}/{config_path}"
    logger.info(f"Fetching urls.txt from {urls_txt_url}")

    async with ClientSession(connector=TCPConnector(limit=MAX_CONCURRENT_REQUESTS)) as session:
        urls_txt_content = await fetch_url_content(session, urls_txt_url)

    if not urls_txt_content:
        logger.error("Failed to fetch urls.txt. Exiting.")
        return

    urls_to_fetch = [url.strip() for url in urls_txt_content.splitlines() if url.strip() and not url.strip().startswith('#')]
    logger.info(f"Fetched {len(urls_to_fetch)} URLs from urls.txt")

    # 限制处理的播放列表数量
    if len(urls_to_fetch) > MAX_PLAYLISTS_TO_FETCH:
        logger.info(f"Limiting to first {MAX_PLAYLISTS_TO_FETCH} playlists.")
        urls_to_fetch = urls_to_fetch[:MAX_PLAYLISTS_TO_FETCH]

    all_channels = []
    logger.info(f"Starting to fetch and parse {len(urls_to_fetch)} M3U playlists concurrently...")

    playlist_fetch_tasks = []
    async with ClientSession(connector=TCPConnector(limit=MAX_CONCURRENT_REQUESTS)) as session:
        for i, url in enumerate(urls_to_fetch):
            playlist_fetch_tasks.append(
                asyncio.create_task(fetch_url_content(session, url))
            )

        for i, task in enumerate(asyncio.as_completed(playlist_fetch_tasks)):
            playlist_url = urls_to_fetch[playlist_fetch_tasks.index(task)] # 找到对应URL
            try:
                m3u_content = await task
                if m3u_content:
                    channels = extract_m3u_channels(m3u_content)
                    all_channels.extend(channels)
                    logger.info(f"Fetched {len(channels)} channels from {playlist_url}")
                else:
                    logger.warning(f"Failed to fetch content from {playlist_url}")
            except Exception as e:
                logger.error(f"Error processing playlist {playlist_url}: {e}")
            logger.info(f"Finished processing playlist {i+1}/{len(urls_to_fetch)}.")

    # 去重
    unique_channels_set = set()
    unique_channels_list = []
    for name, url, group_title in all_channels:
        channel_id = (name, url, group_title)
        if channel_id not in unique_channels_set:
            unique_channels_set.add(channel_id)
            unique_channels_list.append((name, url, group_title))

    logger.info(f"Found {len(unique_channels_list)} unique channels across all playlists.")

    # 加载失效URL缓存
    global failed_cache
    failed_cache = load_failed_cache()

    # 并发验证所有独特的频道URL
    logger.info(f"Starting concurrent validation of {len(unique_channels_list)} channel URLs...")
    validated_channels_results = await process_channel_validation(unique_channels_list, failed_cache, max_workers=MAX_CONCURRENT_REQUESTS)

    classified_channels = {}
    valid_count = 0
    for name, url, group_title, is_valid in validated_channels_results:
        if is_valid:
            category = classify_channel(name, group_title, url)
            if category not in classified_channels:
                classified_channels[category] = []
            classified_channels[category].append((name, url))
            valid_count += 1
            # logger.debug(f"Valid URL: {name}, {url}, Category: {category}")
        else:
            logger.debug(f"Invalid URL: {name}, {url} (skipped)")

    logger.info(f"Validated {valid_count} unique channels.")

    # 如果没有有效频道，则保留旧文件
    if valid_count == 0:
        logger.warning("No valid channels found. Retaining previous TXT file.")
        end_time = time.time()
        logger.info(f"Script finished in {end_time - start_time:.2f} seconds.")
        return

    # 写入文件
    write_channels_to_txt(classified_channels, VALID_URLS_FILE)

    # 保存失效URL缓存
    save_failed_cache(failed_cache)

    end_time = time.time()
    logger.info(f"Script finished in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    # 检查 FFmpeg/FFprobe 是否安装
    try:
        subprocess.run(['ffprobe', '-h'], check=True, capture_output=True)
        logger.info("FFprobe is installed and accessible.")
    except FileNotFoundError:
        logger.error("FFprobe not found. Please install FFmpeg (which includes ffprobe) and ensure it's in your system's PATH.")
        logger.error("On Ubuntu/Debian: sudo apt update && sudo apt install ffmpeg")
        logger.error("On macOS (Homebrew): brew install ffmpeg")
        logger.error("On Windows: Download from ffmpeg.org and add to PATH.")
        exit(1) # 退出脚本，因为 ffprobe 是核心依赖

    asyncio.run(main())
