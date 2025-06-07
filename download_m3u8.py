import re
import os
import time
import logging
import json
import asyncio
import subprocess
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from aiohttp import ClientSession, TCPConnector, ClientTimeout

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
TIMEOUT_SECONDS = 10  # 网络请求和FFprobe的超时时间（秒）
MAX_RETRIES = 3       # 最大重试次数
RETRY_DELAY = 1       # 重试间隔（秒）
MAX_CONCURRENT_REQUESTS = 50 # 并发请求数，用于获取M3U文件和FFprobe验证

DATA_DIR = 'data'
VALID_URLS_FILE = os.path.join(DATA_DIR, 'valid_urls.txt') # 输出文件名为 .txt
FAILED_CACHE_FILE = os.path.join(DATA_DIR, 'failed_cache.json')

# 定义跳过验证的URL模式或文件扩展名
SKIP_VALIDATION_PATTERNS = [
    re.compile(r'\.mpd($|\?)', re.IGNORECASE), # DASH manifest
    re.compile(r'\.ts($|\?)', re.IGNORECASE),  # MPEG transport stream segments (UDP often)
    re.compile(r'udp://', re.IGNORECASE),     # UDP streams
    re.compile(r'rtp://', re.IGNORECASE),     # RTP streams
    re.compile(r'rtsp://', re.IGNORECASE),    # RTSP streams
    re.compile(r'acestream://', re.IGNORECASE) # AceStream
]

# 用于存储已失效URL的缓存
failed_cache = {}

async def fetch_url_content(session, url, retries=MAX_RETRIES, delay=RETRY_DELAY):
    """
    异步获取URL内容，支持重试。
    """
    for attempt in range(retries):
        try:
            async with session.get(url, headers=DEFAULT_HEADERS, timeout=ClientTimeout(total=TIMEOUT_SECONDS)) as response:
                response.raise_for_status() # Raises an error for bad status codes
                return await response.text()
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching {url} on attempt {attempt + 1}/{retries}")
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
            # 提取 tvg-name
            match = re.search(r'tvg-name="([^"]*)"', line)
            name = match.group(1).strip() if match else f"Channel {len(channels) + 1}"

            # 提取 group-title
            match = re.search(r'group-title="([^"]*)"', line)
            group_title = match.group(1).strip() if match else "Unknown"

            if i + 1 < len(lines):
                url = lines[i+1].strip()
                if url and not url.startswith('#'):
                    channels.append((name, url, group_title))
                i += 1 # Consume the URL line
        i += 1
    return channels

def is_url_in_failed_cache(url, cache):
    """
    检查URL是否在失效缓存中，并且未过期。
    缓存有效期为 24 小时。
    """
    if url in cache:
        fail_time = cache[url]
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
    # 清理过期缓存条目
    current_time = time.time()
    cache_to_save = {k: v for k, v in cache.items() if (current_time - v) < 24 * 3600}
    with open(FAILED_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache_to_save, f, ensure_ascii=False, indent=4)

async def validate_url_with_ffprobe(url):
    """
    使用 ffprobe 异步验证 M3U8 URL。
    如果链接是 .m3u8 结尾，使用 ffprobe 检查流信息。
    对于其他类型，执行 HEAD 请求。
    """
    # 检查是否是需要跳过验证的类型
    for pattern in SKIP_VALIDATION_PATTERNS:
        if pattern.search(url):
            logger.debug(f"Skipping FFprobe validation for {url} due to pattern match.")
            return True # 标记为True，因为我们无法直接验证这些，但它们可能是有效的

    # 对于M3U8或M3U文件，使用FFprobe
    if url.endswith('.m3u8') or url.endswith('.m3u'):
        command = [
            'ffprobe',
            '-v', 'error',
            '-select_streams', 'v:0', # 只选择视频流
            '-show_entries', 'stream=codec_name',
            '-of', 'json',
            '-i', url
        ]
        try:
            # 设置 FFprobe 独立超时
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=TIMEOUT_SECONDS)

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
            return False # FFprobe未找到，视为失败
        except asyncio.TimeoutError:
            logger.warning(f"FFprobe command timed out for {url}")
            return False
        except Exception as e:
            logger.warning(f"Error running FFprobe for {url}: {e}")
            return False
    else:
        # 对于其他非M3U8/M3U链接，执行 HEAD 请求
        try:
            async with ClientSession(connector=TCPConnector(limit=MAX_CONCURRENT_REQUESTS)) as session:
                async with session.head(url, headers=DEFAULT_HEADERS, timeout=ClientTimeout(total=TIMEOUT_SECONDS)) as response:
                    is_valid = 200 <= response.status < 400
                    if not is_valid:
                        logger.warning(f"HEAD request for {url} returned status {response.status}")
                    return is_valid
        except Exception as e:
            logger.warning(f"HEAD request failed for non-m3u8 URL {url}: {e}")
            return False

async def process_channel_validation(unique_channels, failed_cache_ref, max_workers=MAX_CONCURRENT_REQUESTS):
    """
    并发验证频道URL。
    """
    tasks = []
    semaphore = asyncio.Semaphore(max_workers)

    async def _validate_single_channel(channel, failed_cache_ref):
        name, url, group_title = channel
        async with semaphore:
            if is_url_in_failed_cache(url, failed_cache_ref):
                logger.debug(f"Skipping {url} (in failed cache)")
                return (name, url, group_title, False)

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
    """
    name_lower = name.lower()
    group_lower = group_title.lower()

    # 更精确的分类规则，考虑多种表述
    if any(k in name_lower for k in ["卫视", "satellite tv", "tvg-name", "卫视高清"]) or \
       any(k in group_lower for k in ["地方卫视", "省级卫视", "中国卫视"]):
        return "卫视频道"
    elif any(k in name_lower for k in ["央视", "cctv", "中央", "中央电视台", "china central television"]) or \
         "央视频道" in group_lower:
        return "央视频道"
    elif any(k in group_lower for k in ["国外", "境外", "国际", "foreign", "international"]) or \
         any(k in name_lower for k in ["cnn", "bbc", "nhk", "dw", "rfi", "voa"]):
        return "国外频道"
    elif any(k in name_lower for k in ["体育", "sport", "nba", "cctv5"]) or \
         "体育" in group_lower:
        return "体育频道"
    elif any(k in name_lower for k in ["电影", "movie", "影院", "cinemax"]) or \
         "电影" in group_lower:
        return "电影频道"
    elif any(k in name_lower for k in ["少儿", "卡通", "儿童", "动画"]) or \
         "少儿" in group_lower:
        return "少儿频道"
    elif any(k in name_lower for k in ["新闻", "news", "资讯"]) or \
         "新闻" in group_lower:
        return "新闻频道"
    elif any(k in name_lower for k in ["记录", "discovery", "documentary"]) or \
         "记录" in group_lower:
        return "记录频道"
    elif any(k in name_lower for k in ["动漫", "cartoon", "anime"]) or \
         "动漫" in group_lower:
        return "动漫频道"
    elif any(k in name_lower for k in ["教育", "education"]) or \
         "教育" in group_lower:
        return "教育频道"
    elif any(k in name_lower for k in ["音乐", "music"]) or \
         "音乐" in group_lower:
        return "音乐频道"
    elif any(k in name_lower for k in ["购物", "shopping"]) or \
         "购物" in group_lower:
        return "购物频道"
    elif any(k in name_lower for k in ["科教", "science"]) or \
         "科教" in group_lower:
        return "科教频道"
    else:
        return "其他频道"


def write_channels_to_txt(classified_channels, output_file):
    """
    将分类后的频道写入TXT文件，使用指定格式。
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        # 写入更新时间
        current_date = time.strftime("%Y-%m-%d", time.localtime())
        current_time_stamp = time.strftime("%H:%M:%S", time.localtime())
        f.write(f"更新时间,#genre#\n")
        f.write(f"{current_date},{current_time_stamp}\n")
        f.write(f"\n") # 空一行

        # 按照分类写入频道
        # 定义一个希望的分类顺序
        preferred_order = ["央视频道", "卫视频道", "新闻频道", "体育频道", "电影频道",
                           "少儿频道", "记录频道", "动漫频道", "音乐频道", "教育频道",
                           "购物频道", "科教频道", "国外频道", "其他频道"]
        
        # 将实际的分类键按照preferred_order排序，未包含的放到最后并按字母排序
        sorted_categories = sorted(classified_channels.keys(), key=lambda x: (preferred_order.index(x) if x in preferred_order else len(preferred_order), x))

        for category in sorted_categories:
            if classified_channels[category]: # 确保该类别下有频道
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
        # 这里不直接退出，而是尝试使用 GITHUB_TOKEN，如果 GITHUB_TOKEN 也不存在，那才退出
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            logger.error("Neither 'BOT' nor 'GITHUB_TOKEN' environment variables are set. Exiting.")
            return

    repo_url_raw = os.getenv('REPO_URL') # 使用 REPO_URL 环境变量作为原始仓库URL
    if not repo_url_raw:
        logger.error("Repository URL (REPO_URL) not found. Please set the REPO_URL environment variable.")
        return

    # 从 REPO_URL 中提取 owner, repo, branch, path
    parts = repo_url_raw.split('/')
    if len(parts) >= 7 and parts[2] == 'raw.githubusercontent.com':
        repo_owner = parts[3]
        repo_name = parts[4]
        if parts[5] == 'refs' and parts[6] == 'heads':
            repo_branch = parts[7]
            config_path_segments = parts[8:]
        else:
            repo_branch = parts[5]
            config_path_segments = parts[6:]
        config_path = '/'.join(config_path_segments)
        logger.info(f"Resolved GitHub Repo: {repo_owner}/{repo_name}, Branch: {repo_branch}, Config Path: {config_path}")
    else:
        logger.error(f"Invalid REPO_URL format: {repo_url_raw}")
        return

    urls_txt_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{repo_branch}/{config_path}"
    logger.info(f"Fetching urls.txt from {urls_txt_url}")

    urls_to_fetch = []
    async with ClientSession(connector=TCPConnector(limit=MAX_CONCURRENT_REQUESTS)) as session:
        urls_txt_content = await fetch_url_content(session, urls_txt_url)
        if urls_txt_content:
            urls_to_fetch = [url.strip() for url in urls_txt_content.splitlines() if url.strip() and not url.strip().startswith('#')]
        else:
            logger.error("Failed to fetch urls.txt. Exiting.")
            return

    logger.info(f"Fetched {len(urls_to_fetch)} URLs from urls.txt")

    all_channels = []
    logger.info(f"Starting to fetch and parse {len(urls_to_fetch)} M3U playlists concurrently...")

    playlist_fetch_tasks = []
    async with ClientSession(connector=TCPConnector(limit=MAX_CONCURRENT_REQUESTS)) as session:
        for url in urls_to_fetch:
            playlist_fetch_tasks.append(asyncio.create_task(fetch_url_content(session, url)))

        # Process results as they complete
        for i, task in enumerate(asyncio.as_completed(playlist_fetch_tasks)):
            try:
                m3u_content = await task
                if m3u_content:
                    channels = extract_m3u_channels(m3u_content)
                    all_channels.extend(channels)
                    # logger.info(f"Fetched {len(channels)} channels from playlist {i+1}.") # Not needed due to async order
                else:
                    # logger.warning(f"Failed to fetch content from one playlist (task {i+1}).") # Not needed due to async order
                    pass # Specific URL logging is already in fetch_url_content
            except Exception as e:
                logger.error(f"Error processing one playlist task: {e}")
            logger.info(f"Processed playlist {i+1}/{len(urls_to_fetch)}.") # This correctly shows progress

    # 去重
    unique_channels_set = set()
    unique_channels_list = []
    for name, url, group_title in all_channels:
        # 使用 url 作为去重的主要依据，因为 name 和 group_title 可能相同但 url 不同
        channel_id = (url, name, group_title) # 将name和group_title也加入，以防URL相同但频道信息不同
        if channel_id not in unique_channels_set:
            unique_channels_set.add(channel_id)
            unique_channels_list.append((name, url, group_title))

    logger.info(f"Found {len(unique_channels_list)} unique channels across all playlists.")

    # 加载失效URL缓存
    global failed_cache
    failed_cache = load_failed_cache()

    # 并发验证所有独特的频道URL
    logger.info(f"Starting concurrent validation of {len(unique_channels_list)} channel URLs...")
    # 确保 max_workers 不超过操作系统允许的最大文件描述符数量
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
            logger.debug(f"Invalid URL or FFprobe failed: {name}, {url}")

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
        logger.error("FFprobe not found. Please ensure FFmpeg is installed and in your system's PATH.")
        logger.error("On Ubuntu/Debian: sudo apt update && sudo apt install ffmpeg")
        logger.error("On macOS (Homebrew): brew install ffmpeg")
        logger.error("On Windows: Download from ffmpeg.org and add to PATH.")
        exit(1) # 退出脚本，因为 ffprobe 是核心依赖

    asyncio.run(main())
