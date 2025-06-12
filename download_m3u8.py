import os
import asyncio
import aiohttp
import logging
import re
import json
from urllib.parse import urlparse, urljoin
from pathlib import Path
from functools import wraps
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('parser.log')]
)
logger = logging.getLogger(__name__)

# 配置类
class Config:
    GITHUB_TOKEN = os.getenv('BOT')
    REPO_URL = os.getenv('REPO_URL', '')
    OUTPUT_DIR = Path('data')
    OUTPUT_FILE = OUTPUT_DIR / 'valid_urls.txt'
    ERROR_LOG = OUTPUT_DIR / 'error_log.txt'
    MAX_URLS = 10000
    MAX_CHANNELS = 50
    SEMAPHORE_LIMIT = 10
    TIMEOUT = aiohttp.ClientTimeout(total=10, connect=3)
    CATEGORIES_FILE = Path('categories.json')

# 自定义异常
class TokenInvalidError(Exception):
    pass

class FetchError(Exception):
    pass

# 工具函数：记录错误
def log_error(message: str, error_log: Path = Config.ERROR_LOG):
    logger.error(message)
    with error_log.open('a', encoding='utf-8') as f:
        f.write(f"{datetime.now()}: {message}\n")

# 装饰器：捕获并记录异常
def handle_exceptions(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            log_error(f"{func.__name__} failed: {str(e)}")
            return [] if func.__name__.startswith('fetch') else False
    return wrapper

# 确保输出目录
def ensure_output_dir():
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory ready: {Config.OUTPUT_DIR}")

# 创建会话
async def create_session():
    return aiohttp.ClientSession(timeout=Config.TIMEOUT)

# 验证 GitHub token
@handle_exceptions
async def validate_token(session: aiohttp.ClientSession) -> bool:
    if not Config.GITHUB_TOKEN:
        raise TokenInvalidError("BOT environment variable is not set.")
    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'}
    async with session.get('https://api.github.com/user', headers=headers) as response:
        if response.status == 200:
            logger.info(f"GitHub token valid for user: {(await response.json()).get('login')}")
            return True
        raise TokenInvalidError(f"Invalid token (status {response.status})")

# 获取 URLs
@handle_exceptions
async def fetch_urls(session: aiohttp.ClientSession) -> List[str]:
    if not Config.REPO_URL:
        raise FetchError("REPO_URL not set")
    parsed_url = urlparse(Config.REPO_URL)
    if parsed_url.netloc == 'github.com':
        path_parts = parsed_url.path.split('/raw/')
        if len(path_parts) != 2:
            raise FetchError(f"Invalid REPO_URL: {Config.REPO_URL}")
        raw_url = f"https://raw.githubusercontent.com{path_parts[0]}/{path_parts[1]}"
    else:
        raw_url = Config.REPO_URL

    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'}
    async with session.get(raw_url, headers=headers) as response:
        response.raise_for_status()
        urls = [line.strip() for line in (await response.text()).splitlines() if line.strip()]
        logger.info(f"Fetched {len(urls)} URLs")
        return urls

# 解析 M3U 内容
def parse_m3u_content(content: str, playlist_index: int, base_url: str = None, playlist_name: str = None) -> Tuple[List[Tuple[str, str, str]], Optional[str]]:
    lines = content.splitlines()
    channels = []
    current_extinf = None
    current_stream_inf = None
    current_extgrp = None
    stream_count = 0
    m3u_name = None
    is_vod = '#EXT-X-PLAYLIST-TYPE:VOD' in content

    for line in lines:
        if stream_count >= Config.MAX_CHANNELS:
            break
        line = line.strip()
        if not line:
            continue
        if line.startswith('#EXTM3U'):
            name_match = re.search(r'name="([^"]*)"', line)
            m3u_name = name_match.group(1) if name_match else playlist_name
        elif line.startswith('#EXTINF'):
            current_extinf = line
            current_stream_inf = None
        elif line.startswith('#EXT-X-STREAM-INF'):
            current_stream_inf = line
            current_extinf = None
        elif line.startswith('#EXTGRP'):
            current_extgrp = line.replace('#EXTGRP:', '').strip()
        elif line.startswith('频道,#genre#'):
            try:
                channel_name, url = line.split(',', 1)
                channel_name = channel_name.replace('频道', '').strip()
                channels.append((channel_name, url, '自定义'))
                stream_count += 1
            except ValueError:
                logger.warning(f"Invalid custom format: {line}")
            continue
        elif re.match(r'^(http|https|udp)://.*\.(m3u8|ve|ts)$|^(http|https|udp)://', line):
            try:
                if current_extinf:
                    channel_name = current_extinf.split(',')[-1].strip() or f"Stream_{playlist_index}_{stream_count}"
                    if is_vod:
                        channel_name += ' [VOD]'
                    group_title = re.search(r'group-title="([^"]*)"', current_extinf)
                    group_title = group_title.group(1) if group_title else current_extgrp
                elif current_stream_inf:
                    program_id = re.search(r'PROGRAM-ID=(\d+)', current_stream_inf)
                    channel_name = f"Stream_{playlist_index}_{stream_count}_{program_id.group(1) if program_id else 'Unknown'}"
                    if is_vod:
                        channel_name += ' [VOD]'
                    group_title = re.search(r'group-title="([^"]*)"', current_stream_inf)
                    group_title = group_title.group(1) if group_title else current_extgrp or m3u_name
                else:
                    continue

                stream_url = urljoin(base_url, line) if base_url and not line.startswith(('http://', 'https://', 'udp://')) else line
                channels.append((channel_name, stream_url, group_title))
                stream_count += 1
            except Exception as e:
                logger.warning(f"Invalid format: {line}, Error: {str(e)}")
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
    return channels, m3u_name

# 获取 M3U 播放列表
@handle_exceptions
async def fetch_m3u_playlist(session: aiohttp.ClientSession, url: str, index: int) -> List[Tuple[str, str, str]]:
    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'} if 'github.com' in url else {}
    async with session.get(url, headers=headers) as response:
        response.raise_for_status()
        base_url = url.rsplit('/', 1)[0] + '/'
        content = await response.text()
        channels, _ = parse_m3u_content(content, index, base_url, url.split('/')[-1])
        if key_match := re.search(r'#EXT-X-KEY:METHOD=AES-128,URI="([^"]*)"', content):
            logger.info(f"Found encryption key: {key_match.group(1)}")
            channels = [(name + ' [Unverified]', url, group) for name, url, group in channels]
        logger.info(f"Fetched {len(channels)} channels from {url}")
        return channels

# 验证 M3U8 URL
@handle_exceptions
async def validate_m3u8_url(session: aiohttp.ClientSession, url: str) -> bool:
    if url.startswith('udp://') or url.endswith('.ts'):
        logger.debug(f"Skipping validation for {url}")
        return True
    async with session.head(url, allow_redirects=True) as response:
        if response.status == 200:
            return True
        log_error(f"Invalid URL (status {response.status}): {url}")
        return False

# 加载分类规则
def load_categories() -> Dict[str, List[str]]:
    if Config.CATEGORIES_FILE.exists():
        with Config.CATEGORIES_FILE.open('r', encoding='utf-8') as f:
            return json.load(f)
    return {
        '综合': ['综合', 'cctv-1', 'general', 'первый канал'],
        '体育': ['sport', 'espn', 'cctv-5'],
        '电影': ['movie', 'cinema', 'cctv-6'],
        '新闻': ['news', 'cnn', 'cctv-13', 'россия 24'],
        '少儿': ['kids', 'cctv-14'],
        '科教': ['science', 'cctv-10'],
        '其他频道': []
    }

# 分类频道
def classify_channel(channel_name: str, group_title: Optional[str], url: Optional[str]) -> str:
    categories = load_categories()
    translations = {
        'Общие': '综合', 'Новостные': '新闻', 'Спорт': '体育', 'Фильмы': '电影'
    }
    if group_title and (translated := translations.get(group_title, group_title)) in categories:
        return translated
    name_lower = channel_name.lower()
    url_lower = url.lower() if url else ''
    for category, keywords in categories.items():
        if any(keyword in name_lower or keyword in url_lower for keyword in keywords):
            return category
    return '其他频道'

# 主逻辑
async def main():
    start_time = datetime.now()
    ensure_output_dir()
    async with await create_session() as session:
        if not await validate_token(session):
            return
        urls = await fetch_urls(session)
        if not urls:
            return

        all_channels = []
        semaphore = asyncio.Semaphore(Config.SEMAPHORE_LIMIT)
        async def fetch_with_semaphore(url: str, index: int):
            async with semaphore:
                return await fetch_m3u_playlist(session, url, index)

        tasks = [fetch_with_semaphore(url, i) for i, url in enumerate(urls[:Config.MAX_URLS])]
        for i, channels in enumerate(await asyncio.gather(*tasks, return_exceptions=True)):
            if not isinstance(channels, Exception):
                all_channels.extend(channels)
                logger.info(f"Processed {i + 1}/{len(tasks)} URLs")

        if all_channels:
            # 去重
            unique_channels = []
            seen = set()
            for name, url, group in all_channels:
                key = (name.lower(), url)
                if key not in seen:
                    seen.add(key)
                    unique_channels.append((name, url, group))

            # 验证并分类
            classified = {}
            valid_count = 0
            async def validate_with_semaphore(name: str, url: str, group: str):
                async with semaphore:
                    if await validate_m3u8_url(session, url):
                        category = classify_channel(name, group, url)
                        classified.setdefault(category, []).append((name, url))
                        return True
                    return False

            tasks = [validate_with_semaphore(name, url, group) for name, url, group in unique_channels]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            valid_count = sum(1 for r in results if r is True)

            # 保存结果
            with Config.OUTPUT_FILE.open('w', encoding='utf-8') as f:
                for category in sorted(classified.keys()):
                    if classified[category]:
                        f.write(f"{category},#genre#\n")
                        for name, url in classified[category]:
                            f.write(f"{name},{url}\n")

            logger.info(f"Saved {valid_count} valid URLs to {Config.OUTPUT_FILE}")
            logger.info(f"Categories: {', '.join(sorted(classified.keys()))}")
            logger.info(f"Total time: {datetime.now() - start_time}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Script interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
