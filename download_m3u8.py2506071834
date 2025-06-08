import os
import asyncio
import aiohttp
import logging
from datetime import datetime
import re
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import signal

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_URL = os.getenv('REPO_URL')

# 输出目录和文件
OUTPUT_DIR = 'data'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'valid_urls.m3u')
ERROR_LOG = os.path.join(OUTPUT_DIR, 'error_log.txt')

# 信号处理，防止脚本卡死
def handle_shutdown(loop):
    tasks = [task for task in asyncio.all_tasks(loop) if task is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    loop.stop()
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()

def ensure_output_dir():
    """确保输出目录存在"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logger.info(f"Output directory ready: {OUTPUT_DIR}")

async def create_session():
    """创建带重试机制的异步会话"""
    timeout = aiohttp.ClientTimeout(total=10, connect=3, sock_connect=3)
    return aiohttp.ClientSession(timeout=timeout)

async def validate_token(session):
    """验证 GitHub token 是否有效"""
    if not GITHUB_TOKEN:
        logger.error("BOT environment variable is not set.")
        return False
    try:
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        async with session.get('https://api.github.com/user', headers=headers) as response:
            if response.status == 200:
                logger.info(f"GitHub token is valid for user: {(await response.json()).get('login')}")
                return True
            else:
                logger.error(f"Invalid GitHub token (status {response.status}): {await response.text()}")
                return False
    except Exception as e:
        logger.error(f"Failed to validate GitHub token: {str(e)}")
        return False

async def fetch_urls(session):
    """从私有仓库获取 urls.txt"""
    if not REPO_URL:
        logger.error("REPO_URL environment variable is not set.")
        return []
    parsed_url = urlparse(REPO_URL)
    if parsed_url.netloc == 'github.com':
        path_parts = parsed_url.path.split('/raw/')
        if len(path_parts) != 2:
            logger.error(f"Invalid REPO_URL format: {REPO_URL}")
            return []
        raw_url = f"https://raw.githubusercontent.com{path_parts[0]}/{path_parts[1]}"
    else:
        raw_url = REPO_URL

    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    try:
        logger.info(f"Fetching urls.txt from {raw_url}")
        async with session.get(raw_url, headers=headers) as response:
            response.raise_for_status()
            urls = [line.strip() for line in (await response.text()).splitlines() if line.strip()]
            logger.info(f"Fetched {len(urls)} URLs from urls.txt")
            return urls
    except Exception as e:
        logger.error(f"Failed to fetch urls.txt from {raw_url}: {str(e)}")
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to fetch {raw_url}: {str(e)}\n")
        return []

def parse_m3u_content(content, playlist_index, base_url=None, playlist_name=None):
    """解析 M3U 内容，提取频道名称、URL 和 group-title 或 EXTGRP"""
    lines = content.splitlines()
    channels = []
    current_extinf = None
    current_stream_inf = None
    current_extgrp = None
    stream_count = 0
    m3u_name = None
    is_vod = '#EXT-X-PLAYLIST-TYPE:VOD' in content
    max_channels = 1000

    for line in lines:
        if stream_count >= max_channels:
            logger.info(f"Reached max channels ({max_channels}) for playlist {playlist_index + 1}")
            break
        line = line.strip()
        if not line:
            continue
        if line.startswith('#EXTM3U'):
            name_match = re.search(r'name="([^"]*)"', line)
            m3u_name = name_match.group(1) if name_match else playlist_name
            continue
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
        elif (line.endswith(('.m3u8', '.ve', '.ts')) or line.startswith(('http://', 'https://', 'udp://'))):
            try:
                if current_extinf:
                    channel_name = current_extinf.split(',')[-1].strip() if ',' in current_extinf else f"Stream_{playlist_index}_{stream_count}"
                    if not channel_name:
                        channel_name = f"Stream_{playlist_index}_{stream_count}"
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
                logger.warning(f"Invalid format: {current_extinf or current_stream_inf}, Error: {str(e)}")
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
    return channels, m3u_name

async def fetch_m3u_playlist(session, url, playlist_index):
    """异步获取并解析 M3U 播放列表"""
    try:
        logger.info(f"Fetching playlist {playlist_index + 1}: {url}")
        headers = {'Authorization': f'token {GITHUB_TOKEN}'} if url.startswith(('https://github.com', 'https://raw.githubusercontent.com')) else {}
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()
            base_url = url.rsplit('/', 1)[0] + '/'
            content = await response.text()
            channels, m3u_name = parse_m3u_content(content, playlist_index, base_url, url.split('/')[-1])

            key_match = re.search(r'#EXT-X-KEY:METHOD=AES-128,URI="([^"]*)"', content)
            if key_match:
                logger.info(f"Found encryption key for playlist {url}: {key_match.group(1)}")
                channels = [(name + ' [Unverified]', stream_url, group_title) for name, stream_url, group_title in channels]

            logger.info(f"Fetched {len(channels)} channels from {url}")
            return channels
    except Exception as e:
        logger.error(f"Failed to fetch playlist {url}: {str(e)}")
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to fetch {url}: {str(e)}\n")
        return []

async def validate_m3u8_url(session, url):
    """异步验证链接是否可用"""
    if url.startswith('udp://') or 'udp/' in url or url.endswith('.ts'):
        logger.info(f"Skipping validation for UDP or .ts URL: {url}")
        return True
    try:
        async with session.head(url, allow_redirects=True) as response:
            if response.status == 200:
                return True
            logger.warning(f"Invalid URL (status {response.status}): {url}")
            with open(ERROR_LOG, 'a', encoding='utf-8') as f:
                f.write(f"Invalid URL (status {response.status}): {url}\n")
            return False
    except Exception as e:
        logger.warning(f"Failed to validate URL {url}: {str(e)}")
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to validate {url}: {str(e)}\n")
        return False

def classify_channel(channel_name, group_title=None, url=None):
    """根据 group-title、EXTGRP、频道名称或 URL 推断分类"""
    if group_title:
        translations = {
            'Общие': '综合', 'Новостные': '新闻', 'Спорт': '体育', 'Фильмы': '电影', 'Музыка': '音乐',
            'Детские': '少儿', 'Документальные': '纪录', 'Образовательные': '科教', 'Развлекательные': '娱乐', 'Познавательные': '教育'
        }
        return translations.get(group_title, group_title)
    categories = {
        '综合': ['综合', 'cctv-1', 'cctv-2', 'general', 'первый канал', 'россия', 'нтв', 'твц', 'рен тв', 'ucomist'],
        '体育': ['sport', 'espn', 'nba', 'cctv-5'],
        '电影': ['movie', 'cinema', 'film', 'cctv-6', 'cinemax'],
        '音乐': ['music', 'mtv', 'cctv-15', 'praise_him', '30a music'],
        '新闻': ['news', 'cnn', 'bbc', 'cctv-13', 'abcnews', 'известия', 'россия 24', 'рбк', 'euronews', 'настоящее время'],
        '少儿': ['kids', 'children', 'cctv-14', '3abn kids'],
        '科教': ['science', 'education', 'cctv-10'],
        '戏曲': ['opera', 'cctv-11'],
        '社会与法': ['law', 'cctv-12'],
        '国防军事': ['military', 'cctv-7'],
        '纪录': ['documentary', 'cctv-9'],
        '国外频道': ['persian', 'french', 'international', 'abtvusa', 'rtvi', 'соловиёвlive', '3abn french'],
        '地方频道': ['sacramento', 'local', 'cablecast', 'access sacramento'],
        '流媒体': ['stream', 'kwikmotion', '30a-tv', 'uplynk', 'jsrdn', 'darcizzle', 'beachy', 'sidewalks'],
        '娱乐': ['entertainment', 'развлекательные'],
        '教育': ['education', 'познавательные'],
        '其他频道': []
    }
    channel_name_lower = channel_name.lower()
    url_lower = url.lower() if url else ''
    for category, keywords in categories.items():
        if any(keyword in channel_name_lower for keyword in keywords) or any(keyword in url_lower for keyword in keywords):
            return category
    return '其他频道'

async def main():
    ensure_output_dir()
    async with await create_session() as session:
        if not await validate_token(session):
            logger.error("Cannot proceed without a valid token. Exiting.")
            return

        urls = await fetch_urls(session)
        if not urls:
            logger.error("No URLs fetched. Exiting.")
            return

        all_channels = []
        max_urls = 10000
        semaphore = asyncio.Semaphore(10)  # 限制并发请求

        async def fetch_with_semaphore(url, index):
            async with semaphore:
                return await fetch_m3u_playlist(session, url, index)

        tasks = [fetch_with_semaphore(url, i) for i, url in enumerate(urls[:max_urls])]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error processing URL {urls[i]}: {str(result)}")
            else:
                all_channels.extend(result)
                logger.info(f"Processed {i + 1}/{min(len(urls), max_urls)} URLs")

        if all_channels:
            unique_channels = []
            seen = set()
            for name, url, group_title in all_channels:
                key = (name.lower(), url)
                if key not in seen:
                    seen.add(key)
                    unique_channels.append((name, url, group_title))

            classified = {}
            valid_count = 0
            semaphore = asyncio.Semaphore(5)  # 验证时的并发限制
            async def validate_with_semaphore(name, url, group_title):
                async with semaphore:
                    if await validate_m3u8_url(session, url):
                        category = classify_channel(name, group_title, url)
                        if category not in classified:
                            classified[category] = []
                        classified[category].append((name, url))
                        return True
                    return False

            tasks = [validate_with_semaphore(name, url, group_title) for name, url, group_title in unique_channels]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning(f"Error validating {unique_channels[i][1]}: {str(result)}")
                elif result:
                    valid_count += 1
                    logger.info(f"Valid URL: {unique_channels[i][0]}, {unique_channels[i][1]}")

            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write('#EXTM3U\n')
                f.write('# Note: [VOD] indicates Video on Demand streams, which may require specific clients (e.g., VLC, Kodi).\n')
                f.write('# Note: [Unverified] indicates streams with potentially inaccessible encryption keys.\n')
                for category in sorted(classified.keys()):
                    if classified[category]:
                        f.write(f"{category},#genre#\n")
                        for name, url in classified[category]:
                            f.write(f"{name},{url}\n")

            logger.info(f"Saved {valid_count} valid URLs to {OUTPUT_FILE}")
            logger.info(f"Categories found: {', '.join(sorted(classified.keys()))}")
        else:
            logger.error("No valid channels found. Exiting.")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: handle_shutdown(loop))
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        logger.info("Script interrupted by user")
        handle_shutdown(loop)
    finally:
        loop.close()
