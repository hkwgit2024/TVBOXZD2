import os
import asyncio
import aiohttp
import logging
import re
import json
import yaml
from urllib.parse import urlparse, urljoin
from pathlib import Path
from functools import wraps
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Any

# 确保 tenacity, beautifulsoup4, fuzzywuzzy 及其相关依赖在文件顶部正确导入
from tenacity import retry, stop_after_attempt, wait_fixed
from bs4 import BeautifulSoup
from fuzzywuzzy import fuzz

# --- 配置日志 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('parser.log', encoding='utf-8')]
)
logger = logging.getLogger(__name__)

# --- 配置类 ---
class Config:
    GITHUB_TOKEN = os.getenv('BOT')
    REPO_URL = os.getenv('REPO_URL', '')
    OUTPUT_DIR = Path('data')
    OUTPUT_FILE = OUTPUT_DIR / 'valid_urls.txt'
    ERROR_LOG = OUTPUT_DIR / 'error_log.txt'
    CATEGORIES_FILE = Path('categories.yaml')  # 使用 YAML 文件定义分类规则
    CATEGORY_CACHE = OUTPUT_DIR / 'category_cache.json' # 分类缓存文件
    MAX_URLS = 100000 # 最大处理的M3U/M3U8文件数量
    MAX_CHANNELS = 100000 # 每个M3U/M3U8文件中最大解析的频道数量
    SEMAPHORE_LIMIT = 10 # 并发请求的限制
    TIMEOUT = aiohttp.ClientTimeout(total=10, connect=3) # 请求超时时间

# --- 自定义异常 ---
class TokenInvalidError(Exception):
    pass

class FetchError(Exception):
    pass

# --- 工具函数：记录错误 ---
def log_error(message: str, error_log: Path = Config.ERROR_LOG):
    """记录错误信息到日志文件和控制台。"""
    logger.error(message)
    with error_log.open('a', encoding='utf-8') as f:
        f.write(f"{datetime.now()}: {message}\n")

# --- 装饰器：捕获并记录异常 ---
def handle_exceptions(func):
    """一个装饰器，用于捕获异步函数中的异常并记录。"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            log_error(f"{func.__name__} failed: {e}")
            # 根据函数类型返回空列表或False，以避免后续处理中断
            return [] if func.__name__.startswith('fetch') else False
    return wrapper

# --- 确保输出目录存在 ---
def ensure_output_dir():
    """确保数据输出目录存在。"""
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory ready: {Config.OUTPUT_DIR}")

# --- 清理文件名中的非法字符 ---
def clean_filename(filename: str) -> str:
    """清理文件名中的非法字符，以确保文件可以在不同文件系统上保存。"""
    cleaned_filename = re.sub(r'[<>:"/\\|?*\n\r]', '_', filename)
    cleaned_filename = cleaned_filename.strip(' .')
    cleaned_filename = re.sub(r'__+', '_', cleaned_filename)
    return cleaned_filename

# --- 创建异步 HTTP 会话 ---
async def create_session():
    """创建并返回一个配置好超时的 aiohttp 客户端会话。"""
    return aiohttp.ClientSession(timeout=Config.TIMEOUT)

# --- 验证 GitHub Token ---
@handle_exceptions
async def validate_token(session: aiohttp.ClientSession) -> bool:
    """验证 GitHub Token 的有效性。"""
    if not Config.GITHUB_TOKEN:
        raise TokenInvalidError("BOT environment variable is not set. GitHub token is required for repository access.")
    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'}
    async with session.get('https://api.github.com/user', headers=headers) as response:
        if response.status == 200:
            user_info = await response.json()
            logger.info(f"GitHub token valid for user: {user_info.get('login')}")
            return True
        error_text = await response.text()
        raise TokenInvalidError(f"Invalid token (status {response.status}, response: {error_text})")

# --- 获取 M3U/M3U8 列表的 URL 源 ---
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), reraise=True)
@handle_exceptions
async def fetch_urls(session: aiohttp.ClientSession) -> List[str]:
    """从配置的 REPO_URL 获取 M3U/M3U8 列表的 URL 列表，排除特定域名。"""
    if not Config.REPO_URL:
        raise FetchError("REPO_URL is not set. Cannot fetch source URLs.")

    parsed_url = urlparse(Config.REPO_URL)
    raw_url = Config.REPO_URL

    if parsed_url.netloc == 'github.com':
        if '/blob/' in parsed_url.path:
            raw_url = parsed_url._replace(netloc='raw.githubusercontent.com').path.replace('/blob/', '/', 1)
            raw_url = f"https://{raw_url}"
        elif '/raw/' in parsed_url.path:
            raw_url = parsed_url._replace(netloc='raw.githubusercontent.com').geturl().replace('/raw/', '/', 1)
        else:
            logger.warning(f"REPO_URL looks like GitHub but is not a raw or blob link: {Config.REPO_URL}. Attempting to fetch as is.")
    elif parsed_url.netloc == 'raw.githubusercontent.com':
        pass
    else:
        pass

    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'} if 'github.com' in raw_url or 'raw.githubusercontent.com' in raw_url else {}
    
    try:
        async with session.get(raw_url, headers=headers) as response:
            if response.status == 404:
                logger.error(f"HTTP 404 Not Found for REPO_URL: {raw_url}. Please check if the URL is correct and exists.")
            response.raise_for_status()
            
            content = await response.text()
            urls = []
            content_type = response.headers.get('Content-Type', '')
            if raw_url.endswith('.html') or 'text/html' in content_type:
                if 'BeautifulSoup' not in globals():
                    logger.error("BeautifulSoup is not installed. Cannot parse HTML content for M3U/M3U8 links.")
                    return []
                soup = BeautifulSoup(content, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    if href.endswith(('.m3u', '.m3u8')):
                        full_url = urljoin(raw_url, href)
                        if 'vd3.bdstatic.com' not in full_url:
                            urls.append(full_url)
                        else:
                            logger.debug(f"Excluded URL containing 'vd3.bdstatic.com': {full_url}")
            else:
                urls.extend([line.strip() for line in content.splitlines() if line.strip() and 'vd3.bdstatic.com' not in line.strip()])
            
            logger.info(f"Fetched {len(urls)} URLs from source: {raw_url}")
            return urls
    except aiohttp.ClientResponseError as e:
        if e.status == 404:
            log_error(f"Source REPO_URL returned 404 Not Found: {raw_url}")
        else:
            log_error(f"Error fetching REPO_URL {raw_url}: {e.status} - {e.message}")
        raise
    except aiohttp.ClientError as e:
        log_error(f"Network error fetching REPO_URL {raw_url}: {type(e).__name__} - {e}")
        raise
    except Exception as e:
        log_error(f"Unexpected error fetching REPO_URL {raw_url}: {type(e).__name__} - {e}")
        raise

# --- 解析 M3U 内容 ---
def parse_m3u_content(content: str, playlist_index: int, base_url: str = None, playlist_name: str = None) -> Tuple[List[Tuple[str, str, str]], Optional[str]]:
    """解析 M3U/M3U8 文件的内容，提取频道信息。"""
    lines = content.splitlines()
    channels = []
    current_extinf = None
    current_stream_inf = None
    current_extgrp = None
    stream_count = 0
    m3u_name = playlist_name
    is_vod = '#EXT-X-PLAYLIST-TYPE:VOD' in content

    for line in lines:
        if stream_count >= Config.MAX_CHANNELS:
            logger.info(f"Reached MAX_CHANNELS limit ({Config.MAX_CHANNELS}) for playlist index {playlist_index}. Skipping further channels.")
            break
        line = line.strip()
        if not line:
            continue

        if line.startswith('#EXTM3U'):
            name_match = re.search(r'name="([^"]*)"', line)
            m3u_name = name_match.group(1) if name_match else m3u_name
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
                parts = line.split(',')
                if len(parts) >= 4 and parts[2] == '#genre#':
                    channel_name = parts[1].strip()
                    url = parts[3].strip()
                    group_title = parts[0].replace('频道', '').strip()
                elif len(parts) >= 2:
                    channel_name = parts[0].replace('频道', '').strip()
                    url = parts[1].strip()
                    group_title = '自定义'
                else:
                    raise ValueError("Invalid custom format parts count")

                if channel_name and url:
                    channels.append((channel_name, url, group_title))
                    stream_count += 1
                else:
                    logger.warning(f"Invalid custom format (missing name or URL): {line}")
            except ValueError as e:
                logger.warning(f"Invalid custom format line: '{line}'. Error: {e}")
            continue
        elif re.match(r'^(http|https|udp)://.*\.(m3u8|ve|ts)$|^(http|https|udp)://', line):
            try:
                channel_name = f"Stream_{playlist_index}_{stream_count}"
                group_title = current_extgrp if current_extgrp else m3u_name

                if current_extinf:
                    name_match = re.search(r',([^,]*)$', current_extinf)
                    if name_match and name_match.group(1).strip():
                        channel_name = name_match.group(1).strip()
                    
                    group_match = re.search(r'group-title="([^"]*)"', current_extinf)
                    if group_match:
                        group_title = group_match.group(1)
                    
                    if is_vod and '[VOD]' not in channel_name:
                        channel_name += ' [VOD]'
                elif current_stream_inf:
                    program_id = re.search(r'PROGRAM-ID=(\d+)', current_stream_inf)
                    channel_name = f"Stream_{playlist_index}_{stream_count}_{program_id.group(1) if program_id else 'Unknown'}"
                    
                    group_match = re.search(r'group-title="([^"]*)"', current_stream_inf)
                    if group_match:
                        group_title = group_match.group(1)
                    elif m3u_name:
                        group_title = m3u_name
                    
                    if is_vod and '[VOD]' not in channel_name:
                        channel_name += ' [VOD]'
                else:
                    logger.debug(f"Skipping URL without EXTINF/EXT-X-STREAM-INF: {line}")
                    continue

                stream_url = urljoin(base_url, line) if base_url and not line.startswith(('http://', 'https://', 'udp://')) else line
                
                channels.append((channel_name, stream_url, group_title))
                stream_count += 1
            except Exception as e:
                logger.warning(f"Failed to parse channel for line: '{line}'. Error: {e}")
            
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
            
    return channels, m3u_name

# --- 获取 M3U 播放列表内容 ---
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), reraise=True)
@handle_exceptions
async def fetch_m3u_playlist(session: aiohttp.ClientSession, url: str, index: int) -> Tuple[List[Tuple[str, str, str]], Optional[str]]:
    """获取 M3U/M3U8 播放列表的内容并进行解析。"""
    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'} if 'github.com' in url else {}
    try:
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()
            
            base_url = response.headers.get('Content-Location', url).rsplit('/', 1)[0] + '/'
            content = await response.text()
            
            playlist_name_from_url = Path(urlparse(url).path).name
            
            channels, m3u_name = parse_m3u_content(content, index, base_url, playlist_name_from_url)
            
            if re.search(r'#EXT-X-KEY:METHOD=AES-128', content):
                logger.info(f"Found encryption key in {url}. Channels from this playlist might be DRM protected.")
                channels = [(name + ' [DRM]', url, group) for name, url, group in channels]
            
            logger.info(f"Fetched {len(channels)} channels from playlist: {url}")
            return channels, m3u_name
    except aiohttp.ClientResponseError as e:
        log_error(f"HTTP error fetching playlist {url}: {e.status} - {e.message}")
        raise
    except aiohttp.ClientError as e:
        log_error(f"Network error fetching playlist {url}: {type(e).__name__} - {e}")
        raise
    except Exception as e:
        log_error(f"Unexpected error fetching playlist {url}: {type(e).__name__} - {e}")
        raise

# --- 验证 M3U8 URL (HEAD请求) ---
@retry(stop=stop_after_attempt(2), wait=wait_fixed(1), reraise=True)
@handle_exceptions
async def validate_m3u8_url(session: aiohttp.ClientSession, url: str) -> bool:
    """通过发送 HEAD 请求验证 M3U8 URL 是否可访问。"""
    if url.startswith('udp://') or url.endswith('.ts'):
        logger.debug(f"Skipping network validation for local/stream file: {url}")
        return True
    
    clean_url_for_log = clean_filename(url)

    try:
        async with session.head(url, allow_redirects=True) as response:
            if response.status == 200:
                logger.debug(f"Valid URL: {url} (Status: {response.status})")
                return True
            log_error(f"Invalid URL (status {response.status}): {clean_url_for_log}")
            return False
    except aiohttp.ClientError as e:
        log_error(f"Network error validating URL {clean_url_for_log}: {type(e).__name__} - {e}")
        return False
    except Exception as e:
        log_error(f"Unexpected error during URL validation for {clean_url_for_log}: {type(e).__name__} - {e}")
        return False

# --- 加载分类规则 (支持 YAML) ---
def load_categories() -> Dict[str, Dict[str, List[str]]]:
    """加载分类规则，优先从 categories.yaml 读取，否则使用默认规则，排除体育和音乐分类。"""
    default_categories = {
        '综合': {
            'keywords': ['综合', 'cctv-1', 'cctv-2', 'general', 'первый канал', 'россия', 'general', 'main'],
            'regex': [r'cctv-\d+$', r'general.*hd', r'первый канал'],
            'url_patterns': [r'general\.iptv\.com'],
            'filename_hints': ['general', 'cctv', 'zonghe']
        },
        '电影': {
            'keywords': ['movie', 'cinema', 'cctv-6', 'film', 'movies', 'кино'],
            'regex': [r'cinema.*hd', r'фильм'],
            'url_patterns': [],
            'filename_hints': ['movie', 'film', 'dianying']
        },
        '新闻': {
            'keywords': ['news', 'cnn', 'bbc', 'cctv-13', 'россия 24', 'новости'],
            'regex': [r'новости'],
            'url_patterns': [r'news\.live'],
            'filename_hints': ['news', 'xinwen']
        },
        '少儿': {
            'keywords': ['kids', 'children', 'cartoon', 'детские', 'мульт'],
            'regex': [r'детский'],
            'url_patterns': [],
            'filename_hints': ['kids', 'children', 'shaor']
        },
        '纪录': {
            'keywords': ['documentary', 'документальные', 'наука'],
            'regex': [r'документальный'],
            'url_patterns': [],
            'filename_hints': ['documentary', 'jilu']
        },
        '娱乐': {
            'keywords': ['entertainment', 'развлекательные', 'шоу'],
            'regex': [r'шоу'],
            'url_patterns': [],
            'filename_hints': ['yule']
        },
        '地方': {
            'keywords': ['local', 'региональные', '地方'],
            'regex': [],
            'url_patterns': [],
            'filename_hints': ['difang']
        },
        '其他频道': {
            'keywords': [], 'regex': [], 'url_patterns': [], 'filename_hints': []
        }
    }
    
    if Config.CATEGORIES_FILE.exists():
        try:
            with Config.CATEGORIES_FILE.open('r', encoding='utf-8') as f:
                custom_categories = yaml.safe_load(f)
                if custom_categories:
                    merged_categories = default_categories.copy()
                    for cat, rules in custom_categories.items():
                        if cat not in ['体育', '音乐']:
                            merged_categories.setdefault(cat, {}).update(rules)
                    logger.info(f"Loaded custom categories from {Config.CATEGORIES_FILE}")
                    return merged_categories
                else:
                    logger.warning(f"Empty or invalid YAML in {Config.CATEGORIES_FILE}. Using default categories.")
                    return default_categories
        except yaml.YAMLError as e:
            logger.error(f"Error parsing categories.yaml: {e}. Using default categories.")
            return default_categories
    logger.info("categories.yaml not found. Using default categories.")
    return default_categories

# --- 加载分类缓存 ---
def load_category_cache() -> Dict[str, str]:
    """从文件中加载频道分类缓存。"""
    if Config.CATEGORY_CACHE.exists():
        try:
            with Config.CATEGORY_CACHE.open('r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"Error decoding category cache JSON: {e}. Starting with empty cache.")
            return {}
    return {}

# --- 保存分类缓存 ---
def save_category_cache(cache: Dict[str, str]):
    """将频道分类缓存保存到文件。"""
    Config.CATEGORY_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with Config.CATEGORY_CACHE.open('w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

# --- 分类频道 ---
def classify_channel(channel_name: str, group_title: Optional[str], url: Optional[str], 
                     playlist_name: Optional[str] = None) -> str:
    """根据规则对频道进行分类，排除体育和音乐相关内容。"""
    cache = load_category_cache()
    cache_key = f"{channel_name}|{group_title or ''}|{url or ''}|{playlist_name or ''}"
    if cache_key in cache:
        logger.debug(f"Using cached category for '{channel_name}': {cache[cache_key]}")
        return cache[cache_key]

    categories = load_categories()
    
    translations = {
        'Общие': '综合', 'Новостные': '新闻', 'Фильмы': '电影',
        'Детские': '少儿', 'Документальные': '纪录', 'Познавательные': '科教',
        'Развлекательные': '娱乐', 'Региональные': '地方', 'Разное': '其他'
    }
    
    name_lower = channel_name.lower()
    url_lower = url.lower() if url else ''
    playlist_lower = playlist_name.lower() if playlist_name else ''
    group_title_translated = translations.get(group_title, group_title) if group_title else None

    if group_title_translated and group_title_translated in categories:
        result = group_title_translated
        cache[cache_key] = result
        save_category_cache(cache)
        logger.debug(f"Rule-based (group-title) classified '{channel_name}' as '{result}'")
        return result

    best_match = ('其他频道', 0)

    for category, rules in categories.items():
        if category == '其他频道':
            continue

        if 'fuzz' in globals():
            for keyword in rules.get('keywords', []):
                kw_lower = keyword.lower()
                score = max(
                    fuzz.partial_ratio(kw_lower, name_lower),
                    fuzz.partial_ratio(kw_lower, url_lower),
                    fuzz.partial_ratio(kw_lower, playlist_lower)
                )
                if score > 80:
                    if score > best_match[1]:
                        best_match = (category, score)
        else:
            for keyword in rules.get('keywords', []):
                kw_lower = keyword.lower()
                if kw_lower in name_lower or kw_lower in url_lower or kw_lower in playlist_lower:
                    if 85 > best_match[1]:
                        best_match = (category, 85)
                    break

        for regex_pattern in rules.get('regex', []):
            try:
                if (re.search(regex_pattern, name_lower) or
                    (url_lower and re.search(regex_pattern, url_lower)) or
                    (playlist_lower and re.search(regex_pattern, playlist_lower))):
                    best_match = (category, 100)
                    break
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{regex_pattern}' for category '{category}': {e}")

        for pattern in rules.get('url_patterns', []):
            try:
                if url_lower and re.search(pattern, url_lower):
                    best_match = (category, 100)
                    break
            except re.error as e:
                logger.warning(f"Invalid URL pattern '{pattern}' for category '{category}': {e}")
        
        for hint in rules.get('filename_hints', []):
            hint_lower = hint.lower()
            if playlist_lower and hint_lower in playlist_lower:
                if 90 > best_match[1]:
                    best_match = (category, 90)
                break

    result = best_match[0]
    cache[cache_key] = result
    save_category_cache(cache)
    logger.debug(f"Rule-based classified '{channel_name}' as '{result}' (Score: {best_match[1]})")
    return result

# --- 主逻辑 ---
async def main():
    """脚本的主执行函数。"""
    start_time = datetime.now()
    logger.info("Script started.")
    
    ensure_output_dir()
    
    if not Config.CATEGORIES_FILE.exists():
        logger.info(f"Creating empty {Config.CATEGORIES_FILE} as it does not exist.")
        try:
            Config.CATEGORIES_FILE.touch()
        except OSError as e:
            logger.error(f"Failed to create {Config.CATEGORIES_FILE}: {e}. Please check directory permissions.")
            return

    async with await create_session() as session:
        if not await validate_token(session):
            logger.critical("GitHub token validation failed. Exiting.")
            return
        
        urls = await fetch_urls(session)
        if not urls:
            logger.warning("No URLs fetched from REPO_URL. Exiting.")
            return

        all_channels = []
        semaphore = asyncio.Semaphore(Config.SEMAPHORE_LIMIT)
        
        async def fetch_playlist_with_semaphore(url: str, index: int):
            async with semaphore:
                return await fetch_m3u_playlist(session, url, index)

        tasks = [fetch_playlist_with_semaphore(url, i) for i, url in enumerate(urls[:Config.MAX_URLS])]
        
        logger.info(f"Initiating fetch for {len(tasks)} M3U/M3U8 playlist sources...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error processing playlist from source URL {urls[i]}: {result}")
                log_error(f"Failed to fetch or parse playlist from: {urls[i]}")
            elif result:
                channels, m3u_name = result
                cleaned_channels = []
                for name, url_ch, group in channels:
                    cleaned_name = clean_filename(name)
                    cleaned_group = clean_filename(group) if group else group
                    cleaned_channels.append((cleaned_name, url_ch, cleaned_group))
                all_channels.extend((name, url, group, m3u_name) for name, url, group in cleaned_channels)
                logger.info(f"Processed {i + 1}/{len(tasks)} playlist sources. Added {len(channels)} channels.")

        if all_channels:
            unique_channels = []
            seen = set()
            for name, url, group, m3u_name in all_channels:
                key = (name.lower(), url)
                if key not in seen:
                    seen.add(key)
                    unique_channels.append((name, url, group, m3u_name))
            
            logger.info(f"Found {len(unique_channels)} unique channels after initial parsing and deduplication.")

            classified_channels: Dict[str, List[Tuple[str, str]]] = {}
            valid_count = 0
            
            async def validate_and_classify_with_semaphore(name: str, url: str, group: str, m3u_name: str):
                async with semaphore:
                    if await validate_m3u8_url(session, url):
                        category = classify_channel(name, group, url, m3u_name)
                        classified_channels.setdefault(category, []).append((name, url))
                        return True
                    return False

            logger.info(f"Starting validation and classification for {len(unique_channels)} unique channels...")
            validation_tasks = [validate_and_classify_with_semaphore(name, url, group, m3u_name) for name, url, group, m3u_name in unique_channels]
            validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
            valid_count = sum(1 for r in validation_results if r is True)

            with Config.OUTPUT_FILE.open('w', encoding='utf-8') as f:
                for category in sorted(classified_channels.keys()):
                    if classified_channels[category]:
                        f.write(f"{category},#genre#\n")
                        for name, url in sorted(classified_channels[category], key=lambda x: x[0]):
                            f.write(f"{name},{url}\n")

            logger.info(f"Script finished. Saved {valid_count} valid URLs to {Config.OUTPUT_FILE}")
            logger.info(f"Discovered categories: {', '.join(sorted(classified_channels.keys()))}")
        else:
            logger.info("No valid channels found to process after deduplication.")

    total_time = datetime.now() - start_time
    logger.info(f"Total script execution time: {total_time}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Script interrupted by user (Ctrl+C).")
    except TokenInvalidError as e:
        logger.critical(f"Critical error: {e}. Please check your BOT token or REPO_URL configuration.")
    except Exception as e:
        logger.critical(f"An unhandled critical error occurred: {e}", exc_info=True)
