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
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Optional
from fuzzywuzzy import fuzz
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_fixed

# 尝试导入机器学习相关的库，如果失败则禁用ML功能
try:
    from sentence_transformers import SentenceTransformer
    from sklearn.linear_model import LogisticRegression
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: Machine Learning libraries (sentence-transformers, scikit-learn, joblib) not found. ML classification will be disabled.")


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
    MODEL_FILE = Path('classifier_model.pkl') # ML 模型文件
    TRAINING_DATA = Path('training_data.json') # ML 训练数据
    MAX_URLS = 10000 # 最大处理的M3U/M3U8文件数量
    MAX_CHANNELS = 50 # 每个M3U/M3U8文件中最大解析的频道数量
    SEMAPHORE_LIMIT = 10 # 并发请求的限制
    TIMEOUT = aiohttp.ClientTimeout(total=10, connect=3) # 请求超时时间
    USE_ML = os.getenv('USE_ML', 'false').lower() == 'true' # 是否启用ML分类

# --- 自定义异常 ---
class TokenInvalidError(Exception):
    pass

class FetchError(Exception):
    pass

# --- 工具函数：记录错误 ---
def log_error(message: str, error_log: Path = Config.ERROR_LOG):
    logger.error(message)
    with error_log.open('a', encoding='utf-8') as f:
        f.write(f"{datetime.now()}: {message}\n")

# --- 装饰器：捕获并记录异常 ---
def handle_exceptions(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            # 记录错误信息，根据函数类型返回空列表或False
            log_error(f"{func.__name__} failed: {e}")
            return [] if func.__name__.startswith('fetch') else False
    return wrapper

# --- 确保输出目录存在 ---
def ensure_output_dir():
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory ready: {Config.OUTPUT_DIR}")

# --- 创建异步 HTTP 会话 ---
async def create_session():
    return aiohttp.ClientSession(timeout=Config.TIMEOUT)

# --- 验证 GitHub Token ---
@handle_exceptions
async def validate_token(session: aiohttp.ClientSession) -> bool:
    if not Config.GITHUB_TOKEN:
        raise TokenInvalidError("BOT environment variable is not set.")
    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'}
    async with session.get('https://api.github.com/user', headers=headers) as response:
        if response.status == 200:
            user_info = await response.json()
            logger.info(f"GitHub token valid for user: {user_info.get('login')}")
            return True
        raise TokenInvalidError(f"Invalid token (status {response.status}, response: {await response.text()})")

# --- 获取 M3U/M3U8 列表的 URL 源 ---
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@handle_exceptions
async def fetch_urls(session: aiohttp.ClientSession) -> List[str]:
    if not Config.REPO_URL:
        raise FetchError("REPO_URL not set")

    # 处理 GitHub raw content URL 转换
    parsed_url = urlparse(Config.REPO_URL)
    if parsed_url.netloc == 'github.com' and '/blob/' in parsed_url.path:
        # 假设是这样的链接: https://github.com/user/repo/blob/branch/path/to/file
        # 转换为 raw 链接: https://raw.githubusercontent.com/user/repo/branch/path/to/file
        raw_url = parsed_url._replace(netloc='raw.githubusercontent.com').path.replace('/blob/', '/', 1)
        raw_url = f"https://{raw_url}"
    elif parsed_url.netloc == 'github.com' and '/raw/' in parsed_url.path:
        # 如果已经是 raw 链接，直接使用
        raw_url = Config.REPO_URL
    else:
        # 其他非GitHub URL，直接使用
        raw_url = Config.REPO_URL

    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'} if 'github.com' in raw_url else {}
    async with session.get(raw_url, headers=headers) as response:
        response.raise_for_status() # 对非200状态码抛出异常
        content = await response.text()
        
        urls = []
        # 如果是 HTML，尝试解析其中的 M3U/M3U8 链接
        if raw_url.endswith('.html') or response.headers.get('Content-Type', '').startswith('text/html'):
            soup = BeautifulSoup(content, 'html.parser')
            # 查找所有以 .m3u 或 .m3u8 结尾的链接
            urls.extend([a['href'] for a in soup.find_all('a', href=True) if a['href'].endswith(('.m3u', '.m3u8'))])
        else:
            # 否则按行解析，每行一个URL
            urls.extend([line.strip() for line in content.splitlines() if line.strip()])
        
        logger.info(f"Fetched {len(urls)} URLs from {raw_url}")
        return urls

# --- 解析 M3U 内容 ---
def parse_m3u_content(content: str, playlist_index: int, base_url: str = None, playlist_name: str = None) -> Tuple[List[Tuple[str, str, str]], Optional[str]]:
    lines = content.splitlines()
    channels = []
    current_extinf = None
    current_stream_inf = None
    current_extgrp = None
    stream_count = 0
    m3u_name = playlist_name # 默认为传入的播放列表名称
    is_vod = '#EXT-X-PLAYLIST-TYPE:VOD' in content # 判断是否为点播列表

    for line in lines:
        if stream_count >= Config.MAX_CHANNels: # 达到最大频道数量限制
            break
        line = line.strip()
        if not line:
            continue

        if line.startswith('#EXTM3U'):
            name_match = re.search(r'name="([^"]*)"', line)
            m3u_name = name_match.group(1) if name_match else m3u_name
        elif line.startswith('#EXTINF'):
            current_extinf = line
            current_stream_inf = None # 重置
        elif line.startswith('#EXT-X-STREAM-INF'):
            current_stream_inf = line
            current_extinf = None # 重置
        elif line.startswith('#EXTGRP'):
            current_extgrp = line.replace('#EXTGRP:', '').strip()
        elif line.startswith('频道,#genre#'): # 处理自定义格式
            try:
                channel_name, url = line.split(',', 1)
                channel_name = channel_name.replace('频道', '').strip()
                channels.append((channel_name, url, '自定义'))
                stream_count += 1
            except ValueError:
                logger.warning(f"Invalid custom format: {line}")
            continue
        elif re.match(r'^(http|https|udp)://.*\.(m3u8|ve|ts)$|^(http|https|udp)://', line):
            # 匹配有效的流URL
            try:
                channel_name = f"Stream_{playlist_index}_{stream_count}" # 默认频道名
                group_title = current_extgrp # 默认组名

                if current_extinf:
                    name_match = re.search(r',([^,]*)$', current_extinf) # 匹配EXTINF后面的频道名
                    if name_match and name_match.group(1).strip():
                        channel_name = name_match.group(1).strip()
                    
                    group_match = re.search(r'group-title="([^"]*)"', current_extinf)
                    if group_match:
                        group_title = group_match.group(1)
                    
                    if is_vod and '[VOD]' not in channel_name:
                        channel_name += ' [VOD]' # 点播内容标记

                elif current_stream_inf: # EXT-X-STREAM-INF 通常不直接跟频道名，而是后面紧跟URL
                    program_id = re.search(r'PROGRAM-ID=(\d+)', current_stream_inf)
                    channel_name = f"Stream_{playlist_index}_{stream_count}_{program_id.group(1) if program_id else 'Unknown'}"
                    
                    group_match = re.search(r'group-title="([^"]*)"', current_stream_inf)
                    if group_match:
                        group_title = group_match.group(1)
                    elif m3u_name: # 如果没有group-title，使用m3u_name作为组名
                        group_title = m3u_name
                    
                    if is_vod and '[VOD]' not in channel_name:
                        channel_name += ' [VOD]'

                else:
                    # 如果没有EXTINF或EXT-X-STREAM-INF，则跳过此URL，因为它没有相关的元数据
                    continue

                # 拼接绝对URL
                stream_url = urljoin(base_url, line) if base_url and not line.startswith(('http://', 'https://', 'udp://')) else line
                
                channels.append((channel_name, stream_url, group_title))
                stream_count += 1
            except Exception as e:
                logger.warning(f"Failed to parse channel for line: {line}, Error: {e}")
            
            # 清空当前EXTINF/STREAM-INF/EXTGRP，避免影响下一个频道
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
            
    return channels, m3u_name

# --- 获取 M3U 播放列表内容 ---
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@handle_exceptions
async def fetch_m3u_playlist(session: aiohttp.ClientSession, url: str, index: int) -> Tuple[List[Tuple[str, str, str]], Optional[str]]:
    headers = {'Authorization': f'token {Config.GITHUB_TOKEN}'} if 'github.com' in url else {}
    async with session.get(url, headers=headers) as response:
        response.raise_for_status() # 对非200状态码抛出异常
        
        # 尝试从Content-Location头获取base_url，否则使用当前URL的目录
        base_url = response.headers.get('Content-Location', url).rsplit('/', 1)[0] + '/'
        content = await response.text()
        
        # 尝试从URL中提取文件名作为播放列表名称
        playlist_name_from_url = Path(urlparse(url).path).name
        channels, m3u_name = parse_m3u_content(content, index, base_url, playlist_name_from_url)
        
        # 检查是否有加密信息，如果有则标记为未验证
        if re.search(r'#EXT-X-KEY:METHOD=AES-128', content):
            logger.info(f"Found encryption key in {url}. Channels from this playlist will be marked as [Unverified].")
            channels = [(name + ' [Unverified]', url, group) for name, url, group in channels]
        
        logger.info(f"Fetched {len(channels)} channels from playlist: {url}")
        return channels, m3u_name

# --- 验证 M3U8 URL (HEAD请求) ---
@retry(stop=stop_after_attempt(2), wait=wait_fixed(1))
@handle_exceptions
async def validate_m3u8_url(session: aiohttp.ClientSession, url: str) -> bool:
    # 跳过UDP和TS文件验证，因为HEAD请求可能不适用
    if url.startswith('udp://') or url.endswith('.ts'):
        logger.debug(f"Skipping validation for {url}")
        return True
    
    # 替换非法字符，避免upload-artifact报错
    # 这一步不是验证URL本身，而是为了避免在错误日志中记录带有非法字符的文件名
    clean_url = re.sub(r'[<>:"/\\|?*\n\r]', '_', url) 

    try:
        async with session.head(url, allow_redirects=True) as response:
            if response.status == 200:
                logger.debug(f"Valid URL: {url} (Status: {response.status})")
                return True
            log_error(f"Invalid URL (status {response.status}): {clean_url}")
            return False
    except aiohttp.ClientError as e:
        log_error(f"Error validating URL {clean_url}: {e}")
        return False
    except Exception as e:
        log_error(f"Unexpected error during URL validation for {clean_url}: {e}")
        return False


# --- 加载分类规则 (支持 YAML) ---
def load_categories() -> Dict[str, Dict[str, List[str]]]:
    # 默认的分类规则
    default_categories = {
        '综合': {
            'keywords': ['综合', 'cctv-1', 'cctv-2', 'general', 'первый канал', 'россия', 'general', 'main'],
            'regex': [r'cctv-\d+$', r'general.*hd', r'первый канал'],
            'url_patterns': [r'general\.iptv\.com'],
            'filename_hints': ['general', 'cctv', 'zonghe']
        },
        '体育': {
            'keywords': ['sport', 'espn', 'cctv-5', 'nba', 'sports'],
            'regex': [r'cctv-5\+', r'sports?.*\d'],
            'url_patterns': [r'sport\.stream\.tv'],
            'filename_hints': ['sport', 'sports', 'tiyu']
        },
        '电影': {
            'keywords': ['movie', 'cinema', 'cctv-6', 'film', 'movies'],
            'regex': [r'cinema.*hd', r'фильм'],
            'url_patterns': [],
            'filename_hints': ['movie', 'film', 'dianying']
        },
        '新闻': {
            'keywords': ['news', 'cnn', 'bbc', 'cctv-13', 'россия 24'],
            'regex': [r'новости'],
            'url_patterns': [r'news\.live'],
            'filename_hints': ['news', 'xinwen']
        },
        '少儿': {
            'keywords': ['kids', 'children', 'cartoon', 'детские'],
            'regex': [r'детский'],
            'url_patterns': [],
            'filename_hints': ['kids', 'children', 'shaor']
        },
        '音乐': {
            'keywords': ['music', 'музыка'],
            'regex': [r'музыкальный'],
            'url_patterns': [],
            'filename_hints': ['music', 'yinyue']
        },
        '纪录': {
            'keywords': ['documentary', 'документальные'],
            'regex': [r'документальный'],
            'url_patterns': [],
            'filename_hints': ['documentary', 'jilu']
        },
        '其他频道': {
            'keywords': [],
            'regex': [],
            'url_patterns': [],
            'filename_hints': []
        }
    }
    
    if Config.CATEGORIES_FILE.exists():
        try:
            with Config.CATEGORIES_FILE.open('r', encoding='utf-8') as f:
                custom_categories = yaml.safe_load(f)
                if custom_categories:
                    # 合并默认分类和自定义分类，自定义分类会覆盖同名默认分类
                    merged_categories = default_categories.copy()
                    merged_categories.update(custom_categories)
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
    Config.CATEGORY_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with Config.CATEGORY_CACHE.open('w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

# --- 加载 ML 分类器 (可选) ---
def load_ml_classifier():
    if not ML_AVAILABLE:
        logger.warning("ML classifier not available (libraries not installed).")
        return None, None
    if not Config.MODEL_FILE.exists():
        logger.warning(f"ML model file missing: {Config.MODEL_FILE}. ML classification cannot be used.")
        return None, None
    try:
        model = SentenceTransformer('paraphrase-MiniLM-L6-v2') # 这会尝试下载模型（如果本地没有）
        classifier = joblib.load(Config.MODEL_FILE)
        logger.info("Successfully loaded ML model and classifier.")
        return model, classifier
    except Exception as e:
        logger.error(f"Failed to load ML classifier components: {e}")
        return None, None

# --- 分类频道 ---
def classify_channel(channel_name: str, group_title: Optional[str], url: Optional[str], playlist_name: Optional[str] = None) -> str:
    cache = load_category_cache()
    # 创建一个唯一的缓存键，考虑所有相关信息
    cache_key = f"{channel_name}|{group_title or ''}|{url or ''}|{playlist_name or ''}"
    if cache_key in cache:
        return cache[cache_key]

    # ML 分类（如果启用且可用）
    if Config.USE_ML and ML_AVAILABLE:
        model, classifier = load_ml_classifier() # 每次调用都加载模型可能效率不高，但确保了可用性
        if model and classifier:
            text = f"{channel_name} {group_title or ''} {url or ''} {playlist_name or ''}".strip()
            if text: # 避免空字符串导致embedding错误
                try:
                    embedding = model.encode([text], convert_to_tensor=True).cpu().numpy()[0] # 确保是numpy数组
                    category = classifier.predict([embedding])[0]
                    cache[cache_key] = category
                    save_category_cache(cache)
                    logger.debug(f"ML classified '{channel_name}' as '{category}'")
                    return category
                except Exception as e:
                    logger.warning(f"ML classification failed for '{channel_name}': {e}. Falling back to rule-based.")

    # 规则分类
    categories = load_categories()
    # 常见的俄语 group-title 翻译，可根据需要扩展
    translations = {
        'Общие': '综合', 'Новостные': '新闻', 'Спорт': '体育', 'Фильмы': '电影',
        'Музыка': '音乐', 'Детские': '少儿', 'Документальные': '纪录', 'Познавательные': '科教'
    }
    
    name_lower = channel_name.lower()
    url_lower = url.lower() if url else ''
    playlist_lower = playlist_name.lower() if playlist_name else ''
    group_title_translated = translations.get(group_title, group_title) if group_title else None

    # 优先匹配 group-title
    if group_title_translated and group_title_translated in categories:
        result = group_title_translated
        cache[cache_key] = result
        save_category_cache(cache)
        logger.debug(f"Rule-based (group-title) classified '{channel_name}' as '{result}'")
        return result

    # 模糊匹配和正则匹配
    best_match = ('其他频道', 0) # 存储 (分类名称, 匹配分数)

    for category, rules in categories.items():
        if category == '其他频道':
            continue # 其他频道是默认值，不用于匹配

        # 关键词模糊匹配
        for keyword in rules.get('keywords', []):
            kw_lower = keyword.lower()
            score = max(
                fuzz.partial_ratio(kw_lower, name_lower),
                fuzz.partial_ratio(kw_lower, url_lower),
                fuzz.partial_ratio(kw_lower, playlist_lower)
            )
            if score > 80: # 设一个阈值，比如80分以上才算有效匹配
                if score > best_match[1]:
                    best_match = (category, score)
        
        # 正则表达式匹配
        for regex_pattern in rules.get('regex', []):
            try:
                if (re.search(regex_pattern, name_lower) or
                    (url_lower and re.search(regex_pattern, url_lower)) or
                    (playlist_lower and re.search(regex_pattern, playlist_lower))):
                    best_match = (category, 100) # 正则匹配认为是完美匹配
                    break # 找到一个正则匹配就够了
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{regex_pattern}' for category '{category}': {e}")

        # URL 模式匹配
        for pattern in rules.get('url_patterns', []):
            try:
                if url_lower and re.search(pattern, url_lower):
                    best_match = (category, 100)
                    break
            except re.error as e:
                logger.warning(f"Invalid URL pattern '{pattern}' for category '{category}': {e}")
        
        # 文件名提示匹配
        for hint in rules.get('filename_hints', []):
            hint_lower = hint.lower()
            if playlist_lower and hint_lower in playlist_lower:
                if 90 > best_match[1]: # 文件名提示优先级略低于正则和URL模式
                    best_match = (category, 90)
                break


    result = best_match[0]
    cache[cache_key] = result
    save_category_cache(cache)
    logger.debug(f"Rule-based classified '{channel_name}' as '{result}' (Score: {best_match[1]})")
    return result

# --- 主逻辑 ---
async def main():
    start_time = datetime.now()
    ensure_output_dir()
    
    # 确保categories.yaml文件存在，即使是空的
    if not Config.CATEGORIES_FILE.exists():
        logger.info(f"Creating empty {Config.CATEGORIES_FILE} as it does not exist.")
        Config.CATEGORIES_FILE.touch()

    async with await create_session() as session:
        # 验证 GitHub Token
        if not await validate_token(session):
            logger.error("GitHub token validation failed. Exiting.")
            return
        
        # 获取 M3U/M3U8 URL 列表
        urls = await fetch_urls(session)
        if not urls:
            logger.warning("No URLs fetched. Exiting.")
            return

        all_channels = []
        semaphore = asyncio.Semaphore(Config.SEMAPHORE_LIMIT) # 控制并发数
        
        # 异步获取所有播放列表内容
        async def fetch_playlist_with_semaphore(url: str, index: int):
            async with semaphore:
                return await fetch_m3u_playlist(session, url, index)

        tasks = [fetch_playlist_with_semaphore(url, i) for i, url in enumerate(urls[:Config.MAX_URLS])]
        
        # 使用 gather 同时运行所有任务，并处理异常
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error fetching playlist {urls[i]}: {result}")
                log_error(f"Failed to fetch or parse playlist: {urls[i]}")
            elif result:
                channels, m3u_name = result
                all_channels.extend((name, url, group, m3u_name) for name, url, group in channels)
                logger.info(f"Processed {i + 1}/{len(tasks)} playlist sources.")

        if all_channels:
            # 去重：基于频道名称（小写）和 URL
            unique_channels = []
            seen = set()
            for name, url, group, m3u_name in all_channels:
                # 修复这里：name.lower()
                key = (name.lower(), url) 
                if key not in seen:
                    seen.add(key)
                    unique_channels.append((name, url, group, m3u_name))
            
            logger.info(f"Found {len(unique_channels)} unique channels after deduplication.")

            # 验证并分类
            classified_channels: Dict[str, List[Tuple[str, str]]] = {}
            valid_count = 0
            
            async def validate_and_classify_with_semaphore(name: str, url: str, group: str, m3u_name: str):
                async with semaphore:
                    if await validate_m3u8_url(session, url):
                        category = classify_channel(name, group, url, m3u_name)
                        classified_channels.setdefault(category, []).append((name, url))
                        return True
                    return False

            validation_tasks = [validate_and_classify_with_semaphore(name, url, group, m3u_name) for name, url, group, m3u_name in unique_channels]
            validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
            valid_count = sum(1 for r in validation_results if r is True)

            # 保存结果
            with Config.OUTPUT_FILE.open('w', encoding='utf-8') as f:
                for category in sorted(classified_channels.keys()):
                    if classified_channels[category]: # 确保该分类下有频道
                        f.write(f"{category},#genre#\n")
                        # 对同一分类下的频道按名称排序
                        for name, url in sorted(classified_channels[category], key=lambda x: x[0]):
                            f.write(f"{name},{url}\n")

            logger.info(f"Saved {valid_count} valid URLs to {Config.OUTPUT_FILE}")
            logger.info(f"Discovered categories: {', '.join(sorted(classified_channels.keys()))}")
        else:
            logger.info("No channels found to process.")

    total_time = datetime.now() - start_time
    logger.info(f"Script finished. Total time: {total_time}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Script interrupted by user (Ctrl+C).")
    except TokenInvalidError as e:
        logger.critical(f"Critical error: {e}. Please check your BOT token.")
    except Exception as e:
        logger.critical(f"An unhandled error occurred: {e}", exc_info=True)
