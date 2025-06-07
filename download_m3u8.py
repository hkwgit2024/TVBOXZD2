import os
import requests
import logging
import json
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse, urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import time

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_URL = os.getenv('REPO_URL')

# 输出目录和文件
OUTPUT_DIR = 'data'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'valid_urls.m3u')
SUCCESS_FILE = os.path.join(OUTPUT_DIR, 'successful_urls.json')
FAILED_FILE = os.path.join(OUTPUT_DIR, 'failed_urls.json')
ERROR_LOG = os.path.join(OUTPUT_DIR, 'error_log.txt')

# 非视频流扩展名
NON_STREAM_EXTENSIONS = {'.txt', '.html', '.htm', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.xml', '.json', '.pdf'}

# 缓存过期时间 (秒)
CACHE_EXPIRATION_SECONDS = 24 * 60 * 60 # 24小时

def ensure_output_dir():
    """确保输出目录存在"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Created output directory: {OUTPUT_DIR}")

def load_cache(file_path):
    """加载缓存文件"""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in {file_path}, starting fresh.")
    return {}

def save_cache(data, file_path):
    """保存缓存文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def backup_m3u():
    """备份现有的 M3U 文件"""
    if os.path.exists(OUTPUT_FILE):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(OUTPUT_DIR, f'valid_urls_backup_{timestamp}.m3u')
        shutil.copy(OUTPUT_FILE, backup_path)
        logger.info(f"Backed up {OUTPUT_FILE} to {backup_path}")

def create_session():
    """创建带重试机制的请求会话"""
    session = requests.Session()
    # 增加重试次数
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def validate_token():
    """验证 GitHub token 是否有效"""
    if not GITHUB_TOKEN:
        logger.error("BOT environment variable is not set. Please set a valid GitHub token with 'repo' scope.")
        return False
    try:
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        session = create_session()
        # 增加超时时间
        response = session.get('https://api.github.com/user', headers=headers, timeout=5)
        if response.status_code == 200:
            logger.info(f"GitHub token is valid for user: {response.json().get('login')}")
            return True
        else:
            logger.error(f"Invalid GitHub token (status {response.status_code}): {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"Failed to validate GitHub token: {str(e)}")
        return False

def fetch_urls():
    """从私有仓库获取 urls.txt"""
    if not validate_token():
        logger.error("Cannot proceed without a valid token. Exiting.")
        return []
    if not REPO_URL:
        logger.error("REPO_URL environment variable is not set. Please set the correct URL for urls.txt.")
        return []
        
    parsed_url = urlparse(REPO_URL)
    if parsed_url.netloc == 'github.com':
        path_parts = parsed_url.path.split('/raw/')
        if len(path_parts) != 2:
            logger.error(f"Invalid REPO_URL format: {REPO_URL}. Expected format: https://github.com/owner/repo/raw/branch/path/to/urls.txt")
            return []
        raw_url = f"https://raw.githubusercontent.com{path_parts[0]}/{path_parts[1]}"
    else:
        raw_url = REPO_URL
        
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    try:
        logger.info(f"Fetching urls.txt from {raw_url}")
        session = create_session()
        response = session.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        urls = [line.strip() for line in response.text.splitlines() if line.strip()]
        if not urls:
            logger.warning(f"urls.txt is empty at {raw_url}. Check the file content.")
        else:
            logger.info(f"Fetched {len(urls)} URLs from urls.txt")
        return urls
    except requests.RequestException as e:
        logger.error(f"Failed to fetch urls.txt from {raw_url}: {str(e)}")
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to fetch {raw_url}: {str(e)}\n")
        return []

def check_url_updated(url, cache):
    """检查 URL 是否自上次运行后更新，或是否过期"""
    if url not in cache:
        return True
    
    # 检查缓存是否过期
    timestamp = cache[url].get('timestamp')
    if timestamp and (time.time() - timestamp) > CACHE_EXPIRATION_SECONDS:
        logger.info(f"Cache for {url} expired, re-checking.")
        return True

    try:
        session = create_session()
        headers = {'If-None-Match': cache[url].get('etag', ''), 'If-Modified-Since': cache[url].get('last_modified', '')}
        # 增加超时时间
        response = session.head(url, headers=headers, timeout=5)
        if response.status_code == 304:
            logger.debug(f"URL {url} not modified since last run, skipping.") # 降低日志级别
            # 更新时间戳以延长缓存生命周期
            cache[url]['timestamp'] = time.time()
            return False
        cache[url]['etag'] = response.headers.get('ETag', '')
        cache[url]['last_modified'] = response.headers.get('Last-Modified', '')
        cache[url]['timestamp'] = time.time() # 更新时间戳
        return True
    except requests.RequestException:
        logger.warning(f"Failed to check update status for {url}, assuming updated.")
        return True

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
    max_channels_per_playlist = 1000 # 显著增加或移除此限制，根据实际需求调整
    
    for line in lines:
        if stream_count >= max_channels_per_playlist:
            logger.info(f"Reached max channels ({max_channels_per_playlist}) for playlist {playlist_index + 1}")
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
        elif any(line.lower().endswith(ext) for ext in ['.m3u8', '.ve', '.ts']) or line.startswith(('http://', 'https://', 'udp://')):
            try:
                if any(line.lower().endswith(ext) for ext in NON_STREAM_EXTENSIONS):
                    logger.debug(f"Skipping non-stream URL: {line}") # 降低日志级别
                    continue
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
            except IndexError:
                logger.warning(f"Invalid format: {current_extinf or current_stream_inf}")
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
        else:
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
            
    return channels, m3u_name

def fetch_m3u_playlist(url, playlist_index, success_cache, failed_cache):
    """获取并解析 M3U 播放列表"""
    # 检查失败缓存是否过期，如果过期则尝试重新获取
    if url in failed_cache:
        timestamp = failed_cache[url].get('timestamp')
        if timestamp and (time.time() - timestamp) < CACHE_EXPIRATION_SECONDS / 2: # 失败的可以短一点重试
            logger.debug(f"Skipping known failed URL: {url} (still in cache)") # 降低日志级别
            return []
        else:
            logger.info(f"Failed URL {url} cache expired, re-attempting.")
            del failed_cache[url] # 清除过期失败记录

    if not check_url_updated(url, success_cache):
        # 如果未更新且在成功缓存中，则直接返回空列表（已处理的频道）
        # 实际这里应该返回缓存中的频道列表，但为了简化，我们假设未更新的不会被再次处理
        # 更好的做法是在成功缓存中存储解析后的频道列表，直接返回
        return []
        
    try:
        logger.info(f"Fetching playlist {playlist_index + 1}: {url}")
        session = create_session()
        headers = {'Authorization': f'token {GITHUB_TOKEN}'} if url.startswith(('https://github.com', 'https://raw.githubusercontent.com')) else {}
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        base_url = url.rsplit('/', 1)[0] + '/'
        channels, m3u_name = parse_m3u_content(response.text, playlist_index, base_url, url.split('/')[-1])
        
        key_match = re.search(r'#EXT-X-KEY:METHOD=AES-128,URI="([^"]*)"', response.text)
        if key_match:
            logger.info(f"Found encryption key for playlist {url}: {key_match.group(1)}")
            for i, (name, stream_url, group_title) in enumerate(channels):
                channels[i] = (name + ' [Unverified]', stream_url, group_title)
        
        # 成功获取后更新缓存
        success_cache[url] = {
            'etag': response.headers.get('ETag', ''),
            'last_modified': response.headers.get('Last-Modified', ''),
            'timestamp': time.time()
        }
        # 如果之前在失败缓存中，现在成功了，从失败缓存中移除
        if url in failed_cache:
            del failed_cache[url]
        logger.info(f"Fetched {len(channels)} channels from {url}")
        return channels
    except requests.RequestException as e:
        logger.error(f"Failed to fetch playlist {url}: {str(e)}")
        failed_cache[url] = {'reason': str(e), 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to fetch {url}: {str(e)}\n")
        return []

def validate_m3u8_url(channel_info, failed_cache):
    """验证链接是否可用，返回 (name, url, category, is_valid)"""
    name, url, group_title = channel_info
    
    # 检查失败缓存是否过期
    if url in failed_cache:
        timestamp = failed_cache[url].get('timestamp')
        if timestamp and (time.time() - timestamp) < CACHE_EXPIRATION_SECONDS / 4 : # 对于单个频道URL，失败重试可以更频繁
            logger.debug(f"Skipping known failed channel URL: {url} (still in cache)")
            return (name, url, group_title, False)
        else:
            logger.info(f"Failed channel URL {url} cache expired, re-attempting.")
            del failed_cache[url] # 清除过期失败记录

    if any(url.lower().endswith(ext) for ext in NON_STREAM_EXTENSIONS):
        logger.debug(f"Skipping non-stream URL: {url}")
        failed_cache[url] = {'reason': 'Non-stream extension', 'timestamp': time.time()}
        return (name, url, group_title, False)
    if url.startswith('udp://') or 'udp/' in url.lower() or url.lower().endswith('.ts'):
        logger.info(f"Skipping validation for UDP or .ts URL: {url}")
        return (name, url, group_title, True) # 标记为True，因为不进行HTTP验证
    try:
        session = create_session()
        # 增加超时时间
        response = session.head(url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            return (name, url, group_title, True)
        logger.warning(f"Invalid URL (status {response.status_code}): {url}")
        failed_cache[url] = {'reason': f'Status {response.status_code}', 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Invalid URL (status {response.status_code}): {url}\n")
        return (name, url, group_title, False)
    except requests.RequestException as e:
        logger.warning(f"Failed to validate URL {url}: {str(e)}")
        failed_cache[url] = {'reason': str(e), 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to validate {url}: {str(e)}\n")
        return (name, url, group_title, False)

def classify_channel(channel_name, group_title=None, url=None):
    """智能分类，支持非中文翻译，移除音乐和体育"""
    # 优先使用group_title进行分类
    if group_title:
        group_title_lower = group_title.lower()
        # 排除音乐和体育的翻译
        if any(keyword in group_title_lower for keyword in ['music', 'музыка', 'musique', 'música', 'sport', 'спорт', 'deportes', 'fitness', 'athletic', 'match']):
            return '其他频道'
        
        translations = {
            # 俄文
            'Общие': '综合', 'Новостные': '新闻', 'Фильмы': '电影', 'Детские': '少儿',
            'Документальные': '纪录', 'Образовательные': '科教', 'Развлекательные': '娱乐',
            'Познавательные': '教育',
            # 英文
            'General': '综合', 'News': '新闻', 'Movies': '电影', 'Kids': '少儿',
            'Documentary': '纪录', 'Education': '科教', 'Entertainment': '娱乐',
            'Learning': '教育', 'Series': '电视剧',
            # 法文
            'Général': '综合', 'Actualités': '新闻', 'Films': '电影', 'Enfants': '少儿',
            'Documentaire': '纪录', 'Éducation': '科教', 'Divertissement': '娱乐',
            # 西班牙文
            'General': '综合', 'Noticias': '新闻', 'Películas': '电影', 'Niños': '少儿',
            'Documental': '纪录', 'Educación': '科教', 'Entretenimiento': '娱乐',
            # 其他语言可扩展
            'أخبار': '新闻',   # 阿拉伯文
            '映画': '电影',     # 日文
            '한국': '韩国',     # 韩文
            '中国': '大陆',     # 中文
            '港台': '港台',
            '海外': '国外频道',
            '体育': '体育', # 仅用于翻译，但最终会排除
            '音乐': '音乐', # 仅用于翻译，但最终会排除
        }
        
        translated_group = translations.get(group_title, None)
        if translated_group:
            # 如果翻译后的组名是音乐或体育，仍然归为其他频道
            if translated_group in ['音乐', '体育']:
                return '其他频道'
            return translated_group

    categories = {
        '综合': ['综合', 'cctv-1', 'cctv-2', 'general', 'первый канал', 'россия', 'нтв', 'твц', 'рен тв', 'ucomist', 'hd', '综合', '卫视'],
        '新闻': ['news', 'cnn', 'bbc', 'cctv-13', 'abcnews', 'известия', 'россия 24', 'рбк', 'euronews', 'настоящее время', '新闻'],
        '电影': ['movie', 'cinema', 'film', 'cctv-6', 'cinemax', 'hbo', '电影', '影院'],
        '少儿': ['kids', 'children', 'cctv-14', '3abn kids', 'cartoon', 'disney', '少儿', '动漫'],
        '科教': ['science', 'education', 'cctv-10', 'discovery', 'national geographic', '科教'],
        '戏曲': ['opera', 'cctv-11', 'theater', '戏曲'],
        '社会与法': ['law', 'cctv-12', 'court', 'justice', '社会与法'],
        '国防军事': ['military', 'cctv-7', 'army', 'defense', '国防军事'],
        '纪录': ['documentary', 'cctv-9', 'docu', 'history', '纪录'],
        '国外频道': ['persian', 'french', 'international', 'abtvusa', 'rtvi', 'соловиёвlive', '3abn french', 'al jazeera', '海外', '国际'],
        '地方频道': ['sacramento', 'local', 'cablecast', 'access sacramento', 'city', '地方', '频道'],
        '流媒体': ['stream', 'kwikmotion', '30a-tv', 'uplynk', 'jsrdn', 'darcizzle', 'beachy', 'sidewalks', '网络'],
        '娱乐': ['entertainment', 'развлекательные', 'fun', 'comedy', 'variety', '娱乐'],
        '教育': ['education', 'познавательные', 'learning', 'study', 'course', '教育'],
        '电视剧': ['drama', 'series', '剧场', '电视剧', '剧集'],
        '其他频道': [] # 最后作为兜底
    }
    
    channel_name_lower = channel_name.lower()
    url_lower = url.lower() if url else ''

    # 排除音乐和体育关键字，无论在频道名、URL还是group_title中出现
    if any(keyword in channel_name_lower for keyword in ['music', 'mtv', 'praise_him', '30a music', 'melody', '音乐']) or \
       any(keyword in url_lower for keyword in ['music']) or \
       any(keyword in (group_title.lower() if group_title else '') for keyword in ['music', 'музыка', 'musique', 'música']):
        return '其他频道' # 归类为其他频道，不单独列出音乐类
    
    if any(keyword in channel_name_lower for keyword in ['sport', 'espn', 'nba', 'football', 'tennis', '体育', '竞技', '比赛', '运动']) or \
       any(keyword in url_lower for keyword in ['sport', 'tvb.com/sports', 'm_s.m3u8']) or \
       any(keyword in (group_title.lower() if group_title else '') for keyword in ['sport', 'спорт', 'deportes', 'fitness', 'athletic', 'match']):
        return '其他频道' # 归类为其他频道，不单独列出体育类

    for category, keywords in categories.items():
        if any(keyword in channel_name_lower for keyword in keywords) or \
           any(keyword in url_lower for keyword in keywords):
            return category
    
    # 如果以上都没有匹配到，再尝试根据group_title的原始值进行最后匹配
    if group_title:
        group_title_lower = group_title.lower()
        for category, keywords in categories.items():
            if any(keyword in group_title_lower for keyword in keywords):
                return category

    return '其他频道'


def process_channel_validation(channel_list, failed_cache, max_workers=50):
    """并发验证频道URL"""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(validate_m3u8_url, channel, failed_cache): channel for channel in channel_list}
        for i, future in enumerate(as_completed(futures)):
            name, url, group_title, is_valid = future.result()
            results.append((name, url, group_title, is_valid))
            if (i + 1) % 100 == 0: # 每处理100个URL输出一次进度
                logger.info(f"Processed {i + 1}/{len(channel_list)} channel URLs for validation.")
    return results


def main():
    start_time = time.time()
    ensure_output_dir()
    backup_m3u()
    urls_to_fetch = fetch_urls()
    if not urls_to_fetch:
        logger.error("No URLs fetched. Exiting.")
        return
        
    success_cache = load_cache(SUCCESS_FILE)
    failed_cache = load_cache(FAILED_FILE)
    all_channels_from_playlists = []
    
    # 限制获取的M3U文件数量，用于测试或资源限制
    max_playlists_to_fetch = 3 
    
    # 并发获取M3U播放列表
    logger.info(f"Starting to fetch and parse {min(len(urls_to_fetch), max_playlists_to_fetch)} M3U playlists concurrently...")
    with ThreadPoolExecutor(max_workers=20) as executor: # 可以调整并发获取M3U文件的线程数
        playlist_futures = {executor.submit(fetch_m3u_playlist, url, i, success_cache, failed_cache): (url, i) 
                            for i, url in enumerate(urls_to_fetch[:max_playlists_to_fetch])}
        
        for i, future in enumerate(as_completed(playlist_futures)):
            channels = future.result()
            if channels:
                all_channels_from_playlists.extend(channels)
            logger.info(f"Finished processing playlist {i + 1}/{min(len(urls_to_fetch), max_playlists_to_fetch)}.")

    if not all_channels_from_playlists:
        logger.error("No channels extracted from any playlist. Retaining previous M3U file if exists.")
        return

    unique_channels = []
    seen_channels = set()
    for name, url, group_title in all_channels_from_playlists:
        key = (name.lower(), url)
        if key not in seen_channels:
            seen_channels.add(key)
            unique_channels.append((name, url, group_title))
    
    logger.info(f"Found {len(unique_channels)} unique channels across all playlists.")
    logger.info(f"Starting concurrent validation of {len(unique_channels)} channel URLs...")

    # 并发验证所有独特的频道URL
    validated_channels_results = process_channel_validation(unique_channels, failed_cache, max_workers=50) # 可以调整并发验证URL的线程数

    classified = {}
    valid_count = 0
    for name, url, group_title, is_valid in validated_channels_results:
        if is_valid:
            category = classify_channel(name, group_title, url)
            if category not in classified:
                classified[category] = []
            classified[category].append((name, url))
            valid_count += 1
            # logger.debug(f"Valid URL: {name}, {url}, Category: {category}") # 降低日志级别
        else:
            logger.debug(f"Invalid URL: {name}, {url} (skipped)") # 降低日志级别
            
    if valid_count > 0:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('#EXTM3U\n')
            f.write('更新时间,#genre#\n')
            f.write(f"{datetime.now().strftime('%Y-%m-%d')},http://example.com/1.m3u8\n")
            f.write(f"{datetime.now().strftime('%H:%M:%S')},http://example.com/2.m3u8\n")
            f.write('# Note: [VOD] indicates Video on Demand streams, which may require specific clients (e.g., VLC, Kodi).\n')
            f.write('# Note: [Unverified] indicates streams with potentially inaccessible encryption keys.\n')
            
            # 对分类进行排序，使输出M3U文件更有序
            for category in sorted(classified.keys()):
                if classified[category]:
                    f.write(f"{category},#genre#\n")
                    # 对每个分类下的频道按名称排序
                    for name, url in sorted(classified[category], key=lambda x: x[0]):
                        f.write(f"{name},{url}\n")
            
        logger.info(f"Saved {valid_count} valid URLs to {OUTPUT_FILE}")
        logger.info(f"Categories found: {', '.join(sorted(classified.keys()))}")
    else:
        logger.error("No valid channels found, retaining previous M3U file.")
        
    save_cache(success_cache, SUCCESS_FILE)
    save_cache(failed_cache, FAILED_FILE)
    
    end_time = time.time()
    logger.info(f"Script finished in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
