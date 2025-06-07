import os
import requests
import logging
import json
from datetime import datetime
import re
from urllib.parse import urlparse, urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor
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
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'valid_urls.txt')
SUCCESS_FILE = os.path.join(OUTPUT_DIR, 'successful_urls.json')
FAILED_FILE = os.path.join(OUTPUT_DIR, 'failed_urls.json')
ERROR_LOG = os.path.join(OUTPUT_DIR, 'error_log.txt')

# 非视频流扩展名
NON_STREAM_EXTENSIONS = {'.txt', '.html', '.htm', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.xml', '.json', '.pdf'}

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

def backup_output():
    """备份现有的输出文件"""
    if os.path.exists(OUTPUT_FILE):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(OUTPUT_DIR, f'valid_urls_backup_{timestamp}.txt')
        shutil.copy(OUTPUT_FILE, backup_path)
        logger.info(f"Backed up {OUTPUT_FILE} to {backup_path}")

def create_session():
    """创建带重试机制的请求会话"""
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
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
        response = session.get('https://api.github.com/user', headers=headers, timeout=1.2)
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
    """检查 URL 是否自上次运行后更新"""
    if url not in cache:
        return True
    try:
        session = create_session()
        headers = {'If-None-Match': cache[url].get('etag', ''), 'If-Modified-Since': cache[url].get('last_modified', '')}
        response = session.head(url, headers=headers, timeout=1.2)
        if response.status_code == 304:
            logger.info(f"URL {url} not modified since last run, skipping.")
            return False
        cache[url]['etag'] = response.headers.get('ETag', '')
        cache[url]['last_modified'] = response.headers.get('Last-Modified', '')
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
    max_channels = 100
    
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
        elif any(line.endswith(ext) for ext in ['.m3u8', '.ve', '.ts']) or line.startswith(('http://', 'https://', 'udp://')):
            try:
                if any(line.endswith(ext) for ext in NON_STREAM_EXTENSIONS):
                    logger.info(f"Skipping non-stream URL: {line}")
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
    if url in failed_cache:
        logger.info(f"Skipping known failed URL: {url}")
        return []
    if not check_url_updated(url, success_cache):
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
        
        success_cache[url] = {
            'etag': response.headers.get('ETag', ''),
            'last_modified': response.headers.get('Last-Modified', ''),
            'timestamp': time.time()
        }
        logger.info(f"Fetched {len(channels)} channels from {url}")
        return channels
    except requests.RequestException as e:
        logger.error(f"Failed to fetch playlist {url}: {str(e)}")
        failed_cache[url] = {'reason': str(e), 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to fetch {url}: {str(e)}\n")
        return []

def validate_m3u8_url(url, failed_cache):
    """验证链接是否可用"""
    if any(url.endswith(ext) for ext in NON_STREAM_EXTENSIONS):
        logger.info(f"Skipping non-stream URL: {url}")
        failed_cache[url] = {'reason': 'Non-stream extension', 'timestamp': time.time()}
        return False
    if url.startswith('udp://') or 'udp/' in url or url.endswith('.ts'):
        logger.info(f"Skipping validation for UDP or .ts URL: {url}")
        return True
    try:
        session = create_session()
        response = session.head(url, timeout=1.2, allow_redirects=True)
        if response.status_code == 200:
            return True
        logger.warning(f"Invalid URL (status {response.status_code}): {url}")
        failed_cache[url] = {'reason': f'Status {response.status_code}', 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Invalid URL (status {response.status_code}): {url}\n")
        return False
    except requests.RequestException as e:
        logger.warning(f"Failed to validate URL {url}: {str(e)}")
        failed_cache[url] = {'reason': str(e), 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to validate {url}: {str(e)}\n")
        return False

def classify_channel(channel_name, group_title=None, url=None):
    """智能分类，支持非中文翻译，移除音乐和体育"""
    if group_title:
        translations = {
            # 俄文
            'Общие': '综合',
            'Новостные': '新闻',
            'Фильмы': '电影',
            'Детские': '少儿',
            'Документальные': '纪录',
            'Образовательные': '科教',
            'Развлекательные': '娱乐',
            'Познавательные': '教育',
            # 英文
            'General': '综合',
            'News': '新闻',
            'Movies': '电影',
            'Kids': '少儿',
            'Documentary': '纪录',
            'Education': '科教',
            'Entertainment': '娱乐',
            'Learning': '教育',
            # 法文
            'Général': '综合',
            'Actualités': '新闻',
            'Films': '电影',
            'Enfants': '少儿',
            'Documentaire': '纪录',
            'Éducation': '科教',
            'Divertissement': '娱乐',
            # 西班牙文
            'General': '综合',
            'Noticias': '新闻',
            'Películas': '电影',
            'Niños': '少儿',
            'Documental': '纪录',
            'Educación': '科教',
            'Entretenimiento': '娱乐',
            # 其他语言
            'أخبار': '新闻',  # 阿拉伯文
            '映画': '电影',    # 日文
        }
        if any(keyword in group_title.lower() for keyword in ['music', 'музыка', 'musique', 'música', 'sport', 'спорт', 'deportes']):
            return '其他频道'
        return translations.get(group_title, '其他频道')
    
    categories = {
        '综合': ['综合', 'cctv-1', 'cctv-2', 'general', 'первый канал', 'россия', 'нтв', 'твц', 'рен тв', 'ucomist', 'hd'],
        '新闻': ['news', 'cnn', 'bbc', 'cctv-13', 'abcnews', 'известия', 'россия 24', 'рбк', 'euronews', 'настоящее время'],
        '电影': ['movie', 'cinema', 'film', 'cctv-6', 'cinemax', 'hbo'],
        '少儿': ['kids', 'children', 'cctv-14', '3abn kids', 'cartoon', 'disney'],
        '科教': ['science', 'education', 'cctv-10', 'discovery', 'national geographic'],
        '戏曲': ['opera', 'cctv-11', 'theater'],
        '社会与法': ['law', 'cctv-12', 'court', 'justice'],
        '国防军事': ['military', 'cctv-7', 'army', 'defense'],
        '纪录': ['documentary', 'cctv-9', 'docu', 'history'],
        '国外频道': ['persian', 'french', 'international', 'abtvusa', 'rtvi', 'соловиёвlive', '3abn french', 'al jazeera'],
        '地方频道': ['sacramento', 'local', 'cablecast', 'access sacramento', 'city'],
        '流媒体': ['stream', 'kwikmotion', '30a-tv', 'uplynk', 'jsrdn', 'darcizzle', 'beachy', 'sidewalks'],
        '娱乐': ['entertainment', 'развлекательные', 'fun', 'comedy', 'variety'],
        '教育': ['education', 'познавательные', 'learning', 'study', 'course'],
        '其他频道': []
    }
    
    channel_name_lower = channel_name.lower()
    url_lower = url.lower() if url else ''
    if any(keyword in channel_name_lower for keyword in ['music', 'mtv', 'praise_him', '30a music', 'melody', 'sport', 'espn', 'nba', 'football', 'tennis']) or \
       any(keyword in url_lower for keyword in ['music', 'sport']):
        return '其他频道'
    
    for category, keywords in categories.items():
        if any(keyword in channel_name_lower for keyword in keywords) or any(keyword in url_lower for keyword in keywords):
            return category
    return '其他频道'

def fetch_playlist_wrapper(args):
    """线程池包装函数"""
    url, index, success_cache, failed_cache = args
    return fetch_m3u_playlist(url, index, success_cache, failed_cache)

def main():
    ensure_output_dir()
    backup_output()
    urls = fetch_urls()
    if not urls:
        logger.error("No URLs fetched. Exiting.")
        return
    
    success_cache = load_cache(SUCCESS_FILE)
    failed_cache = load_cache(FAILED_FILE)
    all_channels = []
    max_urls = 10
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(fetch_playlist_wrapper, [(url, i, success_cache, failed_cache) for i, url in enumerate(urls[:max_urls])])
        for i, channels in enumerate(results):
            all_channels.extend(channels)
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
        for name, url, group_title in unique_channels:
            if validate_m3u8_url(url, failed_cache):
                category = classify_channel(name, group_title, url)
                if category not in classified:
                    classified[category] = []
                classified[category].append((name, url))
                valid_count += 1
                logger.info(f"Valid URL: {name}, {url}, Category: {category}")
            else:
                logger.warning(f"Invalid URL: {name}, {url}")
        
        if valid_count > 0:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
               
                f.write('更新时间,#genre#\n')
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
            logger.error("No valid channels found, retaining previous output file.")
        
        save_cache(success_cache, SUCCESS_FILE)
        save_cache(failed_cache, FAILED_FILE)
    else:
        logger.error("No valid channels found, retaining previous output file.")

if __name__ == "__main__":
    main()
