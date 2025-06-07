import os
import requests
import logging
from datetime import datetime
import re
from urllib.parse import urlparse, urljoin

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 环境变量
GITHUB_TOKEN = os.getenv('BOT')
REPO_URL = os.getenv('REPO_URL')

# 输出目录和文件
OUTPUT_DIR = 'data'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'valid_urls.m3u')

def ensure_output_dir():
    """确保输出目录存在"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Created output directory: {OUTPUT_DIR}")

def validate_token():
    """验证 GitHub token 是否有效"""
    if not GITHUB_TOKEN:
        logger.error("BOT environment variable is not set. Please set a valid GitHub token with 'repo' scope.")
        return False
    try:
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        response = requests.get('https://api.github.com/user', headers=headers, timeout=5)
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
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        urls = [line.strip() for line in response.text.splitlines() if line.strip()]
        if not urls:
            logger.warning(f"urls.txt is empty at {raw_url}. Check the file content.")
        else:
            logger.info(f"Fetched {len(urls)} URLs from urls.txt")
        return urls
    except requests.RequestException as e:
        logger.error(f"Failed to fetch urls.txt from {raw_url}: {str(e)}")
        logger.error(f"Response headers: {response.headers if 'response' in locals() else 'N/A'}")
        logger.error(f"Debug info: Repository host={parsed_url.netloc}, path={parsed_url.path}")
        logger.error("Please verify: 1) REPO_URL points to a valid raw file (e.g., https://raw.githubusercontent.com/.../urls.txt), 2) BOT token has 'repo' scope, 3) urls.txt exists.")
        return []

def parse_m3u_content(content, playlist_index, base_url=None):
    """解析 M3U 内容，提取频道名称、URL 和 group-title"""
    lines = content.splitlines()
    channels = []
    current_extinf = None
    stream_count = 0
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#EXTM3U'):
            continue
        elif line.startswith('#EXTINF'):
            current_extinf = line
        elif line.startswith('#EXT-X-STREAM-INF'):
            current_stream_inf = line
        elif (line.endswith('.m3u8') or line.endswith('.ve') or line.startswith('http://') or line.startswith('udp://')) and (current_extinf or current_stream_inf):
            try:
                if current_extinf:
                    channel_name = current_extinf.split(',')[-1].strip() if ',' in current_extinf else f"Stream_{playlist_index}_{stream_count}"
                    if not channel_name:
                        channel_name = f"Stream_{playlist_index}_{stream_count}"
                    group_title = re.search(r'group-title="([^"]*)"', current_extinf)
                    group_title = group_title.group(1) if group_title else None
                else:  # #EXT-X-STREAM-INF
                    program_id = re.search(r'PROGRAM-ID=(\d+)', current_stream_inf)
                    channel_name = f"Stream_{playlist_index}_{stream_count}_{program_id.group(1) if program_id else 'Unknown'}"
                    group_title = re.search(r'group-title="([^"]*)"', current_stream_inf)
                    group_title = group_title.group(1) if group_title else None
                
                # 处理相对 URL
                stream_url = urljoin(base_url, line) if base_url and not line.startswith(('http://', 'https://', 'udp://')) else line
                channels.append((channel_name, stream_url, group_title))
                stream_count += 1
            except IndexError:
                logger.warning(f"Invalid format: {current_extinf or current_stream_inf}")
            current_extinf = None
            current_stream_inf = None
        else:
            current_extinf = None
            current_stream_inf = None
    
    return channels

def fetch_m3u_playlist(url, playlist_index):
    """获取并解析 M3U 播放列表，处理变体流"""
    try:
        logger.info(f"Fetching playlist: {url}")
        response = requests.get(url, headers={'Authorization': f'token {GITHUB_TOKEN}'}, timeout=10)
        response.raise_for_status()
        base_url = url.rsplit('/', 1)[0] + '/'  # 用于解析相对 URL
        channels = parse_m3u_content(response.text, playlist_index, base_url)
        logger.info(f"Fetched {len(channels)} channels from {url}")
        
        # 处理变体流（#EXT-X-STREAM-INF 指向的 .m3u8）
        variant_channels = []
        for name, stream_url, group_title in channels:
            if stream_url.endswith('.m3u8'):
                try:
                    logger.info(f"Fetching variant playlist: {stream_url}")
                    variant_response = requests.get(stream_url, timeout=10)
                    variant_response.raise_for_status()
                    variant_channels.extend(parse_m3u_content(variant_response.text, playlist_index, stream_url.rsplit('/', 1)[0] + '/'))
                except requests.RequestException as e:
                    logger.warning(f"Failed to fetch variant playlist {stream_url}: {str(e)}")
        channels.extend(variant_channels)
        
        return channels
    except requests.RequestException as e:
        logger.error(f"Failed to fetch playlist {url}: {str(e)}")
        return []

def validate_m3u8_url(url):
    """验证链接是否可用"""
    if url.startswith('udp://') or 'udp/' in url:
        logger.info(f"Skipping validation for UDP URL: {url}")
        return True
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            return True
        logger.warning(f"Invalid URL (status {response.status_code}): {url}")
        return False
    except requests.RequestException as e:
        logger.warning(f"Failed to validate URL {url}: {str(e)}")
        return False

def classify_channel(channel_name, group_title=None):
    """根据 group-title 或频道名称推断分类"""
    if group_title:
        return group_title
    categories = {
        '综合': ['综合', 'cctv-1', 'cctv-2', 'general'],
        '体育': ['sport', 'espn', 'nba', 'cctv-5'],
        '电影': ['movie', 'cinema', 'film', 'cctv-6'],
        '音乐': ['music', 'mtv', 'cctv-15'],
        '新闻': ['news', 'cnn', 'bbc', 'cctv-13'],
        '少儿': ['kids', 'children', 'cctv-14'],
        '科教': ['science', 'education', 'cctv-10'],
        '戏曲': ['opera', 'cctv-11'],
        '社会与法': ['law', 'cctv-12'],
        '国防军事': ['military', 'cctv-7'],
        '纪录': ['documentary', 'cctv-9'],
        '国外频道': ['persian', 'french', 'international'],
        '流媒体': ['stream', 'kwikmotion'],
        '其他频道': []
    }
    channel_name_lower = channel_name.lower()
    for category, keywords in categories.items():
        if any(keyword in channel_name_lower for keyword in keywords):
            return category
    return '其他频道'

def generate_m3u_file(channels):
    """生成可用直播源的 .m3u 文件，符合指定格式"""
    unique_channels = []
    seen = set()
    for name, url, group_title in channels:
        key = (name.lower(), url)
        if key not in seen:
            seen.add(key)
            unique_channels.append((name, url, group_title))
    
    classified = {}
    for name, url, group_title in unique_channels:
        if validate_m3u8_url(url):
            category = classify_channel(name, group_title)
            if category not in classified:
                classified[category] = []
            classified[category].append((name, url))
            logger.info(f"Valid URL: {name}, {url}, Category: {category}")
        else:
            logger.warning(f"Invalid URL: {name}, {url}")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('更新时间,#genre#\n')
        f.write(f"{datetime.now().strftime('%Y-%m-%d')},http://example.com/1.m3u8\n")
        f.write(f"{datetime.now().strftime('%H:%M:%S')},http://example.com/2.m3u8\n")
        for category in sorted(classified.keys()):
            if classified[category]:
                f.write(f"{category},#genre#\n")
                for name, url in classified[category]:
                    f.write(f"{name},{url}\n")
    
    logger.info(f"Saved {sum(len(channels) for channels in classified.values())} valid URLs to {OUTPUT_FILE}")

def main():
    ensure_output_dir()
    urls = fetch_urls()
    if not urls:
        logger.error("No URLs fetched. Exiting.")
        return
    
    all_channels = []
    for i, url in enumerate(urls):
        channels = fetch_m3u_playlist(url, i)
        all_channels.extend(channels)
    
    if all_channels:
        generate_m3u_file(all_channels)
    else:
        logger.error("No valid channels found. Exiting.")

if __name__ == "__main__":
    main()
