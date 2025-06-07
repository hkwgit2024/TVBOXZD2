import os
import requests
import logging
from datetime import datetime
import re
from urllib.parse import urlparse

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
    
    # 转换为 raw.githubusercontent.com 格式
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
        logger.error("Please verify: 1) REPO_URL points to a valid raw file (e.g., https://raw.githubusercontent.com/.../urls.txt), 2) BOT token has 'repo' scope, 3) urls.txt exists in the repository.")
        return []

def parse_m3u_content(content):
    """解析 M3U 内容，提取频道名称、URL 和 group-title"""
    lines = content.splitlines()
    channels = []
    current_extinf = None
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#EXTM3U'):
            continue
        elif line.startswith('#EXTINF'):
            current_extinf = line
        elif line.endswith('.m3u8') and current_extinf:
            try:
                channel_name = current_extinf.split(',')[-1].strip()
                if not channel_name:
                    channel_name = 'Unknown Channel'
                group_title = re.search(r'group-title="([^"]*)"', current_extinf)
                group_title = group_title.group(1) if group_title else None
                channels.append((channel_name, line, group_title))
            except IndexError:
                logger.warning(f"Invalid #EXTINF format: {current_extinf}")
            current_extinf = None
        else:
            current_extinf = None
    
    return channels

def fetch_m3u_playlist(url):
    """获取并解析 M3U 播放列表"""
    try:
        logger.info(f"Fetching playlist: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        channels = parse_m3u_content(response.text)
        logger.info(f"Fetched {len(channels)} channels from {url}")
        return channels
    except requests.RequestException as e:
        logger.error(f"Failed to fetch playlist {url}: {str(e)}")
        return []

def validate_m3u8_url(url):
    """验证 .m3u8 链接是否可用"""
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
        '新闻': ['news', 'cnn', 'bbc'],
        '体育': ['sport', 'espn', 'nba'],
        '电影': ['movie', 'cinema', 'film'],
        '音乐': ['music', 'mtv'],
        '国外频道': ['persian', 'french', 'kids', 'international'],
        '卫视频道': []
    }
    channel_name_lower = channel_name.lower()
    for category, keywords in categories.items():
        if any(keyword in channel_name_lower for keyword in keywords):
            return category
    return '卫视频道'

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
    for url in urls:
        channels = fetch_m3u_playlist(url)
        all_channels.extend(channels)
    
    if all_channels:
        generate_m3u_file(all_channels)
    else:
        logger.error("No valid channels found. Exiting.")

if __name__ == "__main__":
    main()
