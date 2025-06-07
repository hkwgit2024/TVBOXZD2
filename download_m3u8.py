import os
import requests
import logging
from datetime import datetime

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

def fetch_urls():
    """从私有仓库获取 urls.txt"""
    if not GITHUB_TOKEN or not REPO_URL:
        logger.error("Missing BOT token or REPO_URL environment variable")
        return []
    
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    try:
        response = requests.get(REPO_URL, headers=headers, timeout=10)
        response.raise_for_status()
        return [line.strip() for line in response.text.splitlines() if line.strip()]
    except requests.RequestException as e:
        logger.error(f"Failed to fetch urls.txt: {e}")
        return []

def parse_m3u_content(content):
    """解析 M3U 内容，提取频道名称和 URL"""
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
                channels.append((channel_name, line))
            except IndexError:
                logger.warning(f"Invalid #EXTINF format: {current_extinf}")
            current_extinf = None
        else:
            current_extinf = None
    
    return channels

def fetch_m3u_playlist(url):
    """获取并解析 M3U 播放列表"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return parse_m3u_content(response.text)
    except requests.RequestException as e:
        logger.error(f"Failed to fetch playlist {url}: {e}")
        return []

def validate_m3u8_url(url):
    """验证 .m3u8 链接是否可用"""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException:
        return False

def classify_channel(channel_name):
    """根据频道名称推断分类"""
    foreign_keywords = ['persian', 'french', 'kids', 'international']
    channel_name_lower = channel_name.lower()
    for keyword in foreign_keywords:
        if keyword in channel_name_lower:
            return '国外频道'
    return '卫视频道'

def generate_m3u_file(channels):
    """生成可用直播源的 .m3u 文件，符合指定格式"""
    # 去重：基于 (频道名称, URL)
    unique_channels = []
    seen = set()
    for name, url in channels:
        key = (name.lower(), url)
        if key not in seen:
            seen.add(key)
            unique_channels.append((name, url))
    
    # 按分类分组
    classified = {'卫视频道': [], '国外频道': []}
    for name, url in unique_channels:
        if validate_m3u8_url(url):
            category = classify_channel(name)
            classified[category].append((name, url))
            logger.info(f"Valid URL: {name}, {url}")
        else:
            logger.warning(f"Invalid URL: {name}, {url}")
    
    # 写入 M3U 文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # 写入更新时间
        f.write('更新时间,#genre#\n')
        f.write(f"{datetime.now().strftime('%Y-%m-%d')},http://example.com/1.m3u8\n")
        f.write(f"{datetime.now().strftime('%H:%M:%S')},http://example.com/2.m3u8\n")
        
        # 写入分类频道
        for category in ['卫视频道', '国外频道']:
            if classified[category]:
                f.write(f"{category},#genre#\n")
                for name, url in classified[category]:
                    f.write(f"{name},{url}\n")
    
    logger.info(f"Saved {sum(len(channels) for channels in classified.values())} valid URLs to {OUTPUT_FILE}")

def main():
    ensure_output_dir()
    urls = fetch_urls()
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
