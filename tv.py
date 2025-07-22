import asyncio
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import aiohttp
import aiofiles
import yaml
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential
import requests
import dns.resolver
import psutil
import subprocess
import json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iptv_script.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 路径配置
CONFIG_PATH = os.getenv('CONFIG_PATH', 'config/config.yaml')
URLS_PATH = os.getenv('URLS_PATH', 'config/urls.txt')
URL_STATES_PATH = os.getenv('URL_STATES_PATH', 'config/url_states.yaml')
UNCATEGORIZED_CHANNELS_PATH = 'uncategorized_channels.txt'
IPTV_LIST_PATH = 'iptv_list.txt'

# 读取 URL 列表
def load_urls():
    try:
        with open(URLS_PATH, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"Loaded {len(urls)} URLs from {URLS_PATH}")
        return urls
    except Exception as e:
        logger.error(f"Error loading URLs from {URLS_PATH}: {e}")
        return []

# 异步获取 URL 内容
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def fetch_url_content_with_retry(url, timeout=10):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}) as response:
                response.raise_for_status()
                content = await response.text()
                logger.debug(f"Fetched content from {url}")
                return content
    except Exception as e:
        logger.error(f"Request error fetching URL (after retries): {url} - {e}")
        raise

# 提取频道信息
def extract_channels_from_content(content):
    logger.info("Starting channel extraction from content")
    channels = []
    try:
        # 处理 M3U 格式
        if content.startswith('#EXTM3U'):
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if line.startswith('#EXTINF:'):
                    name = line.split(',', 1)[-1].strip()
                    url = lines[i + 1].strip() if i + 1 < len(lines) else ''
                    if url and re.match(r'https?://', url):
                        channels.append((name, url))
        # 处理 JSON 格式
        elif content.startswith('{'):
            data = json.loads(content)
            for item in data.get('channels', []):
                name = item.get('name', '')
                url = item.get('url', '')
                if name and url and re.match(r'https?://', url):
                    channels.append((name, url))
        # 处理纯文本格式（每行：name,url）
        else:
            for line in content.splitlines():
                if ',' in line:
                    name, url = line.split(',', 1)
                    name, url = name.strip(), url.strip()
                    if name and url and re.match(r'https?://', url):
                        channels.append((name, url))
        logger.info(f"Extracted {len(channels)} channels from content")
    except Exception as e:
        logger.error(f"Error extracting channels: {e}")
    return channels

# 保存频道到文件
def save_channels_to_file(channels, filepath):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            if not channels:
                f.write("# No channels extracted\n")
            else:
                for name, url in channels:
                    f.write(f"{name},{url}\n")
        logger.info(f"Saved {len(channels)} channels to {filepath}")
    except Exception as e:
        logger.error(f"Error saving channels to {filepath}: {e}")

# 验证频道有效性（使用 FFmpeg）
def check_channel_validity(url):
    try:
        cmd = ['ffprobe', '-v', 'error', '-timeout', '6000000', '-i', url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout checking channel: {url}")
        return False
    except Exception as e:
        logger.error(f"Error checking channel {url}: {e}")
        return False

# 异步验证频道
async def validate_channels(channels):
    valid_channels = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(executor, check_channel_validity, url) for _, url in channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (name, url), result in zip(channels, results):
            if isinstance(result, bool) and result:
                valid_channels.append((name, url))
            logger.info(f"Checked channel {name}: {'Valid' if result else 'Invalid'}")
    return valid_channels

# 主函数
async def main():
    logger.info("Starting IPTV channel update script")
    
    # 加载 URL 列表
    urls = load_urls()
    if not urls:
        logger.error("No URLs loaded, exiting")
        return
    
    # 提取频道
    raw_channels = []
    for url in urls:
        try:
            content = await fetch_url_content_with_retry(url)
            if content:
                channels = extract_channels_from_content(content)
                raw_channels.extend(channels)
        except Exception as e:
            logger.error(f"Failed to process URL {url}: {e}")
    
    # 保存未分类频道
    logger.info(f"Extracted {len(raw_channels)} raw channels")
    save_channels_to_file(raw_channels, UNCATEGORIZED_CHANNELS_PATH)
    
    # 加载缓存状态（可选）
    url_states = {}
    try:
        with open(URL_STATES_PATH, 'r', encoding='utf-8') as f:
            url_states = yaml.safe_load(f) or {}
        logger.info(f"Loaded {len(url_states)} URL states from {URL_STATES_PATH}")
    except Exception:
        logger.warning(f"No URL states found at {URL_STATES_PATH}, starting fresh")
    
    # 合并频道（去重）
    unique_channels = list(dict.fromkeys(raw_channels))  # 保留顺序去重
    logger.info(f"Total unique channels to check: {len(unique_channels)}")
    
    # 验证频道有效性
    valid_channels = await validate_channels(unique_channels)
    logger.info(f"Completed channel validity check. Valid channels: {len(valid_channels)}")
    
    # 保存最终 IPTV 列表
    save_channels_to_file(valid_channels, IPTV_LIST_PATH)
    
    # 保存 URL 状态
    try:
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as f:
            yaml.safe_dump({url: {'valid': True} for _, url in valid_channels}, f)
        logger.info(f"Saved URL states to {URL_STATES_PATH}")
    except Exception as e:
        logger.error(f"Error saving URL states: {e}")
    
    # 清理临时文件
    try:
        for folder in ['temp_channels', 'output']:
            if os.path.exists(folder):
                for file in os.listdir(folder):
                    os.remove(os.path.join(folder, file))
        logger.info("Temporary files cleanup completed")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
    
    logger.info("Script finished")

if __name__ == "__main__":
    asyncio.run(main())
