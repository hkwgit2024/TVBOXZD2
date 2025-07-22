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
INVALID_URLS_PATH = os.getenv('INVALID_URLS_PATH', 'config/invalid_urls.txt')
UNCATEGORIZED_CHANNELS_PATH = 'uncategorized_channels.txt'
IPTV_LIST_PATH = 'iptv_list.txt'

# 加载 URL 列表
def load_urls():
    try:
        with open(URLS_PATH, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"Loaded {len(urls)} URLs from {URLS_PATH}")
        return urls
    except Exception as e:
        logger.error(f"Error loading URLs from {URLS_PATH}: {e}")
        return []

# 加载无效 URL 列表
def load_invalid_urls():
    try:
        if os.path.exists(INVALID_URLS_PATH):
            with open(INVALID_URLS_PATH, 'r', encoding='utf-8') as f:
                invalid_urls = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            logger.info(f"Loaded {len(invalid_urls)} invalid URLs from {INVALID_URLS_PATH}")
            return invalid_urls
        else:
            logger.info(f"No invalid URLs file found at {INVALID_URLS_PATH}")
            return set()
    except Exception as e:
        logger.error(f"Error loading invalid URLs from {INVALID_URLS_PATH}: {e}")
        return set()

# 保存无效 URL
def save_invalid_url(url):
    try:
        with open(INVALID_URLS_PATH, 'a', encoding='utf-8') as f:
            f.write(f"{url}\n")
        logger.info(f"Added invalid URL to {INVALID_URLS_PATH}: {url}")
    except Exception as e:
        logger.error(f"Error saving invalid URL to {INVALID_URLS_PATH}: {e}")

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
        save_invalid_url(url)  # 记录无效 URL
        raise

# 提取频道信息
def extract_channels_from_content(content):
    logger.info("Starting channel extraction from content")
    channels = []
    try:
        # 处理 M3U 格式
        if content.startswith('#EXTM3U'):
            lines = content.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if line.startswith('#EXTINF:'):
                    # 提取频道名称（优先使用 tvg-name，若无则使用逗号后的名称）
                    name = ''
                    tvg_name_match = re.search(r'tvg-name="([^"]*)"', line)
                    if tvg_name_match:
                        name = tvg_name_match.group(1).strip()
                    else:
                        try:
                            name = line.split(',', 1)[1].strip()
                        except IndexError:
                            logger.warning(f"Invalid #EXTINF line, no name found: {line}")
                            i += 1
                            continue
                    
                    # 获取下一行的 URL
                    if i + 1 < len(lines):
                        url = lines[i + 1].strip()
                        # 验证 URL 格式
                        if url and re.match(r'^https?://[\S]+$', url) and '.m3u' in url.lower():
                            channels.append((name, url))
                            logger.debug(f"Extracted channel: {name}, {url}")
                        else:
                            logger.warning(f"Invalid or non-M3U8 URL skipped: {url}")
                    else:
                        logger.warning(f"No URL found for #EXTINF line: {line}")
                    i += 2  # 跳过 #EXTINF 行和 URL 行
                else:
                    i += 1  # 跳过非 #EXTINF 行
        # 处理 JSON 格式
        elif content.startswith('{'):
            data = json.loads(content)
            for item in data.get('channels', []):
                name = item.get('name', '')
                url = item.get('url', '')
                if name and url and re.match(r'^https?://[\S]+$', url) and '.m3u' in url.lower():
                    channels.append((name, url))
                    logger.debug(f"Extracted JSON channel: {name}, {url}")
                else:
                    logger.warning(f"Invalid JSON channel skipped: name={name}, url={url}")
        # 处理纯文本格式（每行：name,url）
        else:
            for line in content.splitlines():
                line = line.strip()
                if ',' in line and not line.startswith('#'):
                    name, url = line.split(',', 1)
                    name, url = name.strip(), url.strip()
                    if name and url and re.match(r'^https?://[\S]+$', url) and '.m3u' in url.lower():
                        channels.append((name, url))
                        logger.debug(f"Extracted text channel: {name}, {url}")
                    else:
                        logger.warning(f"Invalid text channel skipped: {line}")
        
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
    
    # 加载无效 URL 列表
    invalid_urls = load_invalid_urls()
    
    # 提取频道
    raw_channels = []
    for url in urls:
        if url in invalid_urls:
            logger.info(f"Skipping invalid URL: {url}")
            continue
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
