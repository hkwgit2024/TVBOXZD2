import os
import re
import aiohttp
import asyncio
import logging
from urllib.parse import urlparse
from tqdm.asyncio import tqdm_asyncio
import time
import hashlib
import json
import datetime
from typing import Dict, List, Tuple, Set
from concurrent.futures import ThreadPoolExecutor
from aiohttp import ClientSession, TCPConnector

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('output/process.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 配置文件路径
CONFIG = {
    'urls_file': 'config/urls.txt',
    'output_list': 'output/list.txt',
    'failed_urls': 'output/failed_urls.txt',
    'success_urls': 'output/successful_urls.txt',
    'url_hashes': 'output/url_hashes.json',
    'max_concurrent_requests': 50,
    'timeout_seconds': 15,
    'max_retries': 3,
    'retry_delay': 1
}

# 扩展正则表达式支持更多视频格式
VIDEO_URL_REGEX = re.compile(
    r'^(http(s)?://)?([\w-]+\.)+[\w-]+(/[\w./?%&=-]*?)((\.m3u8|\.mp4|\.flv|\.ctv|\.ts|\.mpd|\.webm|\.ogg|\.avi|\.mov|\.wmv|\.mkv|\.rmvb))$',
    re.IGNORECASE
)

GENRE_REGEX = re.compile(r'^(.*?),\#genre\#$')

def read_urls_with_categories(filepath: str) -> Dict[str, List[Tuple[str, str]]]:
    """从文件中读取带有分类的URL列表"""
    categorized_urls = {}
    current_category = "未分类"
    
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    genre_match = GENRE_REGEX.match(line)
                    if genre_match:
                        current_category = genre_match.group(1).strip()
                        categorized_urls.setdefault(current_category, [])
                    else:
                        parts = line.rsplit(',', 1)
                        description = parts[0].strip() if len(parts) == 2 else ""
                        url = parts[1].strip() if len(parts) == 2 else line.strip()
                        
                        if url:
                            categorized_urls.setdefault(current_category, []).append((description, url))
    except Exception as e:
        logger.error(f"读取URL文件 {filepath} 失败: {e}")
    
    return categorized_urls

def read_urls(filepath: str) -> Set[str]:
    """读取纯URL列表"""
    urls = set()
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        urls.add(url)
    except Exception as e:
        logger.error(f"读取文件 {filepath} 失败: {e}")
    return urls

async def write_urls(filepath: str, urls: Set[str]) -> None:
    """异步写入URL列表"""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            for url in sorted(urls):
                f.write(url + '\n')
    except Exception as e:
        logger.error(f"写入文件 {filepath} 失败: {e}")

def read_url_hashes(filepath: str) -> Dict[str, str]:
    """读取URL哈希字典"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"读取哈希文件 {filepath} 失败: {e}")
    return {}

async def write_url_hashes(filepath: str, url_hashes: Dict[str, str]) -> None:
    """异步写入URL哈希字典"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(url_hashes, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"写入哈希文件 {filepath} 失败: {e}")

def calculate_content_hash(content: str) -> str:
    """计算内容的SHA256哈希值"""
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(hashlib.sha256, content.encode('utf-8')).result().hexdigest()

async def fetch_m3u_content(url: str, session: ClientSession, max_retries: int = 3) -> str | None:
    """异步获取M3U内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for attempt in range(max_retries):
        try:
            async with session.get(url, headers=headers, timeout=CONFIG['timeout_seconds']) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientError as e:
            logger.warning(f"获取 {url} 失败 (尝试 {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(CONFIG['retry_delay'])
    return None

def extract_video_links(content: str) -> Set[str]:
    """从内容中提取视频链接"""
    extracted_links = set()
    for line in content.splitlines():
        line = line.strip()
        if VIDEO_URL_REGEX.match(line):
            extracted_links.add(line)
    return extracted_links

def get_domain(url: str) -> str:
    """获取URL域名"""
    return urlparse(url).netloc

async def process_url(
    url_info: Tuple[str, str, str],
    session: ClientSession,
    prev_url_hashes: Dict[str, str],
    final_channels: Dict[str, List[Tuple[str, str]]],
    success_urls: Set[str],
    failed_urls: Set[str],
    updated_hashes: Dict[str, str]
) -> None:
    """处理单个URL"""
    category, description, url = url_info
    
    content = await fetch_m3u_content(url, session)
    
    if content:
        current_hash = calculate_content_hash(content)
        
        if url in prev_url_hashes and prev_url_hashes[url] == current_hash:
            success_urls.add(url)
            updated_hashes[url] = current_hash
            final_channels.setdefault(category, []).append((description, url))
            return
        
        extracted_links = extract_video_links(content)
        
        final_channels.setdefault(category, [])
        final_channels[category].append((description, url))
        
        for link in extracted_links:
            final_channels[category].append(("", link))
            
        success_urls.add(url)
        updated_hashes[url] = current_hash
        
        if VIDEO_URL_REGEX.match(url) and not extracted_links:
            success_urls.add(url)
            updated_hashes[url] = current_hash
    else:
        failed_urls.add(url)
        updated_hashes.pop(url, None)

async def main():
    # 确保输出目录存在
    os.makedirs('output', exist_ok=True)
    os.makedirs('config', exist_ok=True)
    
    # 读取初始URL和历史数据
    initial_urls = read_urls_with_categories(CONFIG['urls_file'])
    failed_urls = read_urls(CONFIG['failed_urls'])
    prev_url_hashes = read_url_hashes(CONFIG['url_hashes'])
    
    all_initial_urls = {url for _, urls in initial_urls.items() for _, url in urls}
    final_channels: Dict[str, List[Tuple[str, str]]] = {}
    current_success_urls: Set[str] = set()
    current_failed_urls: Set[str] = set()
    updated_hashes = prev_url_hashes.copy()
    
    # 准备待处理URL
    urls_to_process = []
    processed_urls = set()
    
    for category, items in initial_urls.items():
        for description, url in items:
            if url not in failed_urls and url not in processed_urls:
                urls_to_process.append((category, description, url))
                processed_urls.add(url)
    
    logger.info(f"开始处理 {len(urls_to_process)} 个URL...")
    start_time = time.time()
    
    # 异步处理URL
    connector = TCPConnector(limit=CONFIG['max_concurrent_requests'])
    async with ClientSession(connector=connector) as session:
        tasks = [
            process_url(
                url_info, session, prev_url_hashes, final_channels,
                current_success_urls, current_failed_urls, updated_hashes
            )
            for url_info in urls_to_process
        ]
        
        for i, _ in enumerate(await tqdm_asyncio.gather(*tasks, desc="处理URL")):
            if (i + 1) % 1000 == 0:
                elapsed = time.time() - start_time
                percentage = ((i + 1) / len(urls_to_process)) * 100
                logger.info(f"进度: {percentage:.2f}% ({i + 1}/{len(urls_to_process)} 个URL)")
    
    # 写入结果
    async with asyncio.Lock():
        # 写入输出列表
        with open(CONFIG['output_list'], 'w', encoding='utf-8') as f:
            f.write(f"更新时间,#genre#\n")
            f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for category in sorted(final_channels.keys()):
                f.write(f"{category},#genre#\n")
                for desc, link in sorted(set(final_channels[category]), key=lambda x: (x[0], x[1])):
                    f.write(f"{desc},{link}\n" if desc else f"{link}\n")
                f.write('\n')
        
        # 更新配置文件
        rebuild_config = {
            cat: [(desc, url) for desc, url in items if url in current_success_urls]
            for cat, items in initial_urls.items()
        }
        
        with open(CONFIG['urls_file'], 'w', encoding='utf-8') as f:
            for category in sorted(rebuild_config.keys()):
                if rebuild_config[category]:
                    f.write(f"{category},#genre#\n")
                    for desc, url in rebuild_config[category]:
                        f.write(f"{desc},{url}\n")
                    f.write('\n')
        
        # 写入成功和失败URL
        await asyncio.gather(
            write_urls(CONFIG['failed_urls'], failed_urls.union(current_failed_urls)),
            write_urls(CONFIG['success_urls'], current_success_urls),
            write_url_hashes(CONFIG['url_hashes'], updated_hashes)
        )
    
    elapsed = time.time() - start_time
    logger.info(f"处理完成！耗时: {elapsed:.2f}秒")
    logger.info(f"结果已保存到 {CONFIG['output_list']}")
    logger.info(f"失败URL已保存到 {CONFIG['failed_urls']}")
    logger.info(f"成功URL已保存到 {CONFIG['success_urls']}")
    logger.info(f"URL哈希已保存到 {CONFIG['url_hashes']}")

if __name__ == "__main__":
    asyncio.run(main())
