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

# --- 配置日志 ---
# 确保output目录存在，以便日志文件可以创建
os.makedirs('output', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('output/process.log', encoding='utf-8'),
        logging.StreamHandler() # 也将日志输出到控制台
    ]
)
logger = logging.getLogger(__name__)

# --- 全局配置 ---
CONFIG = {
    'urls_file': 'config/urls.txt',
    'output_list': 'output/list.txt',
    'failed_urls': 'output/failed_urls.txt',
    'success_urls': 'output/successful_urls.txt',
    'url_hashes': 'output/url_hashes.json',
    'max_concurrent_requests': 50, # 最大并发请求数
    'timeout_seconds': 15,         # 请求超时时间
    'max_retries': 3,              # 最大重试次数
    'retry_delay': 2               # 重试间隔时间（秒）
}

# --- 正则表达式定义 ---
# 扩展正则表达式支持更多视频格式
# 增加了 .mkv, .rmvb
VIDEO_URL_REGEX = re.compile(
    r'^(http(s)?://)?([\w-]+\.)+[\w-]+(/[\w./?%&=-]*?)((\.m3u8|\.mp4|\.flv|\.ctv|\.ts|\.mpd|\.webm|\.ogg|\.avi|\.mov|\.wmv|\.mkv|\.rmvb))$',
    re.IGNORECASE
)

# 分类标识正则表达式
GENRE_REGEX = re.compile(r'^(.*?),\#genre\#$')

# --- 线程池用于哈希计算 (非阻塞I/O的关键) ---
# 使用一个全局的线程池，避免每次计算哈希时都创建新的线程池
_executor = ThreadPoolExecutor(max_workers=os.cpu_count() or 4) 

# --- 辅助函数 ---

def read_urls_with_categories(filepath: str) -> Dict[str, List[Tuple[str, str]]]:
    """
    从文件中读取带有分类的URL列表。
    返回一个字典，键是分类名，值是该分类下的 (描述, URL) 元组列表。
    """
    categorized_urls = {}
    current_category = "未分类" # 默认分类

    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): # 忽略空行和注释
                        continue

                    genre_match = GENRE_REGEX.match(line)
                    if genre_match:
                        current_category = genre_match.group(1).strip()
                        categorized_urls.setdefault(current_category, [])
                    else:
                        # 尝试按逗号分割，提取描述和URL
                        parts = line.rsplit(',', 1) 
                        description = parts[0].strip() if len(parts) == 2 else ""
                        url = parts[1].strip() if len(parts) == 2 else line.strip()
                        
                        if url: # 确保提取到的URL不为空
                            categorized_urls.setdefault(current_category, []).append((description, url))
    except Exception as e:
        logger.error(f"读取URL文件 {filepath} 失败: {e}")
    
    return categorized_urls

def read_urls(filepath: str) -> Set[str]:
    """读取纯URL列表 (用于 failed_urls.txt 和 successful_urls.txt)"""
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
    """异步写入URL列表到文件"""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            for url in sorted(urls):
                f.write(url + '\n')
    except Exception as e:
        logger.error(f"写入文件 {filepath} 失败: {e}")

def read_url_hashes(filepath: str) -> Dict[str, str]:
    """从文件中读取URL哈希字典"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning(f"读取哈希文件 {filepath} 失败或文件不存在/损坏，将初始化哈希数据: {e}")
    return {}

async def write_url_hashes(filepath: str, url_hashes: Dict[str, str]) -> None:
    """异步写入URL哈希字典到文件"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(url_hashes, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"写入哈希文件 {filepath} 失败: {e}")

async def calculate_content_hash_async(content: str) -> str:
    """异步计算内容的SHA256哈希值，避免阻塞事件循环"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, lambda: hashlib.sha256(content.encode('utf-8')).hexdigest())

async def fetch_content(url: str, session: aiohttp.ClientSession, max_retries: int) -> str | None:
    """异步获取URL内容，包含重试机制"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for attempt in range(max_retries):
        try:
            async with session.get(url, headers=headers, timeout=CONFIG['timeout_seconds']) as response:
                response.raise_for_status() # 检查HTTP状态码
                return await response.text()
        except aiohttp.ClientError as e:
            logger.warning(f"获取 {url} 失败 (尝试 {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(CONFIG['retry_delay'])
        except asyncio.TimeoutError:
            logger.warning(f"获取 {url} 超时 (尝试 {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                await asyncio.sleep(CONFIG['retry_delay'])
    return None

def extract_video_links(content: str) -> Set[str]:
    """从内容中提取符合视频链接正则表达式的链接"""
    extracted_links = set()
    for line in content.splitlines():
        line = line.strip()
        if VIDEO_URL_REGEX.match(line):
            extracted_links.add(line)
    return extracted_links

async def process_single_url(
    url_info: Tuple[str, str, str],
    session: aiohttp.ClientSession,
    prev_url_hashes: Dict[str, str],
    final_channels: Dict[str, List[Tuple[str, str]]],
    current_success_urls: Set[str],
    current_failed_urls: Set[str],
    updated_hashes: Dict[str, str]
) -> None:
    """处理单个URL的异步任务"""
    category, description, url = url_info
    
    content = await fetch_content(url, session, CONFIG['max_retries'])
    
    if content:
        current_hash = await calculate_content_hash_async(content)
        
        # 检查内容是否更新
        if url in prev_url_hashes and prev_url_hashes[url] == current_hash:
            current_success_urls.add(url)
            updated_hashes[url] = current_hash # 更新哈希（即使未变，也确保在最终哈希文件中存在）
            # 如果内容未更新，直接将原始的描述和URL添加到最终列表
            final_channels.setdefault(category, []).append((description, url))
            return # 跳过当前URL的后续处理，因为内容未变
        
        # 内容已更新或首次获取
        extracted_links = extract_video_links(content)
        
        # 将原始URL本身添加为有效节目源 (即使它是M3U播放列表，也先将M3U链接本身作为一个条目)
        final_channels.setdefault(category, []).append((description, url))
        current_success_urls.add(url)
        updated_hashes[url] = current_hash # 更新或添加新哈希
        
        # 添加从内容中提取出的所有子链接，描述为空
        for link in extracted_links:
            # 避免重复添加原始URL如果它被自身内容提取出来
            if link != url:
                final_channels[category].append(("", link))
    else: # 内容获取失败
        current_failed_urls.add(url)
        # 如果URL previously was successful, but now failed, remove its hash
        updated_hashes.pop(url, None) 

# --- 主函数 ---
async def main():
    # 确保必要的目录存在
    os.makedirs('output', exist_ok=True)
    os.makedirs('config', exist_ok=True)

    logger.info("程序开始运行...")
    
    # 读取初始URL和历史数据
    initial_categorized_urls = read_urls_with_categories(CONFIG['urls_file'])
    failed_urls_history = read_urls(CONFIG['failed_urls'])
    prev_url_hashes = read_url_hashes(CONFIG['url_hashes'])
    
    # 用于存储本次运行的结果和状态
    final_categorized_channels: Dict[str, List[Tuple[str, str]]] = {} # 最终要输出的分类节目源
    current_success_urls: Set[str] = set() # 本次运行中成功处理的原始URL
    current_failed_urls: Set[str] = set() # 本次运行中失败的原始URL
    updated_hashes = prev_url_hashes.copy() # 用于构建新的哈希文件

    # 准备待处理URL列表，并过滤掉历史失败的URL和重复URL
    urls_to_process_flat = []
    processed_urls_set = set() 
    
    for category, items in initial_categorized_urls.items():
        for description, url in items:
            # 只有当URL不在历史失败列表且尚未处理过时，才加入待处理队列
            if url not in failed_urls_history and url not in processed_urls_set:
                urls_to_process_flat.append((category, description, url))
                processed_urls_set.add(url) # 标记为已添加到待处理列表

    logger.info(f"将处理 {len(urls_to_process_flat)} 个URL...")
    start_time = time.time()
    
    # 使用 aiohttp ClientSession 进行异步网络请求
    # connector限制并发连接数
    connector = aiohttp.TCPConnector(limit=CONFIG['max_concurrent_requests'], ssl=False) # ssl=False 避免某些证书问题，生产环境慎用
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            process_single_url(
                url_info, session, prev_url_hashes, final_categorized_channels,
                current_success_urls, current_failed_urls, updated_hashes
            )
            for url_info in urls_to_process_flat
        ]
        
        # 使用 tqdm_asyncio 显示异步进度条
        await tqdm_asyncio.gather(*tasks, desc="处理URL", unit="url", ncols=100)
    
    elapsed_total_time = time.time() - start_time
    logger.info(f"所有URL处理完毕。总耗时: {elapsed_total_time:.2f}秒")

    # --- 写入结果文件 ---
    async with asyncio.Lock(): # 使用锁确保文件写入的原子性，尽管这里是串行写入
        # 1. 写入 output/list.txt (分类后的节目源列表)
        with open(CONFIG['output_list'], 'w', encoding='utf-8') as f_out:
            f_out.write(f"更新时间,#genre#\n")
            f_out.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            for category in sorted(final_categorized_channels.keys()):
                f_out.write(f"{category},#genre#\n")
                # 对每个分类下的 (描述, URL) 对进行排序，并去重
                sorted_items = sorted(list(set(final_categorized_channels[category])), key=lambda x: (x[0], x[1]))
                for description, link in sorted_items:
                    if description:
                        f_out.write(f"{description},{link}\n")
                    else: # 如果没有描述，只写入链接
                        f_out.write(f"{link}\n")
                f_out.write('\n') # 每个分类之间空一行

        # 2. 更新 config/urls.txt (只保留成功的原始URL)
        with open(CONFIG['urls_file'], 'w', encoding='utf-8') as f_config:
            # 遍历原始的分类结构
            for category in sorted(initial_categorized_urls.keys()):
                # 过滤出该分类下成功的URL
                successful_items_in_category = [
                    (desc, url) for desc, url in initial_categorized_urls[category] 
                    if url in current_success_urls
                ]
                if successful_items_in_category: # 如果该分类下有成功的URL，才写入分类头和URL
                    f_config.write(f"{category},#genre#\n")
                    for desc, url in successful_items_in_category:
                        f_config.write(f"{desc},{url}\n")
                    f_config.write('\n')
        
        # 3. 写入 output/failed_urls.txt (累积所有失败的URL)
        # 将本次运行失败的URL与历史失败的URL合并
        all_failed_urls = failed_urls_history.union(current_failed_urls)
        await write_urls(CONFIG['failed_urls'], all_failed_urls)

        # 4. 写入 output/successful_urls.txt (本次运行中所有成功的原始URL)
        # 这个文件是本次运行成功URL的快照，不累积历史
        await write_urls(CONFIG['success_urls'], current_success_urls)
        
        # 5. 写入 output/url_hashes.json (更新后的URL内容哈希)
        await write_url_hashes(CONFIG['url_hashes'], updated_hashes)

    logger.info("所有文件写入完成。")
    logger.info(f"最终节目源列表: {CONFIG['output_list']}")
    logger.info(f"失败URL记录: {CONFIG['failed_urls']}")
    logger.info(f"本次成功URL记录: {CONFIG['success_urls']}")
    logger.info(f"URL内容哈希记录: {CONFIG['url_hashes']}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("程序被用户中断。")
    finally:
        # 关闭线程池
        if _executor:
            _executor.shutdown(wait=True)
            logger.info("线程池已关闭。")
