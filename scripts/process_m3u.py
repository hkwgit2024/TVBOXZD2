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
from typing import Dict, List, Tuple, Set, Union
from concurrent.futures import ThreadPoolExecutor

# 配置日志
os.makedirs('output', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('output/process.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 全局配置
CONFIG = {
    'urls_file': 'config/urls.txt',
    'output_list': 'output/list.txt',
    'failed_urls': 'output/failed_urls.txt',
    'success_urls': 'output/successful_urls.txt',
    'url_hashes': 'output/url_hashes.json',
    'max_concurrent_requests': 50,
    'timeout_seconds': 15,
    'max_retries': 3,
    'retry_delay': 2
}

# 正则表达式定义
VIDEO_URL_REGEX = re.compile(
    r'^(http(s)?://)?([\w-]+\.)+[\w-]+(/[\w./?%&=-]*?)((\.m3u8|\.mp4|\.flv|\.ctv|\.ts|\.mpd|\.webm|\.ogg|\.avi|\.mov|\.wmv|\.mkv|\.rmvb))$',
    re.IGNORECASE
)
# 匹配类似 "CCTV央视,#genre#" 的类别行
GENRE_REGEX = re.compile(r'^(.*?),\s*\#genre\#$')

# 全局线程池
_executor = ThreadPoolExecutor(max_workers=os.cpu_count() or 4)

# --- 辅助函数 ---

def read_categorized_urls(filepath: str) -> Dict[str, List[Tuple[str, str]]]:
    """
    从文件中读取带有分类、描述和URL的列表。
    格式示例:
    更新时间,#genre#
    2025-08-01 09:00:41,url
    CCTV央视,#genre#
    CCTV 01,http://111.14.181.15:9901/tsfile/live/0001_1.m3u8
    """
    categorized_urls = {}
    current_category = "未分类" # 默认分类

    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    genre_match = GENRE_REGEX.match(line)
                    if genre_match:
                        # 匹配到类别行
                        current_category = genre_match.group(1).strip()
                        categorized_urls.setdefault(current_category, [])
                    else:
                        # 匹配到描述和URL行
                        parts = line.rsplit(',', 1)
                        if len(parts) == 2:
                            description = parts[0].strip()
                            url = parts[1].strip()
                            if url and VIDEO_URL_REGEX.match(url): # 只添加有效视频URL
                                categorized_urls.setdefault(current_category, []).append((description, url))
                            else:
                                logger.warning(f"跳过无效的URL格式或非视频URL: {line} (在类别: {current_category} 下)")
                        else:
                            logger.warning(f"跳过无法解析的行: {line} (在类别: {current_category} 下)")

    except Exception as e:
        logger.error(f"读取URL文件 {filepath} 失败: {e}")

    return categorized_urls

def read_urls_set(filepath: str) -> Set[str]:
    """读取纯URL集合，通常用于failed_urls或successful_urls"""
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

async def write_urls_set(filepath: str, urls: Set[str]) -> None:
    """异步写入URL集合到文件"""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            for url in sorted(list(urls)): # 排序以便文件内容稳定
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
    """异步计算内容的SHA256哈希值"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, lambda: hashlib.sha256(content.encode('utf-8')).hexdigest())

async def fetch_content(url: str, session: aiohttp.ClientSession, max_retries: int) -> Union[str, None]:
    """异步获取URL内容，包含重试机制"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    for attempt in range(max_retries):
        try:
            async with session.get(url, headers=headers, timeout=CONFIG['timeout_seconds']) as response:
                response.raise_for_status() # 对HTTP错误状态码抛出异常 (4xx 或 5xx)
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

async def process_single_url(
    url_info: Tuple[str, str, str], # (category, description, url)
    session: aiohttp.ClientSession,
    prev_url_hashes: Dict[str, str],
    final_channels: Dict[str, List[Tuple[str, str]]], # {category: [(desc, url), ...]}
    current_success_urls: Set[str], # 只存储URL字符串
    current_failed_urls: Set[str],   # 只存储URL字符串
    updated_hashes: Dict[str, str]
) -> None:
    """处理单个URL的异步任务"""
    category, description, url = url_info

    content = await fetch_content(url, session, CONFIG['max_retries'])

    if content:
        current_hash = await calculate_content_hash_async(content)

        # 检查内容是否更新或是否是新URL
        if url in prev_url_hashes and prev_url_hashes[url] == current_hash:
            # 内容未更新，直接添加
            logger.debug(f"URL: {url} 内容未更新，添加到成功列表。")
        else:
            # 内容已更新或首次获取
            logger.debug(f"URL: {url} 内容已更新或首次获取。")
        
        # 无论内容是否更新，只要成功获取，就添加到 final_channels 和 updated_hashes
        final_channels.setdefault(category, []).append((description, url))
        current_success_urls.add(url)
        updated_hashes[url] = current_hash
    else:
        # 获取失败
        current_failed_urls.add(url)
        # 如果之前有哈希值，则移除，表示此URL目前不可用
        if url in updated_hashes:
            updated_hashes.pop(url)
        logger.warning(f"URL: {url} 获取失败，添加到失败列表。")


async def main():
    # 确保必要的目录存在
    os.makedirs('output', exist_ok=True)
    os.makedirs('config', exist_ok=True) # 确保 config 目录存在

    logger.info("程序开始运行...")

    # 读取初始URL和历史数据
    initial_categorized_urls = read_categorized_urls(CONFIG['urls_file'])
    failed_urls_history = read_urls_set(CONFIG['failed_urls'])
    prev_url_hashes = read_url_hashes(CONFIG['url_hashes'])

    # 用于存储本次运行的结果和状态
    # {category: [(description, url), ...]}
    final_categorized_channels: Dict[str, List[Tuple[str, str]]] = {}
    current_success_urls: Set[str] = set() # 存储本次成功检查的URL字符串
    current_failed_urls: Set[str] = set()   # 存储本次失败检查的URL字符串
    updated_hashes = prev_url_hashes.copy() # 用于保存新的哈希值

    # 准备待处理URL列表 (category, description, url)
    urls_to_process_flat = []
    processed_urls_set = set() # 用于避免重复处理相同的URL

    for category, items in initial_categorized_urls.items():
        for description, url in items:
            if url not in failed_urls_history and url not in processed_urls_set:
                urls_to_process_flat.append((category, description, url))
                processed_urls_set.add(url)
            elif url in failed_urls_history:
                logger.debug(f"跳过历史失败URL: {url} (描述: {description})")
            else: # url in processed_urls_set
                logger.debug(f"跳过重复URL: {url} (描述: {description})")

    logger.info(f"将处理 {len(urls_to_process_flat)} 个有效URL...")
    start_time = time.time()

    # 异步处理URL
    connector = aiohttp.TCPConnector(limit=CONFIG['max_concurrent_requests'], ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            process_single_url(
                url_info, session, prev_url_hashes, final_categorized_channels,
                current_success_urls, current_failed_urls, updated_hashes
            )
            for url_info in urls_to_process_flat
        ]

        await tqdm_asyncio.gather(*tasks, desc="处理URL", unit="url", ncols=100)

    elapsed_total_time = time.time() - start_time
    logger.info(f"所有URL处理完毕。总耗时: {elapsed_total_time:.2f}秒")

    # --- 写入结果文件 ---
    async with asyncio.Lock(): # 使用锁确保文件写入的原子性，尽管这里主要是逻辑上的隔离
        # 1. 写入 output/list.txt - 最终的有效频道列表
        with open(CONFIG['output_list'], 'w', encoding='utf-8') as f_out:
            # 写入更新时间头部
            f_out.write("更新时间,#genre#\n")
            f_out.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n")
            
            # 按类别名称排序，并写入分类和视频源
            for category in sorted(final_categorized_channels.keys()):
                f_out.write(f"{category},#genre#\n")
                # 对每个类别内的频道按描述和URL排序，并去重（防止read_categorized_urls中因为重复行导致添加多次）
                # 这里去重需要保留描述和URL的组合
                sorted_items = sorted(list(set(final_categorized_channels[category])), key=lambda x: (x[0], x[1]))
                for description, link in sorted_items:
                    f_out.write(f"{description},{link}\n")
        
        logger.info(f"最终节目源列表已写入: {CONFIG['output_list']}")

        # 2. 更新 config/urls.txt - 只保留所有原始文件中且本次检查成功的频道
        # 这里的逻辑是：只保留在原始 urls.txt 中出现过，并且在本次运行中被成功验证的频道
        with open(CONFIG['urls_file'], 'w', encoding='utf-8') as f_config:
            # 首先写入更新时间行，如果原始文件有的话
            # 考虑如果初始文件头部有更新时间，也应该保留或更新
            # 这里简单处理为只写入类别和内容，如果需要更新时间，可以在读取时特殊处理
            for category in sorted(initial_categorized_urls.keys()):
                # 获取该类别下所有在原始文件中定义过的 (描述, URL) 对
                original_items_in_category = initial_categorized_urls[category]
                
                # 筛选出本次检查中成功的 (描述, URL) 对
                successful_items_for_config = []
                for desc, url in original_items_in_category:
                    if url in current_success_urls:
                        successful_items_for_config.append((desc, url))
                
                if successful_items_for_config:
                    f_config.write(f"{category},#genre#\n")
                    # 排序以保持文件内容稳定
                    for desc, url in sorted(successful_items_for_config, key=lambda x: (x[0], x[1])):
                        f_config.write(f"{desc},{url}\n")
        logger.info(f"配置URL文件已更新: {CONFIG['urls_file']}")

        # 3. 写入失败和成功URL集合以及更新哈希值
        all_failed_urls = failed_urls_history.union(current_failed_urls) # 将本次失败与历史失败合并
        # 注意：这里如果一个URL之前成功，现在失败了，它会从 successful_urls 中移除，但会添加到 failed_urls
        # 反之，如果一个URL之前失败，现在成功了，它会添加到 successful_urls 中，并从 failed_urls 中移除（因为set的union操作）
        # current_success_urls 已经只包含本次成功的URL
        
        await asyncio.gather(
            write_urls_set(CONFIG['failed_urls'], all_failed_urls),
            write_urls_set(CONFIG['success_urls'], current_success_urls),
            write_url_hashes(CONFIG['url_hashes'], updated_hashes)
        )
        logger.info(f"失败URL记录已更新: {CONFIG['failed_urls']}")
        logger.info(f"本次成功URL记录已更新: {CONFIG['success_urls']}")
        logger.info(f"URL内容哈希记录已更新: {CONFIG['url_hashes']}")

    logger.info("所有文件写入完成。")
    logger.info("程序运行结束。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("程序被用户中断。")
    finally:
        if _executor:
            _executor.shutdown(wait=True)
            logger.info("线程池已关闭。")
