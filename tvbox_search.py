import requests
import json
import os
import sys
import logging
import time
import asyncio
import aiohttp
import hashlib
from typing import Tuple, Set, List, Dict
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import traceback

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# URL有效性检查缓存，避免重复请求
URL_CACHE = {}
MAX_CACHE_SIZE = 10000

# 缓存文件和统计文件路径
CACHE_FILE = 'query_cache.json'
STATS_FILE = 'query_stats.json'

async def fetch_url(session: aiohttp.ClientSession, url: str, headers: Dict[str, str], timeout: int = 10, retries: int = 3) -> str | None:
    """异步获取 URL 内容，带重试机制"""
    for attempt in range(retries):
        try:
            async with session.get(url, headers=headers, timeout=timeout) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientError as e:
            logger.warning(f"获取 {url} 失败 (尝试 {attempt + 1}/{retries}): {e}")
            if response.status == 403:
                logger.warning("遇到 403 Forbidden 错误，等待 60 秒后重试...")
                await asyncio.sleep(60)
            elif attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
            else:
                logger.error(f"在 {retries} 次尝试后仍无法获取 {url}。")
                return None
        except asyncio.TimeoutError:
            logger.warning(f"获取 {url} 超时 (尝试 {attempt + 1}/{retries})")
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
            else:
                logger.error(f"在 {retries} 次尝试后仍无法获取 {url}。")
                return None
        except Exception as e:
            logger.error(f"获取 {url} 时发生意外错误: {e}")
            return None

def validate_tvbox_interface(json_str: str) -> bool:
    """检查 JSON 字符串是否为有效的 TVBox 配置"""
    try:
        data = json.loads(json_str)
        if isinstance(data, dict):
            # 至少包含 'sites' 或 'lives' 键
            return 'sites' in data or 'lives' in data
        # 如果是单个站点对象
        elif isinstance(data, dict) and 'api' in data and 'name' in data:
            return True
        return False
    except json.JSONDecodeError:
        return False

def save_valid_file(repo: str, filepath: str, content: str, content_hashes: Set[str]) -> bool:
    """保存有效文件，并检查内容哈希以避免重复"""
    content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
    if content_hash in content_hashes:
        logger.info(f"文件 {filepath} 内容已存在，跳过。")
        return False
    
    # 确保保存目录存在
    save_path = os.path.join("box", os.path.basename(filepath))
    try:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(content)
        content_hashes.add(content_hash)
        logger.info(f"已保存有效文件: {save_path}")
        return True
    except Exception as e:
        logger.error(f"保存文件 {save_path} 失败: {e}")
        return False

def load_cache(cache_file: str) -> Tuple[Dict, Set]:
    """加载缓存文件，返回缓存字典和已处理URL集合"""
    cache = {}
    processed_urls = set()
    try:
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
                cache = cache_data.get('cache', {})
                processed_urls = set(cache_data.get('processed_urls', []))
                logger.info("已加载缓存文件。")
    except Exception as e:
        logger.warning(f"加载缓存文件失败: {e}。将从空缓存开始。")
    return cache, processed_urls

def save_cache(cache: Dict, processed_urls: Set[str], cache_file: str):
    """保存缓存文件"""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({'cache': cache, 'processed_urls': list(processed_urls)}, f, indent=2, ensure_ascii=False)
        logger.info("已保存缓存文件。")
    except Exception as e:
        logger.error(f"保存缓存文件失败: {e}")

def load_query_stats(stats_file: str) -> Dict:
    """加载查询统计文件"""
    stats = {}
    try:
        if os.path.exists(stats_file):
            with open(stats_file, 'r', encoding='utf-8') as f:
                stats = json.load(f)
                logger.info("已加载查询统计文件。")
    except Exception as e:
        logger.warning(f"加载查询统计文件失败: {e}。将从空统计开始。")
    return stats

def save_query_stats(stats: Dict, stats_file: str):
    """保存查询统计文件"""
    try:
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        logger.info("已保存查询统计文件。")
    except Exception as e:
        logger.error(f"保存查询统计文件失败: {e}")

def load_existing_content_hashes(directory: str) -> Set[str]:
    """加载现有文件的内容哈希值"""
    hashes = set()
    if not os.path.exists(directory):
        return hashes
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                    hashes.add(hashlib.sha256(content).hexdigest())
            except Exception as e:
                logger.warning(f"无法读取文件 {filepath} 以计算哈希值: {e}")
    logger.info(f"已加载 {len(hashes)} 个现有文件的内容哈希值。")
    return hashes

def generate_dynamic_queries(cache: Dict) -> List[str]:
    """根据缓存中的最新 URL 生成动态查询"""
    queries = []
    # 实现动态查询生成逻辑
    return queries

async def process_query(query: str, github_token: str, processed_urls: Set[str], cache: Dict, stats: Dict, content_hashes: Set[str], max_pages: int):
    """异步处理单个查询"""
    headers = {
        'Accept': 'application/vnd.github.v3.text-match+json',
        'Authorization': f'token {github_token}'
    }
    base_url = "https://api.github.com/search/code"
    
    query_stats = stats.setdefault(query, {'valid': 0, 'total': 0})

    async with aiohttp.ClientSession() as session:
        for page in range(1, max_pages + 1):
            params = {'q': query, 'page': page, 'per_page': 100}
            url = f"{base_url}?q={query}&page={page}"
            
            try:
                async with session.get(url, headers=headers, params=params) as response:
                    response.raise_for_status()
                    results = await response.json()
                    
                    if not results['items']:
                        logger.info(f"查询 '{query}', 第 {page} 页没有找到更多结果。")
                        break

                    for item in results['items']:
                        raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                        
                        if raw_url in processed_urls:
                            logger.debug(f"URL {raw_url} 已处理过，跳过。")
                            continue
                        
                        processed_urls.add(raw_url)
                        query_stats['total'] += 1
                        
                        if raw_url in URL_CACHE:
                            is_valid = URL_CACHE[raw_url]
                            if is_valid:
                                logger.info(f"跳过 {raw_url}: 内容已存在本地。")
                                query_stats['valid'] += 1
                                continue
                            else:
                                continue

                        content = await fetch_url(session, raw_url, headers)
                        if content and validate_tvbox_interface(content):
                            if save_valid_file(item['repository']['full_name'], item['path'], content, content_hashes):
                                URL_CACHE[raw_url] = True
                                query_stats['valid'] += 1
                        else:
                            URL_CACHE[raw_url] = False
                            logger.warning(f"验证 {raw_url} 失败。跳过。")
            
            except aiohttp.ClientError as e:
                if response.status == 403:
                    logger.error(f"查询 '{query}', 第 {page} 页遇到 403 Forbidden 错误，可能达到 API 频率限制。等待 60 秒后重试。")
                    await asyncio.sleep(60)
                else:
                    logger.error(f"处理查询 '{query}' 时发生网络错误: {e}")
                
            except Exception as e:
                logger.error(f"处理查询 '{query}' 时发生意外错误: {e}")
                traceback.print_exc()

async def main():
    """主函数，负责执行搜索和文件处理"""
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("请设置 GITHUB_TOKEN 环境变量以使用 GitHub API。")
        sys.exit(1)

    queries = [
        "filename:tvbox.json tvbox in:file",
        "filename:tv.json tvbox in:file",
        "filename:TVBox.json tvbox in:file",
        "filename:home.json tvbox in:file",
        "filename:config.json tvbox in:file",
        "extension:json tvbox in:file path:tvbox",
        "extension:json tvbox in:file path:tv"
    ]
    
    cache, processed_urls = load_cache(CACHE_FILE)
    stats = load_query_stats(STATS_FILE)
    content_hashes = load_existing_content_hashes("box")
    
    dynamic_queries = generate_dynamic_queries(cache)
    queries.extend(dynamic_queries)
    logger.info(f"已添加 {len(dynamic_queries)} 个动态查询: {dynamic_queries}")
    
    def query_priority(query):
        stats_data = stats.get(query, {'valid': 0, 'total': 1})
        hit_rate = stats_data['valid'] / max(stats_data['total'], 1)
        return hit_rate
    queries.sort(key=query_priority, reverse=True)
    logger.info(f"已按命中率排序查询: {queries}")
    
    max_workers = min(len(queries), multiprocessing.cpu_count() * 2)
    max_pages_per_query = 5
    logger.info(f"使用 {max_workers} 个并行任务处理 {len(queries)} 个查询，每个查询最多 {max_pages_per_query} 页。")
    
    tasks = [process_query(query, github_token, processed_urls, cache, stats, content_hashes, max_pages_per_query) for query in queries]
    await asyncio.gather(*tasks)

    save_cache(URL_CACHE, processed_urls, CACHE_FILE)
    save_query_stats(stats, STATS_FILE)
    logger.info("所有查询处理完毕，缓存和统计数据已保存。")

if __name__ == "__main__":
    os.makedirs("box", exist_ok=True)
    asyncio.run(main())
