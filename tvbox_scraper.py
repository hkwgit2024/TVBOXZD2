#搜索
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

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

async def fetch_url(session, url, headers, timeout=10, retries=3):
    """异步获取 URL 内容，带重试机制"""
    for attempt in range(retries):
        try:
            async with session.get(url, headers=headers, timeout=timeout) as response:
                response.raise_for_status()
                return await response.text()
        except Exception as e:
            logger.warning(f"Error fetching {url} (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)  # 指数退避
            else:
                logger.error(f"Failed to fetch {url} after {retries} attempts.")
                return None

def validate_tvbox_interface(json_str: str) -> bool:
    """
    检查 JSON 字符串是否为有效的 TVBox 接口格式，增强非空验证。
    """
    try:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            logger.debug("Validation failed: Not a dictionary.")
            return False

        has_sites_key = 'sites' in data and isinstance(data['sites'], list) and len(data['sites']) > 0
        has_lives_key = 'lives' in data and isinstance(data['lives'], list) and len(data['lives']) > 0
        has_spider_key = 'spider' in data and isinstance(data['spider'], str) and data['spider'].strip()

        if not (has_sites_key or has_lives_key or has_spider_key):
            logger.debug("Validation failed: Missing required keys or empty values.")
            return False

        if has_sites_key:
            for site in data['sites']:
                if isinstance(site, dict) and ('api' in site or 'url' in site):
                    return True
        
        if has_lives_key or has_spider_key:
            return True

        logger.debug("Validation failed: No valid site, live, or spider content.")
        return False
    except json.JSONDecodeError:
        logger.debug("Validation failed: Invalid JSON format.")
        return False

def check_for_updates(file_name: str, last_modified_str: str) -> bool:
    """
    检查本地目录中是否存在同名文件，并比较更新时间。
    """
    if not last_modified_str:
        return False
        
    try:
        github_last_modified = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00'))
        
        for local_file in os.listdir("box"):
            base_name = os.path.splitext(file_name)[0]
            if local_file.startswith(base_name) and local_file.endswith(".json"):
                local_timestamp_str = local_file.rsplit('_', 1)[-1].split('.')[0]
                local_last_modified = datetime.strptime(local_timestamp_str, "%Y%m%d%H%M%S")
                
                if local_last_modified.replace(tzinfo=None) >= github_last_modified.replace(tzinfo=None):
                    return True
    except (ValueError, IndexError):
        return False
        
    return False

def load_cache(cache_file: str = "search_cache.json") -> Dict[str, dict]:
    """加载缓存的搜索结果，移除过期条目（30 天前）"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache = json.load(f)
            # 移除过期缓存（30 天前）
            expiry_date = datetime.now() - timedelta(days=30)
            return {
                k: v for k, v in cache.items()
                if datetime.fromisoformat(v['last_modified'].replace('Z', '+00:00')) > expiry_date
            }
        except Exception as e:
            logger.warning(f"Error loading cache: {e}")
    return {}

def save_cache(cache: Dict[str, dict], cache_file: str = "search_cache.json"):
    """保存搜索结果到缓存"""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error saving cache: {e}")

def generate_dynamic_queries(cache: Dict[str, dict]) -> List[str]:
    """从缓存中提取高频文件名，生成动态查询"""
    filenames = {}
    for data in cache.values():
        file_name = data.get('file_name', '').split('_')[0] + '.json'
        filenames[file_name] = filenames.get(file_name, 0) + 1
    
    # 选择出现频率 >= 2 的文件名
    dynamic_queries = [
        f'filename:{name} tvbox in:file'
        for name, count in filenames.items() if count >= 2
    ]
    return dynamic_queries[:5]  # 限制动态查询数量

def search_github(query: str, github_token: str, page: int = 1) -> Tuple[List[dict], int]:
    """执行 GitHub 搜索请求，带重试机制"""
    search_url = "https://api.github.com/search/code"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    retries = 3
    for attempt in range(retries):
        try:
            response = requests.get(
                search_url,
                params={"q": query, "per_page": 100, "page": page, "sort": "updated", "order": "desc"},
                headers=headers
            )
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning(f"Rate limit exceeded for query '{query}', page {page}. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                continue
            if response.status_code in (403, 502):
                logger.warning(f"Error {response.status_code} for query '{query}', page {page} (attempt {attempt + 1}/{retries})")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue
            response.raise_for_status()
            search_results = response.json()
            return search_results.get('items', []), search_results.get('total_count', 0)
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error searching query '{query}', page {page} (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                logger.error(f"Failed to search query '{query}', page {page} after {retries} attempts.")
                return [], 0
    return [], 0

async def process_query(query: str, github_token: str, processed_urls: Set[str], cache: Dict[str, dict], stats: Dict[str, int]):
    """处理单个查询，搜索并保存 TVBox 配置文件"""
    page = 1
    valid_files = 0
    total_files = 0
    
    while True:
        items, total_count = search_github(query, github_token, page)
        total_files += len(items)
        logger.info(f"Query '{query}', page {page}: Found {len(items)} files, total: {total_count}")
        
        if not items:
            logger.info(f"No more results for query '{query}'. Exiting pagination.")
            break
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for item in items:
                file_name = item["path"].split("/")[-1]
                repo_full_name = item['repository']['full_name']
                last_modified_str = item['repository']['updated_at']
                raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                
                # 使用文件内容的 SHA 或 URL 去重
                file_sha = item.get('sha', '')
                cache_key = file_sha or raw_url
                if cache_key in cache and cache[cache_key]['last_modified'] == last_modified_str:
                    logger.info(f"Skipping cached file: {file_name} from {repo_full_name}")
                    continue
                if raw_url in processed_urls:
                    logger.info(f"Skipping duplicate URL: {raw_url}")
                    continue
                
                logger.info(f"\n--- Processing {file_name} from {repo_full_name} ---")
                
                if check_for_updates(file_name, last_modified_str):
                    logger.info(f"Local file is up-to-date. Skipping download.")
                    continue

                tasks.append((item, fetch_url(session, raw_url, headers={"Accept": "application/vnd.github.v3+json"})))
                processed_urls.add(raw_url)
                cache[cache_key] = {'file_name': file_name, 'last_modified': last_modified_str}
            
            # 批量处理下载任务
            for item, content in [(item, await task) for item, task in tasks]:
                if content is None:
                    logger.warning(f"Skipping {item['path']} due to fetch error.")
                    continue
                
                file_name = item["path"].split("/")[-1]
                if validate_tvbox_interface(content):
                    logger.info(f"Validation successful! It's a valid TVBox JSON. Saving...")
                    
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    new_file_name = f"{os.path.splitext(file_name)[0]}_{timestamp}.json"
                    
                    save_path = os.path.join("box", new_file_name)
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    logger.info(f"Successfully saved {new_file_name} to 'box/'")
                    valid_files += 1
                else:
                    logger.warning("Validation failed: Not a TVBox interface. Skipping.")
        
        # 更新缓存
        save_cache(cache)
        
        # 检查是否有下一页
        page += 1
        if page * 100 >= total_count:
            logger.info(f"Reached end of results for query '{query}'.")
            break
    
    # 记录查询统计
    stats[query] = valid_files
    logger.info(f"Query '{query}' produced {valid_files}/{total_files} valid files.")

async def search_and_save_tvbox_interfaces():
    """
    搜索、验证并保存 TVBox 接口文件，并检查更新。
    """
    github_token = os.environ.get("BOT")
    if not github_token:
        logger.error("BOT token is not set. Exiting.")
        sys.exit(1)

    # 定义查询组合，优先高相关性查询
    queries = [
        'filename:config.json tvbox in:file',
        'filename:tv.json tvbox in:file',
        'filename:interface.json tvbox in:file',
        'extension:json sites in:file language:json',
        'extension:json lives in:file language:json',
        'extension:json spider in:file language:json',
        'extension:json api in:file language:json',
        'extension:json channels in:file language:json'
    ]
    
    os.makedirs("box", exist_ok=True)
    
    # 加载缓存和已处理 URL
    cache = load_cache()
    processed_urls: Set[str] = set()
    stats: Dict[str, int] = {}  # 统计每个查询的有效文件数
    
    # 添加动态查询
    dynamic_queries = generate_dynamic_queries(cache)
    queries.extend(dynamic_queries)
    logger.info(f"Added {len(dynamic_queries)} dynamic queries: {dynamic_queries}")
    
    # 动态调整并行线程数（最多 CPU 核心数）
    max_workers = min(len(queries), multiprocessing.cpu_count())
    logger.info(f"Using {max_workers} parallel threads for {len(queries)} queries.")
    
    # 并行运行查询
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(asyncio.run, process_query(query, github_token, processed_urls, cache, stats))
            for query in queries
        ]
        for future in futures:
            future.result()  # 等待所有查询完成
    
    # 保存查询统计
    try:
        with open("query_stats.json", 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        logger.info("Query statistics saved to 'query_stats.json'.")
    except Exception as e:
        logger.error(f"Error saving query stats: {e}")

if __name__ == "__main__":
    asyncio.run(search_and_save_tvbox_interfaces())
