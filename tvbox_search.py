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

# [其他函数保持不变，如 fetch_url, validate_tvbox_interface, save_valid_file, load_cache, save_cache, generate_dynamic_queries, load_query_stats, save_query_stats, load_existing_content_hashes]
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
                await asyncio.sleep(2 ** attempt)
            else:
                logger.error(f"Failed to fetch {url} after {retries} attempts.")
                return None

def validate_tvbox_interface(json_str: str) -> bool:
    """检查 JSON 字符串是否为有效的 TVBox 接口格式，增强验证逻辑"""
    try:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            return False
        
        has_sites = 'sites' in data and isinstance(data['sites'], list)
        has_lives = 'lives' in data and isinstance(data['lives'], list)
        has_spider = 'spider' in data and isinstance(data['spider'], str) and data['spider'].strip()
        
        if not (has_sites or has_lives or has_spider):
            return False

        if has_sites and any(isinstance(site, dict) and ('api' in site or 'url' in site) for site in data['sites']):
            return True
        
        if has_lives and any(isinstance(live, dict) and 'channels' in live for live in data['lives']):
            return True
            
        if has_spider:
            return True
        
        return False
    except json.JSONDecodeError:
        return False

def load_existing_content_hashes(directory: str) -> Set[str]:
    """遍历本地目录，计算并返回所有文件的 SHA256 哈希值"""
    hashes = set()
    if not os.path.exists(directory):
        return hashes
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                    hashes.add(hashlib.sha256(content).hexdigest())
            except Exception as e:
                logger.warning(f"Could not read or hash file {filepath}: {e}")
    return hashes

def save_valid_file(file_name: str, content: str):
    """保存有效文件到磁盘，添加时间戳"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    base_name = os.path.splitext(file_name)[0]
    new_file_name = f"{base_name}_{timestamp}.json"
    save_path = os.path.join("box", new_file_name)
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info(f"Successfully saved {new_file_name} to 'box/'")

def load_cache(cache_file: str = "search_cache.json") -> Dict[str, dict]:
    """加载缓存的搜索结果，移除过期条目（30 天前）"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache = json.load(f)
            expiry_date = datetime.now() - timedelta(days=30)
            return {
                k: v for k, v in cache.items()
                if datetime.fromisoformat(v['last_modified'].replace('Z', '+00:00')) > expiry_date
            }
        except Exception as e:
            logger.warning(f"Error loading cache: {e}")
    return {}

def save_cache(cache: Dict[str, dict], cache_file: str = "search_cache.json"):
    """保存搜索结果到缓存，优化存储格式"""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=0)
    except Exception as e:
        logger.error(f"Error saving cache: {e}")

def generate_dynamic_queries(cache: Dict[str, dict]) -> List[str]:
    """从缓存中提取高频文件名、路径和仓库，生成动态查询"""
    filenames = {}
    paths = {}
    repos = {}
    for data in cache.values():
        file_name = data.get('file_name', '').split('_')[0] + '.json'
        path = data.get('path', '')
        repo = data.get('repo', '')
        if file_name and file_name != '.json':
            filenames[file_name] = filenames.get(file_name, 0) + 1
        if path:
            dir_path = path.rsplit('/', 1)[0] if '/' in path else ''
            if dir_path:
                paths[dir_path] = paths.get(dir_path, 0) + 1
        if repo:
            repos[repo] = repos.get(repo, 0) + 1
    
    dynamic_queries = []
    dynamic_queries.extend(
        f'filename:{name} tvbox in:file' for name, count in filenames.items() if count >= 2
    )
    dynamic_queries.extend(
        f'extension:json path:{path}' for path, count in paths.items() if count >= 2
    )
    dynamic_queries.extend(
        f'extension:json repo:{repo}' for repo, count in repos.items() if count >= 3
    )
    return dynamic_queries[:5]

def load_query_stats(stats_file: str = "query_stats.json") -> Dict[str, dict]:
    """加载查询统计"""
    if os.path.exists(stats_file):
        try:
            with open(stats_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Error loading query stats: {e}")
    return {}

def save_query_stats(stats: Dict[str, dict], stats_file: str = "query_stats.json"):
    """保存查询统计"""
    try:
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Error saving query stats: {e}")

def search_github(query: str, github_token: str, page: int = 1) -> Tuple[List[dict], int]:
    """执行 GitHub 搜索请求，带重试机制，并对 403 错误进行处理"""
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
            # 明确处理 429 和 403 错误
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning(f"Rate limit exceeded for query '{query}', page {page}. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                continue
            if response.status_code == 403:
                # 当遇到 403 错误时，可能是权限或临时限制。等待更长时间再重试。
                wait_time = 60 * (attempt + 1)
                logger.warning(f"Error 403 for query '{query}', page {page} (attempt {attempt + 1}/{retries}). Waiting for {wait_time} seconds before retrying...")
                time.sleep(wait_time)
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

async def process_query(query: str, github_token: str, processed_urls: Set[str], cache: Dict[str, dict], stats: Dict[str, dict], content_hashes: Set[str], max_pages: int = 10):
    """处理单个查询，搜索并保存 TVBox 配置文件"""
    page = 1
    valid_files = stats.get(query, {}).get('valid', 0)
    total_files = stats.get(query, {}).get('total', 0)
    downloaded_content_hashes: Set[str] = set()

    while page <= max_pages:
        items, total_count = search_github(query, github_token, page)
        total_files += len(items)
        logger.info(f"Query '{query}', page {page}: Found {len(items)} files, total: {total_count}")
        
        if not items:
            logger.info(f"No more results for query '{query}'. Exiting pagination.")
            break
        
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
            tasks = []
            urls_to_process = []
            for item in items:
                raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                
                if raw_url in processed_urls:
                    logger.debug(f"Skipping duplicate URL: {raw_url}")
                    continue
                processed_urls.add(raw_url)
                
                tasks.append(fetch_url(session, raw_url, headers={"Accept": "application/vnd.github.v3+json"}))
                urls_to_process.append(raw_url)

            downloaded_contents = await asyncio.gather(*tasks, return_exceptions=True)

            for i, content in enumerate(downloaded_contents):
                if isinstance(content, Exception) or content is None:
                    logger.warning(f"Skipping {urls_to_process[i]} due to fetch error.")
                    continue
                
                content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                
                if content_hash in content_hashes:
                    logger.info(f"Skipping {urls_to_process[i]}: content already exists locally.")
                    continue
                
                if content_hash in downloaded_content_hashes:
                    logger.info(f"Skipping {urls_to_process[i]}: content is a duplicate within this run.")
                    continue
                
                if validate_tvbox_interface(content):
                    logger.info(f"Validation successful for {urls_to_process[i]}. Saving...")
                    file_name = urls_to_process[i].split("/")[-1]
                    save_valid_file(file_name, content)
                    content_hashes.add(content_hash)
                    downloaded_content_hashes.add(content_hash)
                    valid_files += 1
                else:
                    logger.warning(f"Validation failed for {urls_to_process[i]}. Skipping.")
        
        save_cache(cache)
        
        page += 1
        if page * 100 >= total_count:
            logger.info(f"Reached end of results for query '{query}'.")
            break
    
    stats[query] = {'valid': valid_files, 'total': total_files}
    save_query_stats(stats)

async def search_and_save_tvbox_interfaces():
    """搜索、验证并保存 TVBox 接口文件"""
    github_token = os.environ.get("BOT")
    if not github_token:
        logger.error("BOT token is not set. Exiting.")
        sys.exit(1)

    queries = [
        'filename:config.json tvbox in:file',
        'filename:tv.json tvbox in:file',
        'filename:interface.json tvbox in:file',
        'extension:json path:tvbox',
        'extension:json path:config',
        'extension:json sites in:file language:json',
        'extension:json lives in:file language:json',
        'extension:json spider in:file language:json',
        'extension:json api in:file language:json',
        'extension:json channels in:file language:json'
    ]
    
    os.makedirs("box", exist_ok=True)
    
    cache = load_cache()
    stats = load_query_stats()
    processed_urls: Set[str] = set()
    content_hashes: Set[str] = load_existing_content_hashes("box")
    
    dynamic_queries = generate_dynamic_queries(cache)
    queries.extend(dynamic_queries)
    logger.info(f"Added {len(dynamic_queries)} dynamic queries: {dynamic_queries}")
    
    def query_priority(query):
        stats_data = stats.get(query, {'valid': 0, 'total': 1})
        hit_rate = stats_data['valid'] / max(stats_data['total'], 1)
        return hit_rate
    queries.sort(key=query_priority, reverse=True)
    logger.info(f"Sorted queries by hit rate: {queries}")
    
    # 增加每次查询后的延时，以减少 API 压力
    delay_between_queries = 20 # 秒
    
    max_workers = min(len(queries), multiprocessing.cpu_count())
    max_pages_per_query = 5 if len(queries) > max_workers else 10
    logger.info(f"Using {max_workers} parallel threads for {len(queries)} queries, max {max_pages_per_query} pages per query.")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for query in queries:
            future = executor.submit(asyncio.run, process_query(query, github_token, processed_urls, cache, stats, content_hashes, max_pages_per_query))
            future.result()
            # 每次处理完一个查询，都暂停一下
            logger.info(f"Finished processing query '{query}'. Waiting for {delay_between_queries} seconds.")
            time.sleep(delay_between_queries)
    
    save_query_stats(stats)

if __name__ == "__main__":
    asyncio.run(search_and_save_tvbox_interfaces())
