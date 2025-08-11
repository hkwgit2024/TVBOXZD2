import json
import os
import sys
import logging
from typing import List, Dict, Any
import asyncio
import aiohttp
from urllib.parse import urlparse

# Configure logging with DEBUG level
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for detailed exclusion reasons
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Cache for checked URLs to avoid redundant requests
URL_CACHE = {}
MAX_CACHE_SIZE = 10000  # Limit cache size to prevent memory issues

def strip_proxy(url: str) -> str:
    """
    Strip proxy prefixes like 'https://ghproxy.com/' from the URL.
    """
    proxies = [
        'https://ghproxy.com/',
        'https://ghp.ci/',
        'https://raw.gitmirror.com/',
        'https://github.3x25.com/',
    ]
    for proxy in proxies:
        if url.startswith(proxy):
            original_url = url[len(proxy):]
            if not original_url.startswith(('http://', 'https://')):
                original_url = 'https://' + original_url
            logger.debug(f"Stripped proxy from URL: {url} -> {original_url}")
            return original_url
    return url

async def is_valid_url(url: str, session: aiohttp.ClientSession) -> bool:
    """
    Check if a URL is valid and accessible asynchronously.
    Returns False for local URLs or if the URL is unreachable.
    """
    if url in URL_CACHE:
        logger.debug(f"Using cached result for URL: {url}")
        return URL_CACHE[url]

    url = strip_proxy(url)
    parsed = urlparse(url)

    if parsed.hostname in ('127.0.0.1', 'localhost'):
        logger.debug(f"URL excluded (localhost): {url}")
        URL_CACHE[url] = False
        return False

    if not url.startswith(('http://', 'https://')):
        logger.debug(f"URL excluded (invalid scheme): {url}")
        URL_CACHE[url] = False
        return False

    try:
        async with session.head(url, timeout=10, allow_redirects=True) as response:  # Increased timeout to 10s
            is_valid = response.status == 200
            URL_CACHE[url] = is_valid
            if not is_valid:
                logger.debug(f"URL excluded (status code {response.status}): {url}")
            return is_valid
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"URL excluded (unreachable, {str(e)}): {url}")
        URL_CACHE[url] = False
        return False

async def batch_validate_urls(urls: set, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> dict:
    """
    Batch validate a set of URLs asynchronously with semaphore for rate limiting.
    """
    results = {}
    tasks = []
    for url in urls:
        async def check(url):
            async with sem:
                results[url] = await is_valid_url(url, session)
        tasks.append(check(url))
    await asyncio.gather(*tasks)
    return results

def is_valid_site(site: Dict[str, Any]) -> bool:
    """
    Validate a site configuration synchronously (non-URL checks).
    """
    if not isinstance(site, dict) or not ('api' in site or 'url' in site):
        logger.debug(f"Site excluded (missing api or url): {site.get('name', 'unknown')}")
        return False

    ext = site.get('ext', '')
    if isinstance(ext, str):
        if ext.startswith(('./', 'file://')) or os.path.isabs(ext):
            logger.debug(f"Site excluded (local file path in ext): {site.get('name', 'unknown')}")
            return False

    return True

async def process_file(file_path: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> tuple:
    """
    Process a single JSON file asynchronously.
    """
    sites = []
    lives = []
    spider = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if 'sites' in data and isinstance(data['sites'], list):
            candidate_sites = [site for site in data['sites'] if is_valid_site(site)]
            
            # Collect unique URLs from candidate sites
            urls = set()
            for site in candidate_sites:
                ext = site.get('ext', '')
                api = site.get('api', '')
                if isinstance(ext, str) and ext.startswith(('http://', 'https://')):
                    urls.add(ext)
                if isinstance(api, str) and api.startswith(('http://', 'https://')):
                    urls.add(api)
            
            # Batch validate URLs
            url_results = await batch_validate_urls(urls, session, sem)
            
            # Filter sites based on URL results
            valid_sites = []
            for site in candidate_sites:
                ext = site.get('ext', '')
                api = site.get('api', '')
                ext_valid = not (isinstance(ext, str) and ext.startswith(('http://', 'https://'))) or url_results.get(ext, False)
                api_valid = not (isinstance(api, str) and api.startswith(('http://', 'https://'))) or url_results.get(api, False)
                if ext_valid and api_valid:
                    valid_sites.append(site)
                else:
                    if not ext_valid:
                        logger.debug(f"Site excluded (invalid ext URL {ext}): {site.get('name', 'unknown')}")
                    if not api_valid:
                        logger.debug(f"Site excluded (invalid api URL {api}): {site.get('name', 'unknown')}")

            sites.extend(valid_sites)
            logger.info(f"Processed {len(valid_sites)} valid sites from {os.path.basename(file_path)} "
                        f"({len(data['sites']) - len(valid_sites)} excluded)")

        if 'lives' in data and isinstance(data['lives'], list):
            lives.extend(data['lives'])

        if not spider and 'spider' in data and isinstance(data['spider'], str):
            spider.append(data['spider'])

        logger.info(f"Successfully processed file: {os.path.basename(file_path)}")

        # Clear cache periodically to manage memory
        if len(URL_CACHE) > MAX_CACHE_SIZE:
            URL_CACHE.clear()
            logger.debug("Cleared URL cache to manage memory")

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in file '{file_path}', skipping.")
    except Exception as e:
        logger.error(f"An error occurred while processing file '{file_path}': {e}")

    return sites, lives, spider

async def merge_tvbox_configs(source_dir: str, output_file: str) -> None:
    """
    Merges TVbox configurations asynchronously.
    """
    sites = []
    lives = []
    spider = []

    file_list = [os.path.join(source_dir, f) for f in os.listdir(source_dir) if f.endswith('.json')]
    
    if not file_list:
        logger.warning(f"No JSON files found in directory '{source_dir}'.")
        return

    logger.info(f"Starting to process {len(file_list)} JSON files...")

    # Configure aiohttp session with limited concurrency
    timeout = aiohttp.ClientTimeout(total=10)  # Increased timeout
    connector = aiohttp.TCPConnector(limit=100)  # Increased limit to 100 for better performance
    sem = asyncio.Semaphore(100)  # Semaphore to control concurrency rate
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = [process_file(file_path, session, sem) for file_path in file_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, tuple):
                file_sites, file_lives, file_spider = result
                sites.extend(file_sites)
                lives.extend(file_lives)
                if file_spider and not spider:
                    spider.extend(file_spider)

    merged_data = {
        "sites": sites,
        "lives": lives,
        "spider": spider[0] if spider else ""
    }

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, ensure_ascii=False, indent=2)
        logger.info(f"All configurations successfully merged and saved to '{output_file}'.")
        logger.info(f"Total valid sites: {len(sites)}, Total lives: {len(lives)}")
    except Exception as e:
        logger.error(f"An error occurred while saving the merged file: {e}")

if __name__ == "__main__":
    SOURCE_DIRECTORY = "box"
    OUTPUT_FILE = "merged_tvbox_config.json"
    asyncio.run(merge_tvbox_configs(SOURCE_DIRECTORY, OUTPUT_FILE))
