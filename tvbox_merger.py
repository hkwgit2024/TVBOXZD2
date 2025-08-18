import json
import os
import sys
import logging
from typing import List, Dict, Any, Tuple
import asyncio
import aiohttp
from urllib.parse import urlparse

# Configure logging with DEBUG level
logging.basicConfig(
    level=logging.INFO, # 默认改为 INFO，减少不必要的 DEBUG 输出
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Cache for checked URLs to avoid redundant requests
URL_CACHE = {}
MAX_CACHE_SIZE = 10000  # Limit cache size to prevent memory issues

# Define the domains to be excluded
EXCLUDED_DOMAINS = ["agit.ai", "gitcode.net", "cccimg.com"]

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
    Check if a URL is valid and accessible.
    """
    url_to_check = strip_proxy(url)
    parsed_url = urlparse(url_to_check)
    domain = parsed_url.netloc

    if not all([parsed_url.scheme, parsed_url.netloc]):
        logger.debug(f"Invalid URL format: {url}")
        return False

    if domain in EXCLUDED_DOMAINS:
        logger.debug(f"URL domain is in excluded list: {domain}")
        return False
    
    # Check cache first
    if url_to_check in URL_CACHE:
        logger.debug(f"Using cached result for {url_to_check}: {URL_CACHE[url_to_check]}")
        return URL_CACHE[url_to_check]
    
    # Check if cache is too large and clear if necessary
    if len(URL_CACHE) > MAX_CACHE_SIZE:
        URL_CACHE.clear()
        logger.info("URL cache cleared due to size limit.")

    try:
        async with session.head(url_to_check, timeout=5) as response:
            is_valid = response.status == 200
            URL_CACHE[url_to_check] = is_valid
            if not is_valid:
                logger.debug(f"URL not valid (status {response.status}): {url_to_check}")
            return is_valid
    except aiohttp.ClientError as e:
        logger.debug(f"Failed to connect to {url_to_check}: {e}")
        URL_CACHE[url_to_check] = False
        return False
    except asyncio.TimeoutError:
        logger.debug(f"Timeout checking URL: {url_to_check}")
        URL_CACHE[url_to_check] = False
        return False
    except Exception as e:
        logger.debug(f"An unexpected error occurred for URL {url_to_check}: {e}")
        URL_CACHE[url_to_check] = False
        return False

async def process_file(filepath: str, session: aiohttp.ClientSession) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Read and parse a JSON file, filter sites with valid URLs, and extract sites, lives, and spider.
    Now supports parsing a single site object in addition to a full config.
    """
    sites: List[Dict[str, Any]] = []
    lives: List[Dict[str, Any]] = []
    spider: List[str] = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip():
                logger.warning(f"File '{filepath}' is empty. Skipping.")
                return sites, lives, spider
            
            data = json.loads(content)
            
            # Case 1: The file is a complete config with 'sites', 'lives', etc.
            if isinstance(data, dict) and 'sites' in data:
                all_sites = data.get('sites', [])
                all_lives = data.get('lives', [])
                all_spider = [data.get('spider', "")]
                
                # Check each site's validity
                tasks = [is_valid_url(site.get('api', ''), session) for site in all_sites]
                valid_results = await asyncio.gather(*tasks)

                for site, is_valid in zip(all_sites, valid_results):
                    if is_valid:
                        sites.append(site)
                    else:
                        logger.debug(f"Excluding invalid site from '{filepath}': {site.get('name', 'Unnamed Site')}")
                
                # Lives don't need URL validation, so just add them
                lives.extend(all_lives)
                
                if all_spider and all_spider[0]:
                    spider.extend(all_spider)

            # Case 2: The file is a single site object (new format)
            elif isinstance(data, dict) and 'api' in data and 'name' in data:
                site_url = data.get('api', '')
                if site_url:
                    is_valid = await is_valid_url(site_url, session)
                    if is_valid:
                        sites.append(data)
                    else:
                        logger.debug(f"Excluding invalid single site from '{filepath}': {data.get('name', 'Unnamed Site')}")

            else:
                logger.warning(f"File '{filepath}' does not contain a valid sites config. Skipping.")

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON in file '{filepath}': {e}")
    except Exception as e:
        logger.error(f"An error occurred while processing '{filepath}': {e}")
    
    return sites, lives, spider

async def merge_files(source_files: List[str], output_file: str):
    """
    Merge multiple JSON configuration files into a single one.
    """
    logger.info("Starting file merging process...")
    sites: List[Dict[str, Any]] = []
    lives: List[Dict[str, Any]] = []
    spider: List[str] = []

    async with aiohttp.ClientSession() as session:
        tasks = [process_file(f, session) for f in source_files]
        results = await asyncio.gather(*tasks)
        
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

    # Get a list of all JSON files in the source directory
    if os.path.exists(SOURCE_DIRECTORY) and os.path.isdir(SOURCE_DIRECTORY):
        source_files = [
            os.path.join(SOURCE_DIRECTORY, f)
            for f in os.listdir(SOURCE_DIRECTORY)
            if f.endswith(('.json', '.txt'))
        ]
        if source_files:
            asyncio.run(merge_files(source_files, OUTPUT_FILE))
        else:
            logger.error(f"No .json or .txt files found in the '{SOURCE_DIRECTORY}' directory.")
    else:
        logger.error(f"Source directory '{SOURCE_DIRECTORY}' not found or is not a directory. Please create it and add your JSON/TXT files.")
