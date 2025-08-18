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

# Define the domains to be excluded
EXCLUDED_DOMAINS = ["agit.ai", "gitcode.net","cccimg.com"]

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
    Returns False for local URLs or if the URL does not respond with 200.
    """
    # Check if the URL is a local file path
    if not url.startswith(('http://', 'https://')):
        logger.debug(f"Skipping local URL: {url}")
        return False
    
    # New check: Exclude if the domain is in the excluded list
    try:
        parsed_url = urlparse(url)
        if parsed_url.netloc in EXCLUDED_DOMAINS:
            logger.debug(f"Excluding URL due to domain: {url}")
            return False
    except ValueError:
        logger.debug(f"Invalid URL format: {url}")
        return False

    # Check cache first
    if url in URL_CACHE:
        logger.debug(f"Using cached result for URL: {url}")
        return URL_CACHE[url]

    # Strip proxy for the actual check
    check_url = strip_proxy(url)

    # Check if the URL is a local file path again after stripping proxy
    if not check_url.startswith(('http://', 'https://')):
        logger.debug(f"Skipping local URL after proxy strip: {url}")
        return False
        
    try:
        async with session.get(check_url, timeout=5) as response:
            result = response.status == 200
            if result:
                logger.debug(f"URL is valid: {url}")
            else:
                logger.debug(f"URL responded with status {response.status}: {url}")
            
            # Update cache, managing size
            if len(URL_CACHE) >= MAX_CACHE_SIZE:
                # Simple cache eviction: remove the oldest item
                oldest_key = next(iter(URL_CACHE))
                del URL_CACHE[oldest_key]
            URL_CACHE[url] = result
            
            return result
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"URL is invalid or inaccessible: {url} -> {e}")
        # Mark as invalid in cache
        URL_CACHE[url] = False
        return False

async def process_file(file_path: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> tuple:
    """
    Process a single JSON file to extract and validate configurations.
    """
    sites = []
    lives = []
    spider = ""
    file_name = os.path.basename(file_path)
    async with sem:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, list):
                # Handle list of configurations
                for item in data:
                    if isinstance(item, dict):
                        if "sites" in item:
                            sites.extend(await process_sites(item.get("sites", []), file_name, session))
                        if "lives" in item:
                            lives.extend(await process_lives(item.get("lives", []), file_name, session))
                        if "spider" in item and not spider:
                            spider = item.get("spider", "")
            elif isinstance(data, dict):
                # Handle single object configuration
                sites.extend(await process_sites(data.get("sites", []), file_name, session))
                lives.extend(await process_lives(data.get("lives", []), file_name, session))
                if "spider" in data and not spider:
                    spider = data.get("spider", "")
            else:
                logger.warning(f"File {file_name} has an unexpected root element type: {type(data)}")

        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from file {file_name}: {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {file_name}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while processing {file_name}: {e}")

    return sites, lives, [spider] if spider else []

async def process_sites(sites_data: List[Dict[str, Any]], file_name: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    """
    Validate and return a list of valid site configurations.
    """
    valid_sites = []
    for site in sites_data:
        if await is_valid_site(site, file_name, session):
            valid_sites.append(site)
    return valid_sites

async def process_lives(lives_data: List[Dict[str, Any]], file_name: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    """
    Validate and return a list of valid live configurations.
    """
    valid_lives = []
    for live in lives_data:
        if await is_valid_live(live, file_name, session):
            valid_lives.append(live)
    return valid_lives

async def is_valid_site(site: Dict[str, Any], file_name: str, session: aiohttp.ClientSession) -> bool:
    """
    Check if a site configuration is valid.
    """
    site_name = site.get('name', 'N/A')

    # Add a new check for `ext` field to exclude specific domains
    ext = site.get('ext')
    if ext:
        try:
            parsed_ext_url = urlparse(ext)
            if parsed_ext_url.netloc in EXCLUDED_DOMAINS:
                logger.debug(f"Excluding site '{site_name}' from {file_name}: 'ext' URL domain is in the excluded list.")
                return False
        except ValueError:
            logger.debug(f"Invalid 'ext' URL format for site '{site_name}': {ext}")
            return False
            
    # Check for type 3 csp APIs that require 'ext'
    if site.get('type') == 3 and site.get('api', '').startswith('csp_'):
        ext_value = site.get('ext')
        if not ext_value:
            logger.debug(f"Excluding site '{site_name}' from {file_name}: 'ext' is missing or empty for csp type 3 API.")
            return False
            
    api_url = site.get('api')
    url = site.get('url')
    
    # Check for site types that require a URL
    if site.get('type') in [0, 1]: # Rule and Json types
        if not url:
            logger.debug(f"Excluding site '{site_name}' from {file_name}: 'url' is missing.")
            return False
        # If URL exists, validate it
        if not await is_valid_url(url, session):
            logger.debug(f"Excluding site '{site_name}' from {file_name}: 'url' is not accessible.")
            return False
    
    # Check for site types that require an API URL
    elif site.get('type') == 2: # XBP type
        if not api_url:
            logger.debug(f"Excluding site '{site_name}' from {file_name}: 'api' is missing.")
            return False
        if not await is_valid_url(api_url, session):
            logger.debug(f"Excluding site '{site_name}' from {file_name}: 'api' URL is not accessible.")
            return False
            
    # Check for sites that require 'ext'
    if ext:
        if not await is_valid_url(ext, session):
            logger.debug(f"Excluding site '{site_name}' from {file_name}: 'ext' URL is not accessible.")
            return False
    
    return True

async def is_valid_live(live: Dict[str, Any], file_name: str, session: aiohttp.ClientSession) -> bool:
    """
    Check if a live configuration is valid.
    """
    live_name = live.get('name', 'N/A')
    url = live.get('url')
    
    # Add a new check for `url` field to exclude specific domains
    if url:
        try:
            parsed_url = urlparse(url)
            if parsed_url.netloc in EXCLUDED_DOMAINS:
                logger.debug(f"Excluding live '{live_name}' from {file_name}: 'url' domain is in the excluded list.")
                return False
        except ValueError:
            logger.debug(f"Invalid 'url' URL format for live '{live_name}': {url}")
            return False
            
    if not url:
        logger.debug(f"Excluding live '{live_name}' from {file_name}: 'url' is missing.")
        return False
        
    if not await is_valid_url(url, session):
        logger.debug(f"Excluding live '{live_name}' from {file_name}: 'url' is not accessible.")
        return False
        
    return True

async def merge_files(file_list: List[str], output_file: str):
    """
    Asynchronously merge TVBox configuration files from a list.
    """
    sites = []
    lives = []
    spider = []

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
        logger.error(f"Source directory '{SOURCE_DIRECTORY}' does not exist.")
