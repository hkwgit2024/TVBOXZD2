import json
import os
import sys
import logging
from typing import List, Dict, Any
import asyncio
import aiohttp
from urllib.parse import urlparse
import concurrent.futures

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Cache for checked URLs to avoid redundant requests
URL_CACHE = {}

def strip_proxy(url: str) -> str:
    """
    Strip proxy prefixes like 'https://ghproxy.com/' from the URL,
    returning the original GitHub raw URL if detected.
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
    Returns False for local URLs (127.0.0.1, localhost) or if the URL is unreachable.
    """
    # Check cache first
    if url in URL_CACHE:
        logger.debug(f"Using cached result for URL: {url}")
        return URL_CACHE[url]

    # Strip proxy if present
    url = strip_proxy(url)

    # Exclude localhost URLs
    parsed = urlparse(url)
    if parsed.hostname in ('127.0.0.1', 'localhost'):
        logger.debug(f"URL excluded (localhost): {url}")
        URL_CACHE[url] = False
        return False

    # Skip non-HTTP URLs
    if not url.startswith(('http://', 'https://')):
        logger.debug(f"URL excluded (invalid scheme): {url}")
        URL_CACHE[url] = False
        return False

    try:
        async with session.head(url, timeout=5, allow_redirects=True) as response:
            is_valid = response.status == 200
            URL_CACHE[url] = is_valid
            if not is_valid:
                logger.debug(f"URL excluded (status code {response.status}): {url}")
            return is_valid
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"URL excluded (unreachable, {str(e)}): {url}")
        URL_CACHE[url] = False
        return False

def is_valid_site(site: Dict[str, Any], session: aiohttp.ClientSession) -> bool:
    """
    Validate a site configuration synchronously to integrate with list comprehension.
    Returns True if site is valid, False otherwise.
    """
    # Check for required fields
    if not isinstance(site, dict) or not ('api' in site or 'url' in site):
        logger.debug(f"Site excluded (missing api or url): {site.get('name', 'unknown')}")
        return False

    # Check 'ext' field for local files
    ext = site.get('ext', '')
    if isinstance(ext, str):
        if ext.startswith(('./', 'file://')) or os.path.isabs(ext):
            logger.debug(f"Site excluded (local file path in ext): {site.get('name', 'unknown')}")
            return False

    # Note: URL validation is done asynchronously in validate_urls_for_site
    return True

async def validate_urls_for_site(site: Dict[str, Any], session: aiohttp.ClientSession) -> bool:
    """
    Validate URLs in 'ext' and 'api' fields asynchronously.
    """
    ext = site.get('ext', '')
    api = site.get('api', '')

    # Check 'ext' URL
    if isinstance(ext, str) and ext.startswith(('http://', 'https://')):
        if not await is_valid_url(ext, session):
            return False

    # Check 'api' URL
    if isinstance(api, str) and api.startswith(('http://', 'https://')):
        if not await is_valid_url(api, session):
            return False

    return True

async def process_file(file_path: str, session: aiohttp.ClientSession) -> tuple:
    """
    Process a single JSON file asynchronously.
    Returns a tuple of (sites, lives, spider).
    """
    sites = []
    lives = []
    spider = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Extract sites configuration
        if 'sites' in data and isinstance(data['sites'], list):
            # First filter for basic validity (non-URL checks)
            candidate_sites = [site for site in data['sites'] if is_valid_site(site, session)]
            # Validate URLs asynchronously
            valid_sites = []
            for site in candidate_sites:
                if await validate_urls_for_site(site, session):
                    valid_sites.append(site)
            sites.extend(valid_sites)
            logger.info(f"Processed {len(valid_sites)} valid sites from {os.path.basename(file_path)} "
                        f"({len(data['sites']) - len(valid_sites)} excluded)")

        # Extract lives configuration
        if 'lives' in data and isinstance(data['lives'], list):
            lives.extend(data['lives'])

        # Extract spider configuration, only keeping the first one found
        if not spider and 'spider' in data and isinstance(data['spider'], str):
            spider.append(data['spider'])

        logger.info(f"Successfully processed file: {os.path.basename(file_path)}")

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in file '{file_path}', skipping.")
    except Exception as e:
        logger.error(f"An error occurred while processing file '{file_path}': {e}")

    return sites, lives, spider

async def merge_tvbox_configs(source_dir: str, output_file: str) -> None:
    """
    Traverses a directory of JSON files, merges TVbox configurations, and saves them to a new file.
    Filters out invalid sites based on defined criteria, using async URL checks.
    """
    sites = []
    lives = []
    spider = []

    file_list = [os.path.join(source_dir, f) for f in os.listdir(source_dir) if f.endswith('.json')]
    
    if not file_list:
        logger.warning(f"No JSON files found in directory '{source_dir}'.")
        return

    logger.info(f"Starting to process {len(file_list)} JSON files...")

    # Create aiohttp session with retry configuration
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Process files concurrently
        tasks = [process_file(file_path, session) for file_path in file_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        for result in results:
            if isinstance(result, tuple):
                file_sites, file_lives, file_spider = result
                sites.extend(file_sites)
                lives.extend(file_lives)
                if file_spider and not spider:
                    spider.extend(file_spider)

    # Build the merged configuration
    merged_data = {
        "sites": sites,
        "lives": lives,
        "spider": spider[0] if spider else ""
    }

    # Save the merged JSON file
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
