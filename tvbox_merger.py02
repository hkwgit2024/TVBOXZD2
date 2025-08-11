import json
import os
import sys
import logging
from typing import List, Dict, Any
import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def strip_proxy(url: str) -> str:
    """
    Strip proxy prefixes like 'https://ghproxy.com/' or 'https://ghp.ci/' from the URL,
    returning the original GitHub raw URL if detected.
    """
    proxies = [
        'https://ghproxy.com/',
        'https://ghp.ci/',
        'https://raw.gitmirror.com/',
        'https://github.3x25.com/',
        # Add more proxies if needed
    ]
    
    for proxy in proxies:
        if url.startswith(proxy):
            # Remove the proxy prefix
            original_url = url[len(proxy):]
            # Ensure it's a valid URL; if not starting with http/https, prepend https://
            if not original_url.startswith(('http://', 'https://')):
                original_url = 'https://' + original_url
            logger.debug(f"Stripped proxy from URL: {url} -> {original_url}")
            return original_url
    
    return url

def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid and accessible.
    Returns False for local URLs (127.0.0.1, localhost) or if the URL is unreachable.
    Strips proxy prefixes before checking.
    """
    # Strip proxy if present
    url = strip_proxy(url)

    # Exclude localhost URLs
    parsed = urlparse(url)
    if parsed.hostname in ('127.0.0.1', 'localhost'):
        logger.debug(f"URL excluded (localhost): {url}")
        return False

    # Check if URL is accessible
    try:
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.head(url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            return True
        logger.debug(f"URL excluded (status code {response.status_code}): {url}")
        return False
    except requests.RequestException as e:
        logger.debug(f"URL excluded (unreachable, {str(e)}): {url}")
        return False

def is_valid_site(site: Dict[str, Any]) -> bool:
    """
    Validate a site configuration.
    Excludes sites with:
    - Missing 'api' or 'url' fields
    - Local file paths in 'ext' (e.g., './lib/xxx.json', 'file://', or absolute paths)
    - Invalid or inaccessible URLs in 'ext' or 'api'
    """
    # Check for required fields
    if not isinstance(site, dict) or not ('api' in site or 'url' in site):
        logger.debug(f"Site excluded (missing api or url): {site.get('name', 'unknown')}")
        return False

    # Check 'ext' field for local files or invalid URLs
    ext = site.get('ext', '')
    if isinstance(ext, str):
        # Exclude local file paths
        if ext.startswith(('./', 'file://')) or os.path.isabs(ext):
            logger.debug(f"Site excluded (local file path in ext): {site.get('name', 'unknown')}")
            return False
        # Check if ext is a valid URL
        if ext.startswith(('http://', 'https://')) and not is_valid_url(ext):
            logger.debug(f"Site excluded (invalid ext URL): {site.get('name', 'unknown')}")
            return False

    # Check 'api' field for invalid URLs
    api = site.get('api', '')
    if api.startswith(('http://', 'https://')) and not is_valid_url(api):
        logger.debug(f"Site excluded (invalid api URL): {site.get('name', 'unknown')}")
        return False

    return True

def merge_tvbox_configs(source_dir: str, output_file: str) -> None:
    """
    Traverses a directory of JSON files, merges TVbox configurations, and saves them to a new file.
    Filters out invalid sites based on defined criteria.
    """
    sites = []
    lives = []
    spider = []

    file_list = [f for f in os.listdir(source_dir) if f.endswith('.json')]
    
    if not file_list:
        logger.warning(f"No JSON files found in directory '{source_dir}'.")
        return

    logger.info(f"Starting to process {len(file_list)} JSON files...")

    for file_name in file_list:
        file_path = os.path.join(source_dir, file_name)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # Extract sites configuration
                if 'sites' in data and isinstance(data['sites'], list):
                    valid_sites = [site for site in data['sites'] if is_valid_site(site)]
                    sites.extend(valid_sites)
                    logger.info(f"Processed {len(valid_sites)} valid sites from {file_name} "
                               f"({len(data['sites']) - len(valid_sites)} excluded)")

                # Extract lives configuration
                if 'lives' in data and isinstance(data['lives'], list):
                    lives.extend(data['lives'])

                # Extract spider configuration, only keeping the first one found
                if not spider and 'spider' in data and isinstance(data['spider'], str):
                    spider.append(data['spider'])

                logger.info(f"Successfully processed file: {file_name}")

        except json.JSONDecodeError:
            logger.error(f"Invalid JSON format in file '{file_name}', skipping.")
        except Exception as e:
            logger.error(f"An error occurred while processing file '{file_name}': {e}")

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
    merge_tvbox_configs(SOURCE_DIRECTORY, OUTPUT_FILE)
