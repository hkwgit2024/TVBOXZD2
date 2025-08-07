import asyncio
import aiohttp
import json
import yaml
import os
import sys
import logging
from typing import Tuple

# Configure logging to output to stdout, which is visible in GitHub Actions logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = get_logger(__name__)

async def search_and_save_tvbox_interfaces():
    """
    Asynchronously searches GitHub for TVbox interface files,
    validates them, and saves valid ones.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    # A more precise query that avoids broad terms to prevent the 422 error.
    # We focus on specific filenames and unique keywords that are less likely to be rate-limited.
    query = (
        "filename:tvbox.json OR filename:tvbox.yml OR filename:alist.yml OR "
        "filename:drpy.json OR \"drpy\" in:file OR \"hipy\" in:file"
    )
    search_url = "https://api.github.com/search/code"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {"q": query, "per_page": 100}

    os.makedirs("box", exist_ok=True)

    try:
        logger.info(f"Searching GitHub with query: {query}")
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(search_url, params=params) as response:
                response.raise_for_status()
                search_results = await response.json()
                items = search_results.get('items', [])
                logger.info(f"Found {len(items)} potential interface files.")

                tasks = [process_file(session, item) for item in items]
                await asyncio.gather(*tasks)

    except aiohttp.ClientError as e:
        logger.error(f"Network error occurred: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from search results: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

async def process_file(session: aiohttp.ClientSession, item: dict):
    """
    Process a single file from GitHub search results.
    """
    file_name = item["path"].split("/")[-1]
    repo_full_name = item['repository']['full_name']

    # We can now be a bit more aggressive with filtering, as the query is more specific
    if file_name.endswith(('.jsonc', '.yml', '.yaml')) and not any(
        kw in file_name.lower() for kw in ('tvbox', 'alist', 'drpy', 'hipy')
    ):
        logger.info(f"Skipping potentially irrelevant file: {file_name} from {repo_full_name}")
        return

    logger.info(f"Processing {file_name} from {repo_full_name}")
    raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    try:
        async with session.get(raw_url) as response:
            response.raise_for_status()
            content = await response.text()
            
            is_valid, content_type = validate_file_content(file_name, content)
            if is_valid:
                logger.info(f"Validation successful for {file_name}. Content type: {content_type}")
                save_path = os.path.join("box", file_name)
                # Use a lock to prevent concurrent write conflicts
                async with asyncio.Lock():
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content)
                logger.info(f"Successfully saved {file_name} to 'box/'")
            else:
                logger.warning(f"Validation failed for {file_name}. Skipping.")
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching {raw_url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during file processing: {e}")

def validate_file_content(file_name: str, content: str) -> Tuple[bool, str]:
    """
    Validate the content of a file based on its extension.
    """
    try:
        if file_name.endswith((".json", ".jsonc")):
            return validate_interface_json(content)
        elif file_name.endswith((".yml", ".yaml")):
            return validate_interface_yaml(content)
    except Exception as e:
        logger.error(f"Validation error for {file_name}: {e}")
    return False, "invalid"

def validate_interface_json(json_str: str) -> Tuple[bool, str]:
    """
    Validate JSON content for TVbox interface.
    """
    try:
        data = json.loads(json_str)
        # Check for key TVbox interface fields
        if isinstance(data, dict) and any(key in data for key in ("sites", "lives", "spider")):
            return True, "JSON"
    except json.JSONDecodeError:
        pass
    return False, "invalid"

def validate_interface_yaml(yaml_str: str) -> Tuple[bool, str]:
    """
    Validate YAML content for TVbox interface.
    """
    try:
        data = yaml.safe_load(yaml_str)
        # Check for key TVbox interface fields
        if isinstance(data, dict) and any(key in data for key in ("sites", "spider", "proxies")):
            return True, "YAML"
    except yaml.YAMLError:
        pass
    return False, "invalid"

if __name__ == "__main__":
    asyncio.run(search_and_save_tvbox_interfaces())
