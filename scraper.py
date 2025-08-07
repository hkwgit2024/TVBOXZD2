import asyncio
import aiohttp
import json
import yaml
import os
import sys
import logging
from typing import Tuple, Optional
from urllib.parse import urlencode

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

async def search_and_save_tvbox_interfaces() -> None:
    """
    Asynchronously searches GitHub for TVbox interface files (JSON and YAML),
    validates them, and saves valid ones to a local 'box/' directory.
    """
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    query = (
        "filename:tvbox.json OR filename:tvbox.yml OR filename:alist.yml OR "
        "filename:drpy.json OR \"sites\" in:file OR \"spider\" in:file"
    )
    search_url = "https://api.github.com/search/code"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {"q": query, "per_page": 100}  # 增加每页结果数

    os.makedirs("box", exist_ok=True)  # 简化目录创建

    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            logger.info(f"Searching GitHub with query: {query}")
            async with session.get(search_url, params=params) as response:
                response.raise_for_status()
                search_results = await response.json()
                items = search_results.get('items', [])
                logger.info(f"Found {len(items)} potential interface files.")

                tasks = [process_file(session, item) for item in items]
                await asyncio.gather(*tasks, return_exceptions=True)

        except aiohttp.ClientError as e:
            logger.error(f"Network error occurred: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from search results: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

async def process_file(session: aiohttp.ClientSession, item: dict) -> None:
    """
    Process a single file from GitHub search results.
    """
    file_name = item["path"].split("/")[-1].lower()
    repo_full_name = item['repository']['full_name']

    # 过滤无关文件
    if 'config.yml' in file_name and ('-sdk' in repo_full_name.lower() or 'actions' in repo_full_name.lower()):
        logger.debug(f"Skipping irrelevant file: {file_name} from {repo_full_name}")
        return

    logger.info(f"Processing {file_name} from {repo_full_name}")
    raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    try:
        async with session.get(raw_url) as response:
            if response.status != 200:
                logger.warning(f"Failed to fetch {raw_url}: HTTP {response.status}")
                return
            content = await response.text()

        is_valid, content_type = validate_file_content(file_name, content)
        if is_valid:
            logger.info(f"Validation successful for {file_name}. Content type: {content_type}")
            save_path = os.path.join("box", file_name)
            async with asyncio.Lock():  # 防止并发写文件冲突
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(content)
            logger.info(f"Successfully saved {file_name} to 'box/'")
        else:
            logger.warning(f"Validation failed for {file_name}. Skipping.")
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching {raw_url}: {e}")

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
        if isinstance(data, dict) and any(key in data for key in ("sites", "spider", "proxies")):
            return True, "YAML"
    except yaml.YAMLError:
        pass
    return False, "invalid"

if __name__ == "__main__":
    asyncio.run(search_and_save_tvbox_interfaces())
