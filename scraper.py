import asyncio
import aiohttp
import json
import os
import sys
import logging
from typing import Tuple, Optional

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

async def search_and_save_tvbox_interfaces() -> None:
    """
    Asynchronously searches GitHub for TVbox-related JSON files with specific filenames
    and content containing 'sites', 'lives', or 'spider', and saves valid ones to 'box/'.
    """
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    # 精确查询：仅搜索文件名包含 tvbox、box、drpy 或 hipy 的 JSON 文件
    # 同时要求内容包含 "sites"、"lives" 或 "spider"
    query = (
        'from:*.json tvbox OR box OR drpy OR hipy "sites" OR "lives" OR "spider"'
    )
    search_url = "https://api.github.com/search/code"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {"q": query, "per_page": 30, "page": 1}

    os.makedirs("box", exist_ok=True)

    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            logger.info(f"Searching GitHub with query: {query}")
            while True:
                async with session.get(search_url, params=params) as response:
                    if response.status == 422:
                        logger.error(f"Query failed with HTTP 422: {await response.text()}")
                        sys.exit(1)
                    response.raise_for_status()
                    search_results = await response.json()
                    items = search_results.get('items', [])
                    logger.info(f"Page {params['page']}: Found {len(items)} files")
                    if not items:
                        break
                    tasks = [process_file(session, item) for item in items]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    params["page"] += 1
                    await asyncio.sleep(1)  # 避免速率限制
        except aiohttp.ClientError as e:
            logger.error(f"Network error occurred: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

async def process_file(session: aiohttp.ClientSession, item: dict) -> None:
    """
    Process a single JSON file from GitHub search results.
    """
    file_name = item["path"].split("/")[-1].lower()
    repo_full_name = item['repository']['full_name']

    # 过滤非 JSON 文件和无关文件名
    if not file_name.endswith((".json", ".jsonc")) or not any(keyword in file_name for keyword in ("tvbox", "box", "drpy", "hipy")):
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

        is_valid, content_type = validate_interface_json(content)
        if is_valid:
            logger.info(f"Validation successful for {file_name}. Content type: {content_type}")
            save_path = os.path.join("box", file_name)
            async with asyncio.Lock():
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(content)
            logger.info(f"Successfully saved {file_name} to 'box/'")
        else:
            logger.warning(f"Validation failed for {file_name}. Skipping.")
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching {raw_url}: {e}")

def validate_interface_json(json_str: str) -> Tuple[bool, str]:
    """
    Validate JSON content for TVbox interface, ensuring it contains 'sites', 'lives', or 'spider'.
    """
    try:
        data = json.loads(json_str)
        if isinstance(data, dict) and any(key in data for key in ("sites", "lives", "spider")):
            return True, "JSON"
    except json.JSONDecodeError:
        pass
    return False, "invalid"

if __name__ == "__main__":
    asyncio.run(search_and_save_tvbox_interfaces())
