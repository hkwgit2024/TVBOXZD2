import asyncio
import aiohttp
import json
import os
import sys
import logging
from typing import Tuple

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

async def check_url_availability(session, url):
    """
    异步检查 URL 是否可用（状态码为 200）。
    """
    try:
        async with session.head(url, timeout=5) as response:
            return response.status == 200
    except aiohttp.ClientError:
        return False

def extract_urls_from_json(content):
    """
    从 JSON 内容中提取所有可能的接口 URL。
    """
    try:
        data = json.loads(content)
        urls = []
        if 'sites' in data and isinstance(data['sites'], list):
            for site in data['sites']:
                if 'api' in site:
                    urls.append(site['api'])
                elif 'url' in site:
                    urls.append(site['url'])
        return urls
    except json.JSONDecodeError:
        return []

async def search_and_save_tvbox_interfaces():
    """
    搜索、验证并保存可用的 TVbox JSON 接口文件。
    """
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    query = "filename:tvbox.json OR filename:box.json OR filename:drpy.json OR filename:hipy.json"
    search_url = "https://api.github.com/search/code"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {"q": query, "per_page": 100}
    os.makedirs("box", exist_ok=True)

    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            logger.info(f"Searching GitHub with query: {query}")
            async with session.get(search_url, params=params) as response:
                response.raise_for_status()
                search_results = await response.json()
                items = search_results.get('items', [])
                logger.info(f"Found {len(items)} potential interface files.")

                tasks = [process_and_validate_file(session, item) for item in items]
                await asyncio.gather(*tasks, return_exceptions=True)

        except aiohttp.ClientError as e:
            logger.error(f"Network error occurred during search: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from search results: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

async def process_and_validate_file(session, item):
    file_name = item["path"].split("/")[-1]
    repo_full_name = item['repository']['full_name']
    
    logger.info(f"\n--- Processing {file_name} from {repo_full_name} ---")
    
    raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    
    try:
        async with session.get(raw_url, timeout=10) as file_content_response:
            file_content_response.raise_for_status()
            content = await file_content_response.text()

            # 验证文件是否是有效的 TVbox JSON
            is_tvbox_json, _ = validate_interface_json(content)
            if not is_tvbox_json:
                logger.warning("Validation failed: Not a valid TVbox JSON. Skipping.")
                return

            # 在线验证其包含的接口 URL
            urls_to_check = extract_urls_from_json(content)
            if not urls_to_check:
                logger.warning(f"No valid URLs found in {file_name}. Skipping.")
                return

            # 并发检查所有 URL
            check_tasks = [check_url_availability(session, url) for url in urls_to_check]
            results = await asyncio.gather(*check_tasks)

            if any(results):
                logger.info(f"Online validation successful for {file_name}. At least one URL is reachable.")
                save_path = os.path.join("box", file_name)
                # 防止并发写文件冲突
                async with asyncio.Lock():
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content)
                logger.info(f"Successfully saved {file_name} to 'box/'")
            else:
                logger.warning(f"Online validation failed for all URLs in {file_name}. Skipping.")
    
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching {raw_url}: {e}")
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON from {raw_url}.")

def validate_interface_json(json_str: str) -> Tuple[bool, str]:
    """
    验证 JSON 内容是否是 TVbox 接口。
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
