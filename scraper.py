import requests
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

def search_and_save_tvbox_interfaces():
    """
    搜索并保存符合 TVbox 专用格式的 JSON 接口文件。
    """
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    # 优化的精准搜索查询：
    # 1. 文件名必须是 tvbox、box、drpy 或 hipy 相关的 JSON 文件。
    # 2. 文件内容必须包含 "sites"、"lives" 或 "spider" 键。
    query = (
        "(filename:tvbox.json OR filename:box.json OR filename:drpy.json OR filename:hipy.json)"
        " AND (\"sites\" OR \"lives\" OR \"spider\")"
    )
    
    search_url = "https://api.github.com/search/code"
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.raw"
    }
    
    os.makedirs("box", exist_ok=True)
    
    try:
        logger.info(f"Searching GitHub with query: {query}")
        response = requests.get(search_url, params={"q": query, "per_page": 100}, headers=headers)
        response.raise_for_status()
        
        search_results = response.json()
        items = search_results.get('items', [])
        logger.info(f"Found {len(items)} potential interface files.")
        
        for item in items:
            file_name = item["path"].split("/")[-1]
            repo_full_name = item['repository']['full_name']
            
            logger.info(f"\n--- Processing {file_name} from {repo_full_name} ---")
            
            raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            
            try:
                file_content_response = requests.get(raw_url, timeout=10)
                file_content_response.raise_for_status()
                content = file_content_response.text
                
                is_valid, content_type = validate_interface_json(content)
                if is_valid:
                    logger.info(f"Validation successful! Content type: {content_type}. Saving interface...")
                    
                    save_path = os.path.join("box", file_name)
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    logger.info(f"Successfully saved {file_name} to 'box/'")
                else:
                    logger.warning("Validation failed. Skipping this file.")
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching {raw_url}: {e}")
    
    except requests.exceptions.RequestException as e:
        logger.error(f"An error occurred during search: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from search results: {e}")

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

if __name__ == "__main__":
    search_and_save_tvbox_interfaces()
