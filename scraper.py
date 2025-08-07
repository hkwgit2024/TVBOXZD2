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
    搜索并保存所有有效的 JSON 接口文件，不做在线验证。
    """
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    # 恢复到之前成功的搜索查询，并且只搜索 JSON 文件
    query = "filename:tvbox.json OR filename:box.json OR filename:drpy.json OR filename:hipy.json"
    
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
                
                # 唯一的验证：确保是有效的 JSON 格式
                if is_valid_json(content):
                    logger.info(f"Validation successful! It's a valid JSON file. Saving...")
                    
                    save_path = os.path.join("box", file_name)
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    logger.info(f"Successfully saved {file_name} to 'box/'")
                else:
                    logger.warning("Validation failed: Not a valid JSON format. Skipping.")
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching {raw_url}: {e}")
    
    except requests.exceptions.RequestException as e:
        logger.error(f"An error occurred during search: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from search results: {e}")

def is_valid_json(json_str: str) -> bool:
    """
    检查字符串是否是有效的 JSON 格式。
    """
    try:
        json.loads(json_str)
        return True
    except json.JSONDecodeError:
        return False

if __name__ == "__main__":
    search_and_save_tvbox_interfaces()
