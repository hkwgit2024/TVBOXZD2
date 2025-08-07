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
    搜索、验证并保存与 TVbox 强相关的 JSON 接口文件。
    """
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    # 优化的精准搜索查询：
    # 搜索文件名包含 tvbox、box、drpy 或 hipy 的 JSON 文件
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
                
                # 验证文件是否为有效的 TVbox JSON 接口
                if validate_tvbox_interface(content):
                    logger.info(f"Validation successful! It's a valid TVbox JSON. Saving...")
                    
                    save_path = os.path.join("box", file_name)
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    logger.info(f"Successfully saved {file_name} to 'box/'")
                else:
                    logger.warning("Validation failed: Not a TVbox interface. Skipping.")
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching {raw_url}: {e}")
    
    except requests.exceptions.RequestException as e:
        logger.error(f"An error occurred during search: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from search results: {e}")

def validate_tvbox_interface(json_str: str) -> bool:
    """
    检查 JSON 字符串是否为有效的 TVbox 接口格式。
    验证标准：必须是有效的 JSON，且包含特定的 TVbox 接口键名。
    """
    try:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            return False

        # 检查是否包含核心键
        has_sites_key = 'sites' in data and isinstance(data['sites'], list)
        has_lives_key = 'lives' in data and isinstance(data['lives'], list)
        has_spider_key = 'spider' in data and isinstance(data['spider'], str)

        # 一个文件至少要包含sites、lives或spider中的一个
        if not (has_sites_key or has_lives_key or has_spider_key):
            return False

        # 如果有 sites 键，我们进一步检查其子项是否包含 api 或 url 键
        if has_sites_key:
            for site in data['sites']:
                if isinstance(site, dict) and ('api' in site or 'url' in site):
                    return True
        
        # 如果没有 sites 键，但有 lives 或 spider，也认为是有效接口
        if has_lives_key or has_spider_key:
            return True

        return False
    except json.JSONDecodeError:
        return False

if __name__ == "__main__":
    search_and_save_tvbox_interfaces()
