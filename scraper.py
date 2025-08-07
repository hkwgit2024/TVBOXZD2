import requests
import json
import os
import sys
import logging
from typing import Tuple
from datetime import datetime

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def search_and_save_tvbox_interfaces():
    """
    搜索、验证并保存 TVbox 接口文件，并检查更新。
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    query = "filename:tvbox.json OR filename:box.json OR filename:drpy.json OR filename:hipy.json"
    search_url = "https://api.github.com/search/code"
    
    headers = {
        "Authorization": f"token {github_token}",
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
            
            # 获取 GitHub 文件的最后更新时间
            last_modified_str = item.get('repository', {}).get('updated_at')
            
            try:
                # 检查本地是否已存在同名文件，并比较更新时间
                if check_for_updates(file_name, last_modified_str):
                    logger.info(f"Local file is up-to-date. Skipping download.")
                    continue
                
                file_content_response = requests.get(raw_url, timeout=10)
                file_content_response.raise_for_status()
                content = file_content_response.text
                
                if validate_tvbox_interface(content):
                    logger.info(f"Validation successful! It's a valid TVbox JSON. Saving...")
                    
                    # 生成带时间戳的新文件名
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    new_file_name = f"{os.path.splitext(file_name)[0]}_{timestamp}.json"
                    
                    save_path = os.path.join("box", new_file_name)
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    logger.info(f"Successfully saved {new_file_name} to 'box/'")
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

        has_sites_key = 'sites' in data and isinstance(data['sites'], list)
        has_lives_key = 'lives' in data and isinstance(data['lives'], list)
        has_spider_key = 'spider' in data and isinstance(data['spider'], str)

        if not (has_sites_key or has_lives_key or has_spider_key):
            return False

        if has_sites_key:
            for site in data['sites']:
                if isinstance(site, dict) and ('api' in site or 'url' in site):
                    return True
        
        if has_lives_key or has_spider_key:
            return True

        return False
    except json.JSONDecodeError:
        return False

def check_for_updates(file_name: str, last_modified_str: str) -> bool:
    """
    检查本地目录中是否存在同名文件，并比较更新时间。
    """
    if not last_modified_str:
        return False
        
    try:
        github_last_modified = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00'))
        
        for local_file in os.listdir("box"):
            if local_file.startswith(os.path.splitext(file_name)[0]):
                # 从带时间戳的文件名中提取时间
                local_timestamp_str = local_file.rsplit('_', 1)[-1].split('.')[0]
                local_last_modified = datetime.strptime(local_timestamp_str, "%Y%m%d%H%M%S")
                
                # 如果本地文件的创建时间晚于或等于 GitHub 上的更新时间，则认为已是最新
                if local_last_modified >= github_last_modified.replace(tzinfo=None):
                    return True
    except (ValueError, IndexError):
        # 捕获解析时间或文件名格式的错误
        return False
        
    return False

if __name__ == "__main__":
    search_and_save_tvbox_interfaces()
