# 导入所需的库
import requests
import json
import os
import sys
import logging
from typing import Tuple

# 配置日志记录，确保日志信息能清晰地在 GitHub Actions 中显示
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def search_and_save_tvbox_interfaces():
    """
    使用简化的 GitHub API 查询来搜索和保存 TVbox 接口文件。
    """
    # 从环境变量中获取 GitHub 令牌
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    # 这是一个精简且可靠的搜索查询。
    # 搜索文件名包含 tvbox.json, box.json, drpy.json, hipy.json 中的任意一个，
    # 并且文件内容中包含 sites, lives, 或 spider 这三个关键词中的任意一个。
    # GitHub API 会自动将文件名和关键词的逻辑进行组合，实现 AND 关系。
    query = "filename:tvbox.json OR filename:box.json OR filename:drpy.json OR filename:hipy.json sites OR lives OR spider"
    
    search_url = "https://api.github.com/search/code"
    
    # 设置请求头，包含授权令牌和接受原始文件内容
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3.raw"
    }
    
    # 创建 'box' 目录，如果它不存在的话
    os.makedirs("box", exist_ok=True)
    
    try:
        logger.info(f"Searching GitHub with query: {query}")
        # 发送搜索请求，每页最多获取 100 个结果
        response = requests.get(search_url, params={"q": query, "per_page": 100}, headers=headers)
        # 检查响应状态，如果不是 200，则抛出异常
        response.raise_for_status()
        
        search_results = response.json()
        items = search_results.get('items', [])
        logger.info(f"Found {len(items)} potential interface files.")
        
        # 遍历每个搜索结果
        for item in items:
            file_name = item["path"].split("/")[-1]
            repo_full_name = item['repository']['full_name']
            
            logger.info(f"\n--- Processing {file_name} from {repo_full_name} ---")
            
            # 构造原始文件内容的 URL
            raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            
            try:
                # 下载原始文件内容
                file_content_response = requests.get(raw_url, timeout=10)
                file_content_response.raise_for_status()
                content = file_content_response.text
                
                # 验证文件内容是否符合 TVbox JSON 格式
                is_valid, content_type = validate_interface_json(content)
                if is_valid:
                    logger.info(f"Validation successful! Content type: {content_type}. Saving interface...")
                    
                    # 保存文件到 'box' 目录
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
    验证 JSON 内容是否是 TVbox 接口。
    """
    try:
        data = json.loads(json_str)
        # 检查是否为字典且包含 TVbox 专用键
        if isinstance(data, dict) and any(key in data for key in ("sites", "lives", "spider")):
            return True, "JSON"
    except json.JSONDecodeError:
        pass
    return False, "invalid"

if __name__ == "__main__":
    search_and_save_tvbox_interfaces()
