import os
import requests
import json
import time
from urllib.parse import urlparse
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub API 配置
GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT_TOKEN")  # 确保在环境变量中设置 BOT_TOKEN
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}
SEARCH_QUERY = "/api/v1/client/subscribe?token="

# 数据存储目录
DATA_DIR = "data"
OUTPUT_FILE = os.path.join(DATA_DIR, "subscribe_links.txt")

def ensure_data_dir():
    """确保数据目录存在"""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created directory: {DATA_DIR}")

def test_url_connectivity(url):
    """测试URL连通性"""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException as e:
        logger.error(f"Failed to connect to {url}: {e}")
        return False

def get_domain(url):
    """提取URL的域名"""
    try:
        return urlparse(url).netloc
    except:
        return ""

def search_github():
    """搜索GitHub中的订阅链接"""
    unique_urls = set()
    page = 1
    per_page = 100

    while True:
        params = {
            "q": SEARCH_QUERY,
            "per_page": per_page,
            "page": page
        }
        
        try:
            response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
            response.raise_for_status()
            data = response.json()
            
            if not data.get("items"):
                break
                
            for item in data["items"]:
                # 获取代码片段的原始URL
                raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                if SEARCH_QUERY in item["html_url"]:
                    unique_urls.add(raw_url)
                    
            logger.info(f"Processed page {page}, found {len(unique_urls)} unique URLs so far")
            
            # 处理API速率限制
            if "X-RateLimit-Remaining" in response.headers:
                remaining = int(response.headers["X-RateLimit-Remaining"])
                if remaining < 10:
                    logger.warning("Approaching rate limit, sleeping...")
                    time.sleep(60)
                    
            page += 1
            time.sleep(1)  # 避免请求过快
            
        except requests.RequestException as e:
            logger.error(f"Error during GitHub API request: {e}")
            break
            
    return unique_urls

def save_urls(urls):
    """保存URL到文件，并测试连通性"""
    ensure_data_dir()
    valid_urls = []
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for url in urls:
            if test_url_connectivity(url):
                f.write(f"{url}\n")
                valid_urls.append(url)
                logger.info(f"Valid URL saved: {url}")
            else:
                logger.warning(f"Invalid or unreachable URL: {url}")
                
    return valid_urls

def main():
    """主函数"""
    logger.info("Starting GitHub API search for subscribe links")
    
    # 搜索链接
    urls = search_github()
    logger.info(f"Found {len(urls)} unique URLs")
    
    # 保存并测试连通性
    valid_urls = save_urls(urls)
    logger.info(f"Saved {len(valid_urls)} valid URLs to {OUTPUT_FILE}")
    
    # 按域名统计
    domains = {}
    for url in valid_urls:
        domain = get_domain(url)
        if domain:
            domains[domain] = domains.get(domain, 0) + 1
            
    logger.info("Domain distribution:")
    for domain, count in domains.items():
        logger.info(f"{domain}: {count} URLs")

if __name__ == "__main__":
    main()
