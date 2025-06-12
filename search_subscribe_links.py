import os
import requests
import json
import time
from urllib.parse import urlparse, quote
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT_TOKEN")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3.text-match+json"
}
SEARCH_QUERY = quote("subscribe?token=")  # 放宽查询

DATA_DIR = "data"
OUTPUT_FILE = os.path.join(DATA_DIR, "subscribe_links.txt")

def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created directory: {DATA_DIR}")

def test_url_connectivity(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException as e:
        logger.error(f"Failed to connect to {url}: {e}")
        return False

def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ""

def search_github():
    if not TOKEN:
        logger.error("BOT_TOKEN is not set in environment variables")
        return set()
        
    unique_urls = set()
    page = 1
    per_page = 30

    while True:
        params = {
            "q": SEARCH_QUERY,
            "per_page": per_page,
            "page": page
        }
        
        try:
            logger.info(f"Current time: {datetime.now()}")
            response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
            response.raise_for_status()
            data = response.json()
            items = data.get("items", [])
            logger.info(f"API response items count: {len(items)}, total_count: {data.get('total_count', 0)}")
            
            if not items:
                logger.info("No more results found, stopping search")
                break
                
            for item in items:
                raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                text_matches = item.get("text_matches", [])
                logger.info(f"Text matches for {raw_url}: {json.dumps(text_matches, indent=2)}")
                # 临时跳过 text_matches 检查，添加所有 URL
                unique_urls.add(raw_url)
                logger.info(f"Added URL: {raw_url}")
                        
            logger.info(f"Processed page {page}, found {len(unique_urls)} unique URLs so far")
            
            if "X-RateLimit-Remaining" in response.headers:
                remaining = int(response.headers["X-RateLimit-Remaining"])
                if remaining < 20:
                    logger.warning(f"Approaching rate limit ({remaining} remaining), sleeping...")
                    time.sleep(30)
                    
            page += 1
            time.sleep(5)  # 增加间隔以降低速率限制风险
            
        except requests.RequestException as e:
            logger.error(f"Error during GitHub API request: {e}, Response: {response.text}")
            break
            
    return unique_urls

def save_urls(urls):
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
    logger.info("Starting GitHub API search for subscribe links")
    
    urls = search_github()
    logger.info(f"Found {len(urls)} unique URLs")
    
    valid_urls = save_urls(urls)
    logger.info(f"Saved {len(valid_urls)} valid URLs to {OUTPUT_FILE}")
    
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
