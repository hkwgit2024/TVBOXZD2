import os
import requests
import json
import time
from urllib.parse import urlparse
from datetime import datetime
import logging
import re # 导入re模块用于正则表达式
import random # 导入random模块用于随机User-Agent

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub API 配置
GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT_TOKEN")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3.text-match+json"  # 启用text-match以获取代码片段
}
SEARCH_QUERY = "/api/v1/client/subscribe?token="  # 原始查询字符串
# 用于在文件内容中匹配完整订阅链接的正则表达式
# 匹配 http/https 开头，接着是任意非空白字符直到包含 SEARCH_QUERY，并继续匹配到非空白字符
SUBSCRIBE_LINK_REGEX = r"https?:\/\/[^\s\"']*\/api\/v1\/client\/subscribe\?token=[^\s\"']+"

# 数据存储目录
DATA_DIR = "data"
OUTPUT_FILE = os.path.join(DATA_DIR, "subscribe_links.txt")

# 随机User-Agent列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
]

def get_random_user_agent():
    """获取一个随机User-Agent"""
    return random.choice(USER_AGENTS)

def ensure_data_dir():
    """确保数据目录存在"""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created directory: {DATA_DIR}")

def test_url_connectivity(url):
    """测试URL连通性"""
    try:
        # 使用GET请求，因为HEAD请求可能在某些情况下被阻止或行为不同
        response = requests.get(url, timeout=10, allow_redirects=True, headers={'User-Agent': get_random_user_agent()})
        # 检查状态码是否表示成功（200-299）
        return 200 <= response.status_code < 300
    except requests.RequestException as e:
        logger.error(f"Failed to connect to {url}: {e}")
        return False

def get_domain(url):
    """提取URL的域名"""
    try:
        return urlparse(url).netloc
    except Exception as e:
        logger.error(f"Error parsing domain from URL {url}: {e}")
        return ""

def search_github():
    """搜索GitHub中的包含特定查询字符串的文件URL"""
    if not TOKEN:
        logger.error("BOT_TOKEN is not set in environment variables")
        return set()
        
    unique_raw_github_urls = set()
    page = 1
    per_page = 30  # 减少每页结果以降低速率限制影响

    while True:
        params = {
            "q": SEARCH_QUERY,
            "per_page": per_page,
            "page": page
        }
        
        try:
            logger.info(f"Current time: {datetime.now()}, Searching page {page}")
            # 在API请求头中添加随机User-Agent
            github_headers = HEADERS.copy()
            github_headers['User-Agent'] = get_random_user_agent()

            response = requests.get(GITHUB_API_URL, headers=github_headers, params=params)
            response.raise_for_status() # 对非200状态码抛出HTTPError
            data = response.json()
            items = data.get("items", [])
            logger.info(f"API response items count: {len(items)} for page {page}")
            
            if not items:
                logger.info("No more results found or end of pages, stopping search.")
                break
                
            for item in items:
                # 将html_url转换为raw URL
                # 检查是否是"blob"路径，如果是，则替换为raw.githubusercontent.com的路径
                # 兼容不同GitHub URL格式
                html_url = item["html_url"]
                if "/blob/" in html_url:
                    raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                elif "/tree/" in html_url: # 如果是目录，则跳过
                    logger.warning(f"Skipping directory URL: {html_url}")
                    continue
                else: # 可能是其他格式，尝试直接替换
                    raw_url = html_url.replace("github.com", "raw.githubusercontent.com")

                # 检查text_matches中的代码片段，确保查询字符串存在于片段中
                text_matches = item.get("text_matches", [])
                for match in text_matches:
                    if SEARCH_QUERY in match.get("fragment", ""):
                        unique_raw_github_urls.add(raw_url)
                        logger.debug(f"Found and added raw GitHub file URL: {raw_url}") # 使用debug级别，避免日志过多
                        break # 找到一个匹配即可
                        
            logger.info(f"Processed page {page}, found {len(unique_raw_github_urls)} unique raw GitHub file URLs so far.")
            
            # 检查速率限制
            if "X-RateLimit-Remaining" in response.headers:
                remaining = int(response.headers["X-RateLimit-Remaining"])
                reset_time = int(response.headers["X-RateLimit-Reset"])
                current_time = int(time.time())
                
                if remaining < 50: # 当剩余请求少于50时开始谨慎
                    sleep_duration = max(30, (reset_time - current_time) + 5) # 至少等待30秒，或等到重置时间加5秒
                    logger.warning(f"Approaching GitHub API rate limit ({remaining} remaining), sleeping for {sleep_duration} seconds until reset at {datetime.fromtimestamp(reset_time)}...")
                    time.sleep(sleep_duration)
                elif remaining < 100: # 稍微多等待一下
                    time.sleep(5)
                else:
                    time.sleep(2) # 正常请求间隔
            else:
                time.sleep(2) # 如果没有速率限制信息，默认间隔
            
            page += 1
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during GitHub API request (page {page}): {e}. Response text: {response.text if 'response' in locals() else 'N/A'}")
            if response.status_code == 403:
                logger.error("Rate limit likely exceeded. Please wait or check your BOT_TOKEN.")
            break
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response from GitHub API (page {page}): {e}. Response text: {response.text if 'response' in locals() else 'N/A'}")
            break
            
    return unique_raw_github_urls

def fetch_and_extract_subscribe_links(raw_github_url):
    """
    从给定的GitHub原始文件URL下载内容，并从中提取实际的订阅链接。
    """
    extracted_links = set()
    try:
        logger.info(f"Fetching content from: {raw_github_url}")
        # 在内容下载请求头中添加随机User-Agent
        response = requests.get(raw_github_url, timeout=15, headers={'User-Agent': get_random_user_agent()})
        response.raise_for_status() # 对非200状态码抛出HTTPError
        
        content = response.text
        # 使用正则表达式在文件内容中查找订阅链接
        found_matches = re.findall(SUBSCRIBE_LINK_REGEX, content)
        for link in found_matches:
            extracted_links.add(link)
            logger.debug(f"Extracted subscribe link: {link} from {raw_github_url}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching content from {raw_github_url}: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while processing {raw_github_url}: {e}")
    
    return list(extracted_links) # 返回列表，因为set不能直接被后续函数修改

def save_urls(urls_to_save, filename=OUTPUT_FILE):
    """保存URL到文件，并测试连通性"""
    ensure_data_dir()
    valid_urls_count = 0
    
    with open(filename, "w", encoding="utf-8") as f:
        for url in urls_to_save:
            if test_url_connectivity(url):
                f.write(f"{url}\n")
                valid_urls_count += 1
                logger.info(f"Valid URL saved: {url}")
            else:
                logger.warning(f"Invalid or unreachable URL: {url}")
                
    return valid_urls_count

def main():
    """主函数"""
    logger.info("Starting GitHub search for subscribe links")
    
    # 搜索包含查询字符串的GitHub原始文件URL
    raw_github_file_urls = search_github()
    logger.info(f"Found {len(raw_github_file_urls)} unique raw GitHub file URLs to process.")
    
    all_actual_subscribe_links = set()
    
    # 逐个原始文件URL进行内容抓取和链接提取
    for i, raw_url in enumerate(raw_github_file_urls):
        logger.info(f"Processing raw GitHub file URL {i+1}/{len(raw_github_file_urls)}: {raw_url}")
        actual_links = fetch_and_extract_subscribe_links(raw_url)
        if actual_links:
            for link in actual_links:
                all_actual_subscribe_links.add(link)
        time.sleep(1) # 每次下载内容后稍微等待，避免对GitHub raw内容服务造成压力

    logger.info(f"Found a total of {len(all_actual_subscribe_links)} potential actual subscribe links.")
    
    # 保存并测试连通性
    if all_actual_subscribe_links:
        valid_links_count = save_urls(list(all_actual_subscribe_links)) # 将set转换为list以便传递
        logger.info(f"Successfully saved {valid_links_count} valid actual subscribe links to {OUTPUT_FILE}")
    else:
        logger.info("No actual subscribe links found to save.")
        
    # 按域名统计
    domains = {}
    for url in all_actual_subscribe_links:
        domain = get_domain(url)
        if domain:
            domains[domain] = domains.get(domain, 0) + 1
            
    logger.info("Domain distribution of actual subscribe links:")
    if domains:
        for domain, count in sorted(domains.items(), key=lambda item: item[1], reverse=True):
            logger.info(f"{domain}: {count} URLs")
    else:
        logger.info("No domains to display.")

if __name__ == "__main__":
    main()
