import os
import asyncio
import aiohttp
import json
import yaml
import logging
import re
import random
from urllib.parse import urlparse
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub API 配置
GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT_TOKEN")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3.text-match+json"
}
SEARCH_QUERY = "/api/v1/client/subscribe?token="
SUBSCRIBE_LINK_REGEX = r"https?:\/\/[^\s\"']*\/api\/v1\/client\/subscribe\?token=[^\s\"']+"

# 数据存储目录
DATA_DIR = "data"
OUTPUT_FILE_VALID = os.path.join(DATA_DIR, "valid_subscribe_links.txt")
OUTPUT_FILE_EXPIRED = os.path.join(DATA_DIR, "expired_subscribe_links.txt")
OUTPUT_FILE_NO_TRAFFIC = os.path.join(DATA_DIR, "no_traffic_subscribe_links.txt")

# 随机 User-Agent 列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
]

def get_random_user_agent():
    """获取随机 User-Agent"""
    return random.choice(USER_AGENTS)

def ensure_data_dir():
    """确保数据目录存在"""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created directory: {DATA_DIR}")

def parse_traffic(traffic_str):
    """解析流量字符串（如 '1.5GB'、'500MB'）为字节数"""
    if not traffic_str or isinstance(traffic_str, (int, float)):
        return float(traffic_str or 0)
    traffic_str = traffic_str.strip().upper()
    match = re.match(r'(\d*\.?\d+)\s*(GB|MB|KB|B)?', traffic_str)
    if not match:
        return 0
    value, unit = match.groups()
    value = float(value)
    if unit == 'GB':
        return value * 1024 ** 3
    elif unit == 'MB':
        return value * 1024 ** 2
    elif unit == 'KB':
        return value * 1024
    return value

def parse_expiry(expiry):
    """解析到期时间为 datetime 对象"""
    if not expiry:
        return None
    try:
        if isinstance(expiry, (int, float)):
            return datetime.fromtimestamp(expiry)
        return datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S%z")
    except (ValueError, TypeError):
        try:
            return datetime.strptime(expiry, "%Y-%m-%d")
        except (ValueError, TypeError):
            return None

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def test_subscription_status(session, url, timeout=10):
    """测试订阅链接状态，包括到期时间和剩余流量"""
    headers = {'User-Agent': get_random_user_agent()}
    result = {
        'url': url,
        'is_valid': False,
        'status': 'unknown',
        'remaining_traffic': 0,
        'expiry_date': None,
        'error': None
    }

    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise aiohttp.ClientResponseError(
                    response.request_info, response.history, status=response.status
                )
            content_type = response.headers.get('Content-Type', '').lower()
            text = await response.text()

            if 'json' in content_type:
                data = json.loads(text)
            elif 'yaml' in content_type or text.strip().startswith('---'):
                data = yaml.safe_load(text)
            else:
                data = {'raw': text}

            result['is_valid'] = True

            # 解析常见字段
            for key in ('status', 'state'):
                if key in data:
                    result['status'] = data[key].lower()
                    break

            for key in ('remaining_traffic', 'traffic_left', 'data_left'):
                if key in data:
                    result['remaining_traffic'] = parse_traffic(data[key])
                    break

            for key in ('expire_time', 'expires_at', 'expiry'):
                if key in data:
                    result['expiry_date'] = parse_expiry(data[key])
                    break

            # 判断是否过期
            if result['expiry_date'] and result['expiry_date'] < datetime.now(result['expiry_date'].tzinfo or None):
                result['status'] = 'expired'
                result['is_valid'] = False

            # 判断是否无流量
            if result['remaining_traffic'] <= 0 and result['status'] != 'expired':
                result['status'] = 'no_traffic'
                result['is_valid'] = False

    except (aiohttp.ClientError, json.JSONDecodeError, yaml.YAMLError) as e:
        result['error'] = str(e)
        logger.warning(f"Failed to validate {url}: {e}")

    return result

async def validate_subscriptions(urls, max_concurrent=10):
    """批量验证订阅链接"""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        semaphore = asyncio.Semaphore(max_concurrent)
        async def fetch_with_semaphore(url):
            async with semaphore:
                return await test_subscription_status(session, url)
        tasks = [fetch_with_semaphore(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)

def save_urls_by_status(results):
    """按状态保存 URL"""
    ensure_data_dir()
    valid_urls = []
    expired_urls = []
    no_traffic_urls = []

    for result in results:
        if not isinstance(result, dict) or result.get('error'):
            continue
        if result['is_valid']:
            valid_urls.append(
                f"{result['url']} (Status: {result['status']}, "
                f"Traffic: {result['remaining_traffic'] / 1024 / 1024 / 1024:.2f}GB, "
                f"Expiry: {result['expiry_date'] or 'N/A'})"
            )
        elif result['status'] == 'expired':
            expired_urls.append(f"{result['url']} (Expiry: {result['expiry_date'] or 'N/A'})")
        elif result['status'] == 'no_traffic':
            no_traffic_urls.append(f"{result['url']} (No traffic)")

    for file, urls, label in [
        (OUTPUT_FILE_VALID, valid_urls, "Valid URLs"),
        (OUTPUT_FILE_EXPIRED, expired_urls, "Expired URLs"),
        (OUTPUT_FILE_NO_TRAFFIC, no_traffic_urls, "No Traffic URLs")
    ]:
        with open(file, "w", encoding="utf-8") as f:
            for url in urls:
                f.write(f"{url}\n")
        logger.info(f"Saved {len(urls)} {label} to {file}")

    return len(valid_urls)

async def search_github():
    """搜索GitHub中的包含特定查询字符串的文件URL"""
    if not TOKEN:
        logger.error("BOT_TOKEN is not set in environment variables")
        return set()

    unique_raw_urls = set()
    page = 1
    per_page = 10

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while True:
            params = {"q": SEARCH_QUERY, "per_page": per_page, "page": page}
            try:
                github_headers = HEADERS.copy()
                github_headers['User-Agent'] = get_random_user_agent()

                async with session.get(GITHUB_API_URL, headers=github_headers, params=params) as response:
                    response.raise_for_status()
                    data = await response.json()
                    items = data.get("items", [])

                    if not items:
                        logger.info("No more results found, stopping search.")
                        break

                    for item in items:
                        html_url = item["html_url"]
                        if "/blob/" in html_url:
                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                        elif "/tree/" in html_url:
                            logger.warning(f"Skipping directory URL: {html_url}")
                            continue
                        else:
                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com")

                        text_matches = item.get("text_matches", [])
                        for match in text_matches:
                            if SEARCH_QUERY in match.get("fragment", ""):
                                unique_raw_urls.add(raw_url)
                                logger.debug(f"Found raw URL: {raw_url}")
                                break

                    logger.info(f"Processed page {page}, found {len(unique_raw_urls)} unique raw URLs.")

                    # 速率限制处理
                    remaining = int(response.headers.get("X-RateLimit-Remaining", 100))
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    current_time = int(time.time())

                    if remaining < 50:
                        sleep_duration = max(10, (reset_time - current_time) + 5)
                        logger.warning(f"Approaching rate limit ({remaining}), sleeping {sleep_duration}s.")
                        await asyncio.sleep(sleep_duration)
                    else:
                        await asyncio.sleep(2)

                    page += 1

            except (aiohttp.ClientError, json.JSONDecodeError) as e:
                logger.error(f"GitHub API request failed for page {page}: {e}")
                break

    return unique_raw_urls

async def fetch_and_extract_subscribe_links(raw_url, session):
    """从GitHub raw URL 下载内容并提取订阅链接"""
    try:
        async with session.get(raw_url, headers={'User-Agent': get_random_user_agent()}) as response:
            if response.status != 200:
                logger.error(f"Failed to fetch {raw_url}: Status {response.status}")
                return []

            content = await response.text()
            found_matches = re.findall(SUBSCRIBE_LINK_REGEX, content)
            logger.debug(f"Extracted {len(found_matches)} subscribe links from {raw_url}")
            return found_matches

    except aiohttp.ClientError as e:
        logger.error(f"Error fetching {raw_url}: {e}")
        return []

async def process_raw_urls(raw_urls):
    """处理所有 raw URL，提取订阅链接"""
    all_subscribe_links = set()
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        tasks = [fetch_and_extract_subscribe_links(raw_url, session) for raw_url in raw_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_subscribe_links.update(result)

    return all_subscribe_links

def get_domain(url):
    """提取URL的域名"""
    try:
        return urlparse(url).netloc
    except Exception as e:
        logger.error(f"Error parsing domain from URL {url}: {e}")
        return ""

async def main():
    """主函数"""
    logger.info("Starting GitHub search for subscribe links")

    # 搜索 GitHub raw URLs
    raw_urls = await search_github()
    logger.info(f"Found {len(raw_urls)} unique raw GitHub URLs")

    # 提取订阅链接
    subscribe_links = await process_raw_urls(raw_urls)
    logger.info(f"Extracted {len(subscribe_links)} unique subscribe links")

    # 验证订阅链接状态
    if subscribe_links:
        results = await validate_subscriptions(subscribe_links)
        valid_count = save_urls_by_status(results)
        logger.info(f"Saved {valid_count} valid subscribe links")

    # 按域名统计
    domains = {}
    for link in subscribe_links:
        domain = get_domain(link)
        if domain:
            domains[domain] = domains.get(domain, 0) + 1

    logger.info("Domain distribution:")
    if domains:
        for domain, count in sorted(domains.items(), key=lambda item: item[1], reverse=True):
            logger.info(f"{domain}: {count} URLs")
    else:
        logger.info("No domains to display.")

if __name__ == "__main__":
    asyncio.run(main())
