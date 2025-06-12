import os
import asyncio
import aiohttp
import json
import yaml
import logging
import re
import random
import time
from urllib.parse import urlparse
from datetime import datetime, timezone # 导入 timezone 以处理时区

# --- 新增调试配置 START ---
DEBUG_MODE = True  # 设置为 True 开启调试模式
DEBUG_MAX_SEARCH_PAGES = 3 # 调试模式下最多搜索的页数，例如只搜索 3 页
# --- 新增调试配置 END ---

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
            return datetime.fromtimestamp(expiry, tz=timezone.utc) # 假设时间戳是 UTC
        # 尝试解析带时区的 ISO 格式
        try:
            return datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            # 尝试解析不带时区的 ISO 格式，并假设为 UTC
            dt = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        try:
            # 尝试解析日期格式
            dt = datetime.strptime(expiry, "%Y-%m-%d")
            return dt.replace(tzinfo=timezone.utc) # 假设为 UTC
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
                data = {'raw': text} # 对于非 JSON/YAML 内容，仍然记录 raw text

            result['is_valid'] = True

            # 解析常见字段
            for key in ('status', 'state'):
                if key in data:
                    result['status'] = str(data[key]).lower() # 确保转换为字符串再转小写
                    break

            for key in ('remaining_traffic', 'traffic_left', 'data_left'):
                if key in data:
                    result['remaining_traffic'] = parse_traffic(data[key])
                    break

            for key in ('expire_time', 'expires_at', 'expiry'):
                if key in data:
                    result['expiry_date'] = parse_expiry(data[key])
                    break

            # 判断是否过期 (确保当前时间也带时区信息进行比较)
            now_utc = datetime.now(timezone.utc)
            if result['expiry_date'] and result['expiry_date'] < now_utc:
                result['status'] = 'expired'
                result['is_valid'] = False

            # 判断是否无流量
            if result['remaining_traffic'] <= 0 and result['status'] != 'expired':
                result['status'] = 'no_traffic'
                result['is_valid'] = False

    except (aiohttp.ClientError, json.JSONDecodeError, yaml.YAMLError, ValueError) as e: # 捕获 ValueError for parsing
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
        # filter out None results which might occur from failed retries
        results = [r for r in await asyncio.gather(*tasks, return_exceptions=False) if r is not None]
        return results

def save_urls_by_status(results):
    """按状态保存 URL"""
    ensure_data_dir()
    valid_urls = []
    expired_urls = []
    no_traffic_urls = []

    for result in results:
        # Check if result is an exception or failed retry, skip it
        if isinstance(result, Exception) or result is None or result.get('error'):
            logger.warning(f"Skipping problematic result: {result}")
            continue

        if result['is_valid']:
            valid_urls.append(
                f"{result['url']} (Status: {result['status']}, "
                f"Traffic: {result['remaining_traffic'] / 1024 / 1024 / 1024:.2f}GB, "
                f"Expiry: {result['expiry_date'].strftime('%Y-%m-%d %H:%M:%S%z') if result['expiry_date'] else 'N/A'})"
            )
        elif result['status'] == 'expired':
            expired_urls.append(f"{result['url']} (Expiry: {result['expiry_date'].strftime('%Y-%m-%d %H:%M:%S%z') if result['expiry_date'] else 'N/A'})")
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
    per_page = 100 # <--- 已修改：每次获取 100 个结果，以减少 API 调用次数

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while True:
            # --- 新增调试模式限制 START ---
            if DEBUG_MODE and page > DEBUG_MAX_SEARCH_PAGES:
                logger.info(f"DEBUG_MODE is ON. Reached max search pages ({DEBUG_MAX_SEARCH_PAGES}), stopping GitHub search.")
                break
            # --- 新增调试模式限制 END ---

            params = {"q": SEARCH_QUERY, "per_page": per_page, "page": page}
            try:
                github_headers = HEADERS.copy()
                github_headers['User-Agent'] = get_random_user_agent()

                async with session.get(GITHUB_API_URL, headers=github_headers, params=params) as response:
                    response.raise_for_status()
                    data = await response.json()
                    items = data.get("items", [])

                    if not items:
                        logger.info("No more results found from GitHub, stopping search.")
                        break

                    for item in items:
                        html_url = item["html_url"]
                        if "/blob/" in html_url:
                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                        elif "/tree/" in html_url:
                            logger.debug(f"Skipping directory URL: {html_url}") # 降低日志级别，避免干扰
                            continue
                        else:
                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com")

                        text_matches = item.get("text_matches", [])
                        for match in text_matches:
                            if SEARCH_QUERY in match.get("fragment", ""):
                                unique_raw_urls.add(raw_url)
                                logger.debug(f"Found raw URL: {raw_url}")
                                break

                    logger.info(f"Processed page {page}, found {len(unique_raw_urls)} unique raw URLs so far.")

                    # 速率限制处理
                    remaining = int(response.headers.get("X-RateLimit-Remaining", 100))
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    current_time = int(time.time())

                    # 只有当剩余请求数较低时才休眠
                    if remaining < 100: # 稍微提高阈值，更早进入等待
                        sleep_duration = max(10, (reset_time - current_time) + 5)
                        logger.warning(f"Approaching rate limit ({remaining} remaining), sleeping {sleep_duration}s.")
                        await asyncio.sleep(sleep_duration)
                    else:
                        await asyncio.sleep(1) # 非调试模式下，请求之间短暂等待，避免连续请求过快

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
            if isinstance(result, list): # 确保结果是列表（即没有发生异常）
                all_subscribe_links.update(result)
            elif isinstance(result, Exception): # 记录处理 raw URL 时的异常
                logger.error(f"Error processing raw URL task: {result}")


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
        logger.info(f"Validating {len(subscribe_links)} subscribe links...")
        results = await validate_subscriptions(list(subscribe_links)) # 将 set 转换为 list
        valid_count = save_urls_by_status(results)
        logger.info(f"Saved {valid_count} valid subscribe links")
    else:
        logger.info("No subscribe links found to validate.")

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
