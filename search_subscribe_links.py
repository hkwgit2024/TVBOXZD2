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
from datetime import datetime, timezone, timedelta

# --- 调试配置 START ---
DEBUG_MODE = False  # <--- 将这里设置为 False，以禁用页数限制和调试模式
# DEBUG_MAX_SEARCH_PAGES = 3 # 调试模式下最多搜索的页数，此行现在可以忽略或删除
# --- 搜索时间过滤 START ---
# 只搜索最近 N 天内有更新的仓库。设置为 0 或 None 则不进行时间过滤。
SEARCH_UPDATED_DAYS_AGO = 7 # 例如：只搜索最近 7 天内有更新的仓库
# --- 搜索时间过滤 END ---
# --- 调试配置 END ---

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub API 配置
GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT_TOKEN")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.com.text-match+json"
}
SEARCH_QUERY_BASE = "/api/v1/client/subscribe?token="
SUBSCRIBE_LINK_REGEX = r"https?:\/\/[a-zA-Z0-9.-]+\/[a-zA-Z0-9_/%.-]*api\/v1\/client\/subscribe\?token=[a-zA-Z0-9_-]+"


# 数据存储目录
DATA_DIR = "data"
OUTPUT_FILE_VALID_TEXT = os.path.join(DATA_DIR, "valid_subscribe_links.txt")
OUTPUT_FILE_VALID_JSON = os.path.join(DATA_DIR, "valid_subscribe_links.json")
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
    return random.choice(USER_AGENTS)

def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created directory: {DATA_DIR}")

def parse_traffic(traffic_str):
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
    if not expiry:
        return None
    try:
        if isinstance(expiry, (int, float)):
            return datetime.fromtimestamp(expiry, tz=timezone.utc)
        try:
            return datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            dt = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        try:
            dt = datetime.strptime(expiry, "%Y-%m-%d")
            return dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

async def _test_subscription_status_inner(session, url, timeout):
    headers = {'User-Agent': get_random_user_agent()}
    result = {
        'url': url,
        'is_valid': False,
        'status': 'unknown',
        'remaining_traffic': 0,
        'expiry_date': None,
        'error': None
    }

    async with session.get(url, headers=headers, timeout=timeout) as response:
        if response.status < 200 or response.status >= 300:
            result['error'] = f"HTTP Status {response.status}"
            result['is_valid'] = False
            logger.warning(f"Validation failed for {url}: HTTP {response.status}")
            return result

        content_type = response.headers.get('Content-Type', '').lower()
        text = await response.text()

        if 'json' in content_type:
            data = json.loads(text)
        elif 'yaml' in content_type or text.strip().startswith('---'):
            data = yaml.safe_load(text)
        else:
            data = {'raw_content': text}

        result['is_valid'] = True

        for key in ('status', 'state'):
            if key in data:
                result['status'] = str(data[key]).lower()
                break

        for key in ('remaining_traffic', 'traffic_left', 'data_left'):
            if key in data:
                result['remaining_traffic'] = parse_traffic(data[key])
                break

        for key in ('expire_time', 'expires_at', 'expiry'):
            if key in data:
                result['expiry_date'] = parse_expiry(data[key])
                break

        now_utc = datetime.now(timezone.utc)
        if result['expiry_date'] and result['expiry_date'] < now_utc:
            result['status'] = 'expired'
            result['is_valid'] = False

        if result['remaining_traffic'] <= 0 and result['status'] not in ('expired', 'unavailable'):
            result['status'] = 'no_traffic'
            result['is_valid'] = False

    return result

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def test_subscription_status(session, url, timeout=15):
    try:
        return await _test_subscription_status_inner(session, url, timeout)
    except RetryError as e:
        result = {
            'url': url,
            'is_valid': False,
            'status': 'failed_retry',
            'remaining_traffic': 0,
            'expiry_date': None,
            'error': f"All retries failed: {e.last_attempt.exception()}"
        }
        logger.warning(f"Failed to validate {url} after multiple retries: {result['error']}")
        return result
    except (aiohttp.ClientError, json.JSONDecodeError, yaml.YAMLError, ValueError, TypeError) as e:
        result = {
            'url': url,
            'is_valid': False,
            'status': 'validation_error',
            'remaining_traffic': 0,
            'expiry_date': None,
            'error': f"{type(e).__name__} - {e}"
        }
        logger.warning(f"Failed to validate {url}: {result['error']}")
        return result

async def validate_subscriptions(urls, max_concurrent=10):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        semaphore = asyncio.Semaphore(max_concurrent)
        async def fetch_with_semaphore(url):
            async with semaphore:
                return await test_subscription_status(session, url)
        tasks = [fetch_with_semaphore(url) for url in urls]
        results = [r for r in await asyncio.gather(*tasks, return_exceptions=False) if r is not None]
        return results

def save_urls_by_status(results):
    ensure_data_dir()
    valid_urls_text = []
    valid_data_json = []
    expired_urls = []
    no_traffic_urls = []
    other_failed_urls = []

    for result in results:
        if result is None:
            continue

        if result['is_valid']:
            valid_urls_text.append(
                f"{result['url']} (Status: {result['status']}, "
                f"Traffic: {result['remaining_traffic'] / 1024 / 1024 / 1024:.2f}GB, "
                f"Expiry: {result['expiry_date'].strftime('%Y-%m-%d %H:%M:%S%z') if result['expiry_date'] else 'N/A'})"
            )
            valid_data_json.append({
                "url": result['url'],
                "status": result['status'],
                "remaining_traffic_gb": result['remaining_traffic'] / (1024 ** 3) if result['remaining_traffic'] is not None else 0.0,
                "expiry_date_iso": result['expiry_date'].isoformat() if result['expiry_date'] else None
            })
        elif result['status'] == 'expired':
            expired_urls.append(f"{result['url']} (Expiry: {result['expiry_date'].strftime('%Y-%m-%d %H:%M:%S%z') if result['expiry_date'] else 'N/A'})")
        elif result['status'] == 'no_traffic':
            no_traffic_urls.append(f"{result['url']} (No traffic)")
        else:
            error_msg = result.get('error', 'Unknown error')
            other_failed_urls.append(f"{result['url']} (Failed: {error_msg})")

    with open(OUTPUT_FILE_VALID_TEXT, "w", encoding="utf-8") as f:
        for url_text in valid_urls_text:
            f.write(f"{url_text}\n")
    logger.info(f"Saved {len(valid_urls_text)} Valid URLs (text) to {OUTPUT_FILE_VALID_TEXT}")

    with open(OUTPUT_FILE_VALID_JSON, "w", encoding="utf-8") as f:
        json.dump(valid_data_json, f, ensure_ascii=False, indent=4)
    logger.info(f"Saved {len(valid_data_json)} Valid URLs (JSON) to {OUTPUT_FILE_VALID_JSON}")

    with open(OUTPUT_FILE_EXPIRED, "w", encoding="utf-8") as f:
        for url in expired_urls:
            f.write(f"{url}\n")
    logger.info(f"Saved {len(expired_urls)} Expired URLs to {OUTPUT_FILE_EXPIRED}")

    with open(OUTPUT_FILE_NO_TRAFFIC, "w", encoding="utf-8") as f:
        for url in no_traffic_urls:
            f.write(f"{url}\n")
    logger.info(f"Saved {len(no_traffic_urls)} No Traffic URLs to {OUTPUT_FILE_NO_TRAFFIC}")

    if other_failed_urls:
        OUTPUT_FILE_OTHER_FAILED = os.path.join(DATA_DIR, "other_failed_subscribe_links.txt")
        with open(OUTPUT_FILE_OTHER_FAILED, "w", encoding="utf-8") as f:
            for url in other_failed_urls:
                f.write(f"{url}\n")
        logger.info(f"Saved {len(other_failed_urls)} Other Failed URLs to {OUTPUT_FILE_OTHER_FAILED}")

    return len(valid_urls_text)

async def search_github():
    if not TOKEN:
        logger.error("BOT_TOKEN is not set in environment variables")
        return set()

    unique_raw_urls = set()
    page = 1
    per_page = 100

    final_search_query = SEARCH_QUERY_BASE
    if SEARCH_UPDATED_DAYS_AGO and SEARCH_UPDATED_DAYS_AGO > 0:
        date_n_days_ago = datetime.now() - timedelta(days=SEARCH_UPDATED_DAYS_AGO)
        formatted_date = date_n_days_ago.strftime('%Y-%m-%d')
        final_search_query += f" pushed:>={formatted_date}"
        logger.info(f"Searching for repositories updated since {formatted_date} (last {SEARCH_UPDATED_DAYS_AGO} days)")
    else:
        logger.info("No time filter applied for GitHub repository search.")

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while True:
            # 只有当 DEBUG_MODE 为 True 时，才限制页数
            if DEBUG_MODE and page > DEBUG_MAX_SEARCH_PAGES:
                logger.info(f"DEBUG_MODE is ON. Reached max search pages ({DEBUG_MAX_SEARCH_PAGES}), stopping GitHub search.")
                break

            params = {"q": final_search_query, "per_page": per_page, "page": page}
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
                            logger.debug(f"Skipping directory URL: {html_url}")
                            continue
                        else:
                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com")

                        text_matches = item.get("text_matches", [])
                        for match in text_matches:
                            if SEARCH_QUERY_BASE in match.get("fragment", ""):
                                unique_raw_urls.add(raw_url)
                                logger.debug(f"Found raw URL: {raw_url}")
                                break

                    logger.info(f"Processed page {page}, found {len(unique_raw_urls)} unique raw URLs so far.")

                    remaining = int(response.headers.get("X-RateLimit-Remaining", 100))
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    current_time = int(time.time())

                    if remaining < 100:
                        sleep_duration = max(10, (reset_time - current_time) + 5)
                        logger.warning(f"Approaching rate limit ({remaining} remaining), sleeping {sleep_duration}s.")
                        await asyncio.sleep(sleep_duration)
                    else:
                        await asyncio.sleep(1)

                    page += 1

            except (aiohttp.ClientError, json.JSONDecodeError) as e:
                logger.error(f"GitHub API request failed for page {page}: {e}")
                break

    return unique_raw_urls

async def fetch_and_extract_subscribe_links(raw_url, session):
    try:
        async with session.get(raw_url, headers={'User-Agent': get_random_user_agent()}, timeout=15) as response:
            if response.status != 200:
                logger.error(f"Failed to fetch content from {raw_url}: Status {response.status}")
                return []

            content = await response.text()
            found_matches = re.findall(SUBSCRIBE_LINK_REGEX, content)
            logger.debug(f"Extracted {len(found_matches)} subscribe links from {raw_url}")
            return found_matches

    except aiohttp.ClientError as e:
        logger.error(f"Error fetching raw content from {raw_url}: {type(e).__name__} - {e}")
        return []

    except Exception as e:
        logger.error(f"An unexpected error occurred while processing {raw_url}: {e}")
        return []

async def process_raw_urls(raw_urls):
    all_subscribe_links = set()
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
        tasks = [fetch_and_extract_subscribe_links(raw_url, session) for raw_url in raw_urls]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for result_list in results:
            if isinstance(result_list, list):
                all_subscribe_links.update(result_list)

    return all_subscribe_links

def get_domain(url):
    try:
        return urlparse(url).netloc
    except Exception as e:
        logger.error(f"Error parsing domain from URL {url}: {e}")
        return ""

async def main():
    logger.info("Starting GitHub search for subscribe links")

    raw_urls = await search_github()
    logger.info(f"Found {len(raw_urls)} unique raw GitHub URLs")

    subscribe_links = await process_raw_urls(raw_urls)
    logger.info(f"Extracted {len(subscribe_links)} unique subscribe links")

    if subscribe_links:
        logger.info(f"Validating {len(subscribe_links)} subscribe links...")
        results = await validate_subscriptions(list(subscribe_links))
        valid_count = save_urls_by_status(results)
        logger.info(f"Validation complete. Found {valid_count} valid subscribe links.")
    else:
        logger.info("No subscribe links found to validate.")

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
