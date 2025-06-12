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
from tenacity import retry, stop_after_attempt, wait_exponential, RetryError # 确保这一行在这里！

# --- 调试配置 START ---
DEBUG_MODE = False  # 设置为 False 以禁用页数限制和调试模式，进行完整搜索
# DEBUG_MAX_SEARCH_PAGES = 3 # 调试模式下最多搜索的页数，当 DEBUG_MODE 为 False 时此行无效
# --- 搜索时间过滤 START ---
# 只搜索最近 N 天内有更新的仓库。设置为 0 或 None 则不进行时间过滤。
SEARCH_UPDATED_DAYS_AGO = 70 # 例如：只搜索最近 7 天内有更新的仓库
# --- 搜索时间过滤 END ---
# --- 调试配置 END ---

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub API 配置
GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT_TOKEN") # 确保你的环境变量 BOT_TOKEN 已设置
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.com.text-match+json" # GitHub API 推荐的 Accept Header
}
SEARCH_QUERY_BASE = "/api/v1/client/subscribe?token="
# 更严格的正则，确保匹配的是完整的URL，避免匹配到部分HTML标签或不完整的链接
# 注意：这个正则可能需要根据实际情况进一步调整，以平衡精确度和召回率
SUBSCRIBE_LINK_REGEX = r"https?:\/\/[a-zA-Z0-9.-]+\/[a-zA-Z0-9_/%.-]*api\/v1\/client\/subscribe\?token=[a-zA-Z0-9_-]+"


# 数据存储目录
DATA_DIR = "data"
OUTPUT_FILE_VALID_TEXT = os.path.join(DATA_DIR, "valid_subscribe_links.txt") # 有效链接的文本格式
OUTPUT_FILE_VALID_JSON = os.path.join(DATA_DIR, "valid_subscribe_links.json") # 有效链接的JSON格式
OUTPUT_FILE_EXPIRED = os.path.join(DATA_DIR, "expired_subscribe_links.txt") # 过期链接
OUTPUT_FILE_NO_TRAFFIC = os.path.join(DATA_DIR, "no_traffic_subscribe_links.txt") # 无流量链接

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

async def _test_subscription_status_inner(session, url, timeout):
    """实际执行订阅状态测试的内部函数，用于 tenacity 重试"""
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
            # 对于某些 HTTP 错误码，也认为是无效的，但记录下来
            result['error'] = f"HTTP Status {response.status}"
            result['is_valid'] = False
            logger.warning(f"Validation failed for {url}: HTTP {response.status}")
            return result # 返回结果，而不是抛出异常让 tenacity 重试

        content_type = response.headers.get('Content-Type', '').lower()
        text = await response.text()

        if 'json' in content_type:
            data = json.loads(text)
        elif 'yaml' in content_type or text.strip().startswith('---'):
            data = yaml.safe_load(text)
        else:
            data = {'raw_content': text} # 对于非 JSON/YAML 内容，仍然记录 raw text

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
        if result['remaining_traffic'] <= 0 and result['status'] not in ('expired', 'unavailable'):
            result['status'] = 'no_traffic'
            result['is_valid'] = False

    return result

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def test_subscription_status(session, url, timeout=15):
    """
    测试订阅链接状态，增加了对 RetryError 的处理，
    确保即使重试失败，也不会向上抛出异常，而是返回一个失败结果。
    """
    try:
        # 调用内部函数，实际的重试逻辑在这里执行
        return await _test_subscription_status_inner(session, url, timeout)
    except RetryError as e:
        # 捕获 tenacity 的 RetryError，并返回一个失败结果
        result = {
            'url': url,
            'is_valid': False,
            'status': 'failed_retry',
            'remaining_traffic': 0,
            'expiry_date': None,
            'error': f"All retries failed: {e.last_attempt.exception()}" # 获取最后一次尝试的异常信息
        }
        logger.warning(f"Failed to validate {url} after multiple retries: {result['error']}")
        return result
    except (aiohttp.ClientError, json.JSONDecodeError, yaml.YAMLError, ValueError, TypeError) as e:
        # 其他非 RetryError 的客户端错误
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
    """按状态保存 URL，并新增 JSON 格式输出"""
    ensure_data_dir()
    valid_urls_text = []
    valid_data_json = [] # 用于 JSON 输出的列表
    expired_urls = []
    no_traffic_urls = []
    other_failed_urls = [] # 用于捕获其他验证失败的URL

    for result in results:
        # Check if result is an exception or failed retry, skip it
        if result is None:
            continue

        if result['is_valid']:
            # 文本格式
            valid_urls_text.append(
                f"{result['url']} (Status: {result['status']}, "
                f"Traffic: {result['remaining_traffic'] / 1024 / 1024 / 1024:.2f}GB, "
                f"Expiry: {result['expiry_date'].strftime('%Y-%m-%d %H:%M:%S%z') if result['expiry_date'] else 'N/A'})"
            )
            # JSON 格式数据
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
        else: # 其他所有验证失败的情况，包括带 'error' 字段的
            error_msg = result.get('error', 'Unknown error')
            other_failed_urls.append(f"{result['url']} (Failed: {error_msg})")

    # 保存有效链接到文本文件
    with open(OUTPUT_FILE_VALID_TEXT, "w", encoding="utf-8") as f:
        for url_text in valid_urls_text:
            f.write(f"{url_text}\n")
    logger.info(f"Saved {len(valid_urls_text)} Valid URLs (text) to {OUTPUT_FILE_VALID_TEXT}")

    # 保存有效链接到 JSON 文件
    with open(OUTPUT_FILE_VALID_JSON, "w", encoding="utf-8") as f:
        json.dump(valid_data_json, f, ensure_ascii=False, indent=4) # indent=4 方便阅读
    logger.info(f"Saved {len(valid_data_json)} Valid URLs (JSON) to {OUTPUT_FILE_VALID_JSON}")


    # 保存过期链接到文本文件
    with open(OUTPUT_FILE_EXPIRED, "w", encoding="utf-8") as f:
        for url in expired_urls:
            f.write(f"{url}\n")
    logger.info(f"Saved {len(expired_urls)} Expired URLs to {OUTPUT_FILE_EXPIRED}")

    # 保存无流量链接到文本文件
    with open(OUTPUT_FILE_NO_TRAFFIC, "w", encoding="utf-8") as f:
        for url in no_traffic_urls:
            f.write(f"{url}\n")
    logger.info(f"Saved {len(no_traffic_urls)} No Traffic URLs to {OUTPUT_FILE_NO_TRAFFIC}")

    # 保存其他失败链接到文本文件 (可选，如果你想查看所有失败原因)
    if other_failed_urls:
        OUTPUT_FILE_OTHER_FAILED = os.path.join(DATA_DIR, "other_failed_subscribe_links.txt")
        with open(OUTPUT_FILE_OTHER_FAILED, "w", encoding="utf-8") as f:
            for url in other_failed_urls:
                f.write(f"{url}\n")
        logger.info(f"Saved {len(other_failed_urls)} Other Failed URLs to {OUTPUT_FILE_OTHER_FAILED}")


    return len(valid_urls_text) # 返回有效链接数量

async def search_github():
    """搜索GitHub中的包含特定查询字符串的文件URL"""
    if not TOKEN:
        logger.error("BOT_TOKEN is not set in environment variables. Please set it to a GitHub Personal Access Token.")
        logger.info("You can generate one at: https://github.com/settings/tokens")
        return set()

    unique_raw_urls = set()
    page = 1
    per_page = 100

    # 构建带时间过滤的搜索查询
    final_search_query = SEARCH_QUERY_BASE
    if SEARCH_UPDATED_DAYS_AGO is not None and SEARCH_UPDATED_DAYS_AGO > 0:
        # 计算N天前的日期
        date_n_days_ago = datetime.now() - timedelta(days=SEARCH_UPDATED_DAYS_AGO)
        formatted_date = date_n_days_ago.strftime('%Y-%m-%d')
        # 将时间限定符添加到查询中
        final_search_query += f" pushed:>={formatted_date}"
        logger.info(f"Searching for repositories updated since {formatted_date} (last {SEARCH_UPDATED_DAYS_AGO} days)")
    else:
        logger.info("No time filter applied for GitHub repository search (searching all historical updates).")


    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while True:
            # 只有当 DEBUG_MODE 为 True 时，才限制页数
            if DEBUG_MODE and page > DEBUG_MAX_SEARCH_PAGES:
                logger.info(f"DEBUG_MODE is ON. Reached max search pages ({DEBUG_MAX_SEARCH_PAGES}), stopping GitHub search.")
                break

            params = {"q": final_search_query, "per_page": per_page, "page": page}
            try:
                github_headers = HEADERS.copy()
                github_headers['User-Agent'] = get_random_user_agent() # 使用随机User-Agent

                async with session.get(GITHUB_API_URL, headers=github_headers, params=params) as response:
                    # 检查速率限制信息
                    remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
                    reset_time_unix = int(response.headers.get("X-RateLimit-Reset", 0))
                    
                    if response.status == 403 and remaining == 0:
                        reset_datetime = datetime.fromtimestamp(reset_time_unix, tz=timezone.utc)
                        wait_seconds = max(10, (reset_time_unix - int(time.time())) + 5) # 至少等5秒
                        logger.warning(f"GitHub API rate limit exceeded. {remaining} requests remaining. Reset at {reset_datetime} UTC. Sleeping for {wait_seconds} seconds.")
                        await asyncio.sleep(wait_seconds)
                        continue # 继续尝试当前页，因为可能是临时限制
                    
                    response.raise_for_status() # 对非 2xx 响应抛出异常

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
                            # 尝试处理其他可能的GitHub URL格式，确保能转换为raw内容
                            parsed_url = urlparse(html_url)
                            if parsed_url.netloc == "github.com":
                                parts = parsed_url.path.split('/')
                                if len(parts) >= 3: # /owner/repo/rest_of_path
                                    # 假设是文件路径，直接尝试转换为raw
                                    raw_url = f"https://raw.githubusercontent.com/{parts[1]}/{parts[2]}/master/{'/'.join(parts[3:])}"
                                else:
                                    logger.warning(f"Could not parse GitHub URL for raw content: {html_url}")
                                    continue
                            else:
                                raw_url = html_url # 非github.com域名直接使用原URL，可能用于后续提取
                                
                        text_matches = item.get("text_matches", [])
                        for match in text_matches:
                            if SEARCH_QUERY_BASE in match.get("fragment", ""):
                                unique_raw_urls.add(raw_url)
                                logger.debug(f"Found raw URL: {raw_url}")
                                break

                    logger.info(f"Processed page {page}, found {len(unique_raw_urls)} unique raw URLs so far.")

                    # 正常的请求间隔，避免连续请求过快
                    await asyncio.sleep(1) 
                    page += 1

            except (aiohttp.ClientError, json.JSONDecodeError) as e:
                logger.error(f"GitHub API request failed for page {page}: {e}. Check network, token, or rate limit.")
                # 对于某些持续性错误，直接退出循环，避免无限重试
                break 
            except Exception as e:
                logger.error(f"An unexpected error occurred during GitHub search for page {page}: {e}")
                break

    return unique_raw_urls

async def fetch_and_extract_subscribe_links(raw_url, session):
    """从GitHub raw URL 下载内容并提取订阅链接，增加健壮性"""
    try:
        # 增加下载超时，防止某些链接一直无响应
        async with session.get(raw_url, headers={'User-Agent': get_random_user_agent()}, timeout=15) as response:
            if response.status != 200:
                logger.error(f"Failed to fetch content from {raw_url}: Status {response.status}")
                return []

            content = await response.text()
            found_matches = re.findall(SUBSCRIBE_LINK_REGEX, content)
            logger.debug(f"Extracted {len(found_matches)} subscribe links from {raw_url}")
            return found_matches

    except aiohttp.ClientError as e:
        # 这里捕获所有aiohttp客户端错误，包括连接错误、超时、DNS解析失败等
        logger.error(f"Error fetching raw content from {raw_url}: {type(e).__name__} - {e}")
        return [] # 返回空列表，避免异常向上抛出

    except Exception as e:
        # 捕获其他意外错误，确保不会崩溃
        logger.error(f"An unexpected error occurred while processing {raw_url}: {e}")
        return []

async def process_raw_urls(raw_urls):
    """处理所有 raw URL，提取订阅链接"""
    all_subscribe_links = set()
    # 为整个会话设置一个总超时，防止长时间挂起
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
        tasks = [fetch_and_extract_subscribe_links(raw_url, session) for raw_url in raw_urls]
        # asyncio.gather 返回所有任务的结果，如果子任务内部处理了异常并返回了结果，则不会抛出异常
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for result_list in results: # result_list 是 fetch_and_extract_subscribe_links 返回的列表（可能为空）
            if isinstance(result_list, list): # 确保结果是列表（可能是空列表）
                all_subscribe_links.update(result_list)
            # 由于 fetch_and_extract_subscribe_links 已经捕获并返回空列表，这里不会出现 Exception 类型了

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
    ensure_data_dir() # 确保数据目录在开始时就存在

    raw_urls = await search_github()
    logger.info(f"Found {len(raw_urls)} unique raw GitHub URLs")

    if raw_urls: # 只有当找到raw_urls时才尝试提取和验证
        subscribe_links = await process_raw_urls(raw_urls)
        logger.info(f"Extracted {len(subscribe_links)} unique subscribe links")

        if subscribe_links:
            logger.info(f"Validating {len(subscribe_links)} subscribe links...")
            results = await validate_subscriptions(list(subscribe_links))
            valid_count = save_urls_by_status(results)
            logger.info(f"Validation complete. Found {valid_count} valid subscribe links.")
        else:
            logger.info("No subscribe links found after extraction to validate.")
            save_urls_by_status([]) # 确保即使没有有效链接也生成空文件

    else:
        logger.warning("No raw GitHub URLs found. Skipping subscription link extraction and validation.")
        save_urls_by_status([]) # 确保即使没有找到任何东西也生成空文件

    domains = {}
    # 统计所有（包括无效的）订阅链接的域名分布
    # 为了准确统计，这里需要从原始的 subscribe_links 集合中统计，而不是只统计 valid_urls_text
    # 如果 raw_urls 为空，subscribe_links 也会为空，所以这里是安全的
    if raw_urls:
        final_extracted_links = await process_raw_urls(raw_urls) # 重新提取一次，确保统计的是所有尝试提取到的链接
        for link in final_extracted_links:
            domain = get_domain(link)
            if domain:
                domains[domain] = domains.get(domain, 0) + 1

    logger.info("Domain distribution (based on all extracted links):")
    if domains:
        for domain, count in sorted(domains.items(), key=lambda item: item[1], reverse=True):
            logger.info(f"{domain}: {count} URLs")
    else:
        logger.info("No domains to display.")

if __name__ == "__main__":
    asyncio.run(main())
