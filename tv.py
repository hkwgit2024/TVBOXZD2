import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import requests
import aiohttp
import asyncio
import json
import psutil
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import sys
import traceback

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iptv_crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- 全局配置 ---
CONFIG_DIR = os.path.join(os.getcwd(), 'config')
LAST_MODIFIED_FILE = os.path.join(CONFIG_DIR, "last_modified_urls.txt")
DEFAULT_LAST_MODIFIED = "Thu, 01 Jan 1970 00:00:00 GMT"
URLS_FILE_PATH = os.path.join(CONFIG_DIR, 'urls.txt')
SEARCH_CONFIG_FILE = os.path.join(CONFIG_DIR, 'search_keywords.json')
BLACKLIST_FILE = os.path.join(CONFIG_DIR, 'blacklist.txt')

# --- GitHub API 配置 ---
GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_API_CODE_SEARCH_PATH = "/search/code"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") # 从环境变量获取，用于提高速率限制

# GitHub API 速率限制配置
# GitHub search API limit: 10 requests per minute for unauthenticated users, 30 for authenticated users.
# We add some buffer.
GITHUB_REQUEST_INTERVAL = 6 # 每6秒一次请求，确保每分钟最多10次请求，用于未认证用户。
GITHUB_KEYWORD_SLEEP = 10 # 关键词之间休眠时间，避免连续的复杂查询触发API限制或422错误。

# GitHub 搜索结果分页数量 (每个关键词搜索的页数)
# 增加此值会获取更多结果，但也会增加API请求次数，更容易触及速率限制。
# 建议在有 GITHUB_TOKEN 的情况下适当增加。
MAX_SEARCH_PAGES = 1 # 默认值，你可以根据需求调整

# 异步 HTTP 请求配置
ASYNC_HTTP_TIMEOUT = 10 # 异步HTTP请求超时时间 (秒)
ASYNC_HTTP_CONNECTIONS = 50 # 异步HTTP并发连接数

# M3U 文件处理配置
M3U_TIMEOUT = 5 # M3U文件下载超时时间 (秒)
M3U_CONCURRENCY = 100 # M3U文件下载并发数

# 域名黑名单
BLACKLIST_DOMAINS = set()

# 结果文件路径
RESULT_M3U_FILE = "live.m3u"
RESULT_TXT_FILE = "live.txt"

# 缓存上次修改时间
LAST_MODIFIED_CACHE = {}

# --- 辅助函数 ---

def is_url_accessible(url):
    """
    检查URL是否可访问且内容不为空。
    考虑到有时HTTP响应会是3xx重定向，使用 HEAD 请求可能无法准确判断最终内容，
    因此这里使用 GET 请求，并设置较短的超时时间。
    """
    try:
        # 使用stream=True和iter_content来避免一次性下载大文件，
        # 并在确认响应头和少量内容后关闭连接。
        with requests.get(url, stream=True, timeout=5) as r:
            r.raise_for_status() # 检查HTTP状态码，如果不是2xx则抛出异常

            # 检查Content-Length，如果为0或不存在，可能内容为空
            content_length = r.headers.get('Content-Length')
            if content_length is not None and int(content_length) == 0:
                return False

            # 尝试读取一小部分内容来判断是否真的有数据
            # 避免下载整个文件，只判断响应是否有效
            first_byte = r.iter_content(chunk_size=1).next()
            if not first_byte:
                return False

            return True
    except requests.exceptions.RequestException as e:
        # logging.debug(f"URL {url} 不可访问: {e}") # 访问频繁可开启debug级别
        return False
    except Exception as e:
        # logging.debug(f"检查URL {url} 时发生未知错误: {e}")
        return False

def check_url_and_update_cache(url):
    """检查URL是否可访问，并更新上次修改时间缓存"""
    global LAST_MODIFIED_CACHE

    # 对于已在黑名单中的域名，直接跳过
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain in BLACKLIST_DOMAINS:
        # logging.debug(f"域名 '{domain}' 在黑名单中，跳过URL: {url}")
        return None

    last_modified_str = LAST_MODIFIED_CACHE.get(url, DEFAULT_LAST_MODIFIED)
    headers = {'If-Modified-Since': last_modified_str}
    
    try:
        with requests.head(url, headers=headers, timeout=5) as r:
            r.raise_for_status()

            if r.status_code == 304: # Not Modified
                # logging.debug(f"URL {url} 未修改 (304)")
                return url # 认为可用，因为内容未变
            
            # 检查 Content-Type，确保是文本类型，排除图片、视频等
            content_type = r.headers.get('Content-Type', '').lower()
            if not any(ct_part in content_type for ct_part in ['text', 'application/json', 'application/xml', 'application/x-mpegurl']):
                logging.warning(f"URL {url} 的Content-Type '{content_type}' 不是文本类型，跳过。")
                return None

            # 如果状态码是 200 OK
            new_last_modified = r.headers.get('Last-Modified', datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"))
            LAST_MODIFIED_CACHE[url] = new_last_modified
            # logging.info(f"URL {url} 可访问并已更新缓存。")
            return url
    except requests.exceptions.RequestException as e:
        # logging.debug(f"URL {url} 不可访问或请求错误: {e}")
        return None
    except Exception as e:
        # logging.debug(f"检查URL {url} 时发生未知错误: {e}")
        return None


def extract_m3u_urls(m3u_content, base_url=""):
    """
    从M3U内容中提取所有可能的URL。
    尝试将相对路径解析为绝对路径。
    """
    urls = set()
    # 匹配 #EXTINF 行下方的URL
    matches = re.findall(r'#EXTINF:.*?\n\s*(https?://[^\s]+)', m3u_content, re.IGNORECASE)
    for url in matches:
        urls.add(url.strip())
    
    # 匹配 M3U 文件中直接包含的 URL（不带 #EXTINF）
    # 这种通常是分段列表，也可能是错误的m3u，但仍尝试提取
    # 过滤掉 # 开头的行和空行
    for line in m3u_content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            if line.startswith('http://') or line.startswith('https://'):
                urls.add(line)
            elif base_url: # 尝试解析相对路径
                try:
                    absolute_url = urljoin(base_url, line)
                    if absolute_url.startswith('http'): # 确保是有效的HTTP/HTTPS URL
                        urls.add(absolute_url)
                except ValueError:
                    pass # urljoin可能会因为不规范的base_url或line抛出错误

    return list(urls)


async def fetch_url_content(session, url):
    """异步获取URL内容"""
    try:
        async with session.get(url, timeout=ASYNC_HTTP_TIMEOUT) as response:
            response.raise_for_status() # 检查HTTP状态码
            return await response.text()
    except aiohttp.ClientError as e:
        logging.warning(f"下载M3U URL失败 ({url}): {e}")
        return None
    except asyncio.TimeoutError:
        logging.warning(f"下载M3U URL超时 ({url})")
        return None
    except Exception as e:
        logging.warning(f"下载M3U URL时发生未知错误 ({url}): {e}")
        return None

async def process_m3u_url(session, m3u_url):
    """异步处理M3U URL，下载内容并提取内部URL"""
    logging.info(f"正在处理 M3U URL: {m3u_url}")
    content = await fetch_url_content(session, m3u_url)
    if content:
        # 简单检查是否包含M3U文件头
        if "#EXTM3U" not in content:
            logging.warning(f"URL {m3u_url} 内容不包含 #EXTM3U 头，可能不是有效的M3U文件。")
            return [] # 返回空列表

        extracted_urls = extract_m3u_urls(content, base_url=m3u_url)
        # logging.info(f"从 {m3u_url} 提取了 {len(extracted_urls)} 个URL。")
        return extracted_urls
    return []

# --- 数据加载与保存 ---

def load_blacklist_domains():
    """加载黑名单域名"""
    global BLACKLIST_DOMAINS
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    BLACKLIST_DOMAINS.add(line)
        logging.info(f"已加载 {len(BLACKLIST_DOMAINS)} 个黑名单域名.")
    else:
        logging.info("黑名单文件不存在，跳过加载。")

def load_last_modified_cache():
    """加载上次修改时间缓存"""
    global LAST_MODIFIED_CACHE
    if os.path.exists(LAST_MODIFIED_FILE):
        with open(LAST_MODIFIED_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',', 1)
                if len(parts) == 2:
                    url, timestamp = parts
                    LAST_MODIFIED_CACHE[url] = timestamp
        logging.info(f"已加载 {len(LAST_MODIFIED_CACHE)} 个URL的上次修改时间缓存.")
    else:
        logging.info("上次修改时间缓存文件不存在，将从头开始。")

def save_last_modified_cache():
    """保存上次修改时间缓存"""
    with open(LAST_MODIFIED_FILE, 'w', encoding='utf-8') as f:
        for url, timestamp in LAST_MODIFIED_CACHE.items():
            f.write(f"{url},{timestamp}\n")
    logging.info("已保存上次修改时间缓存.")

def load_initial_urls():
    """从urls.txt加载初始URL列表"""
    urls = set()
    if os.path.exists(URLS_FILE_PATH):
        with open(URLS_FILE_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and (url.startswith('http://') or url.startswith('https://')):
                    urls.add(url)
        logging.info(f"从 {URLS_FILE_PATH} 加载了 {len(urls)} 个初始 URL.")
    else:
        logging.warning(f"初始URL文件 {URLS_FILE_PATH} 不存在。")
    return list(urls)

def load_search_keywords():
    """
    加载 GitHub 搜索关键词。
    优先从 config/search_keywords.json 加载，如果文件不存在或加载失败，则使用默认关键词。
    """
    default_keywords = [
        # 简化并优化高频使用的关键词
        '"raw.githubusercontent.com" extension:m3u8',
        '"raw.githubusercontent.com" extension:m3u',
        'filename:playlist.m3u8',
        'filename:index.m3u8',
        'filename:channels.m3u',
        'filename:tv.m3u8',
        'filename:tv.m3u',
        'filename:live.m3u8',
        'filename:live.m3u',
        'extension:m3u8',
        'extension:m3u',
        '"#EXTM3U" extension:m3u', # 确保M3U文件中包含头
        '"#EXTM3U" extension:m3u8',
        '"iptv playlist" extension:m3u',
        '"iptv playlist" extension:m3u8',
        '"live tv" extension:m3u',
        '"live tv" extension:m3u8',
        '"tv channels" extension:m3u',
        '"tv channels" extension:m3u8',
        '"直播源" extension:m3u',
        '"直播源" extension:m3u8',
        '"电视直播" extension:m3u',
        '"电视直播" extension:m3u8',
        # 以下是可能触发422但保留作为可选的更复杂查询，建议在有令牌时谨慎使用
        # '"raw.githubusercontent.com" path:.txt "#EXTM3U"', # 这个经常422
        # 'filename:iptv.m3u OR filename:iptv.m3u8 OR filename:iptv.txt "#EXTM3U"', # 这个也容易422
        # '"#EXTM3U" "#EXTINF" "tvg-logo" (extension:m3u OR extension:m3u8)' # 太复杂
    ]
    
    custom_keywords = []
    if os.path.exists(SEARCH_CONFIG_FILE):
        try:
            with open(SEARCH_CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                if 'keywords' in config and isinstance(config['keywords'], list):
                    custom_keywords = config['keywords']
                    logging.info("已加载自定义搜索关键词配置文件.")
                else:
                    logging.warning(f"搜索关键词配置文件 {SEARCH_CONFIG_FILE} 格式不正确，缺少 'keywords' 列表。")
        except json.JSONDecodeError as e:
            logging.error(f"加载搜索关键词配置文件出错: {e}")
            logging.error(f"请检查文件 {SEARCH_CONFIG_FILE} 的JSON格式。")
        except Exception as e:
            logging.error(f"加载搜索关键词配置文件时发生未知错误: {e}")
    else:
        logging.info(f"搜索关键词配置文件 {SEARCH_CONFIG_FILE} 不存在，将使用默认关键词。")
    
    # 优先使用自定义关键词，如果自定义为空，则使用默认关键词
    # 如果自定义不为空，则将默认关键词添加到自定义关键词的后面
    if custom_keywords:
        # 确保没有重复，并保留自定义关键词的顺序
        final_keywords = list(dict.fromkeys(custom_keywords + default_keywords))
    else:
        final_keywords = default_keywords
    
    logging.info(f"最终搜索关键词数量: {len(final_keywords)}")
    return final_keywords


async def github_search_code(session, keyword, page=1):
    """
    使用 GitHub Code Search API 搜索代码。
    """
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
        logging.info("GITHUB_TOKEN 环境变量已设置。") # 只在第一次使用时输出
    
    params = {
        "q": keyword,
        "per_page": 100, # 每页最多100个结果
        "page": page
    }
    
    api_url = f"{GITHUB_API_BASE_URL}{GITHUB_API_CODE_SEARCH_PATH}"
    
    async with session.get(api_url, headers=headers, params=params, timeout=ASYNC_HTTP_TIMEOUT) as response:
        # 检查速率限制头
        remaining = response.headers.get('X-RateLimit-Remaining')
        reset_time = response.headers.get('X-RateLimit-Reset')
        if remaining and int(remaining) == 0:
            reset_timestamp = int(reset_time)
            sleep_time = max(0, reset_timestamp - time.time() + 5) # 加5秒缓冲
            logging.warning(f"GitHub API 速率限制已耗尽，将在 {sleep_time:.2f} 秒后重试。")
            await asyncio.sleep(sleep_time)
            # 重新发起请求
            return await github_search_code(session, keyword, page)

        response.raise_for_status() # 抛出HTTP错误，例如403, 404, 422
        return await response.json()


async def main():
    """主程序"""
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

    load_blacklist_domains()
    load_last_modified_cache()
    initial_urls = load_initial_urls()
    
    global SEARCH_KEYWORDS
    SEARCH_KEYWORDS = load_search_keywords() # 加载关键词

    all_found_urls = set(initial_urls)
    
    logging.info("开始 IPTV 频道爬取和整理...")

    # --- 阶段1: 从 GitHub 搜索新的 M3U/M3U8 URL ---
    github_found_urls = await search_github_for_m3u_urls()
    all_found_urls.update(github_found_urls)
    logging.info(f"GitHub 搜索阶段完成，共找到 {len(github_found_urls)} 个新的 URL。")

    # --- 阶段2: 检查现有URL的可访问性并过滤 ---
    logging.info(f"开始检查所有 {len(all_found_urls)} 个URL的可访问性...")
    
    valid_urls = set()
    with ThreadPoolExecutor(max_workers=M3U_CONCURRENCY) as executor:
        future_to_url = {executor.submit(check_url_and_update_cache, url): url for url in all_found_urls}
        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                result_url = future.result()
                if result_url:
                    valid_urls.add(result_url)
            except Exception as exc:
                logging.warning(f"URL {url} 检查时产生异常: {exc}")
            
            if (i + 1) % 100 == 0 or (i + 1) == len(all_found_urls):
                logging.info(f"已检查 {i + 1}/{len(all_found_urls)} 个URL。")
    
    logging.info(f"阶段2完成，筛选出 {len(valid_urls)} 个可访问的 URL。")

    # --- 阶段3: 异步下载并处理 M3U 文件，提取内部URL ---
    logging.info(f"开始下载并处理 {len(valid_urls)} 个M3U文件...")
    
    final_m3u_urls = set()
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in valid_urls:
            # 仅处理看起来像M3U/M3U8的URL，以减少不必要的请求
            if url.endswith('.m3u') or url.endswith('.m3u8') or '.m3u?' in url or '.m3u8?' in url:
                tasks.append(process_m3u_url(session, url))
            else:
                final_m3u_urls.add(url) # 如果不是M3U文件，直接添加到最终列表
        
        # 限制并发任务数量
        results = []
        # 使用 asyncio.gather 来收集所有任务的结果
        # 但为了避免创建过多同时运行的任务，可以使用 aiohttp.Semaphore
        semaphore = asyncio.Semaphore(ASYNC_HTTP_CONNECTIONS)
        
        async def bounded_process_m3u_url(s, url_to_process):
            async with semaphore:
                return await process_m3u_url(s, url_to_process)

        # 重新构建 tasks 列表，确保只处理那些符合 M3U 格式的 URL
        m3u_processing_tasks = [bounded_process_m3u_url(session, url) for url in valid_urls if url.endswith('.m3u') or url.endswith('.m3u8') or '.m3u?' in url or '.m3u8?' in url]
        
        for i, task in enumerate(asyncio.as_completed(m3u_processing_tasks)):
            try:
                extracted_list = await task
                if extracted_list:
                    final_m3u_urls.update(extracted_list)
            except Exception as e:
                logging.warning(f"处理M3U任务时发生错误: {e}")
            
            if (i + 1) % 50 == 0 or (i + 1) == len(m3u_processing_tasks):
                logging.info(f"已处理 {i + 1}/{len(m3u_processing_tasks)} 个M3U URL。")
        
        # 将原始的非M3U URL（如果它们是通过URL检查阶段的）也加入最终列表
        for url in valid_urls:
            if not (url.endswith('.m3u') or url.endswith('.m3u8') or '.m3u?' in url or '.m3u8?' in url):
                final_m3u_urls.add(url)


    logging.info(f"阶段3完成，共整理出 {len(final_m3u_urls)} 个有效的M3U/IPTV URL。")

    # --- 阶段4: 保存结果 ---
    logging.info("开始保存结果...")
    save_last_modified_cache()
    
    with open(RESULT_TXT_FILE, 'w', encoding='utf-8') as f_txt:
        for url in sorted(list(final_m3u_urls)):
            f_txt.write(f"{url}\n")
    logging.info(f"所有有效URL已保存到 {RESULT_TXT_FILE}")

    # TODO: 这里只保存了URL，如果需要生成完整的M3U文件（包含#EXTINF等信息），
    # 需要在前面处理M3U内容时同时提取频道信息，并在此处重构M3U文件。
    # 当前脚本主要侧重于URL的发现和有效性检查。
    logging.info("脚本运行完毕。")


async def search_github_for_m3u_urls():
    """在GitHub上搜索M3U/M3U8 URL"""
    found_urls = set()
    async with aiohttp.ClientSession() as session:
        for keyword_idx, keyword in enumerate(SEARCH_KEYWORDS):
            logging.info(f"GitHub 搜索 ({keyword_idx + 1}/{len(SEARCH_KEYWORDS)}) 使用关键词: '{keyword}'")
            
            for page in range(1, MAX_SEARCH_PAGES + 1):
                try:
                    results = await github_search_code(session, keyword, page)
                    if not results or not results.get('items'):
                        logging.info(f"关键词 '{keyword}' 页面 {page} 未找到结果。")
                        break # No more results for this keyword or page
                    
                    for item in results['items']:
                        raw_url = item['html_url'].replace('/blob/', '/raw/')
                        found_urls.add(raw_url)
                        # logging.debug(f"找到URL: {raw_url}") # 调试信息
                    
                    logging.info(f"关键词 '{keyword}' 页面 {page} 找到 {len(results['items'])} 个结果。")

                    # 如果当前页结果数小于per_page，说明没有更多页了
                    if len(results['items']) < 100:
                        break

                    # Sleep between pages to respect API limits if needed
                    # logging.info(f"页面 {page} 处理完毕，休眠 {GITHUB_REQUEST_INTERVAL} 秒...")
                    await asyncio.sleep(GITHUB_REQUEST_INTERVAL) # 页面之间也休眠
                        
                except aiohttp.ClientResponseError as e:
                    if e.status == 403:
                        logging.error(f"GitHub API 速率限制 (403): {e.status} {e.message}. 请等待或设置 GITHUB_TOKEN。")
                        # 可以尝试等待，或者直接退出
                        # 这里选择直接退出，因为等待可能很长
                        return list(found_urls) # 返回已找到的URL
                    elif e.status == 422:
                        logging.warning(f"GitHub API 请求处理失败 (422). 关键词 '{keyword}' 可能过于复杂或无效。跳过此关键词。")
                        # For other client errors, break page loop and try next keyword after sleep
                        break # 对于 422 错误，跳过当前关键词的所有页面，尝试下一个关键词
                    else:
                        logging.error(f"GitHub API 请求失败 ({e.status}): {e}")
                        break
                except asyncio.TimeoutError:
                    logging.error(f"GitHub API 请求超时 (关键词: '{keyword}', 页面: {page})")
                    break # Break page loop, try next keyword
                except Exception as e:
                    logging.error(f"GitHub 搜索 '{keyword}' 页面 {page} 时发生未知错误: {e}\n{traceback.format_exc()}")
                    break # Break page loop

            # Sleep between keywords
            if keyword_idx < len(SEARCH_KEYWORDS) - 1: # Don't sleep after the last keyword
                logging.info(f"关键词 '{keyword}' 处理完毕，休眠 {GITHUB_KEYWORD_SLEEP} 秒...")
                await asyncio.sleep(GITHUB_KEYWORD_SLEEP)
            
    return list(found_urls)

if __name__ == "__main__":
    try:
        # Windows event loop policy for ProactorEventLoop for subprocesses if needed
        if sys.platform == "win32" and sys.version_info >= (3, 8):
             asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        asyncio.run(main())

    except KeyboardInterrupt:
        logging.info("脚本被用户中断。")
    except Exception as e:
        logging.critical(f"脚本主程序遇到致命错误: {e}")
        logging.critical(traceback.format_exc())
