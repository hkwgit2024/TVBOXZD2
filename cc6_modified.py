import asyncio
import aiohttp
import base64
import json
import logging
import re
import urllib.parse
import yaml # Not explicitly used, but kept for compatibility if you use it elsewhere
import os
import argparse
import csv
import hashlib # For calculating content hash
from collections import defaultdict
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime, timedelta # For managing cache expiry
from bs4 import BeautifulSoup, Comment
from fake_useragent import UserAgent
from playwright.async_api import async_playwright, Page, BrowserContext

# --- 配置 ---
LOG_FILE = 'data/proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_NODES_OUTPUT_DIR = 'data/nodes'
DEFAULT_STATS_FILE = 'data/node_counts.csv'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 30
PLAYWRIGHT_GOTO_TIMEOUT = 45000 # Playwright 页面加载超时，单位毫秒 (45秒)
MAX_BASE64_DECODE_DEPTH = 3
UA = UserAgent()

# 缓存配置
CACHE_FILE = 'data/fetch_cache.json'
CACHE_EXPIRY_HOURS = 48 # 缓存有效期（小时）

# 配置日志系统
os.makedirs('data', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 定义支持的节点协议及其正则表达式模式
NODE_PATTERNS = {
    'ss': r'ss://[^\s#]+(?:#[^\n]*)?',
    'ssr': r'ssr://[^\s#]+(?:#[^\n]*)?',
    'vmess': r'vmess://[^\s#]+(?:#[^\n]*)?',
    'vless': r'vless://[^\s#]+(?:#[^\n]*)?',
    'trojan': r'trojan://[^\s#]+(?:#[^\n]*)?',
    'hy2': r'hy2://[^\s#]+(?:#[^\n]*)?',
    'tuic': r'tuic://[^\s#]+(?:#[^\n]*)?',
    'warp': r'warp://[^\s#]+(?:#[^\n]*)?',
    'hysteria': r'hysteria://[^\s#]+(?:#[^\n]*)?',
    'snell': r'snell://[^\s#]+(?:#[^\n]*)?',
    'socks5': r'socks5://[^\s#]+(?:#[^\n]*)?',
    'http': r'http://[^\s#]+(?:#[^\n]*)?',
    'https': r'https://[^\s#]+(?:#[^\n]*)?',
    # 添加Clash和Sing-box的订阅链接模式
    'clash_sub': r'http(?:s)?://[^\s#]+\.clash(?:[?].*)?',
    'singbox_sub': r'http(?:s)?://[^\s#]+\.s(?:b|b|b)?(?:[?].*)?', # 简化的Sing-box订阅链接
}

# 修正后的用于提取Base64编码内容的正则表达式
BASE64_PATTERNS = [
    re.compile(r'vmess://([a-zA-Z0-9+/=]+)'),
    re.compile(r'vless://([a-zA-Z0-9+/=]+)'),
    re.compile(r'trojan://([a-zA-Z0-9+/=]+)'),
    re.compile(r'ss://([a-zA-Z0-9+/=]+)'),
    re.compile(r'ssr://([a-zA-Z0-9+/=]+)'),
    re.compile(r'(?:vmess|vless|trojan|ss|ssr)://([a-zA-Z0-9+/=]{100,})'), # 捕获较长的base64字符串
    # 修正这一行：使用原始字符串，并处理内部的单引号和双引号
    re.compile(r'(?<=[ "\'])([a-zA-Z0-9+/=]{500,})(?=[ "\'])'), # 捕获可能包含节点的大段base64字符串
]

# 修正后的用于在JavaScript代码中查找vmess/vless/trojan配置的正则表达式
JS_CONFIG_PATTERNS = [
    re.compile(r"(vmess|vless|trojan) = ['\"]([^'\"]+)['\"]"),
    re.compile(r"(vmess|vless|trojan) = JSON\.parse\(['\"]([^'\"]+)['\"]\)")
]

# --- 辅助函数 ---
def sanitize_filename_from_url(url: str) -> str:
    """从URL生成一个安全的文件名，只保留字母数字和点号，替换其他为下划线"""
    parsed = urllib.parse.urlparse(url)
    # 取 hostname，如果 hostname 不存在（如纯路径），则取整个 path
    domain = parsed.hostname if parsed.hostname else parsed.path.replace('/', '_')
    domain = domain.replace('.', '_').replace('-', '_') # 进一步处理域名
    # 移除或替换不安全的字符
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '', domain)
    # 限制文件名长度，避免过长
    return sanitized[:200] + ".txt"

def decode_base64_recursively(encoded_string: str, depth: int = 0) -> str:
    """递归解码Base64字符串，最多 MAX_BASE64_DECODE_DEPTH 层"""
    if depth >= MAX_BASE64_DECODE_DEPTH:
        return encoded_string # 达到最大深度，停止解码
    try:
        decoded_bytes = base64.b64decode(encoded_string.encode('utf-8'))
        decoded_str = decoded_bytes.decode('utf-8')
        if re.search(r'(vmess|vless|trojan|ss|ssr)://', decoded_str): # 如果解码后包含节点关键字，可能还需要进一步解码
            return decode_base64_recursively(decoded_str, depth + 1)
        return decoded_str
    except Exception:
        return encoded_string # 解码失败或不包含节点关键字，返回原始字符串

def extract_nodes(content: str) -> List[str]:
    """从文本内容中提取各种节点链接"""
    all_nodes = set()

    # 1. 直接匹配协议模式
    for pattern_name, pattern in NODE_PATTERNS.items():
        if 'sub' not in pattern_name: # 不直接匹配订阅链接本身作为节点
            matches = re.findall(pattern, content)
            for match in matches:
                all_nodes.add(match)

    # 2. 查找并解码Base64编码的节点
    for pattern in BASE64_PATTERNS:
        matches = pattern.findall(content)
        for encoded in matches:
            decoded = decode_base64_recursively(encoded)
            for node_pattern in NODE_PATTERNS.values():
                if 'sub' not in node_pattern:
                    node_matches = re.findall(node_pattern, decoded)
                    for node in node_matches:
                        all_nodes.add(node)
            # 检查是否解码出订阅链接
            for sub_pattern in ['clash_sub', 'singbox_sub']:
                sub_matches = re.findall(NODE_PATTERNS[sub_pattern], decoded)
                for sub_link in sub_matches:
                    all_nodes.add(sub_link) # 将订阅链接也作为一种节点添加，后续可能需要二次处理

    # 3. 解析HTML以查找潜在节点和JS配置
    try:
        # 使用 lxml 解析器进行优化
        soup = BeautifulSoup(content, 'lxml')

        # 查找所有文本节点，包括可能隐藏在注释中的节点
        for element in soup.find_all(string=True):
            if isinstance(element, Comment):
                # 检查注释内容
                for node_pattern in NODE_PATTERNS.values():
                    if 'sub' not in node_pattern:
                        matches = re.findall(node_pattern, str(element))
                        for match in matches:
                            all_nodes.add(match)
            else:
                # 检查可见文本内容
                for node_pattern in NODE_PATTERNS.values():
                    if 'sub' not in node_pattern:
                        matches = re.findall(node_pattern, element)
                        for match in matches:
                            all_nodes.add(match)
        
        # 查找 script 标签内容中的节点和 Base64
        for script in soup.find_all('script'):
            script_content = script.string
            if script_content:
                # 检查 JS 配置模式
                for pattern in JS_CONFIG_PATTERNS:
                    js_matches = pattern.findall(script_content)
                    for _, encoded in js_matches:
                        decoded = decode_base64_recursively(encoded)
                        for node_pattern in NODE_PATTERNS.values():
                            if 'sub' not in node_pattern:
                                node_matches = re.findall(node_pattern, decoded)
                                for node in node_matches:
                                    all_nodes.add(node)
                # 检查 script 标签中的其他 Base64 字符串
                for pattern in BASE64_PATTERNS:
                    matches = pattern.findall(script_content)
                    for encoded in matches:
                        decoded = decode_base64_recursively(encoded)
                        for node_pattern in NODE_PATTERNS.values():
                            if 'sub' not in node_pattern:
                                node_matches = re.findall(node_pattern, decoded)
                                for node in node_matches:
                                    all_nodes.add(node)
                        # 检查是否解码出订阅链接
                        for sub_pattern in ['clash_sub', 'singbox_sub']:
                            sub_matches = re.findall(NODE_PATTERNS[sub_pattern], decoded)
                            for sub_link in sub_matches:
                                all_nodes.add(sub_link)

        # 查找特定属性中的节点 (例如 data-url, href等)
        for tag in soup.find_all(True): # 查找所有标签
            for attr in ['href', 'src', 'data-url', 'data-link', 'data-node']: # 检查常见属性
                if attr in tag.attrs:
                    value = tag.attrs[attr]
                    for node_pattern in NODE_PATTERNS.values():
                        if 'sub' not in node_pattern:
                            matches = re.findall(node_pattern, value)
                            for match in matches:
                                all_nodes.add(match)
                    # 检查是否是订阅链接
                    for sub_pattern in ['clash_sub', 'singbox_sub']:
                        sub_matches = re.findall(NODE_PATTERNS[sub_pattern], value)
                        for sub_link in sub_matches:
                            all_nodes.add(sub_link)

    except Exception as e:
        logger.warning(f"BeautifulSoup 解析或节点提取出错: {e}")

    return list(all_nodes)

def calculate_content_hash(content: str) -> str:
    """计算内容的 SHA256 哈希值"""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def load_cache() -> Dict[str, Any]:
    """从文件中加载缓存数据"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache = json.load(f)
                # 转换日期字符串为datetime对象
                for url_data in cache.values():
                    if 'last_fetched' in url_data:
                        try:
                            url_data['last_fetched'] = datetime.fromisoformat(url_data['last_fetched'])
                        except ValueError:
                            # 处理旧格式或无效日期，清除该条目以强制重新获取
                            logger.warning(f"缓存中 '{url_data}' 的 last_fetched 日期格式无效，将强制重新获取。")
                            url_data['last_fetched'] = None
                logger.info(f"成功从 '{CACHE_FILE}' 加载缓存。")
                return cache
        except json.JSONDecodeError as e:
            logger.warning(f"缓存文件 '{CACHE_FILE}' 格式错误: {e}。将创建新的空缓存。")
        except Exception as e:
            logger.warning(f"加载缓存文件 '{CACHE_FILE}' 失败: {e}。将创建新的空缓存。")
    return {}

def save_cache(cache: Dict[str, Any]):
    """将缓存数据保存到文件"""
    try:
        # 转换datetime对象为日期字符串
        cache_to_save = {}
        for url, url_data in cache.items():
            data_copy = url_data.copy()
            if 'last_fetched' in data_copy and isinstance(data_copy['last_fetched'], datetime):
                data_copy['last_fetched'] = data_copy['last_fetched'].isoformat()
            cache_to_save[url] = data_copy

        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache_to_save, f, ensure_ascii=False, indent=2)
        logger.info(f"成功保存缓存到 '{CACHE_FILE}'。")
    except Exception as e:
        logger.error(f"保存缓存文件 '{CACHE_FILE}' 失败: {e}")


# --- Fetching Strategies ---
async def fetch_with_aiohttp(session: aiohttp.ClientSession, url: str, timeout: int) -> Optional[str]:
    """使用 aiohttp 获取网页内容"""
    try:
        user_agent = UA.random
        headers = {'User-Agent': user_agent}
        # 暂不实现ETag/Last-Modified，先专注于本地缓存
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), headers=headers, ssl=False) as response:
            response.raise_for_status() # 抛出HTTP错误（4xx或5xx）
            content = await response.text()
            logger.info(f"成功获取 {url} (aiohttp)")
            return content
    except aiohttp.ClientError as e:
        logger.warning(f"aiohttp 请求 {url} 失败: {e}")
    except asyncio.TimeoutError:
        logger.warning(f"aiohttp 请求 {url} 超时 ({timeout}s)")
    except Exception as e:
        logger.error(f"aiohttp 获取 {url} 时发生未预期错误: {e}")
    return None

async def fetch_with_browser(playwright_instance: Any, url: str, timeout: int, browser_context: BrowserContext) -> Optional[str]:
    """使用 Playwright 获取网页内容"""
    page: Optional[Page] = None
    try:
        page = await browser_context.new_page()
        # 设置页面超时，Page.goto 的 timeout 是毫秒
        await page.goto(url, wait_until="load", timeout=PLAYWRIGHT_GOTO_TIMEOUT)
        
        # 针对特定场景的额外等待，例如等待某些元素出现
        # await page.wait_for_selector('body', timeout=timeout * 1000) # 等待body元素加载，防止页面为空
        
        content = await page.content()
        logger.info(f"成功获取 {url} (Playwright)")
        return content
    except Exception as e:
        logger.warning(f"Playwright 请求 {url} 失败: {e.__class__.__name__}: {e}")
    finally:
        if page:
            await page.close()
    return None

async def process_single_url_strategy(
    url: str,
    timeout: int,
    use_browser: bool,
    session: Optional[aiohttp.ClientSession],
    playwright_instance: Optional[Any],
    browser_context: Optional[BrowserContext],
    cache: Dict[str, Any] # 缓存字典
) -> Tuple[str, List[str], str]:
    """处理单个 URL，根据策略选择获取方式并提取节点，并利用缓存。"""
    content = None
    status = "失败"
    extracted_nodes = []

    current_time = datetime.now()
    
    # --- 1. 检查缓存 ---
    if url in cache:
        cached_data = cache[url]
        last_fetched_time = cached_data.get('last_fetched')
        cached_hash = cached_data.get('content_hash')
        cached_nodes_count = cached_data.get('nodes_count', 0)

        if last_fetched_time and isinstance(last_fetched_time, datetime):
            # 缓存未过期
            if current_time - last_fetched_time < timedelta(hours=CACHE_EXPIRY_HOURS):
                logger.info(f"使用缓存获取 {url} (上次获取时间: {last_fetched_time.strftime('%Y-%m-%d %H:%M:%S')}) - 缓存未过期。")
                # 不实际提取节点，仅返回缓存的节点数量
                extracted_nodes = ['_cached_node_'] * cached_nodes_count # 用虚拟节点占位
                status = "成功 (缓存未过期)"
                return url, extracted_nodes, status
            # 缓存已过期，但有哈希值，尝试获取并对比哈希
            elif cached_hash:
                logger.info(f"缓存 {url} 已过期，但有内容哈希，尝试重新获取并对比。")
                # 继续尝试获取，如果内容相同则只更新时间戳

    # --- 2. 获取内容 (如果缓存未命中或已过期) ---
    try:
        fetch_method = ""
        if use_browser and playwright_instance and browser_context:
            content = await fetch_with_browser(playwright_instance, url, timeout, browser_context)
            fetch_method = "Playwright"
            if not content and session: # Playwright 失败，尝试回退
                logger.warning(f"Playwright 未能获取 {url}，尝试回退到 aiohttp。")
                content = await fetch_with_aiohttp(session, url, timeout)
                fetch_method = "HTTP 回退"
        elif session: # 不使用浏览器或浏览器不可用
            content = await fetch_with_aiohttp(session, url, timeout)
            fetch_method = "HTTP"
        else:
            logger.error(f"没有可用的内容获取策略 (URL: {url})")
            status = "失败 (无策略)"
            return url, extracted_nodes, status

        if not content:
            status = f"失败 ({fetch_method})"
            return url, extracted_nodes, status

        # --- 3. 处理内容并更新缓存 ---
        new_content_hash = calculate_content_hash(content)
        
        # 检查内容是否真的发生了变化（如果之前有缓存且有哈希）
        if url in cache and cache[url].get('content_hash') == new_content_hash:
            # 内容未变，只更新缓存时间，不重新提取节点
            cache[url]['last_fetched'] = current_time
            # 使用上次缓存的节点数量
            extracted_nodes = ['_cached_node_'] * cache[url].get('nodes_count', 0) # 仍用虚拟节点占位
            status = f"成功 (内容未变，已更新缓存时间 via {fetch_method})"
            logger.info(f"内容未变 {url} (哈希: {new_content_hash[:8]}...) - 已更新缓存时间。")
        else:
            # 内容发生变化或无缓存，重新提取节点
            extracted_nodes = extract_nodes(content)
            
            # 更新缓存
            cache[url] = {
                'last_fetched': current_time,
                'content_hash': new_content_hash,
                'nodes_count': len(extracted_nodes)
            }
            status = f"成功 (内容已更新，已刷新缓存 via {fetch_method})"
            logger.info(f"处理完成 {len(extracted_nodes)} 个节点来自 {url} (哈希: {new_content_hash[:8]}...) - 已刷新缓存。")

    except Exception as e:
        logger.error(f"处理 URL {url} 时发生未预期错误: {e}")
        status = "失败 (异常)"

    return url, extracted_nodes, status


async def main():
    parser = argparse.ArgumentParser(description="从 sources.list 获取代理节点并保存。")
    parser.add_argument('--sources', type=str, default=DEFAULT_SOURCES_FILE,
                        help='包含代理源URL的文件路径。')
    parser.add_argument('--nodes-output-dir', type=str, default=DEFAULT_NODES_OUTPUT_DIR,
                        help='保存提取到的节点的目录。每个链接的节点将保存为单独的文件。')
    parser.add_argument('--stats-output', type=str, default=DEFAULT_STATS_FILE,
                        help='保存统计数据（CSV格式）的文件路径。')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY,
                        help='同时处理的最大URL数量。')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='单个网络请求的超时时间（秒）。')
    parser.add_argument('--use-browser', action='store_true',
                        help='使用Playwright进行网页内容获取，以处理JavaScript渲染的页面。')
    args = parser.parse_args()

    os.makedirs(args.nodes_output_dir, exist_ok=True) # 确保节点输出目录存在

    sources = []
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"正在从 '{args.sources}' 加载代理源...")
        logger.info(f"共找到 {len(sources)} 个代理源。")
    except FileNotFoundError:
        logger.error(f"错误: 源文件 '{args.sources}' 未找到。请创建该文件并添加代理URL。")
        return

    # 加载缓存
    fetch_cache = load_cache()

    url_node_counts: Dict[str, int] = {}
    url_statuses: Dict[str, str] = {} # 存储每个URL的最终状态

    logger.info(f"启动节点提取过程，最大并发数: {args.max_concurrency}, 超时: {args.timeout}s, 使用浏览器: {args.use_browser}。")
    logger.info(f"缓存有效期设置为 {CACHE_EXPIRY_HOURS} 小时。")


    playwright_instance = None
    browser = None
    browser_context = None

    if args.use_browser:
        try:
            playwright_instance = await async_playwright().start()
            browser = await playwright_instance.chromium.launch() # headless=True by default
            browser_context = await browser.new_context()
            logger.info("Playwright 浏览器已启动。")
        except Exception as e:
            logger.error(f"启动 Playwright 浏览器失败: {e}。将不使用浏览器获取内容。")
            args.use_browser = False # 如果启动失败，禁用浏览器模式

    async with aiohttp.ClientSession() as session:
        logger.info("aiohttp 客户端会话已启动。")
        semaphore = asyncio.Semaphore(args.max_concurrency)
        tasks = []

        async def bounded_process(url: str):
            async with semaphore:
                return await process_single_url_strategy(url, args.timeout, args.use_browser, session, playwright_instance, browser_context, fetch_cache)

        for url in sources:
            tasks.append(bounded_process(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"处理任务时发生未预期异常: {result}")
                continue

            url_domain, extracted_nodes, status = result
            
            # 如果是从缓存中读取的，extracted_nodes 可能是虚拟列表，其长度表示节点数量
            actual_node_count = len(extracted_nodes)
            
            url_node_counts[url_domain] = actual_node_count
            url_statuses[url_domain] = status # 存储详细状态

            # 只有当实际获取并处理了内容（非缓存命中）时才写入文件
            if "缓存未过期" in status and fetch_cache.get(url_domain, {}).get('nodes_count', 0) > 0:
                logger.info(f"源 {url_domain} 节点来自缓存，节点数量: {actual_node_count}。跳过文件写入。")
            elif actual_node_count > 0 and "_cached_node_" not in extracted_nodes[0]: # 确保不是虚拟节点列表
                sanitized_filename = sanitize_filename_from_url(url_domain)
                output_path = os.path.join(args.nodes_output_dir, sanitized_filename)
                try:
                    content_to_write = '\n'.join(extracted_nodes)
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(content_to_write)
                    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
                    logger.info(f"保存 {actual_node_count} 个节点到 {output_path} ({file_size_mb:.2f} MB)")
                except Exception as e:
                    logger.error(f"保存节点到文件 '{output_path}' 失败: {e}")
            else:
                logger.info(f"源 {url_domain} 未提取到节点或节点来自缓存且无变化，跳过文件写入。")

    # --- 统计数据保存为 CSV ---
    try:
        os.makedirs(os.path.dirname(args.stats_output), exist_ok=True)
        with open(args.stats_output, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Source_URL', 'Nodes_Found', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True):
                status_for_csv = url_statuses.get(url, "未知")
                writer.writerow({'Source_URL': url, 'Nodes_Found': count, 'Status': status_for_csv})
        logger.info(f"统计数据已保存到 '{args.stats_output}'")
    except Exception as e:
        logger.error(f"保存统计数据失败: {e}")

    finally:
        # 保存缓存
        save_cache(fetch_cache)

        if browser_context:
            await browser_context.close()
        if browser:
            await browser.close()
        if playwright_instance:
            await playwright_instance.stop()
        logger.info("脚本运行完成。")

if __name__ == "__main__":
    asyncio.run(main())
