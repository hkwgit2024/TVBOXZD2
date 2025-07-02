import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
import yaml
from fake_useragent import UserAgent
from playwright.async_api import async_playwright, Playwright
import logging
import argparse
import os
import csv
from datetime import datetime
from collections import defaultdict
import base64 # 导入 base64 用于解码

# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 全局 Playwright 浏览器实例池 ---
# 避免每次都启动新的浏览器，提高效率
browser_pool: dict = {}
MAX_BROWSER_INSTANCES = 1 # 限制同时存在的浏览器实例数量，防止资源耗尽

async def get_browser(playwright: Playwright):
    """从浏览器池获取或创建浏览器实例"""
    # 简单的池管理，目前只维护一个实例
    if not browser_pool:
        browser = await playwright.chromium.launch()
        browser_pool['default'] = browser
        logger.info("创建新的 Playwright 浏览器实例。")
    return browser_pool['default']

async def close_browser_pool():
    """关闭浏览器池中的所有浏览器实例"""
    for browser in browser_pool.values():
        await browser.close()
        logger.info("关闭 Playwright 浏览器实例。")
    browser_pool.clear()

# --- 辅助函数：提取字符串中的URL ---
def extract_urls(text):
    """从文本中提取所有有效的 URL"""
    # 尽可能匹配各种协议和域名模式
    urls = re.findall(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    return [url for url in urls if "http" in url]

# --- 核心抓取逻辑 ---
async def fetch_url(session: aiohttp.ClientSession, url: str, use_browser: bool,
                    retries: int = 3, timeout: int = 20, is_browser_request: bool = False,
                    playwright_instance: Playwright = None):
    """
    尝试从 URL 获取内容，支持重试和浏览器模式。
    增加了重试的指数退避机制。
    """
    ua = UserAgent()
    headers = {'User-Agent': ua.random}
    initial_timeout = timeout

    for attempt in range(retries):
        current_timeout = initial_timeout * (2 ** attempt) # 指数退避
        if current_timeout > 60: # 限制最大超时时间
            current_timeout = 60

        try:
            if use_browser and is_browser_request:
                if playwright_instance is None:
                    logger.error(f"Playwright 实例未提供，无法使用浏览器获取 {url}")
                    break # 无法继续重试
                browser = await get_browser(playwright_instance)
                page = await browser.new_page()
                try:
                    # 使用 networkidle 或 domcontentloaded，根据实际情况调整
                    # networkidle 通常更稳健，domcontentloaded 更快
                    await page.goto(url, wait_until="networkidle", timeout=current_timeout * 1000)
                    content = await page.content()
                    logger.info(f"成功使用浏览器获取 URL: {url} (尝试 {attempt + 1}/{retries})")
                    return content
                except Exception as e:
                    logger.warning(f"使用浏览器获取 URL {url} 失败 (尝试 {attempt + 1}/{retries}): {e}")
                    # 检测到永久性错误，不再重试
                    if "ERR_NAME_NOT_RESOLVED" in str(e) or "ERR_SSL_VERSION_OR_CIPHER_MISMATCH" in str(e):
                        logger.warning(f"检测到永久性错误 ({e}), 不再重试此 URL.")
                        break
                    await asyncio.sleep(1 + attempt * 2) # 重试前等待
                finally:
                    await page.close()
            else:
                async with session.get(url, headers=headers, timeout=current_timeout, allow_redirects=True) as response:
                    response.raise_for_status()  # 检查 HTTP 状态码
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'text' in content_type or 'json' in content_type or 'xml' in content_type:
                        content = await response.text()
                        logger.info(f"成功使用 HTTP 获取 URL: {url} (尝试 {attempt + 1}/{retries})")
                        return content
                    else:
                        logger.warning(f"URL {url} 返回非文本内容: {content_type} (尝试 {attempt + 1}/{retries})")
                        break # 非文本内容，无需重试

        except aiohttp.ClientError as e:
            logger.warning(f"HTTP 获取 URL {url} 失败 (尝试 {attempt + 1}/{retries}): {e}")
            if "ERR_NAME_NOT_RESOLVED" in str(e) or "DNS lookup failed" in str(e):
                logger.warning(f"检测到域名解析错误，不再重试此 URL.")
                break # 域名解析错误，不再重试
            await asyncio.sleep(1 + attempt * 2) # 重试前等待
        except asyncio.TimeoutError:
            logger.warning(f"获取 URL {url} 超时 (尝试 {attempt + 1}/{retries})")
            await asyncio.sleep(1 + attempt * 2) # 重试前等待
        except Exception as e:
            logger.warning(f"获取 URL {url} 时发生未知错误 (尝试 {attempt + 1}/{retries}): {e}")
            break # 其他未知错误，可能不适合重试

    return None # 所有重试失败

async def process_source(session: aiohttp.ClientSession, url: str, use_browser: bool, timeout: int, playwright_instance: Playwright = None):
    """处理单个代理源，尝试 HTTP 和 HTTPS，并在必要时使用浏览器"""
    nodes = []
    
    # 尝试 HTTP
    logger.info(f"正在获取: {url}")
    content = await fetch_url(session, url, use_browser, timeout=timeout, is_browser_request=False)
    if content:
        extracted_nodes = parse_content(content, url)
        if extracted_nodes:
            nodes.extend(extracted_nodes)
            logger.info(f"从 {url} (HTTP) 提取到 {len(extracted_nodes)} 个节点。")
    
    # 如果 HTTP 失败或无节点，尝试 HTTPS (如果原 URL是 HTTP)
    if not nodes and url.startswith("http://"):
        https_url = url.replace("http://", "https://", 1)
        logger.info(f"HTTP 失败或无节点，尝试获取: {https_url}")
        content = await fetch_url(session, https_url, use_browser, timeout=timeout, is_browser_request=False)
        if content:
            extracted_nodes = parse_content(content, https_url)
            if extracted_nodes:
                nodes.extend(extracted_nodes)
                logger.info(f"从 {https_url} (HTTPS) 提取到 {len(extracted_nodes)} 个节点。")

    # 如果仍然没有节点且启用了浏览器模式，尝试使用浏览器
    # 并且只有当 http/https 尝试都失败时才启用浏览器模式，减少不必要的开销
    if not nodes and use_browser:
        logger.info(f"尝试使用浏览器获取 URL: {url}")
        content_browser = await fetch_url(session, url, use_browser, timeout=timeout, is_browser_request=True, playwright_instance=playwright_instance)
        if content_browser:
            extracted_nodes_browser = parse_content(content_browser, url)
            if extracted_nodes_browser:
                nodes.extend(extracted_nodes_browser)
                logger.info(f"从 {url} (浏览器) 提取到 {len(extracted_nodes_browser)} 个节点。")
        else:
            logger.warning(f"使用浏览器未能从 {url} 提取到节点。")
    
    if not nodes:
        logger.warning(f"HTTP 和 HTTPS 均未能从 {url} 提取到节点。")
        
    return list(set(nodes)) # 去重并返回

def parse_content(content: str, url: str):
    """
    智能解析内容，尝试识别常见的代理订阅格式。
    增加了对 HTML 页面的 <pre> 标签解析，以及 Base64 解码。
    """
    extracted = []

    # 1. 直接尝试 Base64 解码
    try:
        decoded_content = base64.b64decode(content).decode('utf-8', errors='ignore')
        # 如果解码成功，尝试用 YAML 或 JSON 解析，否则当作纯文本处理
        if decoded_content:
            try:
                # 尝试解析为 YAML (适用于 Clash/V2RayN config)
                parsed_yaml = yaml.safe_load(decoded_content)
                if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'outbounds' in parsed_yaml):
                    # 这是一个代理配置文件，我们应该进一步解析
                    # 简化处理，只提取 Vmess, Vless, Trojan, Shadowsocks 等链接
                    # 可以在这里增加更复杂的逻辑来从字典中提取节点
                    # 目前我们假设这些链接会直接出现在 decoded_content 中
                    pass
            except yaml.YAMLError:
                pass # 不是有效的 YAML，继续按纯文本处理

            # 提取所有看起来像代理链接的行
            for line in decoded_content.splitlines():
                line = line.strip()
                if re.match(r"^(vmess|vless|ss|ssr|trojan|hy2|tuic|warp)://", line, re.IGNORECASE):
                    extracted.append(line)
            if extracted:
                logger.info(f"从 {url} (Base64解码内容) 提取到 {len(extracted)} 个节点。")
                return extracted

    except Exception:
        pass # 不是有效的 Base64，继续

    # 2. 尝试解析 HTML 页面
    # 判断是否为 HTML 内容的更严格方式
    if re.search(r"<\s*html\s*>|<\s*body\s*>", content, re.IGNORECASE):
        soup = BeautifulSoup(content, 'html.parser')
        # 寻找 pre 标签中的内容，通常代理订阅会放在这里
        for pre_tag in soup.find_all('pre'):
            text_in_pre = pre_tag.get_text()
            # 尝试 Base64 解码 <pre> 标签中的内容
            try:
                decoded_pre = base64.b64decode(text_in_pre).decode('utf-8', errors='ignore')
                for line in decoded_pre.splitlines():
                    line = line.strip()
                    if re.match(r"^(vmess|vless|ss|ssr|trojan|hy2|tuic|warp)://", line, re.IGNORECASE):
                        extracted.append(line)
            except Exception:
                pass
            
            # 直接从 <pre> 标签文本中提取 URL
            urls_in_pre = extract_urls(text_in_pre)
            if urls_in_pre:
                extracted.extend(urls_in_pre)

        # 尝试寻找所有看起来像代理链接的文本（可能不在 <pre> 中，或页面是纯链接列表）
        body_text = soup.get_text()
        for line in body_text.splitlines():
            line = line.strip()
            if re.match(r"^(vmess|vless|ss|ssr|trojan|hy2|tuic|warp)://", line, re.IGNORECASE):
                extracted.append(line)

        if extracted:
            logger.info(f"从 {url} (HTML 解析) 提取到 {len(extracted)} 个节点。")
            return list(set(extracted)) # 确保去重

    # 3. 如果都不是，就当作纯文本处理（直接寻找代理链接）
    for line in content.splitlines():
        line = line.strip()
        if re.match(r"^(vmess|vless|ss|ssr|trojan|hy2|tuic|warp)://", line, re.IGNORECASE):
            extracted.append(line)
    
    if extracted:
        logger.info(f"从 {url} (纯文本解析) 提取到 {len(extracted)} 个节点。")
    return list(set(extracted)) # 确保去重

# --- 文件操作与分片 ---
def save_nodes_to_file(nodes: list, output_path: str, max_nodes_per_file: int = 2000):
    """
    将节点保存到文件，如果节点数量超过 max_nodes_per_file，则分片保存。
    同时确保目录存在。
    """
    output_dir = os.path.dirname(output_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"创建输出目录: {output_dir}")

    total_nodes = len(nodes)
    if total_nodes <= max_nodes_per_file:
        # 保存为单个文件
        with open(output_path, 'w', encoding='utf-8') as f:
            for node in nodes:
                f.write(node + '\n')
        logger.info(f"所有 {total_nodes} 个节点保存到 {output_path}")
    else:
        # 分片保存
        num_files = (total_nodes + max_nodes_per_file - 1) // max_nodes_per_file
        for i in range(num_files):
            start_index = i * max_nodes_per_file
            end_index = min((i + 1) * max_nodes_per_file, total_nodes)
            part_nodes = nodes[start_index:end_index]
            part_filename = f"{os.path.splitext(output_path)[0]}_part_{i+1:03d}.txt"
            with open(part_filename, 'w', encoding='utf-8') as f:
                for node in part_nodes:
                    f.write(node + '\n')
            logger.info(f"第 {i+1} 部分 ({len(part_nodes)} 个节点) 保存到 {part_filename}")
        logger.info(f"总共 {total_nodes} 个节点分片保存到 {num_files} 个文件。")

def record_node_counts(stats_output_path: str, protocol_counts: dict, total_nodes: int):
    """
    记录节点数量统计到 CSV 文件。
    如果文件不存在则创建头部，否则追加。
    """
    file_exists = os.path.exists(stats_output_path)
    
    with open(stats_output_path, 'a', newline='', encoding='utf-8') as csvfile:
        # 确保 fieldnames 的顺序一致，timestamp 和 total_nodes 在前面，协议类型按字母排序
        fieldnames = ['timestamp', 'total_nodes'] + sorted(protocol_counts.keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()
            logger.info(f"创建节点统计 CSV 文件: {stats_output_path}")
        
        row = {
            'timestamp': datetime.now().isoformat(),
            'total_nodes': total_nodes
        }
        # 填充协议计数，如果某个协议在当前运行中没有，则默认为0
        for proto in fieldnames[2:]: # 从第三个字段开始是协议类型
            row[proto] = protocol_counts.get(proto, 0)
        
        writer.writerow(row)
        logger.info(f"节点统计已记录到 {stats_output_path}")

# --- 主执行逻辑 ---
async def main():
    parser = argparse.ArgumentParser(description="从多个源抓取和转换代理节点。")
    parser.add_argument('--sources', required=True, help="包含代理源URL列表的文件路径。")
    parser.add_argument('--output', default='data/nodes.txt', help="输出节点文件或分片文件的基础路径。")
    parser.add_argument('--stats-output', default='data/node_counts.csv', help="输出节点统计CSV文件的路径。")
    parser.add_argument('--max-concurrency', type=int, default=50, help="HTTP/S 请求的最大并发数。")
    parser.add_argument('--timeout', type=int, default=20, help="每个请求的超时时间（秒）。")
    parser.add_argument('--use-browser', action='store_true', help="如果需要，使用浏览器（Playwright）进行抓取。")
    parser.add_argument('--max-nodes-per-file', type=int, default=2000, help="每个输出文件的最大节点数，用于分片。")

    args = parser.parse_args()

    # 读取源文件
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"从 {args.sources} 读取了 {len(urls)} 个代理源。")
    except FileNotFoundError:
        logger.error(f"源文件未找到: {args.sources}")
        return

    all_extracted_nodes = set()
    protocol_counts = defaultdict(int)

    # 初始化 Playwright (如果需要)
    playwright_instance = None
    if args.use_browser:
        logger.info("初始化 Playwright...")
        playwright_instance = await async_playwright().start()

    async with aiohttp.ClientSession() as session:
        # 使用 asyncio.Semaphore 控制并发数量
        semaphore = asyncio.Semaphore(args.max_concurrency)

        async def bounded_process_source(url):
            async with semaphore:
                return await process_source(session, url, args.use_browser, args.timeout, playwright_instance)

        tasks = [bounded_process_source(url) for url in urls]
        
        # 使用 asyncio.as_completed 允许我们实时处理完成的任务
        for future in asyncio.as_completed(tasks):
            nodes_from_source = await future
            if nodes_from_source:
                for node in nodes_from_source:
                    # 简单提取协议类型进行统计
                    match = re.match(r"^(vmess|vless|ss|ssr|trojan|hy2|tuic|warp)://", node, re.IGNORECASE)
                    if match:
                        protocol_counts[match.group(1).lower()] += 1
                all_extracted_nodes.update(nodes_from_source) # 使用 set 进行自动去重

    final_nodes = list(all_extracted_nodes)
    final_nodes_count = len(final_nodes)
    logger.info(f"所有源处理完成，共提取到 {final_nodes_count} 个不重复的代理节点。")

    # 保存节点
    save_nodes_to_file(final_nodes, args.output, args.max_nodes_per_file)

    # 记录统计
    record_node_counts(args.stats_output, protocol_counts, final_nodes_count)

    # 关闭浏览器实例池
    if playwright_instance:
        await close_browser_pool()
        await playwright_instance.stop()
        logger.info("Playwright 已停止。")

if __name__ == "__main__":
    asyncio.run(main())
