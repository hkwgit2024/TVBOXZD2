#!/usr/bin/env python3
import asyncio
import aiohttp
import aiofiles
import base64
import json
import logging
import re
import urllib.parse
import yaml
import os
import argparse
import csv
from collections import defaultdict
from typing import List, Dict, Set, Optional, Any
from datetime import datetime, timedelta
from bs4 import BeautifulSoup, Comment
from fake_useragent import UserAgent
from playwright.async_api import async_playwright, Page, BrowserContext
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from dataclasses import dataclass
from pathlib import Path
import subprocess
import time

# --- 配置 ---
CONFIG = {
    'LOG_FILE': 'proxy_converter.log',
    'LOG_FORMAT': '%(asctime)s - %(levelname)s - %(message)s',
    'SOURCES_FILE': 'sources.list',
    'OUTPUT_DIR': 'data',
    'OUTPUT_BASE': 'nodes',
    'STATS_FILE': 'data/node_counts.csv',
    'CONFIG_FILE': 'config.yaml',
    'MAX_CONCURRENCY': 50,
    'MIN_CONCURRENCY': 10,
    'TIMEOUT': 20,
    'MAX_BASE64_DECODE_DEPTH': 3,
    'MAX_FILE_SIZE_MB': 90,
    'MIN_LINES_PER_FILE': 10000,
    'CACHE_DIR': '.cache',
    'CACHE_TTL_HOURS': 24,
    'VALIDATE_NODES': False,
    'VALIDATION_TIMEOUT': 5,
    'OUTPUT_FORMATS': ['txt'],  # 支持 txt, json, yaml
    'PROTOCOL_SPLIT': False,  # 是否按协议分割输出
}

NODE_PATTERNS = {
    'ss': r'ss://[^\s#]+(?:#[^\n]*)?',
    'vmess': r'vmess://[^\s]+',
    'trojan': r'trojan://[^\s#]+(?:#[^\n]*)?',
    'vless': r'vless://[^\s#]+(?:#[^\n]*)?',
    'hysteria2': r'hysteria2://[^\s#]+(?:#[^\n]*)?',
    'hy2': r'hy2://[^\s#]+(?:#[^\n]*)?',
    'tuic': r'tuic://[^\s#]+(?:#[^\n]*)?',
    'ssr': r'ssr://[^\s]+',
    'snell': r'snell://[^\s]+',
}
COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values())
BASE64_REGEX = re.compile(
    r'(?:b64|base64|data:application\/octet-stream;base64,)?\s*["\']?((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))["\']?\s*',
    re.MULTILINE | re.IGNORECASE
)
JS_VAR_REGEX = re.compile(
    r'(?:var|let|const)\s+[\w]+\s*=\s*["\'](' + COMBINED_REGEX_PATTERN + r'|' + BASE64_REGEX.pattern + r')["\']',
    re.MULTILINE | re.IGNORECASE
)
JS_FUNC_CALL_REGEX = re.compile(
    r'(?:atob|decodeURIComponent)\s*\(\s*["\']?(' + BASE64_REGEX.pattern + r')["\']?\s*\)',
    re.MULTILINE | re.IGNORECASE
)

# 数据类
@dataclass
class ProxyNode:
    url: str
    protocol: str
    source_url: str
    validated: bool = False
    latency: float = None  # 延迟（毫秒）

# --- 配置和日志 ---
def load_config(config_file: str) -> Dict:
    """加载 YAML 配置文件，覆盖默认配置"""
    config = CONFIG.copy()
    try:
        if Path(config_file).exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f) or {}
            config.update(user_config)
            logging.info(f"已加载配置文件 {config_file}")
    except Exception as e:
        logging.warning(f"加载配置文件 {config_file} 失败: {e}")
    return config

def setup_logging(log_file: str, log_format: str) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

# --- 缓存管理 ---
async def load_cache(cache_file: Path) -> Dict[str, Dict[str, Any]]:
    if cache_file.exists():
        async with aiofiles.open(cache_file, 'r', encoding='utf-8') as f:
            try:
                data = json.loads(await f.read())
                if data.get('timestamp', 0) + CONFIG['CACHE_TTL_HOURS'] * 3600 > datetime.now().timestamp():
                    return {k: {node: ProxyNode(**info) for node, info in v.items()} for k, v in data.get('nodes', {}).items()}
            except json.JSONDecodeError:
                logging.warning(f"缓存文件 {cache_file} 解析失败，忽略缓存")
    return {}

async def save_cache(cache_file: Path, nodes: Dict[str, Dict[str, ProxyNode]]) -> None:
    cache_data = {
        'timestamp': datetime.now().timestamp(),
        'nodes': {k: {node.url: node.__dict__ for node in v.values()} for k, v in nodes.items()}
    }
    async with aiofiles.open(cache_file, 'w', encoding='utf-8') as f:
        await f.write(json.dumps(cache_data, ensure_ascii=False))

async def load_previous_nodes(output_dir: str, output_base: str) -> Set[str]:
    nodes = set()
    for file in Path(output_dir).glob(f"{output_base}*.txt"):
        async with aiofiles.open(file, 'r', encoding='utf-8') as f:
            nodes.update(line.strip() for line in await f.readlines() if line.strip())
    return nodes

# --- 辅助函数 ---
def setup_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='代理节点提取、验证和去重工具')
    parser.add_argument('--sources', default=CONFIG['SOURCES_FILE'], help='输入 URL 文件')
    parser.add_argument('--output-dir', default=CONFIG['OUTPUT_DIR'], help='输出目录')
    parser.add_argument('--output-base', default=CONFIG['OUTPUT_BASE'], help='输出文件基础名称')
    parser.add_argument('--stats-output', default=CONFIG['STATS_FILE'], help='统计数据输出文件')
    parser.add_argument('--config-file', default=CONFIG['CONFIG_FILE'], help='配置文件路径')
    parser.add_argument('--max-concurrency', type=int, default=CONFIG['MAX_CONCURRENCY'], help='最大并发请求数')
    parser.add_argument('--timeout', type=int, default=CONFIG['TIMEOUT'], help='请求超时时间（秒）')
    parser.add_argument('--use-browser', action='store_true', help='启用无头浏览器')
    parser.add_argument('--validate-nodes', action='store_true', help='验证节点有效性')
    parser.add_argument('--protocol-split', action='store_true', help='按协议分割输出')
    parser.add_argument('--output-formats', default=','.join(CONFIG['OUTPUT_FORMATS']), help='输出格式 (txt,json,yaml)')
    parser.add_argument('--cache-dir', default=CONFIG['CACHE_DIR'], help='缓存目录')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    try:
        cleaned_data = re.sub(r'[^A-Za-z0-9+/=]', '', data).replace('-', '+').replace('_', '/')
        padding = len(cleaned_data) % 4
        if padding:
            cleaned_data += '=' * (4 - padding)
        return base64.b64decode(cleaned_data).decode('utf-8', errors='ignore')
    except Exception as e:
        logging.debug(f"Base64 解码错误: {e}")
        return ""

def encode_base64(data: str) -> str:
    try:
        return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8').rstrip('=')
    except Exception:
        return data

def normalize_node_url(url: str) -> str:
    try:
        protocol, _, rest = url.partition('://')
        protocol = protocol.lower()
        if protocol not in NODE_PATTERNS:
            return url
        parsed = urllib.parse.urlparse(url)
        
        if protocol == 'vmess':
            config_json = decode_base64(rest)
            if not config_json:
                return url
            config = json.loads(config_json)
            ordered_keys = ['v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'tls', 'sni', 'host', 'path']
            clean_config = {k: config.get(k, '') for k in ordered_keys if k in config and config[k] is not None}
            clean_config['ps'] = urllib.parse.unquote(clean_config.get('ps', ''))
            clean_config = {k: v for k, v in clean_config.items() if not (k == 'aid' and v == 0) and not (k == 'v' and v == '2')}
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}"
        
        elif protocol == 'ssr':
            decoded = decode_base64(rest)
            if not decoded:
                return url
            core_match = re.match(r'([^/?#]+)(.*)', decoded)
            if not core_match:
                return url
            core, tail = core_match.groups()
            parts = core.split(':')
            if len(parts) < 6:
                return url
            host, port, proto, method, obfs, pwd = parts[:6]
            parsed_tail = urllib.parse.urlparse(tail)
            params = urllib.parse.parse_qs(parsed_tail.query)
            clean_params = {k: encode_base64(decode_base64(v[0]) or v[0]) for k, v in sorted(params.items())}
            query = urllib.parse.urlencode(clean_params)
            remark = encode_base64(decode_base64(parsed_tail.fragment) or '')
            core = f"{host}:{port}:{proto}:{method}:{obfs}:{pwd}"
            if query:
                core += f"/?{query}"
            if remark:
                core += f"#{remark}"
            return f"ssr://{encode_base64(core)}"
        
        else:
            auth = f"{urllib.parse.quote(parsed.username or '', safe='')}:{urllib.parse.quote(parsed.password or '', safe='')}@" if parsed.username or parsed.password else ''
            query = urllib.parse.urlencode({k: urllib.parse.quote(v[0], safe='') for k, v in sorted(urllib.parse.parse_qs(parsed.query).items())})
            fragment = f"#{urllib.parse.quote(urllib.parse.unquote(parsed.fragment), safe='')}" if parsed.fragment else ''
            return f"{protocol}://{auth}{parsed.netloc.lower()}{'?' + query if query else ''}{fragment}"
    except Exception as e:
        logging.debug(f"规范化 URL '{url}' 失败: {e}")
        return url

async def validate_node(node: ProxyNode, timeout: int) -> ProxyNode:
    """验证节点有效性（使用 ping 测试延迟）。"""
    try:
        parsed = urllib.parse.urlparse(node.url)
        host = parsed.hostname
        if not host:
            return ProxyNode(node.url, node.protocol, node.source_url, False)
        
        start_time = time.time()
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), host],
            capture_output=True, text=True, timeout=timeout
        )
        latency = (time.time() - start_time) * 1000  # 毫秒
        if result.returncode == 0:
            return ProxyNode(node.url, node.protocol, node.source_url, True, latency)
        return ProxyNode(node.url, node.protocol, node.source_url, False)
    except Exception as e:
        logging.debug(f"验证节点 {node.url} 失败: {e}")
        return ProxyNode(node.url, node.protocol, node.source_url, False)

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 配置转换为标准 URL（精简版）。"""
    proxy_type = proxy.get('type', '').lower()
    name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', f"{proxy_type}_node").strip()), safe='')
    server = proxy.get('server')
    port = proxy.get('port')
    if not all([server, port, proxy_type]):
        return None
    if proxy_type == 'ss':
        cipher = proxy.get('cipher')
        password = proxy.get('password')
        if not all([cipher, password]):
            return None
        auth = encode_base64(f"{cipher}:{password}")
        return f"ss://{auth}@{server}:{port}#{name}"
    # 其他协议逻辑同原脚本
    return None

def extract_nodes(content: str, decode_depth: int = 0, source_url: str = '') -> List[ProxyNode]:
    """提取代理节点，支持多种格式。"""
    nodes = set()
    if not content or decode_depth > CONFIG['MAX_BASE64_DECODE_DEPTH']:
        return []

    content = content.replace('\r\n', '\n').replace('\r', '\n')

    for protocol, pattern in NODE_PATTERNS.items():
        matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
        nodes.update(ProxyNode(normalize_node_url(m), protocol, source_url) for m in matches)

    try:
        soup = BeautifulSoup(content, 'html.parser')
        for tag in soup.find_all(True):
            for attr in ['href', 'src', 'data-url', 'data-node']:
                if attr in tag.attrs:
                    link = tag.attrs[attr].strip()
                    if re.match(COMBINED_REGEX_PATTERN, link, re.IGNORECASE):
                        nodes.add(ProxyNode(normalize_node_url(link), '', source_url))
                    elif BASE64_REGEX.fullmatch(link):
                        decoded = decode_base64(BASE64_REGEX.search(link).group(1))
                        nodes.update(extract_nodes(decoded, decode_depth + 1, source_url))
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            nodes.update(extract_nodes(str(comment), decode_depth + 1, source_url))
    except Exception as e:
        logging.debug(f"HTML 解析失败: {e}")

    for match in JS_VAR_REGEX.findall(content):
        val = match if isinstance(match, str) else match[0]
        if re.match(COMBINED_REGEX_PATTERN, val, re.IGNORECASE):
            nodes.add(ProxyNode(normalize_node_url(val), '', source_url))
        elif BASE64_REGEX.fullmatch(val):
            nodes.update(extract_nodes(decode_base64(val), decode_depth + 1, source_url))

    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy in yaml_content['proxies']:
                if url := convert_clash_proxy_to_url(proxy):
                    nodes.add(ProxyNode(normalize_node_url(url), proxy.get('type', ''), source_url))
    except yaml.YAMLError:
        pass

    for b64 in BASE64_REGEX.findall(content):
        decoded = decode_base64(b64[0])
        if decoded and len(decoded) > 20:
            nodes.update(extract_nodes(decoded, decode_depth + 1, source_url))

    return sorted(list(nodes), key=lambda x: x.url)

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3) -> tuple[str, float]:
    headers = {'User-Agent': UserAgent().random, 'Referer': url}
    start_time = time.time()
    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    response.raise_for_status()
                    return await response.text(), (time.time() - start_time) * 1000
        except aiohttp.ClientResponseError as e:
            if e.status == 429 and attempt < retries - 1:  # 太多请求
                logging.debug(f"URL {url} 返回 429，等待后重试")
                await asyncio.sleep(2 ** attempt * 5)  # 更长的退避时间
            else:
                logging.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}, 错误: {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)
        except Exception as e:
            logging.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}, 错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
    return "", (time.time() - start_time) * 1000

async def fetch_with_browser(browser_context: BrowserContext, url: str, timeout: int) -> tuple[str, float]:
    page: Page = await browser_context.new_page()
    start_time = time.time()
    try:
        await page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
        return await page.content(), (time.time() - start_time) * 1000
    except Exception as e:
        logging.warning(f"浏览器获取 {url} 失败: {e}")
        return "", (time.time() - start_time) * 1000
    finally:
        await page.close()

async def process_url(session: aiohttp.ClientSession, url: str, timeout: int, use_browser: bool, browser_context: Optional[BrowserContext], cache: Dict[str, Dict[str, ProxyNode]], concurrency: int) -> tuple[Set[ProxyNode], float]:
    if url in cache:
        logging.info(f"从缓存加载 {url} 的节点")
        return set(cache[url].values()), 0

    content, latency = await fetch_with_retry(session, url, timeout)
    if not content and use_browser and browser_context:
        content, latency = await fetch_with_browser(browser_context, url, timeout)
    
    nodes = set(extract_nodes(content, source_url=url))
    cache[url] = {node.url: node for node in nodes}
    
    # 动态调整并发数
    if latency > timeout * 1000 * 0.8:  # 响应时间接近超时
        new_concurrency = max(CONFIG['MIN_CONCURRENCY'], concurrency - 5)
        logging.info(f"响应时间 {latency:.2f}ms 过长，降低并发数到 {new_concurrency}")
        return nodes, new_concurrency
    elif latency < timeout * 1000 * 0.2:  # 响应时间很快
        new_concurrency = min(CONFIG['MAX_CONCURRENCY'], concurrency + 5)
        logging.info(f"响应时间 {latency:.2f}ms 很快，增加并发数到 {new_concurrency}")
        return nodes, new_concurrency
    return nodes, concurrency

async def process_urls(urls: Set[str], args: argparse.Namespace, config: Dict) -> tuple[List[ProxyNode], Dict[str, int], Set[str]]:
    cache_file = Path(args.cache_dir) / 'nodes_cache.json'
    cache = await load_cache(cache_file)
    semaphore = asyncio.Semaphore(args.max_concurrency)
    all_nodes: Set[ProxyNode] = set()
    url_counts = defaultdict(int)
    failed_urls = set()
    current_concurrency = args.max_concurrency

    browser_context = None
    playwright = None
    if args.use_browser:
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch()
        browser_context = await browser.new_context(user_agent=UserAgent().random)

    async with aiohttp.ClientSession() as session:
        tasks = []
        progress = tqdm(total=len(urls), desc="处理 URL", unit="url")
        for url in urls:
            async def task(url=url):
                nonlocal current_concurrency
                async with semaphore:
                    nodes, new_concurrency = await process_url(session, url, args.timeout, args.use_browser, browser_context, cache, current_concurrency)
                    all_nodes.update(nodes)
                    url_counts[url] = len(nodes)
                    if not nodes:
                        failed_urls.add(url)
                    current_concurrency = new_concurrency
                    semaphore._value = min(current_concurrency, semaphore._value + 1)
                    progress.update(1)
            tasks.append(task())
        await asyncio.gather(*tasks, return_exceptions=True)
        progress.close()

    if browser_context:
        await browser_context.close()
        await browser.close()
        await playwright.stop()

    if cache:
        await save_cache(cache_file, cache)

    if args.validate_nodes:
        with ThreadPoolExecutor(max_workers=10) as executor:
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(executor, lambda n: asyncio.run(validate_node(n, config['VALIDATION_TIMEOUT'])), node) for node in all_nodes]
            validated_nodes = await asyncio.gather(*tasks)
            all_nodes = set(validated_nodes)

    return sorted(list(all_nodes), key=lambda x: x.url), url_counts, failed_urls

async def save_nodes(nodes: List[ProxyNode], output_dir: str, output_base: str, formats: List[str], protocol_split: bool) -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    max_file_size = CONFIG['MAX_FILE_SIZE_MB'] * 1024 * 1024
    nodes_per_file = max_file_size // 80
    min_nodes_per_file = CONFIG['MIN_LINES_PER_FILE']

    if protocol_split:
        nodes_by_protocol = defaultdict(list)
        for node in nodes:
            nodes_by_protocol[node.protocol or 'unknown'].append(node)
        for protocol, proto_nodes in nodes_by_protocol.items():
            for fmt in formats:
                if len(proto_nodes) <= nodes_per_file:
                    await save_nodes_format(proto_nodes, f"{output_dir}/{output_base}_{protocol}.{fmt}", fmt)
                else:
                    for i in range(0, len(proto_nodes), nodes_per_file):
                        chunk = proto_nodes[i:i + nodes_per_file]
                        await save_nodes_format(chunk, f"{output_dir}/{output_base}_{protocol}_part_{i // nodes_per_file + 1:03d}.{fmt}", fmt)
    else:
        for fmt in formats:
            if len(nodes) <= nodes_per_file:
                await save_nodes_format(nodes, f"{output_dir}/{output_base}.{fmt}", fmt)
            else:
                for i in range(0, len(nodes), nodes_per_file):
                    chunk = nodes[i:i + nodes_per_file]
                    await save_nodes_format(chunk, f"{output_dir}/{output_base}_part_{i // nodes_per_file + 1:03d}.{fmt}", fmt)

async def save_nodes_format(nodes: List[ProxyNode], path: str, fmt: str) -> None:
    if fmt == 'txt':
        async with aiofiles.open(path, 'w', encoding='utf-8') as f:
            await f.write('\n'.join(node.url for node in nodes))
    elif fmt == 'json':
        async with aiofiles.open(path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps([node.__dict__ for node in nodes], ensure_ascii=False, indent=2))
    elif fmt == 'yaml':
        async with aiofiles.open(path, 'w', encoding='utf-8') as f:
            await f.write(yaml.dump([node.__dict__ for node in nodes], allow_unicode=True, sort_keys=True))
    logging.info(f"保存 {len(nodes)} 个节点到 {path} ({fmt.upper()})")

async def save_stats(url_counts: Dict[str, int], failed_urls: Set[str], stats_file: str, nodes: List[ProxyNode]) -> None:
    Path(stats_file).parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(stats_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['Source_URL', 'Nodes_Found', 'Status', 'Validated_Nodes', 'Average_Latency_ms']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        await f.write(','.join(fieldnames) + '\n')
        for url, count in sorted(url_counts.items()):
            validated_count = sum(1 for node in nodes if node.source_url == url and node.validated)
            avg_latency = sum(node.latency for node in nodes if node.source_url == url and node.latency is not None) / max(validated_count, 1)
            await f.write(f"{url},{count},{'成功' if count > 0 else ('失败' if url in failed_urls else '无节点')},{validated_count},{avg_latency:.2f}\n")

def main():
    args = setup_argparse()
    CONFIG.update(load_config(args.config_file))
    setup_logging(CONFIG['LOG_FILE'], CONFIG['LOG_FORMAT'])

    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls = {urllib.parse.urlparse(line.strip()).netloc or line.strip() for line in f if line.strip() and not line.startswith('#')}
    except FileNotFoundError:
        logging.error(f"源文件 {args.sources} 未找到")
        return

    # 加载旧节点以支持增量更新
    previous_nodes = asyncio.run(load_previous_nodes(args.output_dir, args.output_base))
    start_time = datetime.now()
    logging.info(f"开始处理 {len(urls)} 个唯一域名...")
    nodes, url_counts, failed_urls = asyncio.run(process_urls(urls, args, CONFIG))
    
    # 增量更新：仅保留新节点或变化的节点
    new_nodes = [node for node in nodes if node.url not in previous_nodes]
    logging.info(f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒，提取 {len(nodes)} 个节点（新增 {len(new_nodes)} 个）")

    if new_nodes:
        formats = args.output_formats.split(',')
        asyncio.run(save_nodes(new_nodes, args.output_dir, args.output_base, formats, args.protocol_split))
        asyncio.run(save_stats(url_counts, failed_urls, args.stats_output, new_nodes))
    else:
        logging.info("无新增节点，跳过保存")

    report = [
        f"总计提取 {len(nodes)} 个唯一节点（新增 {len(new_nodes)} 个）",
        "源 URL 统计:",
        "{:<70} {:<15} {:<10} {:<15} {:<15}".format("源URL", "节点数", "状态", "有效节点", "平均延迟(ms)"),
        "-" * 125,
        *[
            f"{url:<70} {count:<15} {'成功' if count > 0 else ('失败' if url in failed_urls else '无节点'):<10} "
            f"{sum(1 for n in new_nodes if n.source_url == url and n.validated):<15} "
            f"{(sum(n.latency for n in new_nodes if n.source_url == url and n.latency is not None) / max(sum(1 for n in new_nodes if n.source_url == url), 1)):.2f}"
            for url, count in sorted(url_counts.items())
        ]
    ]
    if failed_urls:
        report.extend(["\n失败的 URL:", *sorted(failed_urls)])
    logging.info("\n".join(report))

if __name__ == "__main__":
    main()
