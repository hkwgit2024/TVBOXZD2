
import asyncio
import aiohttp
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
from datetime import datetime
from bs4 import BeautifulSoup, Comment
from fake_useragent import UserAgent
from playwright.async_api import async_playwright, Page, BrowserContext

# --- 配置 ---
LOG_FILE = 'proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_OUTPUT_FILE = 'data/nodes.txt'
DEFAULT_STATS_FILE = 'data/node_counts.csv'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20
DEFAULT_CHUNK_SIZE_MB = 95
MAX_BASE64_DECODE_DEPTH = 3
UA = UserAgent()

# 配置日志系统
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
    'vmess': r'vmess://[^\s]+',
    'trojan': r'trojan://[^\s#]+(?:#[^\n]*)?',
    'vless': r'(?:vless|ss)://[^\s#]+(?:#[^\n]*)?',  # 适配伪装为 ss:// 的 VLESS 节点
    'hysteria2': r'hysteria2://[^\s#]+(?:#[^\n]*)?',
    'hy2': r'hy2://[^\s#]+(?:#[^\n]*)?',
    'tuic': r'tuic://[^\s#]+(?:#[^\n]*)?',
    'ssr': r'ssr://[^\s]+',
    'snell': r'snell://[^\s]+',
}
COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values())
BASE64_RAW_PATTERN = r'(?:b64|base64|data:application\/octet-stream;base64,)?\s*["\']?((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))["\']?\s*'
BASE64_REGEX_LOOSE = re.compile(BASE64_RAW_PATTERN, re.MULTILINE | re.IGNORECASE)
JS_VAR_REGEX = re.compile(r'(?:var|let|const)\s+[\w]+\s*=\s*["\'](' + COMBINED_REGEX_PATTERN + r'|' + BASE64_RAW_PATTERN + r')["\']', re.MULTILINE | re.IGNORECASE)
JS_FUNC_CALL_REGEX = re.compile(r'(?:atob|decodeURIComponent)\s*\(\s*["\']?(' + BASE64_RAW_PATTERN + r')["\']?\s*\)', re.MULTILINE | re.IGNORECASE)
HTML_TAG_REGEX = re.compile(r'<[^>]+>', re.MULTILINE)
VLESS_REGEX = re.compile(r'(?:vless|ss)://([0-9a-f-]{36,})@([^:]+):(\d+)\?([^#]*)#(.*)', re.IGNORECASE)

# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='代理节点提取、去重和优化工具')
    parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'包含源 URL 或本地文件的输入路径 (默认为: {DEFAULT_SOURCES_FILE})')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_FILE, help=f'节点输出文件路径 (默认为: {DEFAULT_OUTPUT_FILE})')
    parser.add_argument('--stats-output', default=DEFAULT_STATS_FILE, help=f'节点统计数据输出文件路径 (默认为: {DEFAULT_STATS_FILE})')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认为: {DEFAULT_MAX_CONCURRENCY})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认为: {DEFAULT_TIMEOUT})')
    parser.add_argument('--chunk-size-mb', type=int, default=DEFAULT_CHUNK_SIZE_MB, help=f'每个分片文件的最大大小（MB） (默认为: {DEFAULT_CHUNK_SIZE_MB})')
    parser.add_argument('--use-browser', action='store_true', help='当HTTP请求失败时，尝试使用无头浏览器（Playwright）')
    parser.add_argument('--tls-only', action='store_true', help='仅保留 TLS 节点')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    try:
        cleaned_data = re.sub(r'[^A-Za-z0-9+/=]', '', data)
        cleaned_data = cleaned_data.replace('-', '+').replace('_', '/')
        padding = len(cleaned_data) % 4
        if padding:
            cleaned_data += '=' * (4 - padding)
        return base64.b64decode(cleaned_data).decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"Base64 解码错误（原始内容片段: {data[:min(50, len(data))]}...）: {e}")
        return ""

def encode_base64(data: str) -> str:
    try:
        encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
        return encoded_bytes.decode('utf-8').rstrip('=')
    except Exception as e:
        logger.warning(f"Base64 编码失败: {data[:50]}... 错误: {e}")
        return data

def parse_vless_node(url: str) -> Optional[Dict]:
    """解析 VLESS 节点（包括伪装为 ss:// 的节点）"""
    match = VLESS_REGEX.match(url)
    if not match:
        logger.debug(f"无法解析 VLESS 节点: {url[:50]}...")
        return None

    uuid, host, port, query, name = match.groups()
    params = urllib.parse.parse_qs(query)
    
    config = {
        "type": "vless",
        "uuid": uuid,
        "server": host,
        "port": int(port),
        "name": urllib.parse.unquote(name)[:30],
        "security": params.get("security", ["none"])[0],
        "encryption": params.get("encryption", ["none"])[0],
        "type_network": params.get("type", ["tcp"])[0],
        "sni": params.get("sni", [""])[0],
        "host": params.get("host", [""])[0],
        "path": urllib.parse.unquote(params.get("path", [""])[0]),
        "fp": params.get("fp", [""])[0]
    }
    
    # 提取地区和服务商信息
    region_match = re.search(r'\((.*?)\)', config["name"])
    config["region"] = region_match.group(1) if region_match else "Unknown"
    provider_match = re.search(r'\((.*?)\)-(.*?)(?:-|\])', config["name"])
    config["provider"] = provider_match.group(2) if provider_match else "Unknown"
    
    return config

def normalize_node_url(url: str) -> str:
    """规范化节点 URL，支持 VLESS 和其他协议"""
    try:
        protocol, _, rest = url.partition('://')
        protocol_lower = protocol.lower()
        if protocol_lower not in NODE_PATTERNS:
            logger.debug(f"无法识别协议或不支持的协议: {url[:50]}...")
            return url

        if protocol_lower in ['vless', 'ss']:  # 处理 VLESS（包括伪装为 ss://）
            config = parse_vless_node(url)
            if not config:
                return url
            params = {
                "encryption": config["encryption"],
                "type": config["type_network"],
                "security": config["security"],
                "sni": config["sni"],
                "host": config["host"],
                "path": config["path"],
                "fp": config["fp"]
            }
            params = {k: v for k, v in params.items() if v}
            query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            return f"vless://{config['uuid']}@{config['server']}:{config['port']}?{query_string}#{urllib.parse.quote(config['name'])}"

        # 其他协议的规范化
        parsed_url = urllib.parse.urlparse(url)
        if protocol_lower == 'vmess':
            config_b64 = rest
            config_json = decode_base64(config_b64)
            if not config_json:
                logger.debug(f"VMess 配置Base64解码失败: {url[:50]}...")
                return url
            try:
                config = json.loads(config_json)
            except json.JSONDecodeError as e:
                logger.debug(f"VMess 配置 JSON 解析失败: {e} for {config_json[:min(50, len(config_json))]}...")
                return url
            ordered_keys = [
                'ps', 'add', 'port', 'id', 'net', 'type', 'tls', 'sni', 'host', 'path',
                'serviceName', 'alpn', 'fp', 'allowInsecure', 'maxEarlyData', 'earlyDataHeader', 'mode', 'method', 'scy'
            ]
            clean_config = {}
            for k in ordered_keys:
                if k in config and config[k] is not None:
                    if k == 'ps':
                        clean_config[k] = urllib.parse.unquote(str(config[k]))[:30]
                    elif k == 'port':
                        try:
                            clean_config[k] = int(config[k])
                        except (ValueError, TypeError):
                            clean_config[k] = 0
                            logger.debug(f"VMess 字段 'port' 类型转换失败: {config[k]}")
                    elif k == 'alpn' and isinstance(config[k], list):
                        clean_config[k] = ','.join(sorted(config[k]))
                    elif k in ['host', 'sni', 'path', 'serviceName', 'earlyDataHeader']:
                        clean_config[k] = str(config[k])[:30]
                    else:
                        clean_config[k] = config[k]
            if 'ps' not in clean_config:
                clean_config['ps'] = ''
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}"

        elif protocol_lower == 'ssr':
            decoded_ssr = decode_base64(rest)
            if not decoded_ssr:
                logger.debug(f"SSR Base64解码失败: {url[:50]}...")
                return url
            core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr)
            if not core_part_match:
                logger.debug(f"SSR 链接核心部分解析失败: {url[:50]}...")
                return url
            core_part, tail = core_part_match.groups()
            parts = core_part.split(':')
            if len(parts) < 6:
                logger.debug(f"SSR 核心部分参数不足: {url[:50]}...")
                return url
            host, port, protocol_name, method, obfs_name, password_encoded = parts[:6]
            password = decode_base64(password_encoded)
            parsed_tail = urllib.parse.urlparse(tail)
            query_params = urllib.parse.parse_qs(parsed_tail.query)
            clean_params = {k: encode_base64(decode_base64(v[0])[:30]) if k in ['protoparam', 'obfsparam', 'group'] else urllib.parse.quote(urllib.parse.unquote(v[0]), safe='')[:30] for k, v in query_params.items()}
            query_string = urllib.parse.urlencode(clean_params, quote_via=urllib.parse.quote)
            remark = encode_base64(decode_base64(parsed_tail.fragment)[:30]) if parsed_tail.fragment else ''
            normalized_core = f"{host}:{port}:{protocol_name}:{method}:{obfs_name}:{encode_base64(password)}"
            if query_string:
                normalized_core += f"/?{query_string}"
            if remark:
                normalized_core += f"#{remark}"
            return f"ssr://{encode_base64(normalized_core)}"

        else:
            auth_part = f"{urllib.parse.quote(urllib.parse.unquote(parsed_url.username or ''), safe='')}:{urllib.parse.quote(urllib.parse.unquote(parsed_url.password or ''), safe='')}@" if parsed_url.username or parsed_url.password else ''
            host_port = parsed_url.netloc.lower().split('@')[-1]
            query_params = urllib.parse.parse_qs(parsed_url.query)
            sorted_query_params = {k: urllib.parse.quote(urllib.parse.unquote(v[0]), safe='')[:30] for k, v in sorted(query_params.items())}
            query_string = urllib.parse.urlencode(sorted_query_params, quote_via=urllib.parse.quote)
            fragment = urllib.parse.unquote(parsed_url.fragment)[:30]
            return f"{protocol_lower}://{auth_part}{host_port}{'?' + query_string if query_string else ''}{'#' + urllib.parse.quote(fragment, safe='') if fragment else ''}"
    except Exception as e:
        logger.debug(f"规范化 URL '{url[:50]}...' 失败: {e}", exc_info=True)
        return url

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 配置转换为标准 URL，支持 VLESS"""
    proxy_type = proxy.get('type', '').lower()
    name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', f"{proxy_type}_node").strip())[:30], safe='')
    server = proxy.get('server')
    port = proxy.get('port')
    
    if not all([server, port, proxy_type]):
        logger.debug(f"Clash 代理 {proxy.get('name', '未知')} 缺少核心信息，跳过: {proxy}")
        return None

    if proxy_type == 'vless':
        uuid_val = proxy.get('uuid')
        network = proxy.get('network', 'tcp')
        tls_enabled = proxy.get('tls', False)
        if not uuid_val:
            logger.debug(f"VLESS 代理 {name} 缺少 UUID: {proxy}")
            return None
        params = {"type": network}
        if tls_enabled:
            params['security'] = 'tls'
            sni = proxy.get('servername') or proxy.get('host') or server
            if sni:
                params['sni'] = sni[:30]
            if proxy.get('alpn'):
                params['alpn'] = ",".join(proxy['alpn']) if isinstance(proxy['alpn'], list) else proxy['alpn']
            if proxy.get('client-fingerprint'):
                params['fp'] = proxy['client-fingerprint']
            if proxy.get('skip-cert-verify'):
                params['allowInsecure'] = '1'
            if proxy.get('flow'):
                params['flow'] = proxy['flow']
            if proxy.get('reality-opts'):
                reality_opts = proxy.get('reality-opts', {})
                if reality_opts.get('publicKey'):
                    params['pbk'] = reality_opts['publicKey']
                if reality_opts.get('shortId'):
                    params['sid'] = reality_opts['shortId']
        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            params['path'] = ws_opts.get('path', '/')[:30]
            if 'headers' in ws_opts and 'host' in ws_opts['headers']:
                params['host'] = ws_opts['headers']['host'][:30]
            elif ws_opts.get('host'):
                params['host'] = ws_opts['host'][:30]
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            params['serviceName'] = grpc_opts.get('grpc-service-name', '')[:30]
            if grpc_opts.get('mode'):
                params['mode'] = grpc_opts['mode']
        query_string = urllib.parse.urlencode({k: v for k, v in params.items() if v}, quote_via=urllib.parse.quote)
        return f"vless://{uuid_val}@{server}:{port}?{query_string}#{name}"

    elif proxy_type == 'ss':
        cipher = proxy.get('cipher')
        password = proxy.get('password')
        if not all([cipher, password]):
            logger.debug(f"SS 代理 {name} 缺少加密方法或密码: {proxy}")
            return None
        auth = encode_base64(f"{cipher}:{password}")
        params = []
        plugin = proxy.get('plugin')
        if plugin:
            plugin_opts = proxy.get('plugin-opts', {})
            if plugin == 'obfs':
                params.append(f"plugin={plugin}")
                params.append(f"obfs-host={urllib.parse.quote(plugin_opts.get('host', '')[:30], safe='')}")
                params.append(f"obfs-mode={plugin_opts.get('mode', '')}")
            elif plugin == 'v2ray-plugin':
                params.append(f"plugin={plugin}")
                params.append(f"v2ray-plugin-mode={plugin_opts.get('mode', 'websocket')}")
                params.append(f"v2ray-plugin-host={urllib.parse.quote(plugin_opts.get('host', '')[:30], safe='')}")
                params.append(f"v2ray-plugin-path={urllib.parse.quote(plugin_opts.get('path', '')[:30], safe='')}")
                if plugin_opts.get('tls'):
                    params.append("v2ray-plugin-tls=true")
                if plugin_opts.get('skip-cert-verify'):
                    params.append("v2ray-plugin-skip-cert-verify=true")
        query_string = "?" + "&".join(params) if params else ""
        return f"ss://{auth}@{server}:{port}{query_string}#{name}"

    elif proxy_type == 'vmess':
        uuid_val = proxy.get('uuid')
        network = proxy.get('network', 'tcp')
        tls_enabled = proxy.get('tls', False)
        if not uuid_val:
            logger.debug(f"VMess 代理 {name} 缺少 UUID: {proxy}")
            return None
        config = {
            "ps": urllib.parse.unquote(name),
            "add": server,
            "port": int(port),
            "id": uuid_val,
            "net": network,
            "type": proxy.get('cipher', 'auto'),
        }
        if tls_enabled:
            config["tls"] = "tls"
            sni = proxy.get('servername') or proxy.get('host')
            if sni:
                config["host"] = sni[:30]
                config["sni"] = sni[:30]
            if proxy.get('skip-cert-verify'):
                config["allowInsecure"] = 1
            if proxy.get('alpn'):
                config["alpn"] = ",".join(proxy['alpn']) if isinstance(proxy['alpn'], list) else proxy['alpn']
        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            config["path"] = ws_opts.get('path', '/')[:30]
            if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
                config['host'] = ws_opts['headers']['Host'][:30]
            elif ws_opts.get('host'):
                config['host'] = ws_opts['host'][:30]
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            config["serviceName"] = grpc_opts.get('grpc-service-name', '')[:30]
        return f"vmess://{encode_base64(json.dumps(config, ensure_ascii=False, sort_keys=True))}"

    logger.debug(f"不支持的代理类型: {proxy_type}")
    return None

def extract_nodes(content: str, decode_depth: int = 0) -> List[str]:
    """提取节点，支持 VLESS 伪装为 ss://"""
    nodes_found = set()
    if not content or decode_depth > MAX_BASE64_DECODE_DEPTH:
        return []

    content = content.replace('\r\n', '\n').replace('\r', '\n')

    def strip_html_tags(text: str) -> str:
        try:
            soup = BeautifulSoup(text, 'html.parser')
            cleaned = soup.get_text(separator='', strip=True)
            cleaned = HTML_TAG_REGEX.sub('', cleaned)
            return cleaned
        except Exception as e:
            logger.debug(f"HTML 标签清理失败: {text[:50]}... 错误: {e}")
            return HTML_TAG_REGEX.sub('', text)

    # 提取 VLESS 节点（包括伪装为 ss://）
    matches = re.findall(NODE_PATTERNS['vless'], content, re.MULTILINE | re.IGNORECASE)
    for node in matches:
        cleaned_node = strip_html_tags(node)
        config = parse_vless_node(cleaned_node)
        if config:
            nodes_found.add(normalize_node_url(cleaned_node))

    # 提取其他协议节点
    for pattern_key, pattern_val in NODE_PATTERNS.items():
        if pattern_key != 'vless':  # VLESS 已单独处理
            matches = re.findall(pattern_val, content, re.MULTILINE | re.IGNORECASE)
            for node in matches:
                cleaned_node = strip_html_tags(node)
                nodes_found.add(normalize_node_url(cleaned_node))

    # 处理 Base64 编码内容
    base64_candidates = BASE64_REGEX_LOOSE.findall(content)
    for b64_candidate_tuple in base64_candidates:
        b64_str = b64_candidate_tuple[0]
        if len(b64_str) < 50:
            continue
        decoded_content = decode_base64(b64_str)
        if decoded_content and len(decoded_content) > 20:
            nodes_found.update(extract_nodes(decoded_content, decode_depth + 1))

    # 处理 YAML 和 JSON
    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    nodes_found.add(normalize_node_url(url_node))
    except yaml.YAMLError:
        pass

    try:
        json_content = json.loads(content)
        if isinstance(json_content, dict) and 'proxies' in json_content:
            for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    nodes_found.add(normalize_node_url(url_node))
    except json.JSONDecodeError:
        pass

    return sorted(list(nodes_found))

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3, backoff_factor: float = 1.0) -> str:
    headers = {'User-Agent': UA.random, 'Referer': url}
    for attempt in range(retries):
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                response.raise_for_status()
                return await response.text()
        except Exception as e:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}, 错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
    return ""

async def fetch_with_browser(browser_context: BrowserContext, url: str, timeout: int) -> str:
    page: Page = await browser_context.new_page()
    page.set_default_timeout(timeout * 1000)
    try:
        await page.goto(url, wait_until="networkidle")
        return await page.content()
    except Exception as e:
        logger.warning(f"使用浏览器获取 URL {url} 失败: {e}")
        return ""
    finally:
        await page.close()

async def process_single_url_strategy(session: aiohttp.ClientSession, url: str, timeout: int, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> Set[str]:
    content = await fetch_with_retry(session, url, timeout)
    if not content and use_browser and browser_context:
        content = await fetch_with_browser(browser_context, url, timeout)
    return set(extract_nodes(content)) if content else set()

async def process_domain(session: aiohttp.ClientSession, domain: str, timeout: int, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> Set[str]:
    nodes_from_domain = set()
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"
    
    async with semaphore:
        http_nodes = await process_single_url_strategy(session, http_url, timeout, use_browser, browser_context)
        url_node_counts[http_url] = len(http_nodes)
        nodes_from_domain.update(http_nodes)
        if not http_nodes:
            https_nodes = await process_single_url_strategy(session, https_url, timeout, use_browser, browser_context)
            url_node_counts[https_url] = len(https_nodes)
            nodes_from_domain.update(https_nodes)
            if not https_nodes:
                failed_urls.add(http_url)
                failed_urls.add(https_url)
    
    return nodes_from_domain

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int, use_browser: bool) -> tuple[List[str], Dict, Set]:
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int)
    failed_urls = set()
    all_nodes_collected = set()
    
    browser_context = None
    playwright_instance = None
    if use_browser:
        try:
            playwright_instance = await async_playwright().start()
            browser = await playwright_instance.chromium.launch()
            browser_context = await browser.new_context(user_agent=UA.random, ignore_https_errors=True)
        except Exception as e:
            logger.error(f"初始化 Playwright 失败: {e}")
            use_browser = False

    async with aiohttp.ClientSession() as session:
        tasks = [process_domain(session, domain, timeout, semaphore, url_node_counts, failed_urls, use_browser, browser_context) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for nodes_or_exception in results:
            if isinstance(nodes_or_exception, set):
                all_nodes_collected.update(nodes_or_exception)
            else:
                logger.error(f"处理域名时发生异常: {nodes_or_exception}")

    if browser_context:
        await browser_context.close()
        await browser.close()
        await playwright_instance.stop()

    return sorted(list(all_nodes_collected)), url_node_counts, failed_urls

def save_nodes_to_json(nodes: List[Dict], output_dir: str, filename_base: str):
    """保存节点为 JSON 格式，按地区分类"""
    os.makedirs(output_dir, exist_ok=True)
    nodes_by_region = defaultdict(list)
    for node in nodes:
        nodes_by_region[node['region']].append(node)
    
    for region, region_nodes in nodes_by_region.items():
        output_path = os.path.join(output_dir, f"{filename_base}_{region}.json")
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(region_nodes, f, ensure_ascii=False, indent=2)
            file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
            logger.info(f"已保存 {len(region_nodes)} 个节点到 {output_path} ({file_size_mb:.2f} MB)")
        except Exception as e:
            logger.error(f"保存 JSON 文件 {output_path} 失败: {e}")

def main():
    global args
    args = setup_argparse()
    
    logger.info(f"命令行参数: sources={args.sources}, output={args.output}, stats_output={args.stats_output}, max_concurrency={args.max_concurrency}, timeout={args.timeout}, chunk_size_mb={args.chunk_size_mb}, use_browser={args.use_browser}, tls_only={args.tls_only}")
    
    # 读取源文件（支持 URL 和本地文件）
    unique_domains = set()
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for source in sources:
            if os.path.isfile(source):
                with open(source, 'r', encoding='utf-8') as f:
                    nodes = [line.strip() for line in f if line.strip()]
                    unique_domains.update(nodes)
            else:
                parsed = urllib.parse.urlparse(source)
                domain = parsed.netloc or parsed.path
                if domain:
                    unique_domains.add(domain)
                else:
                    logger.warning(f"无法解析源: {source}")
    except FileNotFoundError:
        logger.error(f"源文件 '{args.sources}' 未找到")
        return

    # 处理节点
    start_time = datetime.now()
    unique_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(unique_domains, args.max_concurrency, args.timeout, args.use_browser))
    
    # 解析节点为结构化数据
    parsed_nodes = []
    for node in unique_nodes:
        config = parse_vless_node(node)
        if config and (not args.tls_only or config['security'] == 'tls'):
            parsed_nodes.append(config)
    
    # 保存节点为 JSON
    output_dir = os.path.dirname(args.output)
    output_filename_base = os.path.splitext(os.path.basename(args.output))[0]
    save_nodes_to_json(parsed_nodes, output_dir, output_filename_base)
    
    # 保存分片文件
    target_file_size_bytes = args.chunk_size_mb * 1024 * 1024
    avg_node_length = sum(len(node.encode('utf-8')) for node in unique_nodes) // len(unique_nodes) if unique_nodes else 50
    max_nodes_per_file = target_file_size_bytes // avg_node_length
    min_nodes_per_file = 8000
    
    if unique_nodes:
        if len(unique_nodes) <= max_nodes_per_file:
            output_path = args.output
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(unique_nodes))
            logger.info(f"已保存 {len(unique_nodes)} 个节点到 {output_path}")
        else:
            num_files = max(1, (len(unique_nodes) + min_nodes_per_file - 1) // min_nodes_per_file)
            nodes_per_file = (len(unique_nodes) + num_files - 1) // num_files
            for i in range(num_files):
                start_idx = i * nodes_per_file
                end_idx = min((i + 1) * nodes_per_file, len(unique_nodes))
                output_path = os.path.join(output_dir, f"{output_filename_base}_part_{i+1:03d}.txt")
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(unique_nodes[start_idx:end_idx]))
                logger.info(f"已保存 {end_idx - start_idx} 个节点到 {output_path}")
    
    # 保存统计数据
    with open(args.stats_output, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Source_URL', 'Nodes_Found', 'Status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True):
            status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点")
            writer.writerow({'Source_URL': url, 'Nodes_Found': count, 'Status': status})
    
    logger.info(f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒，提取到 {len(parsed_nodes)} 个唯一节点")

if __name__ == '__main__':
    main()
