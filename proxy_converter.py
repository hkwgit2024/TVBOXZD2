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
from collections import defaultdict
from typing import List, Dict, Set, Optional
from datetime import datetime

# --- 配置 ---
LOG_FILE = 'proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_OUTPUT_FILE = 'data/nodes.txt'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20

# 配置日志系统，将日志输出到文件和控制台
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
    'vless': r'vless://[^\s#]+(?:#[^\n]*)?',
    'hysteria2': r'hysteria2://[^\s#]+(?:#[^\n]*)?',
}
COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values())

# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='代理节点提取和去重工具')
    parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'包含源 URL 的输入文件路径 (默认为: {DEFAULT_SOURCES_FILE})')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_FILE, help=f'提取到的节点输出文件路径 (默认为: {DEFAULT_OUTPUT_FILE})')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认为: {DEFAULT_MAX_CONCURRENCY})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认为: {DEFAULT_TIMEOUT})')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    """解码 Base64 字符串，并修复可能存在的填充问题。"""
    try:
        data = data.strip().replace('-', '+').replace('_', '/')
        # 添加缺失的填充字符
        padding = len(data) % 4
        if padding:
            data += '=' * (4 - padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"Base64 解码错误: {e}")
        return ""

def encode_base64(data: str) -> str:
    """编码字符串为 URL 安全的 Base64 格式。"""
    encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8').rstrip('=')

def normalize_node_url(url: str) -> str:
    """规范化节点 URL 以提高去重效率，保持关键参数一致。"""
    try:
        protocol, _, rest = url.partition('://')
        if not protocol or protocol not in NODE_PATTERNS:
            return url # 如果不是已知协议，不进行规范化

        if protocol == 'vmess':
            config_b64 = rest
            config_json = decode_base64(config_b64)
            if not config_json:
                return url
            config = json.loads(config_json)
            # 定义一个固定顺序的键列表，用于规范化 JSON 结构
            ordered_keys = [
                'v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'tls',
                'sni', 'host', 'path', 'serviceName', 'alpn', 'fp', 'allowInsecure',
                'maxEarlyData', 'earlyDataHeader', 'mode', 'method'
            ]
            clean_config = {k: config.get(k) for k in ordered_keys if config.get(k) is not None}
            # 特殊处理某些字段的默认值或类型
            if 'v' not in clean_config: clean_config['v'] = '2'
            if 'aid' in clean_config: clean_config['aid'] = int(clean_config['aid'])
            if 'port' in clean_config: clean_config['port'] = int(clean_config['port'])
            if 'ps' not in clean_config: clean_config['ps'] = '' # 确保 ps 存在

            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}"
        else:
            # 通用协议规范化 (ss, trojan, vless, hysteria2)
            parsed_url = urllib.parse.urlparse(url)
            # username/password 部分（ss, trojan）
            auth = f"{parsed_url.username}:{parsed_url.password}@" if parsed_url.username or parsed_url.password else ''
            
            # host:port 部分
            netloc = parsed_url.netloc.lower() # 统一小写域名
            if parsed_url.username or parsed_url.password: # 如果有 auth，netloc 已经包含了 auth@
                netloc = netloc.split('@', 1)[-1] # 移除 auth 部分

            # Query parameters
            query_params = urllib.parse.parse_qs(parsed_url.query)
            sorted_query_params = {}
            for k in sorted(query_params.keys()):
                # 对列表值取第一个，并确保排序
                sorted_query_params[k] = sorted(query_params[k])[0] if isinstance(query_params[k], list) else query_params[k]
            
            query_string = urllib.parse.urlencode(sorted_query_params, quote_via=urllib.parse.quote)
            if query_string:
                query_string = '?' + query_string

            # Fragment (node name)
            fragment = urllib.parse.unquote(parsed_url.fragment) # 确保名称解码，但编码时会再次编码
            if fragment:
                fragment = '#' + urllib.parse.quote(fragment)
            
            # 重构 URL
            return f"{protocol}://{auth}{netloc}{query_string}{fragment}"

    except Exception as e:
        logger.debug(f"规范化 URL '{url}' 失败: {e}", exc_info=True) # 记录完整堆栈信息方便调试
        return url

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 代理配置字典转换为标准 URL 格式。"""
    proxy_type = proxy.get('type', '').lower()
    name = urllib.parse.quote(proxy.get('name', f"{proxy_type}_node").strip(), safe='')
    server = proxy.get('server')
    port = proxy.get('port')
    
    if not all([server, port, proxy_type]):
        logger.debug(f"缺少 Clash 代理 {proxy.get('name', '未知')} 的核心信息: {proxy}")
        return None

    if proxy_type == 'ss':
        cipher = proxy.get('cipher')
        password = proxy.get('password')
        plugin = proxy.get('plugin')
        plugin_opts = proxy.get('plugin-opts', {})
        if not all([cipher, password]):
            logger.debug(f"SS 代理 {name} 缺少加密方法或密码: {proxy}")
            return None
        auth = encode_base64(f"{cipher}:{password}")
        params = []
        if plugin:
            if plugin == 'obfs' and 'mode' in plugin_opts:
                params.append(f"plugin={plugin}")
                params.append(f"obfs-host={urllib.parse.quote(plugin_opts.get('host', ''), safe='')}")
                params.append(f"obfs-mode={plugin_opts['mode']}")
            elif plugin == 'v2ray-plugin':
                params.append(f"plugin={plugin}")
                params.append(f"v2ray-plugin-mode={plugin_opts.get('mode', 'websocket')}")
                params.append(f"v2ray-plugin-host={urllib.parse.quote(plugin_opts.get('host', ''), safe='')}")
                params.append(f"v2ray-plugin-path={urllib.parse.quote(plugin_opts.get('path', ''), safe='')}")
                if plugin_opts.get('tls'): params.append("v2ray-plugin-tls=true")
                if plugin_opts.get('skip-cert-verify'): params.append("v2ray-plugin-skip-cert-verify=true")
                if plugin_opts.get('mux'): params.append("v2ray-plugin-mux=true")
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
            "v": "2",
            "ps": urllib.parse.unquote(name), # VMess 的 ps 通常不进行 URL 编码
            "add": server,
            "port": int(port),
            "id": uuid_val,
            "aid": proxy.get('alterId', 0),
            "net": network,
            "type": proxy.get('cipher', 'auto'),
        }
        
        if tls_enabled:
            config["tls"] = "tls"
            sni = proxy.get('servername') or proxy.get('host')
            if sni:
                config["host"] = sni # vmess 的 host 可能同时作为 sni
                config["sni"] = sni
            if proxy.get('skip-cert-verify'):
                config["allowInsecure"] = 1
            if proxy.get('alpn'):
                config["alpn"] = ",".join(proxy['alpn'])
            if proxy.get('client-fingerprint'):
                config["fp"] = proxy['client-fingerprint']

        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            config["path"] = ws_opts.get('path', '/')
            if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
                # Clash 的 headers.Host 对应 vmess 的 host
                config['host'] = ws_opts['headers']['Host']
            elif ws_opts.get('host'): # 旧版 Clash 可能直接在 ws-opts 下有 host
                config['host'] = ws_opts['host']
            if ws_opts.get('max-early-data'): config['maxEarlyData'] = ws_opts['max-early-data']
            if ws_opts.get('early-data-header'): config['earlyDataHeader'] = ws_opts['early-data-header']
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            config["serviceName"] = grpc_opts.get('grpc-service-name', '')
            if grpc_opts.get('mode'): config["mode"] = grpc_opts['mode']
        elif network == 'http': # 虽然 Clash vmess 配置中 network=http 很少见，但协议支持
            http_opts = proxy.get('http-opts', {})
            if http_opts.get('method'):
                config['method'] = http_opts['method']
            if http_opts.get('headers'):
                for header_key, header_value in http_opts['headers'].items():
                    if header_key.lower() == 'host':
                        config['host'] = header_value[0] if isinstance(header_value, list) else header_value
                        break
        
        # 移除空值或默认值，使 JSON 更简洁
        final_config = {k: v for k, v in config.items() if v is not None and v != '' and not (k == 'aid' and v == 0) and not (k == 'v' and v == '2')}
        
        try:
            return f"vmess://{encode_base64(json.dumps(final_config, ensure_ascii=False))}"
        except Exception as e:
            logger.debug(f"VMess 配置 JSON 编码失败，节点：{name}。错误：{e}", exc_info=True)
            return None

    elif proxy_type == 'trojan':
        password = proxy.get('password')
        tls_enabled = proxy.get('tls', False) # Clash Trojan 协议通常强制 TLS
        if not all([password, tls_enabled]):
            logger.debug(f"Trojan 代理 {name} 缺少密码或未启用 TLS: {proxy}")
            return None
        params = []
        sni = proxy.get('servername') or proxy.get('host') or server
        if sni: params.append(f"sni={urllib.parse.quote(sni, safe='')}")
        if proxy.get('alpn'): params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']), safe='')}")
        if proxy.get('client-fingerprint'): params.append(f"fp={urllib.parse.quote(proxy['client-fingerprint'], safe='')}")
        if proxy.get('skip-cert-verify'): params.append("allowInsecure=1")
        if not proxy.get('udp', True): params.append("udp=false") # Clash 默认 udp=true

        network = proxy.get('network')
        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            params.append(f"type=ws")
            params.append(f"path={urllib.parse.quote(ws_opts.get('path', '/'), safe='')}")
            if 'headers' in ws_opts and 'host' in ws_opts['headers']:
                params.append(f"host={urllib.parse.quote(ws_opts['headers']['host'], safe='')}")
            elif ws_opts.get('host'):
                params.append(f"host={urllib.parse.quote(ws_opts['host'], safe='')}")
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            params.append(f"type=grpc")
            params.append(f"serviceName={urllib.parse.quote(grpc_opts.get('grpc-service-name', ''), safe='')}")
            if grpc_opts.get('mode'): params.append(f"mode={urllib.parse.quote(grpc_opts['mode'], safe='')}")
        query_string = "?" + "&".join(params) if params else ""
        return f"trojan://{password}@{server}:{port}{query_string}#{name}"

    elif proxy_type == 'vless':
        uuid_val = proxy.get('uuid')
        network = proxy.get('network', 'tcp')
        tls_enabled = proxy.get('tls', False) # VLESS 协议通常强制 TLS
        if not uuid_val:
            logger.debug(f"VLESS 代理 {name} 缺少 UUID: {proxy}")
            return None
        params = {"type": network}
        if tls_enabled:
            params['security'] = 'tls'
            sni = proxy.get('servername') or proxy.get('host') or server
            if sni: params['sni'] = sni
            if proxy.get('alpn'): params['alpn'] = ",".join(proxy['alpn'])
            if proxy.get('client-fingerprint'): params['fp'] = proxy['client-fingerprint']
            if proxy.get('skip-cert-verify'): params['allowInsecure'] = '1'
            if proxy.get('flow'): params['flow'] = proxy['flow'] # VLESS flow
            if proxy.get('reality-opts'): # 尝试提取 Reality 配置
                reality_opts = proxy['reality-opts']
                if reality_opts.get('publicKey'): params['pbk'] = reality_opts['publicKey']
                if reality_opts.get('shortId'): params['sid'] = reality_opts['shortId']
                if reality_opts.get('spiderX'): params['spx'] = reality_opts['spiderX']

        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            params['path'] = ws_opts.get('path', '/')
            if 'headers' in ws_opts and 'host' in ws_opts['headers']:
                params['host'] = ws_opts['headers']['host']
            elif ws_opts.get('host'):
                params['host'] = ws_opts['host']
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            params['serviceName'] = grpc_opts.get('grpc-service-name', '')
            if grpc_opts.get('mode'): params['mode'] = grpc_opts['mode']
        
        query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        return f"vless://{uuid_val}@{server}:{port}?{query_string}#{name}"

    elif proxy_type == 'hysteria2':
        password = proxy.get('password', '')
        server = proxy.get('server', '')
        port = proxy.get('port', 0)
        if not (password and server and port):
            logger.debug(f"Hysteria2 代理 {name} 缺少密码、服务器或端口: {proxy}")
            return None
        params = []
        if proxy.get('sni'):
            params.append(f"sni={urllib.parse.quote(proxy['sni'], safe='')}")
        if proxy.get('skip-cert-verify', False):
            params.append("insecure=1")
        if proxy.get('fast-open', False):
            params.append("fastopen=1")
        if proxy.get('up', 0):
            params.append(f"up_mbps={proxy['up']}")
        if proxy.get('down', 0):
            params.append(f"down_mbps={proxy['down']}")
        if proxy.get('alpn'):
            params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']), safe='')}")
        if proxy.get('obfs'):
            params.append(f"obfs={proxy['obfs']}")
            if proxy.get('obfs-password'):
                params.append(f"obfsParam={urllib.parse.quote(proxy['obfs-password'], safe='')}")
        params_str = '&'.join(params) if params else ''
        return f"hysteria2://{password}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"
        
    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}")
    return None

def extract_nodes(content: str) -> List[str]:
    """
    从内容中提取代理节点，支持多种格式：
    1. 直接匹配标准协议链接
    2. 从 HTML 属性中提取
    3. 尝试 YAML (Clash) 配置解析
    4. 尝试 JSON (Vmess/Clash) 配置解析
    5. 尝试 Base64 解码后再次解析
    """
    nodes_found = set()
    # 统一换行符
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # 策略 1: 直接匹配标准订阅链接
    for pattern in NODE_PATTERNS.values():
        matches = re.findall(pattern, content, re.MULTILINE)
        for node in matches:
            nodes_found.add(normalize_node_url(node))
    
    # 策略 2: 从 HTML 属性中提取订阅链接
    html_link_matches = re.findall(rf'["\']({COMBINED_REGEX_PATTERN})["\']', content)
    for link in html_link_matches:
        # 再次确认链接是否符合任意一种协议模式
        if any(re.match(pattern, link) for pattern in NODE_PATTERNS.values()):
            nodes_found.add(normalize_node_url(link))

    # 策略 3: 尝试 YAML 解析 (Clash 配置)
    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    nodes_found.add(normalize_node_url(url_node))
        elif isinstance(yaml_content, list): # 有些订阅直接是代理列表
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item:
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node:
                        nodes_found.add(normalize_node_url(url_node))
    except yaml.YAMLError:
        pass # 不是有效的 YAML，忽略

    # 策略 4: 尝试 JSON 解析 (Vmess/Clash 配置)
    try:
        json_content = json.loads(content)
        if isinstance(json_content, list): # 可能是 Vmess 订阅的 JSON 数组
            for config_dict in json_content:
                if isinstance(config_dict, dict) and config_dict.get('v') == '2' and config_dict.get('id'):
                    # 假定 Vmess JSON 配置直接是 Vmess 节点列表
                    # 尝试将其转换为 Clash 格式再调用 convert_clash_proxy_to_url
                    clash_vmess_proxy = {
                        "type": "vmess",
                        "name": config_dict.get('ps', 'vmess_node'),
                        "server": config_dict.get('add'),
                        "port": config_dict.get('port'),
                        "uuid": config_dict.get('id'),
                        "alterId": config_dict.get('aid', 0),
                        "cipher": config_dict.get('type', 'auto'),
                        "network": config_dict.get('net', 'tcp'),
                        "tls": config_dict.get('tls') == 'tls',
                        "servername": config_dict.get('sni') or config_dict.get('host'),
                        "alpn": config_dict.get('alpn').split(',') if config_dict.get('alpn') else None,
                        "skip-cert-verify": config_dict.get('allowInsecure') == 1,
                        "client-fingerprint": config_dict.get('fp'),
                    }
                    if config_dict.get('net') == 'ws':
                        clash_vmess_proxy['ws-opts'] = {
                            'path': config_dict.get('path', '/'),
                            'headers': {'Host': config_dict.get('host')} if config_dict.get('host') else {}
                        }
                    elif config_dict.get('net') == 'grpc':
                        clash_vmess_proxy['grpc-opts'] = {
                            'grpc-service-name': config_dict.get('serviceName', ''),
                            'mode': config_dict.get('mode')
                        }
                    
                    url_node = convert_clash_proxy_to_url(clash_vmess_proxy)
                    if url_node:
                        nodes_found.add(normalize_node_url(url_node))
        elif isinstance(json_content, dict) and 'proxies' in json_content: # 可能是 Clash YAML 转换为 JSON
            for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    nodes_found.add(normalize_node_url(url_node))
    except json.JSONDecodeError:
        pass # 不是有效的 JSON，忽略

    # 策略 5: 尝试 Base64 解码，然后再次应用以上策略
    decoded_content = decode_base64(content)
    if decoded_content and len(decoded_content) > 20: # 避免解码过短的无效内容
        # 递归调用 extract_nodes 来处理解码后的内容
        nodes_found.update(extract_nodes(decoded_content))

    # 最终过滤：确保所有节点都符合至少一个已知协议的模式，并且长度足够
    # 避免 normalize_node_url 返回的原始无效 URL 被保留
    final_filtered_nodes = [
        node for node in nodes_found 
        if any(re.match(pattern, node) for pattern in NODE_PATTERNS.values()) 
        and len(node) > 20 # 过滤掉过短的无效匹配
    ]
    return sorted(list(final_filtered_nodes))

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3, backoff_factor: float = 1.0) -> str:
    """带重试机制地获取 URL 内容。"""
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                response.raise_for_status() # 对 4xx/5xx 状态码抛出异常
                return await response.text()
        except aiohttp.ClientError as e:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt)) # 指数退避
        except asyncio.TimeoutError:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: 请求超时")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
    logger.warning(f"在 {retries} 次尝试后未能成功获取 URL: {url}")
    return ""

async def process_single_url_strategy(session: aiohttp.ClientSession, url: str, timeout: int) -> Set[str]:
    """尝试获取并处理单个 URL，返回提取到的节点集合。"""
    content = await fetch_with_retry(session, url, timeout)
    if content:
        return set(extract_nodes(content))
    return set()

async def process_domain(session: aiohttp.ClientSession, domain: str, timeout: int, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set) -> None:
    """处理单个域名，先尝试 http，再尝试 https，并更新结果字典。"""
    nodes = set()
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"

    async with semaphore: # 在这里控制并发
        # 优先尝试 http
        logger.info(f"正在获取: {http_url}")
        http_nodes = await process_single_url_strategy(session, http_url, timeout)
        
        if http_nodes:
            nodes.update(http_nodes)
            url_node_counts[http_url] = len(http_nodes)
            logger.info(f"从 {http_url} 提取到 {len(http_nodes)} 个节点。")
        else:
            url_node_counts[http_url] = 0
            # http 失败，尝试 https
            logger.info(f"HTTP 失败，尝试获取: {https_url}")
            https_nodes = await process_single_url_strategy(session, https_url, timeout)
            
            if https_nodes:
                nodes.update(https_nodes)
                url_node_counts[https_url] = len(https_nodes)
                logger.info(f"从 {https_url} 提取到 {len(https_nodes)} 个节点。")
            else:
                url_node_counts[https_url] = 0
                failed_urls.add(http_url) # 记录失败的原始 URL
                failed_urls.add(https_url) # 记录失败的原始 URL
                logger.warning(f"HTTP 和 HTTPS 均未能从 {domain} 提取到节点。")
    
    # 将此域名下的所有有效节点返回给调用者
    return nodes # 返回提取到的节点集合，以便在 process_urls 中汇总

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int) -> tuple[List[str], Dict, Set]:
    """并发处理去重后的域名，优先尝试 http，失败后尝试 https。"""
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int)
    failed_urls = set()
    all_nodes = set()
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for domain in domains:
            # 创建一个 Task，并传递 url_node_counts 和 failed_urls，让子任务直接更新
            tasks.append(process_domain(session, domain, timeout, semaphore, url_node_counts, failed_urls))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for nodes_or_exception in results:
            if isinstance(nodes_or_exception, set):
                all_nodes.update(nodes_or_exception) # 汇总所有任务返回的节点

    # 对最终收集到的所有节点进行一次全局去重和规范化，以防不同来源提取到相同节点但未被规范化识别
    final_unique_nodes = set()
    for node in all_nodes:
        final_unique_nodes.add(normalize_node_url(node))
            
    return sorted(list(final_unique_nodes)), url_node_counts, failed_urls

# --- 主程序 ---

def main():
    """主函数，负责程序的整体流程。"""
    global args
    args = setup_argparse()
    
    # 读取 URL 列表
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls_raw = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"源文件 '{args.sources}' 未找到。请确保文件存在。")
        return
    
    # 从原始 URL 中提取并去重域名
    unique_domains = set()
    for url in urls_raw:
        parsed = urllib.parse.urlparse(url)
        # 优先使用 netloc (scheme://netloc/path?query#fragment)
        # 如果没有 netloc (例如只有 path/domain.com)，则尝试使用 path 作为域名
        domain = parsed.netloc
        if not domain and parsed.path:
            # 尝试从 path 中提取一个看似域名的部分，但这会比较模糊
            # 更好的做法是用户在 sources.list 中提供明确的订阅URL
            domain_match = re.match(r'^(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(?::\d+)?(?:/.*)?)$', parsed.path)
            if domain_match:
                domain = domain_match.group(1).split('/')[0] # 只取域名部分
            else:
                logger.warning(f"无法从路径 '{parsed.path}' 中识别有效域名。跳过此条目。")
                continue
        
        if domain:
            unique_domains.add(domain)
        else:
            logger.warning(f"无法从 URL '{url}' 中识别有效域名。跳过此条目。")

    if not unique_domains:
        logger.info("未找到任何有效域名进行处理。程序退出。")
        return

    # 处理 URL 并提取节点
    start_time = datetime.now()
    logger.info(f"开始处理 {len(unique_domains)} 个唯一域名...")
    
    unique_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(unique_domains, args.max_concurrency, args.timeout))
    
    # 生成报告
    total_nodes_extracted = len(unique_nodes)
    report_lines = [
        f"--- 报告 ---",
        f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒",
        f"总共提取到 {total_nodes_extracted} 个唯一节点。",
        "\n每个源 URL 的节点提取数量:"
    ]
    report_lines.append("{:<70} {:<15} {:<10}".format("源URL", "找到的节点数", "状态"))
    report_lines.append("-" * 95)
    
    # 按节点数量降序排序
    sorted_url_counts = sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True)
    for url, count in sorted_url_counts:
        status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点")
        report_lines.append(f"{url:<70} {count:<15} {status:<10}")
    
    if failed_urls:
        report_lines.append("\n未能成功获取或处理的源 URL:")
        report_lines.extend(sorted(list(failed_urls)))
    
    report_lines.append("\n--- 报告结束 ---")
    for line in report_lines:
        logger.info(line)
    
    # 保存节点到文件
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_nodes))
        logger.info(f"已将 {total_nodes_extracted} 个节点保存到 {args.output}")
    except Exception as e:
        logger.error(f"保存节点到 '{args.output}' 时发生错误: {e}")

if __name__ == '__main__':
    main()
