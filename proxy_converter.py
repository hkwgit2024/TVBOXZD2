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
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime
from bs4 import BeautifulSoup, Comment
from fake_useragent import UserAgent
from playwright.async_api import async_playwright, Page, BrowserContext
import time

# --- 配置 ---
LOG_FILE = 'proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_NODES_OUTPUT_FILE = 'data/nodes.txt'
DEFAULT_STATS_FILE = 'data/node_counts.csv'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20
DEFAULT_CHUNK_SIZE_MB = 190
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
    'vless': r'vless://[^\s#]+(?:#[^\n]*)?',
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

# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='代理节点提取和去重工具')
    parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'包含源 URL 的输入文件路径 (默认为: {DEFAULT_SOURCES_FILE})')
    parser.add_argument('--nodes-output', default=DEFAULT_NODES_OUTPUT_FILE, help=f'提取到的节点输出文件路径 (默认为: {DEFAULT_NODES_OUTPUT_FILE})')
    parser.add_argument('--stats-output', default=DEFAULT_STATS_FILE, help=f'节点统计数据输出文件路径 (默认为: {DEFAULT_STATS_FILE})')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认为: {DEFAULT_MAX_CONCURRENCY})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认为: {DEFAULT_TIMEOUT})')
    parser.add_argument('--chunk-size-mb', type=int, default=DEFAULT_CHUNK_SIZE_MB, help=f'每个分片文件的最大大小（MB） (默认为: {DEFAULT_CHUNK_SIZE_MB})')
    parser.add_argument('--use-browser', action='store_true', help='当HTTP请求失败时，尝试使用无头浏览器（Playwright）')
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

async def test_node(node_url: str, timeout: int = 5) -> Tuple[bool, Optional[float]]:
    """测试节点是否可用（简单 TCP 连接测试）"""
    try:
        protocol, _, rest = node_url.partition('://')
        protocol_lower = protocol.lower()
        server = port = None
        if protocol_lower == 'vmess':
            config_json = decode_base64(rest)
            if config_json:
                config = json.loads(config_json)
                server = config.get('add')
                port = config.get('port')
        elif protocol_lower in ['ss', 'trojan', 'vless', 'hysteria2', 'hy2', 'tuic', 'snell']:
            parsed = urllib.parse.urlparse(node_url)
            server = parsed.hostname
            port = parsed.port or 443
        elif protocol_lower == 'ssr':
            decoded_ssr = decode_base64(rest)
            if decoded_ssr:
                parts = decoded_ssr.split(':')
                if len(parts) >= 2:
                    server, port = parts[0], parts[1]
        
        if not server or not port:
            logger.debug(f"无法解析节点 {node_url[:50]}... 的 server 或 port")
            return False, None
        
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            async with session.get(f"http://{server}:{port}", timeout=timeout) as response:
                if response.status == 200:
                    latency = (time.time() - start_time) * 1000  # 毫秒
                    logger.debug(f"节点 {server}:{port} 有效，延迟: {latency:.2f}ms")
                    return True, latency
                else:
                    logger.debug(f"节点 {server}:{port} 返回状态码 {response.status}")
                    return False, None
    except Exception as e:
        logger.debug(f"节点 {node_url[:50]}... 测试失败: {e}")
        return False, None

async def filter_valid_nodes(nodes: List[str], max_concurrency: int = 10) -> List[Dict[str, Any]]:
    """异步测试节点有效性，返回有效节点及其延迟"""
    valid_nodes = []
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def test_with_semaphore(node: str):
        async with semaphore:
            is_valid, latency = await test_node(node)
            return {"url": node, "latency": latency} if is_valid else None
    
    tasks = [test_with_semaphore(node) for node in nodes]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    valid_nodes = [r for r in results if r is not None]
    
    logger.info(f"有效节点: {len(valid_nodes)}/{len(nodes)}")
    return valid_nodes

def score_node(node_url: str, url_counts: Dict[str, int]) -> int:
    """改进节点评分，综合延迟、协议、来源可靠性"""
    try:
        protocol, _, rest = node_url.partition('://')
        protocol_lower = protocol.lower()
        score = 0
        source_url = node_url.get('source_url', '')  # 假设节点包含来源 URL

        # 协议优先级（更安全的协议得分更高）
        protocol_scores = {
            'trojan': 10,
            'vless': 8,
            'vmess': 6,
            'hysteria2': 6,
            'hy2': 6,
            'tuic': 6,
            'snell': 4,
            'ss': 2,
            'ssr': 1
        }
        score += protocol_scores.get(protocol_lower, 0)

        # 来源可靠性（HTTPS 优先，节点数量多的 URL 优先）
        if source_url.startswith('https://'):
            score += 5
        score += min(url_counts.get(source_url, 0) // 10, 5)  # 节点多的 URL 更可靠

        # TLS 启用优先
        if protocol_lower == 'vmess':
            config_json = decode_base64(rest)
            if config_json:
                config = json.loads(config_json)
                if config.get('tls') == 'tls':
                    score += 5
        elif protocol_lower in ['trojan', 'vless']:
            parsed = urllib.parse.urlparse(node_url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if 'security' in query_params and query_params['security'][0] == 'tls':
                score += 5

        # 备注长度惩罚（过长备注降低分数）
        if '#' in node_url:
            remark = urllib.parse.unquote(node_url.split('#')[-1])
            score -= len(remark) // 10

        return max(score, 0)
    except Exception as e:
        logger.debug(f"评分节点 {node_url[:50]}... 失败: {e}")
        return 0

def generate_node_fingerprint(node_url: str) -> str:
    """生成节点唯一指纹，仅基于核心字段，用于去重"""
    try:
        protocol, _, rest = node_url.partition('://')
        protocol_lower = protocol.lower()
        if protocol_lower not in NODE_PATTERNS:
            return node_url

        if protocol_lower == 'vmess':
            config_json = decode_base64(rest)
            if not config_json:
                return node_url
            try:
                config = json.loads(config_json)
                core_fields = (
                    config.get('add', '').lower(),
                    str(config.get('port', 0)),
                    config.get('id', '').lower(),
                    config.get('security', 'auto').lower()
                )
                return f"vmess://{':'.join(str(x) for x in core_fields)}"
            except json.JSONDecodeError:
                return node_url

        elif protocol_lower == 'ssr':
            decoded_ssr = decode_base64(rest)
            if not decoded_ssr:
                return node_url
            core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr)
            if not core_part_match:
                return node_url
            core_part = core_part_match.group(1)
            parts = core_part.split(':')
            if len(parts) < 6:
                return node_url
            host, port, _, method, _, password_b64 = parts[:6]
            password = decode_base64(password_b64.split('/')[0].split('?')[0].split('#')[0])
            return f"ssr://{host.lower()}:{port}:{method.lower()}:{password.lower()}"

        elif protocol_lower in ['ss', 'trojan', 'vless', 'hysteria2', 'hy2', 'tuic', 'snell']:
            parsed = urllib.parse.urlparse(node_url)
            host_port = parsed.netloc.lower()
            auth = parsed.username or ''
            if protocol_lower in ['ss', 'trojan']:
                auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username
            elif protocol_lower == 'vless':
                auth = parsed.username
                query_params = urllib.parse.parse_qs(parsed.query)
                flow = query_params.get('flow', [''])[0]
                auth = f"{auth}:{flow}" if flow else auth
            elif protocol_lower == 'tuic':
                auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username
            elif protocol_lower == 'snell':
                auth = parsed.username or ''
            return f"{protocol_lower}://{auth.lower()}@{host_port}"
        
        return node_url
    except Exception as e:
        logger.debug(f"生成指纹失败: {node_url[:50]}... 错误: {e}")
        return node_url

def normalize_node_url(url: str) -> str:
    """规范化节点 URL，移除非必要字段，限制备注长度"""
    try:
        protocol, _, rest = url.partition('://')
        if not protocol or protocol.lower() not in NODE_PATTERNS:
            logger.debug(f"无法识别协议或不支持的协议: {url}")
            return url

        parsed_url = urllib.parse.urlparse(url)
        protocol_lower = protocol.lower()

        if protocol_lower == 'vmess':
            config_json = decode_base64(rest)
            if not config_json:
                logger.debug(f"VMess 配置Base64解码失败: {url}")
                return url
            try:
                config = json.loads(config_json)
            except json.JSONDecodeError as e:
                logger.debug(f"VMess 配置 JSON 解析失败: {e} for {config_json[:50]}...")
                return url

            core_keys = ['add', 'port', 'id', 'security']
            optional_keys = ['net', 'tls']
            clean_config = {}
            for k in core_keys + optional_keys:
                if k in config and config[k] is not None:
                    if k == 'port':
                        try:
                            clean_config[k] = int(config[k])
                        except (ValueError, TypeError):
                            clean_config[k] = 0
                            logger.debug(f"VMess 字段 'port' 类型转换失败: {config[k]}")
                    else:
                        clean_config[k] = str(config[k])
            clean_config['ps'] = urllib.parse.unquote(config.get('ps', ''))[:10] or 'node'
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}"
        
        elif protocol_lower == 'ssr':
            decoded_ssr = decode_base64(rest)
            if not decoded_ssr:
                logger.debug(f"SSR Base64解码失败: {url}")
                return url
            core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr)
            if not core_part_match:
                raise ValueError("SSR 链接核心部分解析失败")
            core_part = core_part_match.group(1)
            parts = core_part.split(':')
            if len(parts) < 6:
                raise ValueError(f"SSR 核心部分参数不足，预期6个，实际{len(parts)}")
            host, port, protocol_name, method, obfs_name, password_b64 = parts[:6]
            password = decode_base64(password_b64.split('/')[0].split('?')[0].split('#')[0])
            normalized_core = f"{host}:{port}:{protocol_name}:{method}:{obfs_name}:{password_b64}"
            fragment = decode_base64(core_part_match.group(2).split('#')[-1])[:10] if '#' in core_part_match.group(2) else 'node'
            normalized_core += f"#{encode_base64(fragment)}"
            return f"ssr://{encode_base64(normalized_core)}"
        
        else:
            auth_part = ''
            if parsed_url.username or parsed_url.password:
                auth_user = parsed_url.username if parsed_url.username else ''
                auth_pass = parsed_url.password if parsed_url.password else ''
                auth_part = f"{urllib.parse.quote(auth_user, safe='')}:{urllib.parse.quote(auth_pass, safe='')}@"
            host_port = parsed_url.netloc.lower()
            if '@' in host_port:
                host_port = host_port.split('@', 1)[-1]
            query_params = urllib.parse.parse_qs(parsed_url.query)
            essential_params = {}
            if protocol_lower == 'vless' and 'flow' in query_params:
                essential_params['flow'] = query_params['flow'][0][:10]
            query_string = urllib.parse.urlencode(essential_params, quote_via=urllib.parse.quote) if essential_params else ''
            fragment = urllib.parse.unquote(parsed_url.fragment)[:10] or 'node'
            return f"{protocol_lower}://{auth_part}{host_port}{'?' + query_string if query_string else ''}#{urllib.parse.quote(fragment)}"
    except Exception as e:
        logger.debug(f"规范化 URL '{url}' 失败: {e}")
        return url

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 配置转换为标准 URL，简化次要字段"""
    proxy_type = proxy.get('type', '').lower()
    name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', 'node')[:10]), safe='')
    server = proxy.get('server')
    port = proxy.get('port')
    
    if not all([server, port, proxy_type]):
        logger.debug(f"Clash 代理 {name} 缺少核心信息，跳过: {proxy}")
        return None

    if proxy_type == 'ss':
        cipher = proxy.get('cipher')
        password = proxy.get('password')
        if not all([cipher, password]):
            logger.debug(f"SS 代理 {name} 缺少加密方法或密码: {proxy}")
            return None
        auth = encode_base64(f"{cipher}:{password}")
        return f"ss://{auth}@{server}:{port}#{name}"

    elif proxy_type == 'vmess':
        uuid_val = proxy.get('uuid')
        network = proxy.get('network', 'tcp')
        tls_enabled = proxy.get('tls', False)
        if not uuid_val:
            logger.debug(f"VMess 代理 {name} 缺少 UUID: {proxy}")
            return None
        config = {
            "add": server,
            "port": int(port),
            "id": uuid_val,
            "security": proxy.get('cipher', 'auto'),
            "net": network,
            "ps": urllib.parse.unquote(name)
        }
        if tls_enabled:
            config["tls"] = "tls"
        try:
            return f"vmess://{encode_base64(json.dumps(config, ensure_ascii=False, sort_keys=True))}"
        except Exception as e:
            logger.debug(f"VMess 配置 JSON 编码失败，节点：{name}。错误：{e}")
            return None

    elif proxy_type == 'trojan':
        password = proxy.get('password')
        if not password:
            logger.debug(f"Trojan 代理 {name} 缺少密码: {proxy}")
            return None
        return f"trojan://{password}@{server}:{port}#{name}"

    elif proxy_type == 'vless':
        uuid_val = proxy.get('uuid')
        if not uuid_val:
            logger.debug(f"VLESS 代理 {name} 缺少 UUID: {proxy}")
            return None
        params = {}
        if proxy.get('flow'):
            params['flow'] = proxy['flow'][:10]
        query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        return f"vless://{uuid_val}@{server}:{port}{'?' + query_string if query_string else ''}#{name}"

    elif proxy_type in ['hysteria2', 'hy2']:
        password = proxy.get('password', '')
        if not (password and server and port):
            logger.debug(f"Hysteria2 代理 {name} 缺少密码、服务器或端口: {proxy}")
            return None
        return f"hysteria2://{password}@{server}:{port}#{name}"
    
    elif proxy_type == 'tuic':
        uuid_val = proxy.get('uuid')
        password = proxy.get('password')
        if not all([uuid_val, password, server, port]):
            logger.debug(f"TUIC 代理 {name} 缺少 UUID、密码、服务器或端口: {proxy}")
            return None
        return f"tuic://{uuid_val}:{password}@{server}:{port}#{name}"

    elif proxy_type == 'ssr':
        password = proxy.get('password', '')
        cipher = proxy.get('cipher', 'auto')
        protocol = proxy.get('protocol', 'origin')
        obfs = proxy.get('obfs', 'plain')
        password_b64 = encode_base64(password)
        ssr_core = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{password_b64}"
        return f"ssr://{encode_base64(ssr_core)}#{encode_base64(urllib.parse.unquote(name))}"

    elif proxy_type == 'snell':
        psk = proxy.get('psk', '')
        if not all([psk, server, port]):
            logger.debug(f"Snell 代理 {name} 缺少 PSK、服务器或端口: {proxy}")
            return None
        return f"snell://{urllib.parse.quote(psk, safe='')}@{server}:{port}#{name}"
    
    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}")
    return None

def extract_nodes(content: str, decode_depth: int = 0) -> List[str]:
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

    for pattern_key, pattern_val in NODE_PATTERNS.items():
        matches = re.findall(pattern_val, content, re.MULTILINE | re.IGNORECASE)
        for node in matches:
            cleaned_node = strip_html_tags(node)
            nodes_found.add(normalize_node_url(cleaned_node))

    try:
        soup = BeautifulSoup(content, 'html.parser')
        for tag in soup.find_all(True):
            for attr in ['href', 'src', 'data-url', 'data-node', 'data-config', 'data-link', 'data-href', 'content']:
                if attr in tag.attrs and tag.attrs[attr]:
                    link_val = tag.attrs[attr].strip()
                    cleaned_link = strip_html_tags(link_val)
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_link)
                    if b64_match:
                        decoded_attr = decode_base64(b64_match.group(1))
                        if decoded_attr:
                            nodes_found.update(extract_nodes(decoded_attr, decode_depth + 1))
                    if re.match(COMBINED_REGEX_PATTERN, cleaned_link, re.IGNORECASE):
                        nodes_found.add(normalize_node_url(cleaned_link))
        
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment).strip()
            cleaned_comment = strip_html_tags(comment_text)
            if re.search(COMBINED_REGEX_PATTERN, cleaned_comment, re.MULTILINE | re.IGNORECASE):
                for pattern_val in NODE_PATTERNS.values():
                    matches = re.findall(pattern_val, cleaned_comment, re.MULTILINE | re.IGNORECASE)
                    for node in matches:
                        cleaned_node = strip_html_tags(node)
                        nodes_found.add(normalize_node_url(cleaned_node))
            base64_matches = BASE64_REGEX_LOOSE.findall(cleaned_comment)
            for b64_match_tuple in base64_matches:
                b64_str = b64_match_tuple[0]
                decoded_comment_content = decode_base64(b64_str)
                if decoded_comment_content:
                    nodes_found.update(extract_nodes(decoded_comment_content, decode_depth + 1))
    except Exception as e:
        logger.debug(f"HTML 解析失败: {e}")

    js_variable_matches = JS_VAR_REGEX.findall(content)
    for match_group in js_variable_matches:
        js_val = match_group if isinstance(match_group, str) else match_group[0]
        cleaned_js_val = strip_html_tags(js_val)
        if re.match(COMBINED_REGEX_PATTERN, cleaned_js_val, re.IGNORECASE):
            nodes_found.add(normalize_node_url(cleaned_js_val))
        elif BASE64_REGEX_LOOSE.fullmatch(cleaned_js_val):
            decoded_js_var = decode_base64(cleaned_js_val)
            if decoded_js_var:
                nodes_found.update(extract_nodes(decoded_js_var, decode_depth + 1))
    
    js_func_call_matches = JS_FUNC_CALL_REGEX.findall(content)
    for match_group in js_func_call_matches:
        b64_str_in_func = match_group if isinstance(match_group, str) else match_group[0]
        cleaned_b64_str = strip_html_tags(b64_str_in_func)
        decoded_func_param = decode_base64(cleaned_b64_str)
        if decoded_func_param:
            nodes_found.update(extract_nodes(decoded_func_param, decode_depth + 1))

    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                        nodes_found.add(normalize_node_url(url_node))
        elif isinstance(yaml_content, list):
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item:
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node:
                        if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                            nodes_found.add(normalize_node_url(url_node))
        if isinstance(yaml_content, (dict, list)):
            iterable_content = yaml_content.values() if isinstance(yaml_content, dict) else yaml_content
            for value in iterable_content:
                if isinstance(value, str):
                    cleaned_value = strip_html_tags(value)
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_value)
                    if b64_match:
                        decoded_sub_content = decode_base64(b64_match.group(1))
                        if decoded_sub_content:
                            nodes_found.update(extract_nodes(decoded_sub_content, decode_depth + 1))
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败: {e}")

    try:
        json_content = json.loads(content)
        if isinstance(json_content, list):
            for config_dict in json_content:
                if isinstance(config_dict, dict) and 'id' in config_dict:
                    clash_vmess_proxy = {
                        "type": "vmess",
                        "name": config_dict.get('ps', 'node')[:10],
                        "server": config_dict.get('add'),
                        "port": config_dict.get('port'),
                        "uuid": config_dict.get('id'),
                        "cipher": config_dict.get('type', 'auto'),
                        "network": config_dict.get('net', 'tcp'),
                        "tls": config_dict.get('tls') == 'tls',
                    }
                    url_node = convert_clash_proxy_to_url(clash_vmess_proxy)
                    if url_node:
                        if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                            nodes_found.add(normalize_node_url(url_node))
                elif isinstance(config_dict, dict) and 'protocol' in config_dict and 'settings' in config_dict:
                    protocol_type = config_dict['protocol'].lower()
                    if protocol_type in [p for p in NODE_PATTERNS.keys()]:
                        outbound_settings = config_dict['settings'].get('vnext', [{}])[0] if protocol_type in ['vmess', 'vless'] else config_dict['settings']
                        users = outbound_settings.get('users', [{}])
                        for user_config in users:
                            proxy_cfg = {
                                "type": protocol_type,
                                "name": user_config.get('id', user_config.get('email', 'node'))[:10],
                                "server": outbound_settings.get('address') or user_config.get('address'),
                                "port": outbound_settings.get('port') or user_config.get('port'),
                            }
                            if protocol_type == 'vmess':
                                proxy_cfg.update({"uuid": user_config.get('id'), "cipher": user_config.get('security', 'auto')})
                            elif protocol_type == 'vless':
                                proxy_cfg.update({"uuid": user_config.get('id'), "flow": user_config.get('flow')})
                            elif protocol_type == 'trojan':
                                proxy_cfg.update({"password": user_config.get('password')})
                            url_node = convert_clash_proxy_to_url(proxy_cfg)
                            if url_node:
                                if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                                    nodes_found.add(normalize_node_url(url_node))
        elif isinstance(json_content, dict) and 'proxies' in json_content:
            for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                        nodes_found.add(normalize_node_url(url_node))
    except json.JSONDecodeError as e:
        logger.debug(f"JSON 解析失败: {e}")

    if decode_depth < MAX_BASE64_DECODE_DEPTH:
        base64_candidates = BASE64_REGEX_LOOSE.findall(content)
        for b64_candidate_tuple in base64_candidates:
            b64_str = b64_candidate_tuple[0]
            if len(b64_str) < 50:
                continue
            decoded_content_full = decode_base64(b64_str)
            if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != content:
                nodes_found.update(extract_nodes(decoded_content_full, decode_depth + 1))

    final_filtered_nodes = [
        node for node in nodes_found 
        if any(re.match(pattern, node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()) 
        and len(node) > 20
    ]
    return sorted(list(final_filtered_nodes))

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3) -> str:
    headers = {'User-Agent': UA.random, 'Referer': url}
    for attempt in range(retries):
        try:
            logger.debug(f"尝试获取 URL ({attempt + 1}/{retries}): {url}")
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                response.raise_for_status()
                return await response.text()
        except Exception as e:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(1.0 * (2 ** attempt))
    logger.warning(f"在 {retries} 次尝试后未能成功获取 URL: {url}")
    return ""

async def fetch_with_browser(browser_context: BrowserContext, url: str, timeout: int) -> str:
    page: Page = await browser_context.new_page()
    page.set_default_timeout(timeout * 1000)
    try:
        logger.info(f"尝试使用浏览器获取 URL: {url}")
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
        logger.info(f"正在获取: {http_url}")
        http_nodes = await process_single_url_strategy(session, http_url, timeout, use_browser, browser_context)
        if http_nodes:
            nodes_from_domain.update(http_nodes)
            url_node_counts[http_url] = len(http_nodes)
        else:
            url_node_counts[http_url] = 0
            logger.info(f"HTTP 失败或无节点，尝试获取: {https_url}")
            https_nodes = await process_single_url_strategy(session, https_url, timeout, use_browser, browser_context)
            if https_nodes:
                nodes_from_domain.update(https_nodes)
                url_node_counts[https_url] = len(https_nodes)
            else:
                url_node_counts[https_url] = 0
                failed_urls.add(http_url)
                failed_urls.add(https_url)
    
    return nodes_from_domain

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int, use_browser: bool) -> tuple[List[str], Dict, Set]:
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int)
    failed_urls = set()
    all_nodes_collected = set()
    
    browser_context: Optional[BrowserContext] = None
    if use_browser:
        logger.info("初始化无头浏览器...")
        try:
            playwright_instance = await async_playwright().start()
            browser = await playwright_instance.chromium.launch()
            browser_context = await browser.new_context(user_agent=UA.random, ignore_https_errors=True)
        except Exception as e:
            logger.error(f"初始化 Playwright 失败: {e}. 将不使用浏览器模式。")
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
        try:
            await browser_context.close()
            await browser.close()
            await playwright_instance.stop()
        except Exception as e:
            logger.error(f"关闭 Playwright 时发生错误: {e}")

    # 增强去重逻辑：基于指纹、来源优先级和节点有效性
    logger.info(f"去重前节点数: {len(all_nodes_collected)}")
    fingerprint_to_nodes = defaultdict(list)
    for node in all_nodes_collected:
        normalized_node = normalize_node_url(node)
        fingerprint = generate_node_fingerprint(normalized_node)
        fingerprint_to_nodes[fingerprint].append({"url": normalized_node, "source_url": node.get('source_url', '')})

    # 验证节点有效性
    valid_nodes = await filter_valid_nodes([node["url"] for nodes in fingerprint_to_nodes.values() for node in nodes], max_concurrency)

    # 筛选高质量节点
    max_nodes_per_url = 50  # 限制每个 URL 的节点数量
    url_counts = defaultdict(int)
    high_quality_nodes = []
    for node in sorted(valid_nodes, key=lambda x: x.get("latency", float("inf"))):
        source_url = next((n["source_url"] for n in fingerprint_to_nodes[generate_node_fingerprint(node["url"])] if n["url"] == node["url"]), '')
        if url_counts[source_url] < max_nodes_per_url:
            score = score_node(node["url"], url_node_counts)
            if score > 0 and node.get("latency", float("inf")) < 200:  # 延迟低于 200ms
                high_quality_nodes.append(node["url"])
                url_counts[source_url] += 1

    final_unique_nodes = sorted(high_quality_nodes)
    logger.info(f"去重后节点数: {len(fingerprint_to_nodes)}, 有效且高质量节点数: {len(final_unique_nodes)}")
    logger.info(f"协议统计: {dict(defaultdict(int, [(node.split('://')[0].lower(), 1) for node in final_unique_nodes]))}")
    
    return final_unique_nodes, url_node_counts, failed_urls

def main():
    args = setup_argparse()
    logger.info(f"命令行参数: sources={args.sources}, nodes_output={args.nodes_output}, stats_output={args.stats_output}, max_concurrency={args.max_concurrency}, timeout={args.timeout}, chunk_size_mb={args.chunk_size_mb}, use_browser={args.use_browser}")
    
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls_raw = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"源文件 '{args.sources}' 未找到。")
        return
    
    unique_domains = set()
    for url in urls_raw:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or re.match(r'^(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}(?::\d{1,5})?)(?:/.*)?$', parsed.path)
        if domain:
            unique_domains.add(domain if isinstance(domain, str) else domain.group(1).split('/')[0])
        else:
            logger.warning(f"无法从 URL '{url}' 中识别有效域名。")

    if not unique_domains:
        logger.info("未找到有效域名。")
        return

    start_time = datetime.now()
    logger.info(f"开始处理 {len(unique_domains)} 个域名...")
    
    unique_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(unique_domains, args.max_concurrency, args.timeout, args.use_browser))
    
    logger.info(f"前10个节点样本: {unique_nodes[:10]}")
    
    total_nodes_extracted = len(unique_nodes)
    report_lines = [
        f"--- 报告 ---",
        f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒",
        f"总共提取到 {total_nodes_extracted} 个唯一节点。",
        "\n每个源 URL 的节点提取数量:"
    ]
    report_lines.append("{:<70} {:<15} {:<10}".format("源URL", "找到的节点数", "状态"))
    report_lines.append("-" * 95)
    
    for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True):
        status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点")
        report_lines.append(f"{url:<70} {count:<15} {status:<10}")
    
    if failed_urls:
        report_lines.append("\n未能成功获取或处理的源 URL:")
        report_lines.extend(sorted(list(failed_urls)))
    
    for line in report_lines:
        logger.info(line)

    # 保留原始文件保存逻辑
    output_dir = os.path.dirname(args.nodes_output)
    os.makedirs(output_dir, exist_ok=True)
    target_file_size_bytes = args.chunk_size_mb * 1024 * 1024
    avg_node_length_bytes = 50 if not unique_nodes else sum(len(node.encode('utf-8')) for node in unique_nodes) // len(unique_nodes)
    max_nodes_per_file = target_file_size_bytes // max(avg_node_length_bytes, 50)
    min_nodes_per_file = 20000

    logger.info(f"分片参数: target_file_size_mb={args.chunk_size_mb}, max_nodes_per_file={max_nodes_per_file}, min_nodes_per_file={min_nodes_per_file}")

    # 限制 nodes.txt 的节点数量（例如前 1000 个高质量节点）
    max_nodes_in_main_file = 1000
    if total_nodes_extracted == 0:
        logger.info("没有提取到节点，跳过保存。")
    elif total_nodes_extracted <= max_nodes_per_file:
        try:
            with open(args.nodes_output, 'w', encoding='utf-8') as f:
                content = '\n'.join(unique_nodes[:max_nodes_in_main_file])
                if len(content.encode('utf-8')) > target_file_size_bytes:
                    raise ValueError("文件过大，需分片")
                f.write(content)
            file_size_mb = os.path.getsize(args.nodes_output) / (1024 * 1024)
            logger.info(f"保存 {min(total_nodes_extracted, max_nodes_in_main_file)} 个节点到 {args.nodes_output} ({file_size_mb:.2f} MB)")
        except Exception as e:
            logger.error(f"保存节点失败: {e}")
            num_files = max(1, (total_nodes_extracted + min_nodes_per_file - 1) // min_nodes_per_file)
            estimated_lines_per_file = (total_nodes_extracted + num_files - 1) // num_files
            current_node_idx = 0
            for i in range(num_files):
                end_node_idx = min(current_node_idx + estimated_lines_per_file, total_nodes_extracted)
                nodes_for_file = unique_nodes[current_node_idx:end_node_idx]
                output_path = os.path.join(output_dir, f"nodes_part_{i + 1:03d}.txt")
                try:
                    content = '\n'.join(nodes_for_file)
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
                    logger.info(f"保存 {len(nodes_for_file)} 个节点到 {output_path} ({file_size_mb:.2f} MB)")
                    current_node_idx = end_node_idx
                except Exception as e:
                    logger.error(f"保存分片文件 '{output_path}' 失败: {e}")
                    current_node_idx = end_node_idx
    else:
        # 保存主文件 nodes.txt（限制节点数量）
        try:
            with open(args.nodes_output, 'w', encoding='utf-8') as f:
                content = '\n'.join(unique_nodes[:max_nodes_in_main_file])
                f.write(content)
            file_size_mb = os.path.getsize(args.nodes_output) / (1024 * 1024)
            logger.info(f"保存 {min(total_nodes_extracted, max_nodes_in_main_file)} 个节点到 {args.nodes_output} ({file_size_mb:.2f} MB)")
        except Exception as e:
            logger.error(f"保存主文件 {args.nodes_output} 失败: {e}")

        # 保存分片文件
        num_files = max(1, (total_nodes_extracted + min_nodes_per_file - 1) // min_nodes_per_file)
        estimated_lines_per_file = (total_nodes_extracted + num_files - 1) // num_files
        current_node_idx = 0
        for i in range(num_files):
            end_node_idx = min(current_node_idx + estimated_lines_per_file, total_nodes_extracted)
            nodes_for_file = unique_nodes[current_node_idx:end_node_idx]
            output_path = os.path.join(output_dir, f"nodes_part_{i + 1:03d}.txt")
            try:
                content = '\n'.join(nodes_for_file)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
                logger.info(f"保存 {len(nodes_for_file)} 个节点到 {output_path} ({file_size_mb:.2f} MB)")
                current_node_idx = end_node_idx
            except Exception as e:
                logger.error(f"保存分片文件 '{output_path}' 失败: {e}")
                current_node_idx = end_node_idx

    try:
        with open(args.stats_output, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Source_URL', 'Nodes_Found', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True):
                status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点")
                writer.writerow({'Source_URL': url, 'Nodes_Found': count, 'Status': status})
        logger.info(f"统计数据保存到 {args.stats_output}")
    except Exception as e:
        logger.error(f"保存统计数据失败: {e}")

if __name__ == '__main__':
    main()
