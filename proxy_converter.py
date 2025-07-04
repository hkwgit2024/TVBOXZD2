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

# --- 配置 ---
LOG_FILE = 'proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_NODES_OUTPUT_FILE = 'data/nodes.txt'
DEFAULT_STATS_FILE = 'data/node_counts.csv'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20
DEFAULT_CHUNK_SIZE_MB = 190
MAX_BASE64_DECODE_DEPTH = 3 # 保持不变，兼顾深度和性能
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
# HTML_TAG_REGEX 不再用于内容清理，仅作为正则示例，实际由BeautifulSoup处理
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

def score_node(url: str) -> int:
    """评估节点质量，返回得分（越高越好） - 此函数主要用于选择最优重复节点，与文件大小优化无关，保持不变。"""
    try:
        protocol, _, rest = url.partition('://')
        protocol_lower = protocol.lower()
        score = 0

        if protocol_lower == 'vmess':
            config_json = decode_base64(rest)
            if not config_json:
                return 0
            try:
                config = json.loads(config_json)
                if config.get('tls') == 'tls':
                    score += 5  # 启用 TLS 优先
                score += len(config)  # 更多字段得分更高
                if config.get('ps'):
                    score -= len(config['ps']) // 10  # 备注越短越好
            except json.JSONDecodeError:
                return 0
        elif protocol_lower in ['ss', 'trojan', 'vless', 'hysteria2', 'hy2', 'tuic', 'snell']:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if 'security' in query_params and query_params['security'][0] == 'tls':
                score += 5  # 启用 TLS 优先
            score += len(query_params)  # 更多参数得分更高
            if parsed.fragment:
                score -= len(parsed.fragment) // 10  # 备注越短越好
        elif protocol_lower == 'ssr':
            decoded_ssr = decode_base64(rest)
            if not decoded_ssr:
                return 0
            if 'tls' in decoded_ssr.lower():
                score += 5
            score += decoded_ssr.count('&')  # 更多参数得分更高
            if '#' in decoded_ssr:
                remark = decoded_ssr.split('#')[-1]
                score -= len(decode_base64(remark)) // 10
        return max(score, 0)
    except Exception:
        return 0

def generate_node_fingerprint(url: str) -> str:
    """生成节点唯一指纹，仅基于核心字段，用于去重 - 优化指纹粒度。"""
    try:
        protocol, _, rest = url.partition('://')
        protocol_lower = protocol.lower()
        if protocol_lower not in NODE_PATTERNS:
            return url

        if protocol_lower == 'vmess':
            config_json = decode_base64(rest)
            if not config_json:
                return url
            try:
                config = json.loads(config_json)
                # 移除 'type' 字段，因为它可能因来源不同而有细微差异，但实质上是同一个节点
                core_fields = (
                    config.get('add', ''),
                    str(config.get('port', 0)),
                    config.get('id', '')
                )
                return f"vmess://{':'.join(str(x) for x in core_fields)}"
            except json.JSONDecodeError:
                return url

        elif protocol_lower == 'ssr':
            decoded_ssr = decode_base64(rest)
            if not decoded_ssr:
                return url
            # 核心部分：host:port:protocol:method:obfs:password
            # 这里的password是base64编码的，需要解码后再用于指纹
            core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr)
            if not core_part_match:
                return url
            core_part = core_part_match.group(1)
            parts = core_part.split(':')
            if len(parts) < 6:
                return url
            host, port, _, method, _, password_b64 = parts[:6]
            # 确保密码的解码一致性，用于指纹
            password = decode_base64(password_b64.split('/')[0].split('?')[0].split('#')[0]) 
            # 考虑到 protocol_name 和 obfs_name 可能不影响去重核心，可以移除
            return f"ssr://{host}:{port}:{method}:{password}"

        elif protocol_lower in ['ss', 'trojan', 'vless', 'hysteria2', 'hy2', 'tuic', 'snell']:
            parsed = urllib.parse.urlparse(url)
            host_port = parsed.netloc.lower()
            auth = parsed.username or ''
            if protocol_lower in ['ss', 'trojan']:
                auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username
            elif protocol_lower == 'vless':
                auth = parsed.username
                query_params = urllib.parse.parse_qs(parsed.query)
                flow = query_params.get('flow', [''])[0]
                # flow对于VLESS是关键路由参数，应该保留在指纹中
                auth = f"{auth}:{flow}" if flow else auth 
            elif protocol_lower == 'tuic':
                auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username
            elif protocol_lower == 'snell':
                auth = parsed.username or ''
            return f"{protocol_lower}://{auth}@{host_port}"
        
        return url
    except Exception as e:
        logger.debug(f"生成指纹失败: {url[:50]}... 错误: {e}")
        return url

def normalize_node_url(url: str) -> str:
    """规范化节点 URL，移除非必要字段，限制备注长度 - 优化备注长度和VMess字段。"""
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

            core_keys = ['add', 'port', 'id'] # 核心字段
            clean_config = {}
            for k in core_keys:
                if k in config and config[k] is not None:
                    if k == 'port':
                        try:
                            clean_config[k] = int(config[k])
                        except (ValueError, TypeError):
                            clean_config[k] = 0
                            logger.debug(f"VMess 字段 'port' 类型转换失败: {config[k]}")
                    else:
                        clean_config[k] = str(config[k])
            
            # 有条件地添加可选字段，如果它们不是默认值
            # 假设 'tcp' 是 network 的默认值，'auto' 是 type 的默认值
            if config.get('net') and config['net'].lower() != 'tcp':
                clean_config['net'] = str(config['net'])
            if config.get('tls') == 'tls': # 只有当明确为 'tls' 时才添加
                clean_config['tls'] = 'tls'
            if config.get('type') and config['type'].lower() != 'auto': # 只有当明确不为 'auto' 时才添加
                clean_config['type'] = str(config['type'])

            # 激进缩短备注长度到 5 个字符
            clean_config['ps'] = urllib.parse.unquote(config.get('ps', ''))[:5] or 'node' 
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
            # 激进缩短备注长度到 5 个字符
            fragment = decode_base64(core_part_match.group(2).split('#')[-1])[:5] if '#' in core_part_match.group(2) else 'node'
            normalized_core += f"#{encode_base64(fragment)}"
            return f"ssr://{encode_base64(normalized_core)}"
        
        else: # SS, Trojan, VLESS, Hysteria2, TUIC, Snell
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
                # VLESS的flow参数是关键，保持不变
                essential_params['flow'] = query_params['flow'][0] 
            query_string = urllib.parse.urlencode(essential_params, quote_via=urllib.parse.quote) if essential_params else ''
            # 激进缩短备注长度到 5 个字符
            fragment = urllib.parse.unquote(parsed_url.fragment)[:5] or 'node' 
            return f"{protocol_lower}://{auth_part}{host_port}{'?' + query_string if query_string else ''}#{urllib.parse.quote(fragment)}"
    except Exception as e:
        logger.debug(f"规范化 URL '{url}' 失败: {e}")
        return url

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 配置转换为标准 URL，简化次要字段和备注长度 - 优化备注长度和VMess字段。"""
    proxy_type = proxy.get('type', '').lower()
    # 激进缩短备注长度到 5 个字符
    name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', 'node')[:5]), safe='')
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
        security_cipher = proxy.get('cipher', 'auto') # Vmess 'type' is 'security' in clash
        if not uuid_val:
            logger.debug(f"VMess 代理 {name} 缺少 UUID: {proxy}")
            return None
        config = {
            "add": server,
            "port": int(port),
            "id": uuid_val,
            "ps": urllib.parse.unquote(name) # 备注已在name处理时缩短
        }
        # 有条件地添加可选字段
        if network.lower() != 'tcp': # 假设tcp是默认
            config["net"] = network
        if tls_enabled:
            config["tls"] = "tls"
        if security_cipher.lower() != 'auto': # 假设auto是默认
            config["type"] = security_cipher

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
            params['flow'] = proxy['flow'] # VLESS flow是关键
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
        # 备注已在name处理时缩短
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
        """使用BeautifulSoup更鲁棒地清理HTML标签 - 移除冗余的HTML_TAG_REGEX.sub。"""
        try:
            soup = BeautifulSoup(text, 'html.parser')
            # get_text(strip=True) 已经可以去除空白符
            cleaned = soup.get_text(separator='', strip=True) 
            return cleaned
        except Exception as e:
            logger.debug(f"HTML 标签清理失败: {text[:min(50, len(text))]}... 错误: {e}")
            # 如果BeautifulSoup失败，回退到正则清理，但通常BeautifulSoup更优
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
                        "name": config_dict.get('ps', 'node')[:5], # 备注缩短
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
                                "name": user_config.get('id', user_config.get('email', 'node'))[:5], # 备注缩短
                                "server": outbound_settings.get('address') or user_config.get('address'),
                                "port": outbound_settings.get('port') or user_config.get('port'),
                            }
                            if protocol_type == 'vmess':
                                proxy_cfg.update({"uuid": user_config.get('id'), "cipher": user_config.get('security', 'auto')})
                            elif protocol_type == 'vless':
                                proxy_cfg.update({"uuid": user_config.get('id'), "flow": user_config.get('flow')}) # VLESS flow是关键
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
            if len(b64_str) < 50: # 避免解码过短的非有效Base64字符串
                continue
            decoded_content_full = decode_base64(b64_str)
            if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != content:
                nodes_found.update(extract_nodes(decoded_content_full, decode_depth + 1))

    final_filtered_nodes = [
        node for node in nodes_found 
        if any(re.match(pattern, node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()) 
        and len(node) > 20 # 确保过滤掉无效的过短节点
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

    # 增强去重逻辑：基于指纹和得分
    fingerprint_to_node = {}
    protocol_counts = defaultdict(int)
    for node in all_nodes_collected:
        normalized_node = normalize_node_url(node) # 再次确保所有节点都经过规范化
        fingerprint = generate_node_fingerprint(normalized_node)
        protocol = normalized_node.split('://')[0].lower()
        protocol_counts[protocol] += 1
        current_score = score_node(normalized_node)
        if fingerprint not in fingerprint_to_node or current_score > score_node(fingerprint_to_node[fingerprint]):
            fingerprint_to_node[fingerprint] = normalized_node

    final_unique_nodes = sorted(list(fingerprint_to_node.values()))
    logger.info(f"去重前节点数: {len(all_nodes_collected)}, 去重后节点数: {len(final_unique_nodes)}")
    logger.info(f"协议统计: {dict(protocol_counts)}")
    
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
        # 修正域名提取逻辑：确保只提取域名部分
        domain = parsed.netloc
        if not domain and parsed.path: # 如果没有netloc，尝试从path中提取，例如 raw.githubusercontent.com/user/repo/file
            match_domain_from_path = re.match(r'^(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63})(?::\d{1,5})?(?:/.*)?$', parsed.path)
            if match_domain_from_path:
                domain = match_domain_from_path.group(1)
        
        if domain:
            unique_domains.add(domain)
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

    output_dir = os.path.dirname(args.nodes_output)
    os.makedirs(output_dir, exist_ok=True)
    target_file_size_bytes = args.chunk_size_mb * 1024 * 1024
    
    # 重新计算平均节点长度，以获得更精确的分片
    avg_node_length_bytes = 50 
    if unique_nodes:
        # 实际计算平均长度，考虑UTF-8编码
        total_length = sum(len(node.encode('utf-8')) for node in unique_nodes)
        avg_node_length_bytes = max(1, total_length // len(unique_nodes)) # 确保不为0

    max_nodes_per_file = target_file_size_bytes // avg_node_length_bytes
    min_nodes_per_file = 20000 # 保持不变，作为强制最小分片大小

    logger.info(f"分片参数: target_file_size_mb={args.chunk_size_mb}, avg_node_length_bytes={avg_node_length_bytes}, max_nodes_per_file={max_nodes_per_file}, min_nodes_per_file={min_nodes_per_file}")

    if total_nodes_extracted == 0:
        logger.info("没有提取到节点，跳过保存。")
    # 如果总节点数小于等于最大每文件节点数，尝试保存到一个文件
    elif total_nodes_extracted <= max_nodes_per_file or total_nodes_extracted <= min_nodes_per_file: 
        output_path = args.nodes_output
        try:
            content = '\n'.join(unique_nodes)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
            logger.info(f"保存 {total_nodes_extracted} 个节点到 {output_path} ({file_size_mb:.2f} MB)")
        except Exception as e:
            logger.error(f"保存节点失败: {e}。将尝试分片保存。")
            # 如果保存单个文件失败（例如因为文件过大），则回退到分片
            num_files = max(1, (total_nodes_extracted + min_nodes_per_file - 1) // min_nodes_per_file)
            estimated_lines_per_file = (total_nodes_extracted + num_files - 1) // num_files
            current_node_idx = 0
            for i in range(num_files):
                end_node_idx = min(current_node_idx + estimated_lines_per_file, total_nodes_extracted)
                nodes_for_file = unique_nodes[current_node_idx:end_node_idx]
                output_path_part = os.path.join(output_dir, f"nodes_part_{i + 1:03d}.txt")
                try:
                    content = '\n'.join(nodes_for_file)
                    with open(output_path_part, 'w', encoding='utf-8') as f:
                        f.write(content)
                    file_size_mb = os.path.getsize(output_path_part) / (1024 * 1024)
                    logger.info(f"保存 {len(nodes_for_file)} 个节点到 {output_path_part} ({file_size_mb:.2f} MB)")
                    current_node_idx = end_node_idx
                except Exception as e_part:
                    logger.error(f"保存分片文件 '{output_path_part}' 失败: {e_part}")
                    current_node_idx = end_node_idx
    else: # 节点数超过最大单文件限制，需要分片
        num_files = max(1, (total_nodes_extracted + max_nodes_per_file - 1) // max_nodes_per_file) # 使用max_nodes_per_file计算分片数量
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
