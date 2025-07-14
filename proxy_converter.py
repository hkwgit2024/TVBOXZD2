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
from logging.handlers import RotatingFileHandler # 导入 RotatingFileHandler

# --- 配置 ---
LOG_FILE = 'proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_NODES_OUTPUT_FILE = 'data/nodes.txt'
DEFAULT_STATS_FILE = 'data/node_counts.csv'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20
MAX_BASE64_DECODE_DEPTH = 5
UA = UserAgent()

# 配置日志系统（默认级别为 INFO）
# 使用 RotatingFileHandler 限制日志文件大小和数量
log_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5,              # 最多保留 5 个旧日志文件
    encoding='utf-8'
)
log_handler.setFormatter(logging.Formatter(LOG_FORMAT))

# 创建一个控制台处理器
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

logging.basicConfig(
    level=logging.INFO, # 默认设置为 INFO
    handlers=[
        log_handler,
        console_handler
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
} # [cite: 2]
COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values()) # [cite: 2]
BASE64_RAW_PATTERN = r'(?:b64|base64|data:application\/octet-stream;base64,)?\s*["\']?((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))["\']?\s*' # [cite: 2]
BASE64_REGEX_LOOSE = re.compile(BASE64_RAW_PATTERN, re.MULTILINE | re.IGNORECASE) # [cite: 2, 3]
JS_VAR_REGEX = re.compile(r'(?:var|let|const)\s+[\w]+\s*=\s*["\'](' + COMBINED_REGEX_PATTERN + r'|' + BASE64_RAW_PATTERN + r')["\']', re.MULTILINE | re.IGNORECASE) # [cite: 3]
JS_FUNC_CALL_REGEX = re.compile(r'(?:atob|decodeURIComponent)\s*\(\s*["\']?(' + BASE64_RAW_PATTERN + r')["\']?\s*\)', re.MULTILINE | re.IGNORECASE) # [cite: 3]
HTML_TAG_REGEX = re.compile(r'<[^>]+>', re.MULTILINE) # [cite: 3]

# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='代理节点提取和去重工具') # [cite: 4]
    parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'包含源 URL 的输入文件路径 (默认为: {DEFAULT_SOURCES_FILE})') # [cite: 4]
    parser.add_argument('--nodes-output', default=DEFAULT_NODES_OUTPUT_FILE, help=f'提取到的节点输出文件路径 (默认为: {DEFAULT_NODES_OUTPUT_FILE})') # [cite: 4]
    parser.add_argument('--stats-output', default=DEFAULT_STATS_FILE, help=f'节点统计数据输出文件路径 (默认为: {DEFAULT_STATS_FILE})') # [cite: 4]
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认为: {DEFAULT_MAX_CONCURRENCY})') # [cite: 4]
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认为: {DEFAULT_TIMEOUT})') # [cite: 4]
    parser.add_argument('--use-browser', action='store_true', help='当HTTP请求失败时，尝试使用无头浏览器（Playwright）') # [cite: 4]
    parser.add_argument('--debug', action='store_true', help='启用 DEBUG 日志级别') # [cite: 4]
    return parser.parse_args() # [cite: 4]

def decode_base64(data: str) -> str:
    try:
        cleaned_data = re.sub(r'[^A-Za-z0-9+/=]', '', data) # [cite: 4]
        cleaned_data = cleaned_data.replace('-', '+').replace('_', '/') # [cite: 4]
        padding = len(cleaned_data) % 4 # [cite: 4]
        if padding: # [cite: 4]
            cleaned_data += '=' * (4 - padding) # [cite: 4]
        decoded = base64.b64decode(cleaned_data).decode('utf-8', errors='ignore') # [cite: 4, 5]
        logger.debug(f"Base64 解码成功: {data[:50]}... -> {decoded[:50]}...") # [cite: 5]
        return decoded # [cite: 5]
    except Exception as e:
        logger.debug(f"Base64 解码错误（原始内容片段: {data[:min(50, len(data))]}...）: {e}") # [cite: 5]
        return "" # [cite: 5]

def encode_base64(data: str) -> str:
    try:
        encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8')) # [cite: 5]
        encoded = encoded_bytes.decode('utf-8').rstrip('=') # [cite: 5]
        logger.debug(f"Base64 编码成功: {data[:50]}... -> {encoded[:50]}...") # [cite: 5]
        return encoded # [cite: 5]
    except Exception as e:
        logger.warning(f"Base64 编码失败: {data[:50]}... 错误: {e}") # [cite: 5, 6]
        return data # [cite: 6]

def score_node(node_url: str, url_counts: Dict[str, int]) -> int:
    try:
        protocol, _, rest = node_url.partition('://') # [cite: 6]
        protocol_lower = protocol.lower() # [cite: 6]
        score = 0 # [cite: 6]
        source_url = node_url.get('source_url', '') # [cite: 6]

        protocol_scores = {
            'trojan': 10, 'vless': 8, 'vmess': 6, 'hysteria2': 6,
            'hy2': 6, 'tuic': 6, 'snell': 4, 'ss': 2, 'ssr': 1
        } # [cite: 6, 7]
        score += protocol_scores.get(protocol_lower, 0) # [cite: 7]

        if source_url.startswith('https://'): # [cite: 7]
            score += 5 # [cite: 7]
        score += min(url_counts.get(source_url, 0) // 10, 5) # [cite: 7]

        if protocol_lower == 'vmess': # [cite: 7]
            config_json = decode_base64(rest) # [cite: 7]
            if config_json: # [cite: 8]
                config = json.loads(config_json) # [cite: 8]
                if config.get('tls') == 'tls': # [cite: 8]
                    score += 5 # [cite: 8]
        elif protocol_lower in ['trojan', 'vless']: # [cite: 8]
            parsed = urllib.parse.urlparse(node_url) # [cite: 8]
            query_params = urllib.parse.parse_qs(parsed.query) # [cite: 9]
            if 'security' in query_params and query_params['security'][0] == 'tls': # [cite: 9]
                score += 5 # [cite: 9]

        if '#' in node_url: # [cite: 9]
            remark = urllib.parse.unquote(node_url.split('#')[-1]) # [cite: 9]
            score -= len(remark) // 10 # [cite: 9]

        logger.debug(f"节点 {node_url[:50]}... 得分: {score}") # [cite: 9]
        return max(score, 0) # [cite: 10]
    except Exception as e:
        logger.debug(f"评分节点 {node_url[:50]}... 失败: {e}") # [cite: 10]
        return 0 # [cite: 10]

def generate_node_fingerprint(node_url: str) -> str:
    try:
        protocol, _, rest = node_url.partition('://') # [cite: 10]
        protocol_lower = protocol.lower() # [cite: 10]
        if protocol_lower not in NODE_PATTERNS: # [cite: 10]
            logger.debug(f"不支持的协议: {node_url[:50]}...") # [cite: 11]
            return node_url # [cite: 11]

        if protocol_lower == 'vmess': # [cite: 11]
            config_json = decode_base64(rest) # [cite: 11]
            if not config_json: # [cite: 11]
                logger.debug(f"VMess Base64 解码失败: {node_url[:50]}...") # [cite: 11]
                return node_url # [cite: 11]
            try:
                config = json.loads(config_json) # [cite: 12]
                core_fields = (
                    config.get('add', '').lower(),
                    str(config.get('port', 0)),
                    config.get('id', '').lower(),
                    config.get('security', 'auto').lower()
                ) # [cite: 12, 13]
                return f"vmess://{':'.join(str(x) for x in core_fields)}" # [cite: 13]
            except json.JSONDecodeError as e:
                logger.debug(f"VMess JSON 解析失败: {e}") # [cite: 13]
                return node_url # [cite: 13]

        elif protocol_lower == 'ssr': # [cite: 14]
            decoded_ssr = decode_base64(rest) # [cite: 14]
            if not decoded_ssr: # [cite: 14]
                logger.debug(f"SSR Base64 解码失败: {node_url[:50]}...") # [cite: 14]
                return node_url # [cite: 14]
            core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr) # [cite: 14]
            if not core_part_match: # [cite: 14]
                logger.debug(f"SSR 核心部分解析失败: {node_url[:50]}...") # [cite: 15]
                return node_url # [cite: 15]
            core_part = core_part_match.group(1) # [cite: 15]
            parts = core_part.split(':') # [cite: 15]
            if len(parts) < 6: # [cite: 15]
                logger.debug(f"SSR 参数不足: {node_url[:50]}...") # [cite: 15]
                return node_url # [cite: 16]
            host, port, _, method, _, password_b64 = parts[:6] # [cite: 16]
            password = decode_base64(password_b64.split('/')[0].split('?')[0].split('#')[0]) # [cite: 16]
            return f"ssr://{host.lower()}:{port}:{method.lower()}:{password.lower()}" # [cite: 16]

        elif protocol_lower in ['ss', 'trojan', 'vless', 'hysteria2', 'hy2', 'tuic', 'snell']: # [cite: 16]
            parsed = urllib.parse.urlparse(node_url) # [cite: 17]
            host_port = parsed.netloc.lower() # [cite: 17]
            auth = parsed.username or '' # [cite: 17]
            if protocol_lower in ['ss', 'trojan']: # [cite: 17]
                auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username # [cite: 17]
            elif protocol_lower == 'vless': # [cite: 17]
                auth = parsed.username # [cite: 17]
                query_params = urllib.parse.parse_qs(parsed.query) # [cite: 18]
                flow = query_params.get('flow', [''])[0] # [cite: 18]
                auth = f"{auth}:{flow}" if flow else auth # [cite: 18]
            elif protocol_lower == 'tuic': # [cite: 18]
                auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username # [cite: 19]
            elif protocol_lower == 'snell': # [cite: 19]
                auth = parsed.username or '' # [cite: 19]
            return f"{protocol_lower}://{auth.lower()}@{host_port}" # [cite: 19]
        
        return node_url # [cite: 19]
    except Exception as e:
        logger.debug(f"生成指纹失败: {node_url[:50]}... 错误: {e}") # [cite: 19]
        return node_url # [cite: 19]

def normalize_node_url(url: str) -> str:
    try:
        protocol, _, rest = url.partition('://') # [cite: 19, 20]
        if not protocol or protocol.lower() not in NODE_PATTERNS: # [cite: 20]
            logger.debug(f"无法识别协议或不支持的协议: {url[:50]}...") # [cite: 20]
            return url # [cite: 20]

        parsed_url = urllib.parse.urlparse(url) # [cite: 20]
        protocol_lower = protocol.lower() # [cite: 20]

        if protocol_lower == 'vmess': # [cite: 20]
            config_json = decode_base64(rest) # [cite: 20]
            if not config_json: # [cite: 21]
                logger.debug(f"VMess 配置Base64解码失败: {url[:50]}...") # [cite: 21]
                return url # [cite: 21]
            try:
                config = json.loads(config_json) # [cite: 21]
            except json.JSONDecodeError as e:
                logger.debug(f"VMess 配置 JSON 解析失败: {e} for {config_json[:50]}...") # [cite: 21]
                return url # [cite: 22]

            core_keys = ['add', 'port', 'id', 'security'] # [cite: 22]
            optional_keys = ['net', 'tls'] # [cite: 22]
            clean_config = {} # [cite: 22]
            for k in core_keys + optional_keys: # [cite: 22]
                if k in config and config[k] is not None: # [cite: 23]
                    if k == 'port': # [cite: 23]
                        try:
                            clean_config[k] = int(config[k]) # [cite: 23, 24]
                        except (ValueError, TypeError):
                            clean_config[k] = 0 # [cite: 24]
                            logger.debug(f"VMess 字段 'port' 类型转换失败: {config[k]}") # [cite: 24]
                    else:
                        clean_config[k] = str(config[k]) # [cite: 25]
            clean_config['ps'] = urllib.parse.unquote(config.get('ps', ''))[:10] or 'node' # [cite: 25]
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}" # [cite: 25]
        
        elif protocol_lower == 'ssr': # [cite: 25]
            decoded_ssr = decode_base64(rest) # [cite: 25]
            if not decoded_ssr: # [cite: 26]
                logger.debug(f"SSR Base64解码失败: {url[:50]}...") # [cite: 26]
                return url # [cite: 26]
            core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr) # [cite: 26]
            if not core_part_match: # [cite: 26]
                raise ValueError("SSR 链接核心部分解析失败")
            core_part = core_part_match.group(1) # [cite: 27]
            parts = core_part.split(':') # [cite: 27]
            if len(parts) < 6: # [cite: 27]
                raise ValueError(f"SSR 核心部分参数不足，预期6个，实际{len(parts)}") # [cite: 27]
            host, port, protocol_name, method, obfs_name, password_b64 = parts[:6] # [cite: 27]
            password = decode_base64(password_b64.split('/')[0].split('?')[0].split('#')[0]) # [cite: 27]
            normalized_core = f"{host}:{port}:{protocol_name}:{method}:{obfs_name}:{password_b64}" # [cite: 27]
            fragment = decode_base64(core_part_match.group(2).split('#')[-1])[:10] if '#' in core_part_match.group(2) else 'node' # [cite: 27, 28]
            normalized_core += f"#{encode_base64(fragment)}" # [cite: 28]
            return f"ssr://{encode_base64(normalized_core)}" # [cite: 28]
        
        else:
            auth_part = '' # [cite: 28]
            if parsed_url.username or parsed_url.password: # [cite: 28]
                auth_user = parsed_url.username if parsed_url.username else '' # [cite: 29]
                auth_pass = parsed_url.password if parsed_url.password else '' # [cite: 29]
                auth_part = f"{urllib.parse.quote(auth_user, safe='')}:{urllib.parse.quote(auth_pass, safe='')}@" # [cite: 29]
            host_port = parsed_url.netloc.lower() # [cite: 29]
            if '@' in host_port: # [cite: 29]
                host_port = host_port.split('@', 1)[-1] # [cite: 29]
            query_params = urllib.parse.parse_qs(parsed_url.query) # [cite: 30]
            essential_params = {} # [cite: 30]
            if protocol_lower == 'vless' and 'flow' in query_params: # [cite: 30]
                essential_params['flow'] = query_params['flow'][0][:10] # [cite: 30, 31]
            query_string = urllib.parse.urlencode(essential_params, quote_via=urllib.parse.quote) if essential_params else '' # [cite: 31]
            fragment = urllib.parse.unquote(parsed_url.fragment)[:10] or 'node' # [cite: 31]
            return f"{protocol_lower}://{auth_part}{host_port}{'?' + query_string if query_string else ''}#{urllib.parse.quote(fragment)}" # [cite: 31]
    except Exception as e:
        logger.debug(f"规范化 URL '{url[:50]}...' 失败: {e}") # [cite: 31]
        return url # [cite: 31]

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    proxy_type = proxy.get('type', '').lower() # [cite: 32]
    name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', 'node')[:10]), safe='') # [cite: 32]
    server = proxy.get('server') # [cite: 32]
    port = proxy.get('port') # [cite: 32]
    
    if not all([server, port, proxy_type]): # [cite: 32]
        logger.debug(f"Clash 代理 {name} 缺少核心信息，跳过: {proxy}") # [cite: 32]
        return None # [cite: 32]

    if proxy_type == 'ss': # [cite: 32]
        cipher = proxy.get('cipher') # [cite: 32]
        password = proxy.get('password') # [cite: 32]
        if not all([cipher, password]): # [cite: 32]
            logger.debug(f"SS 代理 {name} 缺少加密方法或密码: {proxy}") # [cite: 33]
            return None # [cite: 33]
        auth = encode_base64(f"{cipher}:{password}") # [cite: 33]
        return f"ss://{auth}@{server}:{port}#{name}" # [cite: 33]

    elif proxy_type == 'vmess': # [cite: 33]
        uuid_val = proxy.get('uuid') # [cite: 33]
        network = proxy.get('network', 'tcp') # [cite: 33]
        tls_enabled = proxy.get('tls', False) # [cite: 33]
        if not uuid_val: # [cite: 33]
            logger.debug(f"VMess 代理 {name} 缺少 UUID: {proxy}") # [cite: 33]
            return None # [cite: 33]
        config = {
            "add": server,
            "port": int(port),
            "id": uuid_val, # [cite: 34]
            "security": proxy.get('cipher', 'auto'), # [cite: 34]
            "net": network, # [cite: 34]
            "ps": urllib.parse.unquote(name) # [cite: 34]
        }
        if tls_enabled: # [cite: 34]
            config["tls"] = "tls" # [cite: 35]
        try:
            return f"vmess://{encode_base64(json.dumps(config, ensure_ascii=False, sort_keys=True))}" # [cite: 35]
        except Exception as e:
            logger.debug(f"VMess 配置 JSON 编码失败，节点：{name}。错误：{e}") # [cite: 35]
            return None # [cite: 35]

    elif proxy_type == 'trojan': # [cite: 35]
        password = proxy.get('password') # [cite: 36]
        if not password: # [cite: 36]
            logger.debug(f"Trojan 代理 {name} 缺少密码: {proxy}") # [cite: 36]
            return None # [cite: 36]
        return f"trojan://{password}@{server}:{port}#{name}" # [cite: 36]

    elif proxy_type == 'vless': # [cite: 36]
        uuid_val = proxy.get('uuid') # [cite: 36]
        if not uuid_val: # [cite: 36]
            logger.debug(f"VLESS 代理 {name} 缺少 UUID: {proxy}") # [cite: 37]
            return None # [cite: 37]
        params = {} # [cite: 37]
        if proxy.get('flow'): # [cite: 37]
            params['flow'] = proxy['flow'][:10] # [cite: 37]
        query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote) # [cite: 37]
        return f"vless://{uuid_val}@{server}:{port}{'?' + query_string if query_string else ''}#{name}" # [cite: 38]

    elif proxy_type in ['hysteria2', 'hy2']: # [cite: 38]
        password = proxy.get('password', '') # [cite: 38]
        if not (password and server and port): # [cite: 38]
            logger.debug(f"Hysteria2 代理 {name} 缺少密码、服务器或端口: {proxy}") # [cite: 39]
            return None # [cite: 39]
        return f"hysteria2://{password}@{server}:{port}#{name}" # [cite: 39]
    
    elif proxy_type == 'tuic': # [cite: 39]
        uuid_val = proxy.get('uuid') # [cite: 39]
        password = proxy.get('password') # [cite: 39]
        if not all([uuid_val, password, server, port]): # [cite: 39]
            logger.debug(f"TUIC 代理 {name} 缺少 UUID、密码、服务器或端口: {proxy}") # [cite: 39]
            return None # [cite: 39]
        return f"tuic://{uuid_val}:{password}@{server}:{port}#{name}" # [cite: 39]

    elif proxy_type == 'ssr': # [cite: 39]
        password = proxy.get('password', '') # [cite: 40]
        cipher = proxy.get('cipher', 'auto') # [cite: 40]
        protocol = proxy.get('protocol', 'origin') # [cite: 40]
        obfs = proxy.get('obfs', 'plain') # [cite: 40]
        password_b64 = encode_base64(password) # [cite: 40]
        ssr_core = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{password_b64}" # [cite: 40]
        return f"ssr://{encode_base64(ssr_core)}#{encode_base64(urllib.parse.unquote(name))}" # [cite: 40]

    elif proxy_type == 'snell': # [cite: 40]
        psk = proxy.get('psk', '') # [cite: 41]
        if not all([psk, server, port]): # [cite: 41]
            logger.debug(f"Snell 代理 {name} 缺少 PSK、服务器或端口: {proxy}") # [cite: 41]
            return None # [cite: 41]
        return f"snell://{urllib.parse.quote(psk, safe='')}@{server}:{port}#{name}" # [cite: 41]
    
    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}") # [cite: 41]
    return None # [cite: 41]

def extract_nodes(content: str, decode_depth: int = 0, source_url: str = '') -> List[Dict[str, str]]:
    nodes_found = set() # [cite: 42]
    
    if not content or decode_depth > MAX_BASE64_DECODE_DEPTH: # [cite: 42]
        logger.debug(f"内容为空或解码深度超限: {decode_depth}/{MAX_BASE64_DECODE_DEPTH}") # [cite: 42]
        return [] # [cite: 42]

    content = content.replace('\r\n', '\n').replace('\r', '\n') # [cite: 42]
    logger.info(f"提取节点，内容长度: {len(content)}, 来源: {source_url[:50]}...") # [cite: 42]

    def strip_html_tags(text: str) -> str:
        try:
            soup = BeautifulSoup(text, 'html.parser') # [cite: 42]
            cleaned = soup.get_text(separator='', strip=True) # [cite: 42]
            cleaned = HTML_TAG_REGEX.sub('', cleaned) # [cite: 42]
            return cleaned # [cite: 42]
        except Exception as e:
            logger.debug(f"HTML 标签清理失败: {text[:50]}... 错误: {e}") # [cite: 43]
        return HTML_TAG_REGEX.sub('', text) # [cite: 43]

    for pattern_key, pattern_val in NODE_PATTERNS.items(): # [cite: 43]
        matches = re.findall(pattern_val, content, re.MULTILINE | re.IGNORECASE) # [cite: 43, 44]
        for node in matches: # [cite: 44]
            cleaned_node = strip_html_tags(node) # [cite: 44]
            normalized_node = normalize_node_url(cleaned_node) # [cite: 44]
            logger.debug(f"匹配到节点: {cleaned_node[:50]}... -> 规范化: {normalized_node[:50]}...") # [cite: 44]
            nodes_found.add((normalized_node, source_url)) # [cite: 44]

    try:
        soup = BeautifulSoup(content, 'html.parser') # [cite: 44]
        for tag in soup.find_all(True): # [cite: 45]
            for attr in ['href', 'src', 'data-url', 'data-node', 'data-config', 'data-link', 'data-href', 'content']: # [cite: 45]
                if attr in tag.attrs and tag.attrs[attr]: # [cite: 45]
                    link_val = tag.attrs[attr].strip() # [cite: 45]
                    cleaned_link = strip_html_tags(link_val) # [cite: 46]
                    logger.debug(f"检查 HTML 标签属性 {attr}: {cleaned_link[:50]}...") # [cite: 46]
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_link) # [cite: 46]
                    if b64_match: # [cite: 46]
                        decoded_attr = decode_base64(b64_match.group(1)) # [cite: 46]
                        if decoded_attr: # [cite: 47]
                            nodes_found.update((node, source_url) for node in extract_nodes(decoded_attr, decode_depth + 1, source_url)) # [cite: 47]
                    if re.match(COMBINED_REGEX_PATTERN, cleaned_link, re.IGNORECASE): # [cite: 47]
                        normalized_node = normalize_node_url(cleaned_link) # [cite: 47]
                        nodes_found.add((normalized_node, source_url)) # [cite: 48]
        
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)): # [cite: 48]
            comment_text = str(comment).strip() # [cite: 48]
            cleaned_comment = strip_html_tags(comment_text) # [cite: 48]
            logger.debug(f"检查 HTML 注释: {cleaned_comment[:50]}...") # [cite: 48]
            if re.search(COMBINED_REGEX_PATTERN, cleaned_comment, re.MULTILINE | re.IGNORECASE): # [cite: 48, 49]
                for pattern_val in NODE_PATTERNS.values(): # [cite: 49]
                    matches = re.findall(pattern_val, cleaned_comment, re.MULTILINE | re.IGNORECASE) # [cite: 49]
                    for node in matches: # [cite: 49]
                        cleaned_node = strip_html_tags(node) # [cite: 50]
                        normalized_node = normalize_node_url(cleaned_node) # [cite: 50]
                        nodes_found.add((normalized_node, source_url)) # [cite: 50]
            base64_matches = BASE64_REGEX_LOOSE.findall(cleaned_comment) # [cite: 50]
            for b64_match_tuple in base64_matches: # [cite: 50]
                b64_str = b64_match_tuple[0] # [cite: 51]
                decoded_comment_content = decode_base64(b64_str) # [cite: 51]
                if decoded_comment_content: # [cite: 51]
                    nodes_found.update((node, source_url) for node in extract_nodes(decoded_comment_content, decode_depth + 1, source_url)) # [cite: 51]
    except Exception as e:
        logger.debug(f"HTML 解析失败: {e}") # [cite: 52]

    js_variable_matches = JS_VAR_REGEX.findall(content) # [cite: 52]
    for match_group in js_variable_matches: # [cite: 52]
        js_val = match_group if isinstance(match_group, str) else match_group[0] # [cite: 52]
        cleaned_js_val = strip_html_tags(js_val) # [cite: 52]
        logger.debug(f"检查 JS 变量: {cleaned_js_val[:50]}...") # [cite: 52]
        if re.match(COMBINED_REGEX_PATTERN, cleaned_js_val, re.IGNORECASE): # [cite: 52]
            normalized_node = normalize_node_url(cleaned_js_val) # [cite: 52]
            nodes_found.add((normalized_node, source_url)) # [cite: 53]
        elif BASE64_REGEX_LOOSE.fullmatch(cleaned_js_val): # [cite: 53]
            decoded_js_var = decode_base64(cleaned_js_val) # [cite: 53]
            if decoded_js_var: # [cite: 53]
                nodes_found.update((node, source_url) for node in extract_nodes(decoded_js_var, decode_depth + 1, source_url)) # [cite: 53]
    
    js_func_call_matches = JS_FUNC_CALL_REGEX.findall(content) # [cite: 53]
    for match_group in js_func_call_matches: # [cite: 54]
        b64_str_in_func = match_group if isinstance(match_group, str) else match_group[0] # [cite: 54]
        cleaned_b64_str = strip_html_tags(b64_str_in_func) # [cite: 54]
        logger.debug(f"检查 JS 函数调用: {cleaned_b64_str[:50]}...") # [cite: 54]
        decoded_func_param = decode_base64(cleaned_b64_str) # [cite: 54]
        if decoded_func_param: # [cite: 54]
            nodes_found.update((node, source_url) for node in extract_nodes(decoded_func_param, decode_depth + 1, source_url)) # [cite: 54]

    try:
        yaml_content = yaml.safe_load(content) # [cite: 54]
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content: # [cite: 55]
            for proxy_dict in yaml_content['proxies']: # [cite: 55]
                url_node = convert_clash_proxy_to_url(proxy_dict) # [cite: 55]
                if url_node: # [cite: 55]
                    if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 55]
                        normalized_node = normalize_node_url(url_node) # [cite: 55]
                        nodes_found.add((normalized_node, source_url)) # [cite: 55]
        elif isinstance(yaml_content, list): # [cite: 55]
            for item in yaml_content: # [cite: 56]
                if isinstance(item, dict) and 'type' in item: # [cite: 56]
                    url_node = convert_clash_proxy_to_url(item) # [cite: 56]
                    if url_node: # [cite: 56]
                        if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 56]
                            normalized_node = normalize_node_url(url_node) # [cite: 57]
                            nodes_found.add((normalized_node, source_url)) # [cite: 57]
        if isinstance(yaml_content, (dict, list)): # [cite: 57]
            iterable_content = yaml_content.values() if isinstance(yaml_content, dict) else yaml_content # [cite: 57, 58]
            for value in iterable_content: # [cite: 58]
                if isinstance(value, str): # [cite: 58]
                    cleaned_value = strip_html_tags(value) # [cite: 58]
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_value) # [cite: 58]
                    if b64_match: # [cite: 58]
                        decoded_sub_content = decode_base64(b64_match.group(1)) # [cite: 59]
                        if decoded_sub_content: # [cite: 59]
                            nodes_found.update((node, source_url) for node in extract_nodes(decoded_sub_content, decode_depth + 1, source_url)) # [cite: 59]
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败: {e}") # [cite: 59]

    try:
        json_content = json.loads(content) # [cite: 59]
        if isinstance(json_content, list): # [cite: 60]
            for config_dict in json_content: # [cite: 60]
                if isinstance(config_dict, dict) and 'id' in config_dict: # [cite: 60]
                    clash_vmess_proxy = {
                        "type": "vmess", # [cite: 60]
                        "name": config_dict.get('ps', 'node')[:10], # [cite: 61]
                        "server": config_dict.get('add'), # [cite: 61]
                        "port": config_dict.get('port'), # [cite: 61]
                        "uuid": config_dict.get('id'), # [cite: 61]
                        "cipher": config_dict.get('type', 'auto'), # [cite: 62]
                        "network": config_dict.get('net', 'tcp'), # [cite: 62]
                        "tls": config_dict.get('tls') == 'tls', # [cite: 62]
                    }
                    url_node = convert_clash_proxy_to_url(clash_vmess_proxy) # [cite: 63]
                    if url_node: # [cite: 63]
                        if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 63]
                            normalized_node = normalize_node_url(url_node) # [cite: 63]
                            nodes_found.add((normalized_node, source_url)) # [cite: 64]
                elif isinstance(config_dict, dict) and 'protocol' in config_dict and 'settings' in config_dict: # [cite: 64]
                    protocol_type = config_dict['protocol'].lower() # [cite: 64]
                    if protocol_type in [p for p in NODE_PATTERNS.keys()]: # [cite: 64, 65]
                        outbound_settings = config_dict['settings'].get('vnext', [{}])[0] if protocol_type in ['vmess', 'vless'] else config_dict['settings'] # [cite: 65]
                        users = outbound_settings.get('users', [{}]) # [cite: 65]
                        for user_config in users: # [cite: 65]
                            proxy_cfg = {
                                "type": protocol_type, # [cite: 66]
                                "name": user_config.get('id', user_config.get('email', 'node'))[:10], # [cite: 66, 67]
                                "server": outbound_settings.get('address') or user_config.get('address'), # [cite: 67]
                                "port": outbound_settings.get('port') or user_config.get('port'), # [cite: 67]
                            }
                            if protocol_type == 'vmess': # [cite: 68]
                                proxy_cfg.update({"uuid": user_config.get('id'), "cipher": user_config.get('security', 'auto')}) # [cite: 68]
                            elif protocol_type == 'vless': # [cite: 68]
                                proxy_cfg.update({"uuid": user_config.get('id'), "flow": user_config.get('flow')}) # [cite: 69]
                            elif protocol_type == 'trojan': # [cite: 69]
                                proxy_cfg.update({"password": user_config.get('password')}) # [cite: 69]
                            url_node = convert_clash_proxy_to_url(proxy_cfg) # [cite: 70]
                            if url_node: # [cite: 70]
                                if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 70]
                                    normalized_node = normalize_node_url(url_node) # [cite: 71]
                                    nodes_found.add((normalized_node, source_url)) # [cite: 71]
        elif isinstance(json_content, dict) and 'proxies' in json_content: # [cite: 71]
            for proxy_dict in json_content['proxies']: # [cite: 72]
                url_node = convert_clash_proxy_to_url(proxy_dict) # [cite: 72]
                if url_node: # [cite: 72]
                    if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 72]
                        normalized_node = normalize_node_url(url_node) # [cite: 72]
                        nodes_found.add((normalized_node, source_url)) # [cite: 72]
    except json.JSONDecodeError as e: # [cite: 73]
        logger.debug(f"JSON 解析失败: {e}") # [cite: 73]

    if decode_depth < MAX_BASE64_DECODE_DEPTH: # [cite: 73]
        base64_candidates = BASE64_REGEX_LOOSE.findall(content) # [cite: 73]
        for b64_candidate_tuple in base64_candidates: # [cite: 73]
            b64_str = b64_candidate_tuple[0] # [cite: 74]
            if len(b64_str) < 20: # [cite: 74]
                continue # [cite: 74]
            decoded_content_full = decode_base64(b64_str) # [cite: 74]
            if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != content: # [cite: 74]
                logger.debug(f"处理 Base64 解码内容: {decoded_content_full[:50]}...") # [cite: 74]
                nodes_found.update((node, source_url) for node in extract_nodes(decoded_content_full, decode_depth + 1, source_url)) # [cite: 75]

    final_filtered_nodes = [
        {"url": node, "source_url": source} 
        for node, source in nodes_found 
        if any(re.match(pattern, node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()) # [cite: 75]
        and len(node) > 20
    ] # [cite: 75]
    logger.info(f"从内容提取到 {len(final_filtered_nodes)} 个节点") # [cite: 75]
    return sorted(final_filtered_nodes, key=lambda x: x["url"]) # [cite: 75]

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3) -> str:
    headers = {'User-Agent': UA.random, 'Referer': url} # [cite: 76]
    for attempt in range(retries): # [cite: 76]
        try:
            logger.info(f"尝试获取 URL ({attempt + 1}/{retries}): {url}") # [cite: 76]
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response: # [cite: 76]
                response.raise_for_status() # [cite: 76]
                content = await response.text() # [cite: 76]
                logger.info(f"成功获取 URL: {url}, 内容长度: {len(content)}") # [cite: 76]
                return content # [cite: 76]
        except Exception as e:
            logger.warning(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: {e}") # [cite: 77]
            if attempt < retries - 1: # [cite: 77]
                await asyncio.sleep(1.0 * (2 ** attempt)) # [cite: 77]
    logger.error(f"在 {retries} 次尝试后未能成功获取 URL: {url}") # [cite: 77]
    return "" # [cite: 77]

async def fetch_with_browser(browser_context: BrowserContext, url: str, timeout: int) -> str:
    page: Page = await browser_context.new_page() # [cite: 78]
    page.set_default_timeout(timeout * 1000) # [cite: 78]
    try:
        logger.info(f"尝试使用浏览器获取 URL: {url}") # [cite: 78]
        await page.goto(url, wait_until="networkidle") # [cite: 78]
        content = await page.content() # [cite: 78]
        logger.info(f"浏览器获取 URL: {url}, 内容长度: {len(content)}") # [cite: 78]
        return content # [cite: 78]
    except Exception as e:
        logger.warning(f"使用浏览器获取 URL {url} 失败: {e}") # [cite: 78]
        return "" # [cite: 78]
    finally:
        await page.close() # [cite: 78]

async def process_single_url_strategy(session: aiohttp.ClientSession, url: str, timeout: int, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> List[Dict[str, str]]:
    content = await fetch_with_retry(session, url, timeout) # [cite: 79]
    if not content and use_browser and browser_context: # [cite: 79]
        content = await fetch_with_browser(browser_context, url, timeout) # [cite: 79]
    nodes = extract_nodes(content, source_url=url) if content else [] # [cite: 79]
    logger.info(f"从 URL {url} 提取到 {len(nodes)} 个节点") # [cite: 79]
    return nodes # [cite: 79]

async def process_domain(session: aiohttp.ClientSession, domain: str, timeout: int, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> List[Dict[str, str]]:
    nodes_from_domain = [] # [cite: 80]
    http_url = f"http://{domain}" # [cite: 80]
    https_url = f"https://{domain}" # [cite: 80]
   
    async with semaphore: # [cite: 80]
        logger.info(f"正在获取: {http_url}") # [cite: 80]
        http_nodes = await process_single_url_strategy(session, http_url, timeout, use_browser, browser_context) # [cite: 80]
        url_node_counts[http_url] = len(http_nodes) # [cite: 80]
        if http_nodes: # [cite: 81]
            nodes_from_domain.extend(http_nodes) # [cite: 81]
            logger.info(f"HTTP URL {http_url} 提取到 {len(http_nodes)} 个节点") # [cite: 81]
        else:
            logger.info(f"HTTP URL {http_url} 无节点，尝试 HTTPS: {https_url}") # [cite: 81]
            https_nodes = await process_single_url_strategy(session, https_url, timeout, use_browser, browser_context) # [cite: 81]
            url_node_counts[https_url] = len(https_nodes) # [cite: 81]
            if https_nodes: # [cite: 81]
                nodes_from_domain.extend(https_nodes) # [cite: 82]
                logger.info(f"HTTPS URL {https_url} 提取到 {len(https_nodes)} 个节点") # [cite: 82]
            else:
                failed_urls.add(http_url) # [cite: 82]
                failed_urls.add(https_url) # [cite: 82]
                logger.warning(f"HTTP 和 HTTPS URL ({http_url}, {https_url}) 均无节点") # [cite: 82]
    
    return nodes_from_domain # [cite: 82]

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int, use_browser: bool) -> tuple[List[str], Dict, Set]:
    semaphore = asyncio.Semaphore(max_concurrency) # [cite: 83]
    url_node_counts = defaultdict(int) # [cite: 83]
    failed_urls = set() # [cite: 83]
    all_nodes_collected = [] # [cite: 83]
 
    browser_context: Optional[BrowserContext] = None # [cite: 83]
    if use_browser: # [cite: 83]
        logger.info("初始化无头浏览器...") # [cite: 83]
        try:
            playwright_instance = await async_playwright().start() # [cite: 84]
            browser = await playwright_instance.chromium.launch() # [cite: 84]
            browser_context = await browser.new_context(user_agent=UA.random, ignore_https_errors=True) # [cite: 84]
        except Exception as e:
            logger.error(f"初始化 Playwright 失败: {e}. 将不使用浏览器模式。") # [cite: 84]
            use_browser = False # [cite: 84]

    async with aiohttp.ClientSession() as session: # [cite: 84]
        tasks = [process_domain(session, domain, timeout, semaphore, url_node_counts, failed_urls, use_browser, browser_context) for domain in domains] # [cite: 84]
        results = await asyncio.gather(*tasks, return_exceptions=True) # [cite: 85]
        for nodes_or_exception in results: # [cite: 85]
            if isinstance(nodes_or_exception, list): # [cite: 85]
                all_nodes_collected.extend(nodes_or_exception) # [cite: 85]
            else:
                logger.error(f"处理域名时发生异常: {nodes_or_exception}") # [cite: 85]

    if browser_context: # [cite: 85]
        try:
            await browser_context.close() # [cite: 86]
            await browser.close() # [cite: 86]
            await playwright_instance.stop() # [cite: 86]
        except Exception as e:
            logger.error(f"关闭 Playwright 时发生错误: {e}") # [cite: 86]

    logger.info(f"去重前节点数: {len(all_nodes_collected)}") # [cite: 86]
    fingerprint_to_nodes = defaultdict(list) # [cite: 86]
    for node in all_nodes_collected: # [cite: 86]
        normalized_node = normalize_node_url(node["url"]) # [cite: 87]
        fingerprint = generate_node_fingerprint(normalized_node) # [cite: 87]
        fingerprint_to_nodes[fingerprint].append(node) # [cite: 87]

    final_unique_nodes = [] # [cite: 87]
    protocol_counts = defaultdict(int) # [cite: 87]
    for fingerprint, nodes in fingerprint_to_nodes.items(): # [cite: 87]
        best_node = max(nodes, key=lambda n: score_node(n["url"], url_node_counts)) # [cite: 87]
        final_unique_nodes.append(best_node["url"]) # [cite: 87]
        protocol = best_node["url"].split('://')[0].lower() # [cite: 87]
        protocol_counts[protocol] += 1 # [cite: 87]

    final_unique_nodes = sorted(final_unique_nodes) # [cite: 87]
    logger.info(f"去重后节点数: {len(final_unique_nodes)}") # [cite: 88]
    logger.info(f"协议统计: {dict(protocol_counts)}") # [cite: 88]
    
    return final_unique_nodes, url_node_counts, failed_urls # [cite: 88]

def main():
    args = setup_argparse() # [cite: 88]
    if args.debug:
        logger.setLevel(logging.DEBUG) # [cite: 88]
        # 同样设置 handler 的级别
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    logger.info(f"命令行参数: sources={args.sources}, nodes_output={args.nodes_output}, stats_output={args.stats_output}, max_concurrency={args.max_concurrency}, timeout={args.timeout}, use_browser={args.use_browser}, debug={args.debug}") # [cite: 88]
    
    try:
        with open(args.sources, 'r', encoding='utf-8') as f: # [cite: 88]
            urls_raw = [line.strip() for line in f if line.strip() and not line.startswith('#')] # [cite: 88]
    except FileNotFoundError:
        logger.error(f"源文件 '{args.sources}' 未找到。") # [cite: 89]
        return # [cite: 89]
    
    unique_domains = set() # [cite: 89]
    for url in urls_raw: # [cite: 89]
        parsed = urllib.parse.urlparse(url) # [cite: 89]
        domain = parsed.netloc or re.match(r'^(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}(?::\d{1,5})?)(?:/.*)?$', parsed.path) # [cite: 89]
        if domain: # [cite: 89]
            unique_domains.add(domain if isinstance(domain, str) else domain.group(1).split('/')[0]) # [cite: 89]
        else:
            logger.warning(f"无法从 URL '{url}' 中识别有效域名。") # [cite: 89]

    if not unique_domains: # [cite: 90]
        logger.error("未找到有效域名，退出。") # [cite: 90]
        return # [cite: 90]

    start_time = datetime.now() # [cite: 90]
    logger.info(f"开始处理 {len(unique_domains)} 个域名...") # [cite: 90]
    
    unique_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(unique_domains, args.max_concurrency, args.timeout, args.use_browser)) # [cite: 90]
    
    logger.info(f"前10个节点样本: {unique_nodes[:10]}") # [cite: 90]
    
    total_nodes_extracted = len(unique_nodes) # [cite: 91]
    report_lines = [
        f"--- 报告 ---",
        f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒",
        f"总共提取到 {total_nodes_extracted} 个唯一节点。",
        "\n每个源 URL 的节点提取数量:"
    ] # [cite: 91]
    report_lines.append("{:<70} {:<15} {:<10}".format("源URL", "找到的节点数", "状态")) # [cite: 91]
    report_lines.append("-" * 95) # [cite: 91]
    
    for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True): # [cite: 91]
        status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点") # [cite: 91]
        report_lines.append(f"{url:<70} {count:<15} {status:<10}") # [cite: 92]
    
    if failed_urls: # [cite: 92]
        report_lines.append("\n未能成功获取或处理的源 URL:") # [cite: 92]
        report_lines.extend(sorted(list(failed_urls))) # [cite: 92]
    
    for line in report_lines: # [cite: 92]
        logger.info(line) # [cite: 92]

    output_dir = os.path.dirname(args.nodes_output) # [cite: 92]
    os.makedirs(output_dir, exist_ok=True) # [cite: 92]
    if total_nodes_extracted == 0: # [cite: 92]
        logger.error("没有提取到节点，跳过保存 nodes.txt。") # [cite: 92]
    else:
        try:
            with open(args.nodes_output, 'w', encoding='utf-8') as f: # [cite: 92]
                content = '\n'.join(unique_nodes) # [cite: 93]
                f.write(content) # [cite: 93]
            file_size_mb = os.path.getsize(args.nodes_output) / (1024 * 1024) # [cite: 93]
            logger.info(f"保存 {total_nodes_extracted} 个节点到 {args.nodes_output} ({file_size_mb:.2f} MB)") # [cite: 93]
        except Exception as e:
            logger.error(f"保存 nodes.txt 失败: {e}") # [cite: 93]

    try:
        logger.info(f"开始保存统计数据到 {args.stats_output}") # [cite: 93]
        with open(args.stats_output, 'w', newline='', encoding='utf-8') as csvfile: # [cite: 93]
            fieldnames = ['Source_URL', 'Nodes_Found', 'Status'] # [cite: 94]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames) # [cite: 94]
            writer.writeheader() # [cite: 94]
            for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True): # [cite: 94]
                status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点") # [cite: 94]
                writer.writerow({'Source_URL': url, 'Nodes_Found': count, 'Status': status}) # [cite: 94]
        file_size_mb = os.path.getsize(args.stats_output) / (1024 * 1024) # [cite: 94]
        logger.info(f"统计数据保存到 {args.stats_output} ({file_size_mb:.2f} MB)") # [cite: 95]
    except Exception as e: # [cite: 95]
        logger.error(f"保存 node_counts.csv 失败: {e}") # [cite: 95]

if __name__ == '__main__':
    main()
