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
LOG_FILE = 'data/proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_NODES_OUTPUT_FILE = 'data/all_nodes.txt' # 修改：统一输出到一个文件
DEFAULT_STATS_FILE = 'data/node_counts.csv'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20
MAX_BASE64_DECODE_DEPTH = 3
UA = UserAgent()

# 配置日志系统
os.makedirs('data', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,  # 调整日志级别为INFO
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# [cite_start]定义支持的节点协议及其正则表达式模式 [cite: 104]
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
[cite_start]COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values()) # [cite: 104]
[cite_start]BASE64_RAW_PATTERN = r'(?:b64|base64|data:application\/octet-stream;base64,)?\s*["\']?((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))["\']?\s*' # [cite: 104]
[cite_start]BASE64_REGEX_LOOSE = re.compile(BASE64_RAW_PATTERN, re.MULTILINE | re.IGNORECASE) # [cite: 104, 105]
[cite_start]JS_VAR_REGEX = re.compile(r'(?:var|let|const)\s+[\w]+\s*=\s*["\'](' + COMBINED_REGEX_PATTERN + r'|' + BASE64_RAW_PATTERN + r')["\']', re.MULTILINE | re.IGNORECASE) # [cite: 105]
[cite_start]JS_FUNC_CALL_REGEX = re.compile(r'(?:atob|decodeURIComponent)\s*\(\s*["\']?(' + BASE64_RAW_PATTERN + r')["\']?\s*\)', re.MULTILINE | re.IGNORECASE) # [cite: 105]
[cite_start]HTML_TAG_REGEX = re.compile(r'<[^>]+>', re.MULTILINE) # [cite: 105]

# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    [cite_start]parser = argparse.ArgumentParser(description='代理节点提取和去重工具') # [cite: 105]
    [cite_start]parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'包含源 URL 的输入文件路径 (默认为: {DEFAULT_SOURCES_FILE})') # [cite: 105]
    parser.add_argument('--nodes-output-file', default=DEFAULT_NODES_OUTPUT_FILE, help=f'所有节点输出文件路径 (默认为: {DEFAULT_NODES_OUTPUT_FILE})') # 修改：统一输出到一个文件
    [cite_start]parser.add_argument('--stats-output', default=DEFAULT_STATS_FILE, help=f'节点统计数据输出文件路径 (默认为: {DEFAULT_STATS_FILE})') # [cite: 105]
    [cite_start]parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认为: {DEFAULT_MAX_CONCURRENCY})') # [cite: 105]
    [cite_start]parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认为: {DEFAULT_TIMEOUT})') # [cite: 105]
    [cite_start]parser.add_argument('--use-browser', action='store_true', help='当HTTP请求失败时，尝试使用无头浏览器（Playwright）') # [cite: 105]
    [cite_start]return parser.parse_args() # [cite: 106]

def decode_base64(data: str) -> str:
    try:
        [cite_start]cleaned_data = re.sub(r'[^A-Za-z0-9+/=]', '', data) # [cite: 106]
        [cite_start]cleaned_data = cleaned_data.replace('-', '+').replace('_', '/') # [cite: 106]
        [cite_start]padding = len(cleaned_data) % 4 # [cite: 106]
        if padding:
            [cite_start]cleaned_data += '=' * (4 - padding) # [cite: 106]
        [cite_start]return base64.b64decode(cleaned_data).decode('utf-8', errors='ignore') # [cite: 106]
    except Exception as e:
        [cite_start]logger.debug(f"Base64 解码错误（原始内容片段: {data[:min(50, len(data))]}...）: {e}") # [cite: 106, 107]
        return ""

def encode_base64(data: str) -> str:
    try:
        [cite_start]encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8')) # [cite: 107]
        [cite_start]return encoded_bytes.decode('utf-8').rstrip('=') # [cite: 107]
    except Exception as e:
        [cite_start]logger.warning(f"Base64 编码失败: {data[:50]}... 错误: {e}") # [cite: 107]
        return data

def score_node(url: str) -> int:
    [cite_start]"""评估节点质量，返回得分（越高越好）""" # [cite: 107]
    try:
        [cite_start]protocol, _, rest = url.partition('://') # [cite: 107]
        [cite_start]protocol_lower = protocol.lower() # [cite: 108]
 
        [cite_start]score = 0 # [cite: 108]

        if protocol_lower == 'vmess':
            [cite_start]config_json = decode_base64(rest) # [cite: 108]
            if not config_json:
                return 0
            try:
                [cite_start]config = json.loads(config_json) # [cite: 109]
                if config.get('tls') == 'tls':
                    [cite_start]score += 5  # 启用 TLS 优先 # [cite: 109]
                [cite_start]score += len(config)  # 更多字段得分更高 # [cite: 109]
                if config.get('ps'):
                    [cite_start]score -= len(config['ps']) // 10  # 备注越短越好 # [cite: 110]
            except json.JSONDecodeError:
                return 0
        elif protocol_lower in ['ss', 'trojan', 'vless', 'hysteria2', 'hy2', 'tuic', 'snell']:
            [cite_start]parsed = urllib.parse.urlparse(url) # [cite: 110]
            [cite_start]query_params = urllib.parse.parse_qs(parsed.query) # [cite: 110]
            if 'security' in query_params and query_params['security'][0] == 'tls':
                [cite_start]score += 5  # 启用 TLS 优先 # [cite: 111]
            [cite_start]score += len(query_params)  # 更多参数得分更高 # [cite: 111]
            if parsed.fragment:
                [cite_start]score -= len(parsed.fragment) // 10  # 备注越短越好 # [cite: 111]
        elif protocol_lower == 'ssr':
            [cite_start]decoded_ssr = decode_base64(rest) # [cite: 112]
            if not decoded_ssr:
                return 0
            if 'tls' in decoded_ssr.lower():
                [cite_start]score += 5 # [cite: 112]
            [cite_start]score += decoded_ssr.count('&')  # 更多参数得分更高 # [cite: 112]
            if '#' in decoded_ssr:
                [cite_start]remark = decoded_ssr.split('#')[-1] # [cite: 113]
                [cite_start]score -= len(decode_base64(remark)) // 10 # [cite: 113]
        [cite_start]return max(score, 0) # [cite: 113]
    except Exception:
        [cite_start]return 0 # [cite: 113]

def generate_node_fingerprint(url: str) -> str:
    [cite_start]"""生成节点唯一指纹，仅基于核心字段，用于去重""" # [cite: 113]
    try:
        [cite_start]protocol, _, rest = url.partition('://') # [cite: 114]
        [cite_start]protocol_lower = protocol.lower() # [cite: 114]
        if protocol_lower not in NODE_PATTERNS:
            [cite_start]return url # [cite: 114]

        if protocol_lower == 'vmess':
            [cite_start]config_json = decode_base64(rest) # [cite: 114]
            if not config_json:
                [cite_start]return url # [cite: 115]
            try:
                [cite_start]config = json.loads(config_json) # [cite: 115]
                core_fields = (
                    [cite_start]config.get('add', ''), # [cite: 115]
                    [cite_start]str(config.get('port', 0)), # [cite: 116]
                    [cite_start]config.get('id', ''), # [cite: 116]
                    [cite_start]config.get('type', 'auto') # [cite: 116]
                )
                [cite_start]return f"vmess://{':'.join(str(x) for x in core_fields)}" # [cite: 116]
            except json.JSONDecodeError:
                [cite_start]return url # [cite: 116]

        elif protocol_lower == 'ssr':
            [cite_start]decoded_ssr = decode_base64(rest) # [cite: 117]
            if not decoded_ssr:
                [cite_start]return url # [cite: 117]
            [cite_start]core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr) # [cite: 117]
            if not core_part_match:
                [cite_start]return url # [cite: 117]
            [cite_start]core_part = core_part_match.group(1) # [cite: 118]
            [cite_start]parts = core_part.split(':') # [cite: 118]
            if len(parts) < 6:
                [cite_start]return url # [cite: 118]
            [cite_start]host, port, _, method, _, password_b64 = parts[:6] # [cite: 118]
            [cite_start]password = decode_base64(password_b64.split('/')[0].split('?')[0].split('#')[0]) # [cite: 118]
            [cite_start]return f"ssr://{host}:{port}:{method}:{password}" # [cite: 119]

        elif protocol_lower in ['ss', 'trojan', 'vless', 'hysteria2', 'hy2', 'tuic', 'snell']:
            [cite_start]parsed = urllib.parse.urlparse(url) # [cite: 119]
            [cite_start]host_port = parsed.netloc.lower() # [cite: 119]
            [cite_start]auth = parsed.username or '' # [cite: 119]
            if protocol_lower in ['ss', 'trojan']:
                [cite_start]auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username # [cite: 119]
            elif protocol_lower == 'vless':
                [cite_start]auth = parsed.username # [cite: 120]
                [cite_start]query_params = urllib.parse.parse_qs(parsed.query) # [cite: 120]
                [cite_start]flow = query_params.get('flow', [''])[0] # [cite: 120]
                [cite_start]auth = f"{auth}:{flow}" if flow else auth # [cite: 120]
            elif protocol_lower == 'tuic':
                [cite_start]auth = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username # [cite: 121]
            elif protocol_lower == 'snell':
                [cite_start]auth = parsed.username or '' # [cite: 121]
            [cite_start]return f"{protocol_lower}://{auth}@{host_port}" # [cite: 121]
        
        [cite_start]return url # [cite: 122]
    except Exception as e:
        [cite_start]logger.debug(f"生成指纹失败: {url[:50]}... 错误: {e}") # [cite: 122]
        return url

def normalize_node_url(url: str) -> str:
    [cite_start]"""规范化节点 URL，移除非必要字段，限制备注长度""" # [cite: 122]
    try:
        [cite_start]protocol, _, rest = url.partition('://') # [cite: 122]
        if not protocol or protocol.lower() not in NODE_PATTERNS:
            [cite_start]logger.debug(f"无法识别协议或不支持的协议: {url}") # [cite: 122]
            return url

        [cite_start]parsed_url = urllib.parse.urlparse(url) # [cite: 123]
        [cite_start]protocol_lower = protocol.lower() # [cite: 123]

        if protocol_lower == 'vmess':
            [cite_start]config_json = decode_base64(rest) # [cite: 123]
            if not config_json:
                [cite_start]logger.debug(f"VMess 配置Base64解码失败: {url}") # [cite: 123]
                return url
            try:
                [cite_start]config = json.loads(config_json) # [cite: 124]
            except json.JSONDecodeError as e:
                [cite_start]logger.debug(f"VMess 配置 JSON 解析失败: {e} for {config_json[:50]}...") # [cite: 124]
                return url

            [cite_start]core_keys = ['add', 'port', 'id', 'type'] # [cite: 124]
            [cite_start]optional_keys = ['net', 'tls'] # [cite: 125]
            [cite_start]clean_config = {} # [cite: 125]
            [cite_start]for k in core_keys + optional_keys: # [cite: 125]
                if k in config and config[k] is not None:
                    if k == 'port':
                        try:
                            [cite_start]clean_config[k] = int(config[k]) # [cite: 126]
                        except (ValueError, TypeError):
                            [cite_start]clean_config[k] = 0 # [cite: 126]
                            [cite_start]logger.debug(f"VMess 字段 'port' 类型转换失败: {config[k]}") # [cite: 126]
                    else:
                        [cite_start]clean_config[k] = str(config[k]) # [cite: 127]
            [cite_start]clean_config['ps'] = urllib.parse.unquote(config.get('ps', ''))[:20] or 'node' # [cite: 127]
            [cite_start]return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}" # [cite: 127]
        
        elif protocol_lower == 'ssr':
            [cite_start]decoded_ssr = decode_base64(rest) # [cite: 128]
            if not decoded_ssr:
                [cite_start]logger.debug(f"SSR Base64解码失败: {url}") # [cite: 128]
                return url
            [cite_start]core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr) # [cite: 128]
            if not core_part_match:
                [cite_start]raise ValueError("SSR 链接核心部分解析失败") # [cite: 129]
            [cite_start]core_part = core_part_match.group(1) # [cite: 129]
            [cite_start]parts = core_part.split(':') # [cite: 129]
            if len(parts) < 6:
                [cite_start]raise ValueError(f"SSR 核心部分参数不足，预期6个，实际{len(parts)}") # [cite: 129]
            [cite_start]host, port, protocol_name, method, obfs_name, password_b64 = parts[:6] # [cite: 129]
            [cite_start]password = decode_base64(password_b64.split('/')[0].split('?')[0].split('#')[0]) # [cite: 129]
            [cite_start]normalized_core = f"{host}:{port}:{protocol_name}:{method}:{obfs_name}:{password_b64}" # [cite: 130]
            [cite_start]fragment = decode_base64(core_part_match.group(2).split('#')[-1])[:20] if '#' in core_part_match.group(2) else 'node' # [cite: 130]
            [cite_start]normalized_core += f"#{encode_base64(fragment)}" # [cite: 130]
            [cite_start]return f"ssr://{encode_base64(normalized_core)}" # [cite: 131]
        
        else:
            [cite_start]auth_part = '' # [cite: 131]
            if parsed_url.username or parsed_url.password:
                [cite_start]auth_user = parsed_url.username if parsed_url.username else '' # [cite: 131]
                [cite_start]auth_pass = parsed_url.password if parsed_url.password else '' # [cite: 131]
                [cite_start]auth_part = f"{urllib.parse.quote(auth_user, safe='')}:{urllib.parse.quote(auth_pass, safe='')}@" # [cite: 131]
            [cite_start]host_port = parsed_url.netloc.lower() # [cite: 132]
            if '@' in host_port:
                [cite_start]host_port = host_port.split('@', 1)[-1] # [cite: 132]
            [cite_start]query_params = urllib.parse.parse_qs(parsed_url.query) # [cite: 132]
            [cite_start]essential_params = {} # [cite: 132]
            if protocol_lower == 'vless' and 'flow' in query_params:
                [cite_start]essential_params['flow'] = query_params['flow'][0][:20] # [cite: 132]
            [cite_start]query_string = urllib.parse.urlencode(essential_params, quote_via=urllib.parse.quote) if essential_params else '' # [cite: 133]
            [cite_start]fragment = urllib.parse.unquote(parsed_url.fragment)[:20] or 'node' # [cite: 133]
            return f"{protocol_lower}://{auth_part}{host_port}{'?' + [cite_start]query_string if query_string else ''}#{urllib.parse.quote(fragment)}" # [cite: 134]
    except Exception as e:
        [cite_start]logger.debug(f"规范化 URL '{url}' 失败: {e}") # [cite: 134]
        return url

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    [cite_start]"""将 Clash 配置转换为标准 URL，简化次要字段""" # [cite: 134]
    [cite_start]proxy_type = proxy.get('type', '').lower() # [cite: 134]
    [cite_start]name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', 'node')[:20]), safe='') # [cite: 134]
    [cite_start]server = proxy.get('server') # [cite: 135]
    [cite_start]port = proxy.get('port') # [cite: 135]
    
    if not all([server, port, proxy_type]):
        [cite_start]logger.debug(f"Clash 代理 {name} 缺少核心信息，跳过: {proxy}") # [cite: 135]
        [cite_start]return None # [cite: 135]

    if proxy_type == 'ss':
        [cite_start]cipher = proxy.get('cipher') # [cite: 135]
        [cite_start]password = proxy.get('password') # [cite: 135]
        if not all([cipher, password]):
            [cite_start]logger.debug(f"SS 代理 {name} 缺少加密方法或密码: {proxy}") # [cite: 135]
            return None
        [cite_start]auth = encode_base64(f"{cipher}:{password}") # [cite: 136]
        [cite_start]return f"ss://{auth}@{server}:{port}#{name}" # [cite: 136]

    elif proxy_type == 'vmess':
        [cite_start]uuid_val = proxy.get('uuid') # [cite: 136]
        [cite_start]network = proxy.get('network', 'tcp') # [cite: 136]
        [cite_start]tls_enabled = proxy.get('tls', False) # [cite: 136]
        if not uuid_val:
            [cite_start]logger.debug(f"VMess 代理 {name} 缺少 UUID: {proxy}") # [cite: 136]
            return None
        config = {
            [cite_start]"add": server, # [cite: 137]
            [cite_start]"port": int(port), # [cite: 137]
            [cite_start]"id": uuid_val, # [cite: 137]
            [cite_start]"type": proxy.get('cipher', 'auto'), # [cite: 137]
            [cite_start]"net": network, # [cite: 137]
            [cite_start]"ps": urllib.parse.unquote(name) # [cite: 137]
        }
        if tls_enabled:
            [cite_start]config["tls"] = "tls" # [cite: 138]
        try:
            [cite_start]return f"vmess://{encode_base64(json.dumps(config, ensure_ascii=False, sort_keys=True))}" # [cite: 138]
        except Exception as e:
            [cite_start]logger.debug(f"VMess 配置 JSON 编码失败，节点：{name}。错误：{e}") # [cite: 138]
            return None

    elif proxy_type == 'trojan':
        [cite_start]password = proxy.get('password') # [cite: 138]
        if not password:
            [cite_start]logger.debug(f"Trojan 代理 {name} 缺少密码: {proxy}") # [cite: 139]
            [cite_start]return None # [cite: 139]
        [cite_start]return f"trojan://{password}@{server}:{port}#{name}" # [cite: 139]

    elif proxy_type == 'vless':
        [cite_start]uuid_val = proxy.get('uuid') # [cite: 139]
        if not uuid_val:
            [cite_start]logger.debug(f"VLESS 代理 {name} 缺少 UUID: {proxy}") # [cite: 139]
            return None
        [cite_start]params = {} # [cite: 140]
        if proxy.get('flow'):
            [cite_start]params['flow'] = proxy['flow'][:20] # [cite: 140]
        [cite_start]query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote) # [cite: 140]
        return f"vless://{uuid_val}@{server}:{port}{'?' + [cite_start]query_string if query_string else ''}#{name}" # [cite: 141]

    elif proxy_type in ['hysteria2', 'hy2']:
        [cite_start]password = proxy.get('password', '') # [cite: 141]
        if not (password and server and port):
            [cite_start]logger.debug(f"Hysteria2 代理 {name} 缺少密码、服务器或端口: {proxy}") # [cite: 141]
            return None
        [cite_start]return f"hysteria2://{password}@{server}:{port}#{name}" # [cite: 142]
    
    elif proxy_type == 'tuic':
        [cite_start]uuid_val = proxy.get('uuid') # [cite: 142]
        [cite_start]password = proxy.get('password') # [cite: 142]
        if not all([uuid_val, password, server, port]):
            [cite_start]logger.debug(f"TUIC 代理 {name} 缺少 UUID、密码、服务器或端口: {proxy}") # [cite: 142]
            return None
        [cite_start]return f"tuic://{uuid_val}:{password}@{server}:{port}#{name}" # [cite: 142]

    elif proxy_type == 'ssr':
        [cite_start]password = proxy.get('password', '') # [cite: 142]
        [cite_start]cipher = proxy.get('cipher', 'auto') # [cite: 143]
        [cite_start]protocol = proxy.get('protocol', 'origin') # [cite: 143]
        [cite_start]obfs = proxy.get('obfs', 'plain') # [cite: 143]
        [cite_start]password_b64 = encode_base64(password) # [cite: 143]
        [cite_start]ssr_core = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{password_b64}" # [cite: 143]
        [cite_start]return f"ssr://{encode_base64(ssr_core)}#{encode_base64(urllib.parse.unquote(name))}" # [cite: 143]

    elif proxy_type == 'snell':
        [cite_start]psk = proxy.get('psk', '') # [cite: 144]
        if not all([psk, server, port]):
            [cite_start]logger.debug(f"Snell 代理 {name} 缺少 PSK、服务器或端口: {proxy}") # [cite: 144]
            return None
        [cite_start]return f"snell://{urllib.parse.quote(psk, safe='')}@{server}:{port}#{name}" # [cite: 144]
    
    [cite_start]logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}") # [cite: 144]
    return None

def extract_nodes(content: str, decode_depth: int = 0) -> List[str]:
    [cite_start]nodes_found = set() # [cite: 145]
    
    if not content or decode_depth > MAX_BASE64_DECODE_DEPTH:
        [cite_start]return [] # [cite: 145]

    [cite_start]content = content.replace('\r\n', '\n').replace('\r', '\n') # [cite: 145]

    def strip_html_tags(text: str) -> str:
        try:
            [cite_start]soup = BeautifulSoup(text, 'html.parser') # [cite: 146]
            # 移除所有脚本和样式标签
            for script_or_style in soup(["script", "style"]):
                script_or_style.extract()
            # 获取文本并清理
            cleaned = soup.get_text(separator=' ', strip=True) # 修改：使用空格作为分隔符，更自然
            return cleaned
        except Exception as e:
            [cite_start]logger.debug(f"HTML 标签清理失败: {text[:50]}... 错误: {e}") # [cite: 146]
            [cite_start]return HTML_TAG_REGEX.sub('', text) # [cite: 146]

    # 优先从原始内容中提取已知协议节点
    [cite_start]for pattern_key, pattern_val in NODE_PATTERNS.items(): # [cite: 146]
        [cite_start]matches = re.findall(pattern_val, content, re.MULTILINE | re.IGNORECASE) # [cite: 147]
        for node in matches:
            [cite_start]cleaned_node = strip_html_tags(node) # [cite: 147]
            [cite_start]nodes_found.add(normalize_node_url(cleaned_node)) # [cite: 147]

    # 解析 HTML 内容
    try:
        [cite_start]soup = BeautifulSoup(content, 'html.parser') # [cite: 147]
        # 提取 <pre> 标签中的内容
        for pre_tag in soup.find_all('pre'):
            pre_text = pre_tag.get_text(separator='\n', strip=True)
            nodes_found.update(extract_nodes(pre_text, decode_depth + 1)) # 递归处理 <pre> 标签内容

        # 提取 <textarea> 标签中的内容
        for textarea_tag in soup.find_all('textarea'):
            textarea_text = textarea_tag.get_text(separator='\n', strip=True)
            nodes_found.update(extract_nodes(textarea_text, decode_depth + 1)) # 递归处理 <textarea> 标签内容

        # 提取 data-* 属性中的内容
        [cite_start]for tag in soup.find_all(True): # [cite: 148]
            for attr in ['href', 'src', 'data-url', 'data-node', 'data-config', 'data-link', 'data-href', 'content', 'data-clipboard-text', 'value']: # 增加更多常见属性
                if attr in tag.attrs and tag.attrs[attr]:
                    [cite_start]link_val = tag.attrs[attr].strip() # [cite: 148]
                    [cite_start]cleaned_link = strip_html_tags(link_val) # [cite: 148]
                    # 尝试解码 Base64
                    [cite_start]b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_link) # [cite: 148]
                    if b64_match:
                        [cite_start]decoded_attr = decode_base64(b64_match.group(1)) # [cite: 149]
                        if decoded_attr:
                            [cite_start]nodes_found.update(extract_nodes(decoded_attr, decode_depth + 1)) # [cite: 149]
                    # 直接匹配协议链接
                    if re.match(COMBINED_REGEX_PATTERN, cleaned_link, re.IGNORECASE):
                        [cite_start]nodes_found.add(normalize_node_url(cleaned_link)) # [cite: 150]
        
        # [cite_start]提取 HTML 注释中的内容 [cite: 150]
        [cite_start]for comment in soup.find_all(string=lambda text: isinstance(text, Comment)): # [cite: 150]
            [cite_start]comment_text = str(comment).strip() # [cite: 151]
            [cite_start]cleaned_comment = strip_html_tags(comment_text) # [cite: 151]
            [cite_start]if re.search(COMBINED_REGEX_PATTERN, cleaned_comment, re.MULTILINE | re.IGNORECASE): # [cite: 151]
                [cite_start]for pattern_val in NODE_PATTERNS.values(): # [cite: 151]
                    [cite_start]matches = re.findall(pattern_val, cleaned_comment, re.MULTILINE | re.IGNORECASE) # [cite: 152]
                    for node in matches:
                        [cite_start]cleaned_node = strip_html_tags(node) # [cite: 152]
                        [cite_start]nodes_found.add(normalize_node_url(cleaned_node)) # [cite: 152]
            [cite_start]base64_matches = BASE64_REGEX_LOOSE.findall(cleaned_comment) # [cite: 152]
            for b64_match_tuple in base64_matches:
                [cite_start]b64_str = b64_match_tuple[0] # [cite: 153]
                [cite_start]decoded_comment_content = decode_base64(b64_str) # [cite: 153]
                if decoded_comment_content:
                    [cite_start]nodes_found.update(extract_nodes(decoded_comment_content, decode_depth + 1)) # [cite: 153]
    except Exception as e:
        [cite_start]logger.debug(f"HTML 解析失败: {e}") # [cite: 153]

    # [cite_start]从 JavaScript 变量和函数调用中提取 [cite: 153]
    [cite_start]js_variable_matches = JS_VAR_REGEX.findall(content) # [cite: 154]
    for match_group in js_variable_matches:
        [cite_start]js_val = match_group if isinstance(match_group, str) else match_group[0] # [cite: 154]
        [cite_start]cleaned_js_val = strip_html_tags(js_val) # [cite: 154]
        if re.match(COMBINED_REGEX_PATTERN, cleaned_js_val, re.IGNORECASE):
            [cite_start]nodes_found.add(normalize_node_url(cleaned_js_val)) # [cite: 154]
        elif BASE64_REGEX_LOOSE.fullmatch(cleaned_js_val):
            [cite_start]decoded_js_var = decode_base64(cleaned_js_val) # [cite: 154]
            if decoded_js_var:
                [cite_start]nodes_found.update(extract_nodes(decoded_js_var, decode_depth + 1)) # [cite: 154]
    
    [cite_start]js_func_call_matches = JS_FUNC_CALL_REGEX.findall(content) # [cite: 155]
    for match_group in js_func_call_matches:
        [cite_start]b64_str_in_func = match_group if isinstance(match_group, str) else match_group[0] # [cite: 155]
        [cite_start]cleaned_b64_str = strip_html_tags(b64_str_in_func) # [cite: 155]
        [cite_start]decoded_func_param = decode_base64(cleaned_b64_str) # [cite: 155]
        if decoded_func_param:
            [cite_start]nodes_found.update(extract_nodes(decoded_func_param, decode_depth + 1)) # [cite: 155]

    # [cite_start]解析 YAML 内容 [cite: 155]
    try:
        [cite_start]yaml_content = yaml.safe_load(content) # [cite: 155]
        [cite_start]if isinstance(yaml_content, dict) and 'proxies' in yaml_content: # [cite: 155]
            [cite_start]for proxy_dict in yaml_content['proxies']: # [cite: 156]
                [cite_start]url_node = convert_clash_proxy_to_url(proxy_dict) # [cite: 156]
                if url_node:
                    [cite_start]if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 156]
                        [cite_start]nodes_found.add(normalize_node_url(url_node)) # [cite: 156]
        [cite_start]elif isinstance(yaml_content, list): # [cite: 156]
            for item in yaml_content:
                [cite_start]if isinstance(item, dict) and 'type' in item: # [cite: 157]
                    [cite_start]url_node = convert_clash_proxy_to_url(item) # [cite: 157]
                    if url_node:
                        [cite_start]if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 158]
                            [cite_start]nodes_found.add(normalize_node_url(url_node)) # [cite: 158]
        [cite_start]if isinstance(yaml_content, (dict, list)): # [cite: 158]
            [cite_start]iterable_content = yaml_content.values() if isinstance(yaml_content, dict) else yaml_content # [cite: 158]
            for value in iterable_content:
                if isinstance(value, str):
                    [cite_start]cleaned_value = strip_html_tags(value) # [cite: 159]
                    [cite_start]b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_value) # [cite: 159]
                    if b64_match:
                        [cite_start]decoded_sub_content = decode_base64(b64_match.group(1)) # [cite: 159]
                        if decoded_sub_content:
                            [cite_start]nodes_found.update(extract_nodes(decoded_sub_content, decode_depth + 1)) # [cite: 160]
    except yaml.YAMLError as e:
        [cite_start]logger.debug(f"YAML 解析失败: {e}") # [cite: 160]

    # [cite_start]解析 JSON 内容 [cite: 160]
    try:
        [cite_start]json_content = json.loads(content) # [cite: 160]
        [cite_start]if isinstance(json_content, list): # [cite: 160]
            [cite_start]for config_dict in json_content: # [cite: 161]
                [cite_start]if isinstance(config_dict, dict) and 'id' in config_dict: # [cite: 161]
                    clash_vmess_proxy = {
                        [cite_start]"type": "vmess", # [cite: 161]
                        [cite_start]"name": config_dict.get('ps', 'node')[:20], # [cite: 161]
                        [cite_start]"server": config_dict.get('add'), # [cite: 162]
                        [cite_start]"port": config_dict.get('port'), # [cite: 162]
                        [cite_start]"uuid": config_dict.get('id'), # [cite: 162]
                        [cite_start]"cipher": config_dict.get('type', 'auto'), # [cite: 162]
                        [cite_start]"network": config_dict.get('net', 'tcp'), # [cite: 163]
                        [cite_start]"tls": config_dict.get('tls') == 'tls', # [cite: 163]
                    }
                    [cite_start]url_node = convert_clash_proxy_to_url(clash_vmess_proxy) # [cite: 163]
                    if url_node:
                        [cite_start]if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 164]
                            [cite_start]nodes_found.add(normalize_node_url(url_node)) # [cite: 164]
                [cite_start]elif isinstance(config_dict, dict) and 'protocol' in config_dict and 'settings' in config_dict: # [cite: 164]
                    [cite_start]protocol_type = config_dict['protocol'].lower() # [cite: 165]
                    [cite_start]if protocol_type in [p for p in NODE_PATTERNS.keys()]: # [cite: 165]
                        [cite_start]outbound_settings = config_dict['settings'].get('vnext', [{}])[0] if protocol_type in ['vmess', 'vless'] else config_dict['settings'] # [cite: 165]
                        [cite_start]users = outbound_settings.get('users', [{}]) # [cite: 166]
                        [cite_start]for user_config in users: # [cite: 166]
                            proxy_cfg = {
                                [cite_start]"type": protocol_type, # [cite: 166]
                                [cite_start]"name": user_config.get('id', user_config.get('email', 'node'))[:20], # [cite: 167]
                                [cite_start]"server": outbound_settings.get('address') or user_config.get('address'), # [cite: 167]
                                [cite_start]"port": outbound_settings.get('port') or user_config.get('port'), # [cite: 167]
                            }
                            if protocol_type == 'vmess':
                                [cite_start]proxy_cfg.update({"uuid": user_config.get('id'), "cipher": user_config.get('security', 'auto')}) # [cite: 168]
                            elif protocol_type == 'vless':
                                [cite_start]proxy_cfg.update({"uuid": user_config.get('id'), "flow": user_config.get('flow')}) # [cite: 169]
                            elif protocol_type == 'trojan':
                                [cite_start]proxy_cfg.update({"password": user_config.get('password')}) # [cite: 170]
                            [cite_start]url_node = convert_clash_proxy_to_url(proxy_cfg) # [cite: 170]
                            if url_node:
                                [cite_start]if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 171]
                                    [cite_start]nodes_found.add(normalize_node_url(url_node)) # [cite: 171]
        [cite_start]elif isinstance(json_content, dict) and 'proxies' in json_content: # [cite: 171]
            [cite_start]for proxy_dict in json_content['proxies']: # [cite: 172]
                [cite_start]url_node = convert_clash_proxy_to_url(proxy_dict) # [cite: 172]
                if url_node:
                    [cite_start]if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()): # [cite: 172]
                        [cite_start]nodes_found.add(normalize_node_url(url_node)) # [cite: 172]
    except json.JSONDecodeError as e:
        [cite_start]logger.debug(f"JSON 解析失败: {e}") # [cite: 172]

    # [cite_start]递归解码 Base64 内容 [cite: 173]
    [cite_start]if decode_depth < MAX_BASE64_DECODE_DEPTH: # [cite: 173]
        [cite_start]base64_candidates = BASE64_REGEX_LOOSE.findall(content) # [cite: 173]
        for b64_candidate_tuple in base64_candidates:
            [cite_start]b64_str = b64_candidate_tuple[0] # [cite: 173]
            if len(b64_str) < 50: # 避免解码过短的非节点数据
                continue
            [cite_start]decoded_content_full = decode_base64(b64_str) # [cite: 173]
            if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != content: # 避免无限递归或重复处理
                [cite_start]nodes_found.update(extract_nodes(decoded_content_full, decode_depth + 1)) # [cite: 174]

    final_filtered_nodes = [
        node for node in nodes_found 
        if any(re.match(pattern, node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()) 
        and len(node) > 20
    [cite_start]] # [cite: 174]
    [cite_start]return sorted(list(final_filtered_nodes)) # [cite: 174]

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3) -> str:
    [cite_start]headers = {'User-Agent': UA.random, 'Referer': url} # [cite: 175]
    for attempt in range(retries):
        try:
            [cite_start]logger.debug(f"尝试获取 URL ({attempt + 1}/{retries}): {url}") # [cite: 175]
            [cite_start]async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response: # [cite: 175]
                [cite_start]response.raise_for_status() # [cite: 175]
                [cite_start]return await response.text() # [cite: 175]
        except Exception as e:
            [cite_start]logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: {e}") # [cite: 176]
            if attempt < retries - 1:
                [cite_start]await asyncio.sleep(1.0 * (2 ** attempt)) # [cite: 176]
    [cite_start]logger.warning(f"在 {retries} 次尝试后未能成功获取 URL: {url}") # [cite: 176]
    return ""

async def fetch_with_browser(browser_context: BrowserContext, url: str, timeout: int) -> str:
    [cite_start]page: Page = await browser_context.new_page() # [cite: 177]
    [cite_start]page.set_default_timeout(timeout * 1000) # [cite: 177]
    try:
        [cite_start]logger.info(f"尝试使用浏览器获取 URL: {url}") # [cite: 177]
        [cite_start]await page.goto(url, wait_until="networkidle") # [cite: 177]
        [cite_start]return await page.content() # [cite: 177]
    except Exception as e:
        [cite_start]logger.warning(f"使用浏览器获取 URL {url} 失败: {e}") # [cite: 177]
        return ""
    finally:
        [cite_start]await page.close() # [cite: 177]

async def process_single_url_strategy(session: aiohttp.ClientSession, url: str, timeout: int, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> Set[str]:
    [cite_start]content = await fetch_with_retry(session, url, timeout) # [cite: 178]
    if not content and use_browser and browser_context:
        [cite_start]content = await fetch_with_browser(browser_context, url, timeout) # [cite: 178]
    [cite_start]nodes = set(extract_nodes(content)) if content else set() # [cite: 178]
    [cite_start]logger.debug(f"URL {url} 提取到 {len(nodes)} 个节点") # [cite: 178]
    return nodes

async def process_domain(session: aiohttp.ClientSession, domain: str, timeout: int, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> Tuple[str, Set[str]]:
    [cite_start]nodes_from_domain = set() # [cite: 178]
    [cite_start]http_url = f"http://{domain}" # [cite: 179]
    [cite_start]https_url = f"https://{domain}" # [cite: 179]
    
    [cite_start]async with semaphore: # [cite: 179]
        [cite_start]logger.info(f"正在获取: {http_url}") # [cite: 179]
        [cite_start]http_nodes = await process_single_url_strategy(session, http_url, timeout, use_browser, browser_context) # [cite: 179]
        if http_nodes:
            [cite_start]nodes_from_domain.update(http_nodes) # [cite: 179]
            [cite_start]url_node_counts[http_url] = len(http_nodes) # [cite: 179]
        else:
            [cite_start]url_node_counts[http_url] = 0 # [cite: 180]
            [cite_start]logger.info(f"HTTP 失败或无节点，尝试获取: {https_url}") # [cite: 180]
            [cite_start]https_nodes = await process_single_url_strategy(session, https_url, timeout, use_browser, browser_context) # [cite: 180]
            if https_nodes:
                [cite_start]nodes_from_domain.update(https_nodes) # [cite: 180]
                [cite_start]url_node_counts[https_url] = len(https_nodes) # [cite: 180]
            else:
                [cite_start]url_node_counts[https_url] = 0 # [cite: 180]
                [cite_start]failed_urls.add(http_url) # [cite: 181]
                [cite_start]failed_urls.add(https_url) # [cite: 181]
    
    return domain, nodes_from_domain

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int, use_browser: bool) -> Tuple[Dict[str, Set[str]], Dict, Set]:
    [cite_start]semaphore = asyncio.Semaphore(max_concurrency) # [cite: 181]
    [cite_start]url_node_counts = defaultdict(int) # [cite: 181]
    [cite_start]failed_urls = set() # [cite: 181]
    [cite_start]url_to_nodes = {} # [cite: 181]
    
    browser_context: Optional[BrowserContext] = None
    browser = None # 添加浏览器实例变量
    playwright_instance = None # 添加 playwright 实例变量
    if use_browser:
        [cite_start]logger.info("初始化无头浏览器...") # [cite: 181]
        try:
            [cite_start]playwright_instance = await async_playwright().start() # [cite: 182]
            [cite_start]browser = await playwright_instance.chromium.launch() # [cite: 182]
            [cite_start]browser_context = await browser.new_context(user_agent=UA.random, ignore_https_errors=True) # [cite: 182]
        except Exception as e:
            [cite_start]logger.error(f"初始化 Playwright 失败: {e}. 将不使用浏览器模式。") # [cite: 183]
            use_browser = False

    async with aiohttp.ClientSession() as session:
        [cite_start]tasks = [process_domain(session, domain, timeout, semaphore, url_node_counts, failed_urls, use_browser, browser_context) for domain in domains] # [cite: 183]
        [cite_start]results = await asyncio.gather(*tasks, return_exceptions=True) # [cite: 183]
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                [cite_start]domain, nodes = result # [cite: 184]
                [cite_start]url_to_nodes[domain] = nodes # [cite: 184]
            elif isinstance(result, Exception):
                [cite_start]logger.error(f"处理域名时发生异常: {result}") # [cite: 184]

    if browser_context:
        try:
            [cite_start]await browser_context.close() # [cite: 185]
            if browser: # 确保浏览器实例存在
                [cite_start]await browser.close() # [cite: 185]
            if playwright_instance: # 确保 playwright 实例存在
                [cite_start]await playwright_instance.stop() # [cite: 185]
        except Exception as e:
            [cite_start]logger.error(f"关闭 Playwright 时发生错误: {e}") # [cite: 185]

    # [cite_start]增强去重逻辑：基于指纹和得分 [cite: 185]
    [cite_start]all_nodes_collected = set() # [cite: 185]
    [cite_start]protocol_counts = defaultdict(int) # [cite: 186]
    [cite_start]for domain, nodes in url_to_nodes.items(): # [cite: 186]
        [cite_start]fingerprint_to_node = {} # [cite: 186]
        for node in nodes:
            [cite_start]normalized_node = normalize_node_url(node) # [cite: 186]
            [cite_start]fingerprint = generate_node_fingerprint(normalized_node) # [cite: 186]
            [cite_start]protocol = normalized_node.split('://')[0].lower() # [cite: 186]
            [cite_start]protocol_counts[protocol] += 1 # [cite: 186]
            [cite_start]current_score = score_node(normalized_node) # [cite: 186]
            [cite_start]if fingerprint not in fingerprint_to_node or current_score > score_node(fingerprint_to_node[fingerprint]): # [cite: 187]
                [cite_start]fingerprint_to_node[fingerprint] = normalized_node # [cite: 187]
        [cite_start]url_to_nodes[domain] = sorted(list(fingerprint_to_node.values())) # [cite: 187]
        [cite_start]all_nodes_collected.update(url_to_nodes[domain]) # [cite: 187]

    logger.info(f"去重前节点数: {sum(len(nodes) for nodes in url_to_nodes.values())}, 去重后节点数: {len(all_nodes_collected)}") # 修改日志信息
    [cite_start]logger.info(f"协议统计: {dict(protocol_counts)}") # [cite: 187]
    
    return url_to_nodes, url_node_counts, failed_urls

def main():
    [cite_start]args = setup_argparse() # [cite: 187]
    logger.info(f"命令行参数: sources={args.sources}, nodes_output_file={args.nodes_output_file}, stats_output={args.stats_output}, max_concurrency={args.max_concurrency}, timeout={args.timeout}, use_browser={args.use_browser}") # 修改日志信息
    
    try:
        [cite_start]with open(args.sources, 'r', encoding='utf-8') as f: # [cite: 188]
            [cite_start]urls_raw = [line.strip() for line in f if line.strip() and not line.startswith('#')] # [cite: 188]
    except FileNotFoundError:
        [cite_start]logger.error(f"源文件 '{args.sources}' 未找到。") # [cite: 188]
        return
    
    [cite_start]unique_domains = set() # [cite: 188]
    for url in urls_raw:
        [cite_start]parsed = urllib.parse.urlparse(url) # [cite: 188]
        [cite_start]domain = parsed.netloc or re.match(r'^(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}(?::\d{1,5})?)(?:/.*)?$', parsed.path) # [cite: 188]
        if domain:
            [cite_start]unique_domains.add(domain if isinstance(domain, str) else domain.group(1).split('/')[0]) # [cite: 189]
        else:
            [cite_start]logger.warning(f"无法从 URL '{url}' 中识别有效域名。") # [cite: 189]

    if not unique_domains:
        [cite_start]logger.info("未找到有效域名。") # [cite: 189]
        return

    [cite_start]start_time = datetime.now() # [cite: 189]
    [cite_start]logger.info(f"开始处理 {len(unique_domains)} 个域名...") # [cite: 189]
    
    [cite_start]url_to_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(unique_domains, args.max_concurrency, args.timeout, args.use_browser)) # [cite: 190]
    
    [cite_start]total_nodes_extracted = sum(len(nodes) for nodes in url_to_nodes.values()) # [cite: 190]
    [cite_start]logger.info(f"前10个节点样本: {list(url_to_nodes.values())[0][:10] if url_to_nodes else []}") # [cite: 190]
    
    report_lines = [
        [cite_start]f"--- 报告 ---", # [cite: 190]
        [cite_start]f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒", # [cite: 190]
        [cite_start]f"总共提取到 {total_nodes_extracted} 个唯一节点。", # [cite: 190]
        [cite_start]"\n每个源 URL 的节点提取数量:" # [cite: 190]
    ]
    [cite_start]report_lines.append("{:<70} {:<15} {:<10}".format("源URL", "找到的节点数", "状态")) # [cite: 190]
    [cite_start]report_lines.append("-" * 95) # [cite: 190]
    
    [cite_start]for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True): # [cite: 191]
        [cite_start]status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点") # [cite: 191]
        [cite_start]report_lines.append(f"{url:<70} {count:<15} {status:<10}") # [cite: 191]
    
    if failed_urls:
        [cite_start]report_lines.append("\n未能成功获取或处理的源 URL:") # [cite: 191]
        [cite_start]report_lines.extend(sorted(list(failed_urls))) # [cite: 192]
    
    for line in report_lines:
        [cite_start]logger.info(line) # [cite: 192]

    # 将所有去重后的节点保存到一个文件
    output_file = args.nodes_output_file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    all_unique_nodes = set()
    for nodes in url_to_nodes.values():
        all_unique_nodes.update(nodes)
    
    if all_unique_nodes:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for node in sorted(list(all_unique_nodes)):
                    f.write(node + '\n')
            logger.info(f"所有 {len(all_unique_nodes)} 个唯一节点已保存到 {output_file}")
        except Exception as e:
            logger.error(f"保存所有节点到文件 '{output_file}' 失败: {e}")
    else:
        logger.info("未提取到任何唯一节点，跳过保存。")

    try:
        [cite_start]os.makedirs(os.path.dirname(args.stats_output), exist_ok=True) # [cite: 203]
        [cite_start]with open(args.stats_output, 'w', newline='', encoding='utf-8') as csvfile: # [cite: 203]
            [cite_start]fieldnames = ['Source_URL', 'Nodes_Found', 'Status'] # [cite: 203]
            [cite_start]writer = csv.DictWriter(csvfile, fieldnames=fieldnames) # [cite: 203]
            [cite_start]writer.writeheader() # [cite: 203]
            [cite_start]for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True): # [cite: 204]
                [cite_start]status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点") # [cite: 204]
                [cite_start]writer.writerow({'Source_URL': url, 'Nodes_Found': count, 'Status': status}) # [cite: 204]
        [cite_start]logger.info(f"统计数据保存到 {args.stats_output}") # [cite: 204]
    except Exception as e:
        logger.error(f"保存统计数据失败: {e}") #

if __name__ == '__main__':
    main()
