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

# --- 配置常量 ---
LOG_FILE = 'data/proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_NODES_OUTPUT_DIR = 'data/nodes'
DEFAULT_STATS_FILE = 'data/node_counts.csv'
DEFAULT_MAX_CONCURRENCY = 10
DEFAULT_TIMEOUT = 30 # 通用超时时间（秒）
PLAYWRIGHT_GOTO_TIMEOUT = 45000 # Playwright 页面加载超时时间（毫秒），略高于通用超时

MAX_BASE64_DECODE_DEPTH = 3
UA = UserAgent()

# 配置日志系统
os.makedirs('data', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,  # 默认设置为 INFO 级别，调试时可以设为 DEBUG
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 定义支持的节点协议及其正则表达式模式 (预编译正则表达式)
NODE_PATTERNS = {
    'ss': re.compile(r'ss://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'ssr': re.compile(r'ssr://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'vmess': re.compile(r'vmess://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'trojan': re.compile(r'trojan://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'vless': re.compile(r'vless://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'hy2': re.compile(r'hy2://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'warp': re.compile(r'warp://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'tuic': re.compile(r'tuic://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'h1': re.compile(r'h1://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'http': re.compile(r'(?:http|https)://(?:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,6})(?::\d{1,5})?(?:/\S*)?', re.IGNORECASE),
    'snell': re.compile(r'snell://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'socks5': re.compile(r'socks5://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'wireguard': re.compile(r'wireguard://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'naive': re.compile(r'naive://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE),
    'juicity': re.compile(r'juicity://[a-zA-Z0-9\-_./\+%&=:@]+', re.IGNORECASE)
}

COMBINED_REGEX_PATTERN = re.compile(
    '|'.join([pattern.pattern for pattern in NODE_PATTERNS.values()]),
    re.IGNORECASE
)

# 宽松的 Base64 匹配，避免误判短字符串
BASE64_REGEX_LOOSE = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
# 更精确的 Base64 匹配，通常用于 URL Safe 或标准 Base64 编码的节点内容
# 考虑 Base64 字符串的最小长度，避免匹配到普通文本
BASE64_REGEX_STRICT = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
# JavaScript 变量和函数调用中的 Base64 字符串
JS_VAR_REGEX = re.compile(r'(?:var|const|let)\s+\w+\s*=\s*[\'"]((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)[\'"]', re.IGNORECASE)
JS_FUNC_CALL_REGEX = re.compile(r'\w+\s*\(\s*[\'"]((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)[\'"]\s*\)', re.IGNORECASE)

# --- 辅助函数 ---

def decode_base64(data: str) -> Optional[str]:
    """尝试解码 Base64 字符串，支持 URL Safe 和标准 Base64。"""
    try:
        # 尝试 URL Safe Base64 解码
        decoded_bytes = base64.urlsafe_b64decode(data + '=' * (4 - len(data) % 4))
        return decoded_bytes.decode('utf-8', errors='ignore')
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        logger.debug(f"URL Safe Base64 解码失败: {e}. 尝试标准 Base64 解码。")
        try:
            # 尝试标准 Base64 解码
            decoded_bytes = base64.b64decode(data + '=' * (4 - len(data) % 4))
            return decoded_bytes.decode('utf-8', errors='ignore')
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            logger.debug(f"标准 Base64 解码失败: {e}")
            return None

def encode_base64(data: str) -> str:
    """编码字符串为 URL Safe Base64。"""
    encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8').rstrip('=')

def strip_html_tags(text: str) -> str:
    """去除字符串中的 HTML 标签。"""
    # 使用 BeautifulSoup 更健壮地去除 HTML 标签
    soup = BeautifulSoup(text, 'html.parser')
    return soup.get_text(separator=' ', strip=True)

def sanitize_filename_from_url(url: str) -> str:
    """从 URL 中生成一个安全的文件名。"""
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    sanitized = re.sub(r'[^\w\-_\.]', '_', domain)
    return sanitized + ".txt"

def normalize_node_url(node_url: str) -> str:
    """规范化节点 URL，例如去除重复的斜杠。"""
    # 进一步清理 URL 中的 HTML 实体和空白
    node_url = urllib.parse.unquote(node_url).strip()
    # 替换多个斜杠为单个斜杠，但保留协议头部的双斜杠
    node_url = re.sub(r'(?<!:)/{2,}', '/', node_url)
    return node_url

def convert_clash_proxy_to_url(proxy_dict: Dict[str, Any]) -> Optional[str]:
    """将 Clash 代理字典转换为 URL 格式。"""
    p_type = proxy_dict.get('type')
    name = urllib.parse.quote(proxy_dict.get('name', 'node'))
    server = proxy_dict.get('server')
    port = proxy_dict.get('port')
    password = proxy_dict.get('password', '')
    uuid = proxy_dict.get('uuid', '')
    flow = proxy_dict.get('flow', '')
    alterId = proxy_dict.get('alterId', 0)
    cipher = proxy_dict.get('cipher', '')
    network = proxy_dict.get('network', 'tcp')
    tls = proxy_dict.get('tls', False)
    udp = proxy_dict.get('udp', False)
    sni = proxy_dict.get('sni', '')
    skip_cert_verify = proxy_dict.get('skip-cert-verify', False)
    ws_path = proxy_dict.get('ws-path', '/')
    ws_headers = proxy_dict.get('ws-headers', {})
    grpc_service_name = proxy_dict.get('grpc-service-name', '')
    fingerprint = proxy_dict.get('fingerprint', '')
    publicKey = proxy_dict.get('publicKey', '') # 对于 tuic v5

    if not all([server, port]):
        return None

    try:
        if p_type == 'ss':
            method = cipher
            encoded_password = encode_base64(password)
            return f"ss://{encoded_password}@{server}:{port}#{name}"
        elif p_type == 'ssr':
            # SSR 格式复杂，通常需要额外参数如协议、混淆等
            # 这里仅提供基础框架，可能需要更多信息来构建完整 URL
            obfs = proxy_dict.get('obfs', '')
            protocol = proxy_dict.get('protocol', '')
            obfsparam = proxy_dict.get('obfsparam', '')
            protoparam = proxy_dict.get('protoparam', '')
            encoded_password = encode_base64(password)
            params = f":{protocol}:{cipher}:{obfs}:{encoded_password}/?obfsparam={encode_base64(obfsparam)}&protoparam={encode_base64(protoparam)}"
            return f"ssr://{encode_base64(f'{server}:{port}{params}#{name}')}"
        elif p_type == 'vmess':
            vmess_config = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": int(port),
                "id": uuid,
                "aid": int(alterId),
                "net": network,
                "type": "none",
                "host": ws_headers.get('Host', ''),
                "path": ws_path,
                "tls": "tls" if tls else "",
                "sni": sni,
                "fp": fingerprint
            }
            return "vmess://" + encode_base64(json.dumps(vmess_config))
        elif p_type == 'trojan':
            params = []
            if sni: params.append(f"sni={sni}")
            if allow_insecure := skip_cert_verify: params.append(f"allowInsecure={str(allow_insecure).lower()}")
            if flow: params.append(f"flow={flow}")
            return f"trojan://{password}@{server}:{port}?{'&'.join(params)}#{name}"
        elif p_type == 'vless':
            params = [f"type={network}"]
            if tls: params.append("security=tls")
            if sni: params.append(f"sni={sni}")
            if flow: params.append(f"flow={flow}")
            if skip_cert_verify: params.append("allowInsecure=1")
            if fingerprint: params.append(f"fp={fingerprint}")

            if network == 'ws':
                params.append(f"path={urllib.parse.quote(ws_path)}")
                if 'Host' in ws_headers:
                    params.append(f"host={ws_headers['Host']}")
            elif network == 'grpc':
                params.append(f"serviceName={urllib.parse.quote(grpc_service_name)}")

            return f"vless://{uuid}@{server}:{port}?{'&'.join(params)}#{name}"
        elif p_type == 'tuic': # 假设 tuic v5 格式
            params = []
            if password: params.append(f"password={urllib.parse.quote(password)}")
            if network: params.append(f"type={network}")
            if tls: params.append("security=tls")
            if sni: params.append(f"sni={sni}")
            if skip_cert_verify: params.append("allowInsecure=1")
            if fingerprint: params.append(f"fp={fingerprint}")
            if publicKey: params.append(f"publicKey={urllib.parse.quote(publicKey)}") # For TUIC v5

            return f"tuic://{server}:{port}?{'&'.join(params)}#{name}"
        elif p_type == 'hysteria2':
            params = []
            if password: params.append(f"password={urllib.parse.quote(password)}")
            if sni: params.append(f"sni={sni}")
            if skip_cert_verify: params.append("insecure=1")
            return f"hy2://{server}:{port}?{'&'.join(params)}#{name}"
        elif p_type == 'naïve':
            return f"naive+https://{username}:{password}@{server}:{port}#{name}" # 假设 naive 有 username/password
        elif p_type == 'juicity':
            params = []
            if password: params.append(f"password={urllib.parse.quote(password)}")
            if sni: params.append(f"sni={sni}")
            if skip_cert_verify: params.append("insecure=1")
            if publicKey: params.append(f"publicKey={urllib.parse.quote(publicKey)}")
            return f"juicity://{server}:{port}?{'&'.join(params)}#{name}"
        # 添加其他协议转换
    except Exception as e:
        logger.warning(f"转换 Clash 代理配置到 URL 失败 ({name}): {e}")
    return None

def score_node(node: str) -> int:
    """根据节点 URL 的特性进行评分，用于排序。"""
    score = 0
    node_lower = node.lower()

    # 匹配流行协议
    for proto in ['vmess', 'trojan', 'vless', 'ss', 'ssr']:
        if node_lower.startswith(f"{proto}://"):
            score += 100

    # 包含特定国家/地区或城市名称（示例）
    for loc in ['hongkong', 'hk', 'singapore', 'sg', 'japan', 'jp', 'united states', 'us']:
        if loc in node_lower:
            score += 50

    # 包含质量关键词
    for keyword in ['fast', 'vip', 'premium', 'highspeed']:
        if keyword in node_lower:
            score += 30

    # 包含日期或数字（可能表示新旧）
    if re.search(r'\d{4}[-/]\d{2}[-/]\d{2}|\d{2,4}', node_lower):
        score += 10

    # 长度（太短或太长的可能是无效的）
    if 50 < len(node) < 500:
        score += 5

    return score

def generate_node_fingerprint(node_url: str) -> str:
    """为节点 URL 生成一个标准化指纹，用于去重。
    尝试去除 URL 中的动态部分，例如时间戳、计数器等。
    """
    parsed_url = urllib.parse.urlparse(node_url)
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc

    # 对于包含参数的 URL，尝试解析并去除可能的动态参数
    query_params = urllib.parse.parse_qs(parsed_url.query)
    fragment_params = urllib.parse.parse_qs(parsed_url.fragment)

    # 常见的可能动态变化的参数
    dynamic_params = ['t', 'time', 'date', 'ts', 'count', 'id', 'name', 'tag', 'remark', 'group']

    cleaned_query_params = {k: v for k, v in query_params.items() if k.lower() not in dynamic_params}
    cleaned_fragment_params = {k: v for k, v in fragment_params.items() if k.lower() not in dynamic_params}

    # 重新构建查询和片段
    cleaned_query = urllib.parse.urlencode(cleaned_query_params, doseq=True)
    cleaned_fragment = urllib.parse.urlencode(cleaned_fragment_params, doseq=True)

    # 尝试去除路径中的数字或随机字符串
    path_cleaned = re.sub(r'/[0-9a-fA-F]{8,}/', '/', parsed_url.path) # 移除类似 UUID 的路径段

    # 构建指纹，忽略端口（对于某些协议，端口可能是动态的或者不重要）
    fingerprint_components = [scheme, netloc.split(':')[0], path_cleaned, cleaned_query, cleaned_fragment]
    fingerprint = "://".join(filter(None, fingerprint_components)) # 过滤空字符串

    # 对于 base64 编码的节点，解码后取内容指纹
    if scheme in ['vmess', 'ss', 'ssr', 'trojan', 'vless', 'hy2', 'tuic', 'naive', 'juicity']:
        try:
            # 尝试解码并规范化
            decoded_content = decode_base64(node_url.split('://', 1)[1].split('#', 1)[0])
            if decoded_content:
                # 简单哈希或去除变动部分后取前缀
                return f"{scheme}::{hash(frozenset(decoded_content.splitlines()))}"
        except Exception:
            pass # 无法解码则回退到原始指纹

    return fingerprint

def _extract_from_html(html_content: str, decode_depth: int) -> Set[str]:
    """从 HTML 内容中提取节点或 Base64 编码的潜在内容。"""
    nodes_found = set()
    try:
        soup = BeautifulSoup(html_content, 'html.parser')

        # 提取 <pre> 和 <textarea> 标签内的文本
        for tag_name in ['pre', 'textarea']:
            for tag in soup.find_all(tag_name):
                text_content = tag.get_text(separator='\n', strip=True)
                nodes_found.update(extract_nodes(text_content, decode_depth + 1))

        # 提取常见属性中的链接和 Base64 内容
        attrs_to_check = ['href', 'src', 'data-url', 'data-node', 'data-config', 'data-link', 'data-href', 'content', 'data-clipboard-text', 'value']
        for tag in soup.find_all(True):
            for attr in attrs_to_check:
                if attr in tag.attrs and tag.attrs[attr]:
                    link_val = tag.attrs[attr].strip()
                    cleaned_link = strip_html_tags(link_val)
                    
                    if re.match(COMBINED_REGEX_PATTERN, cleaned_link):
                        nodes_found.add(normalize_node_url(cleaned_link))
                    else:
                        b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_link)
                        if b64_match:
                            decoded_attr = decode_base64(b64_match.group(0)) # group(0) 获取完整匹配
                            if decoded_attr:
                                nodes_found.update(extract_nodes(decoded_attr, decode_depth + 1))

        # 提取 HTML 注释中的内容
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment).strip()
            cleaned_comment = strip_html_tags(comment_text)
            
            if re.search(COMBINED_REGEX_PATTERN, cleaned_comment, re.MULTILINE):
                for pattern_val in NODE_PATTERNS.values():
                    matches = pattern_val.findall(cleaned_comment)
                    for node in matches:
                        nodes_found.add(normalize_node_url(strip_html_tags(node)))
            
            base64_matches = BASE64_REGEX_LOOSE.findall(cleaned_comment)
            for b64_str in base64_matches: # findall 返回的是字符串列表
                decoded_comment_content = decode_base64(b64_str)
                if decoded_comment_content:
                    nodes_found.update(extract_nodes(decoded_comment_content, decode_depth + 1))

    except Exception as e: # 更具体的异常捕获如 `html.parser.HTMLParseError`
        logger.debug(f"HTML 解析失败: {e}")
    return nodes_found

def _extract_from_base64(encoded_content: str, decode_depth: int) -> Set[str]:
    """解码 Base64 字符串并递归提取节点。"""
    nodes_found = set()
    if decode_depth < MAX_BASE64_DECODE_DEPTH:
        b64_matches = BASE64_REGEX_LOOSE.findall(encoded_content)
        for b64_str in b64_matches:
            if len(b64_str) < 50: # 避免解码过短的非节点 Base64 字符串
                continue
            decoded_content_full = decode_base64(b64_str)
            if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != encoded_content:
                nodes_found.update(extract_nodes(decoded_content_full, decode_depth + 1))
    return nodes_found

def extract_nodes(content: str, decode_depth: int = 0) -> List[str]:
    """
    从给定的内容中提取代理节点 URL。
    会尝试解码 Base64、解析 HTML、JSON、YAML 和直接匹配模式。
    """
    nodes_found = set()
    if not content or decode_depth > MAX_BASE64_DECODE_DEPTH:
        return []

    # 将所有回车符统一为换行符
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # 直接匹配节点模式
    for pattern_key, pattern_val in NODE_PATTERNS.items():
        matches = pattern_val.findall(content)
        for node in matches:
            nodes_found.add(normalize_node_url(strip_html_tags(node)))

    # 尝试作为 HTML 解析
    nodes_found.update(_extract_from_html(content, decode_depth))

    # 尝试从 JavaScript 变量和函数调用中提取
    js_variable_matches = JS_VAR_REGEX.findall(content)
    for match_group in js_variable_matches:
        js_val = match_group if isinstance(match_group, str) else match_group[0]
        cleaned_js_val = strip_html_tags(js_val)
        if re.match(COMBINED_REGEX_PATTERN, cleaned_js_val):
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

    # 尝试作为 YAML 解析
    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node and any(re.match(pattern, url_node) for pattern in NODE_PATTERNS.values()):
                    nodes_found.add(normalize_node_url(url_node))
        elif isinstance(yaml_content, list):
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item:
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node and any(re.match(pattern, url_node) for pattern in NODE_PATTERNS.values()):
                        nodes_found.add(normalize_node_url(url_node))
        
        # 递归处理 YAML 中的 Base64
        if isinstance(yaml_content, (dict, list)):
            iterable_content = yaml_content.values() if isinstance(yaml_content, dict) else yaml_content
            for value in iterable_content:
                if isinstance(value, str):
                    cleaned_value = strip_html_tags(value)
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(cleaned_value)
                    if b64_match:
                        decoded_sub_content = decode_base64(b64_match.group(0))
                        if decoded_sub_content:
                            nodes_found.update(extract_nodes(decoded_sub_content, decode_depth + 1))
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败: {e}")
    except Exception as e:
        logger.debug(f"处理 YAML 内容时发生错误: {e}")

    # 尝试作为 JSON 解析
    try:
        json_content = json.loads(content)

        def traverse_json(obj: Any):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        cleaned_v = strip_html_tags(v)
                        if re.match(COMBINED_REGEX_PATTERN, cleaned_v):
                            nodes_found.add(normalize_node_url(cleaned_v))
                        elif BASE64_REGEX_LOOSE.fullmatch(cleaned_v):
                            decoded_json_val = decode_base64(cleaned_v)
                            if decoded_json_val:
                                nodes_found.update(extract_nodes(decoded_json_val, decode_depth + 1))
                    else:
                        traverse_json(v)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, str):
                        cleaned_item = strip_html_tags(item)
                        if re.match(COMBINED_REGEX_PATTERN, cleaned_item):
                            nodes_found.add(normalize_node_url(cleaned_item))
                        elif BASE64_REGEX_LOOSE.fullmatch(cleaned_item):
                            decoded_json_item = decode_base64(cleaned_item)
                            if decoded_json_item:
                                nodes_found.update(extract_nodes(decoded_json_item, decode_depth + 1))
                    else:
                        traverse_json(item)

        traverse_json(json_content)

    except json.JSONDecodeError as e:
        logger.debug(f"JSON 解析失败: {e}")
    except Exception as e:
        logger.debug(f"处理 JSON 内容时发生错误: {e}")

    # 递归处理 Base64 编码的内容
    nodes_found.update(_extract_from_base64(content, decode_depth))
    
    # 最终过滤和排序，确保节点符合模式且长度合理
    final_filtered_nodes = [
        node for node in nodes_found 
        if any(pattern.match(node) for pattern in NODE_PATTERNS.values()) 
        and len(node) > 20 # 过滤掉过短的非节点字符串
    ]
    
    # 根据评分进行排序
    sorted_nodes = sorted(list(set(final_filtered_nodes)), key=score_node, reverse=True)
    return sorted_nodes

async def fetch_with_aiohttp(session: aiohttp.ClientSession, url: str, timeout: int) -> Optional[str]:
    """使用 aiohttp 异步获取 URL 内容。"""
    headers = {'User-Agent': UA.random}
    try:
        async with session.get(url, headers=headers, timeout=timeout, ssl=False) as response:
            response.raise_for_status()  # 检查 HTTP 状态码
            content = await response.text()
            logger.info(f"成功获取 {url} (aiohttp)")
            return content
    except aiohttp.ClientError as e:
        logger.warning(f"aiohttp 请求 {url} 失败: {e}")
        return None
    except asyncio.TimeoutError:
        logger.warning(f"aiohttp 请求 {url} 超时 ({timeout}s)")
        return None
    except Exception as e:
        logger.error(f"aiohttp 请求 {url} 发生未知错误: {e}")
        return None

async def fetch_with_browser(
    playwright_instance: Any, url: str, timeout: int, browser_context: BrowserContext
) -> Optional[str]:
    """使用 Playwright 异步获取 URL 内容 (渲染 JavaScript)。"""
    try:
        page = await browser_context.new_page()
        user_agent_str = UA.random
        await page.set_extra_http_headers({"User-Agent": user_agent_str})
        
        # 调整 Playwright 的等待策略和超时
        # wait_until='load' 比 'networkidle' 宽松，等待主要资源加载完毕
        # 使用 PLAYWRIGHT_GOTO_TIMEOUT 常量作为 goto 的超时时间
        await page.goto(url, wait_until='load', timeout=PLAYWRIGHT_GOTO_TIMEOUT)
        
        # 这里不再使用 page.wait_for_load_state('networkidle')，以避免长时间等待
        
        content = await page.content()
        logger.info(f"成功获取 {url} (Playwright)")
        return content
    except Exception as e:
        # Playwright 的异常通常已经包含详细信息
        logger.warning(f"Playwright 请求 {url} 失败: {e}")
        return None
    finally:
        if 'page' in locals() and not page.is_closed():
            await page.close()

async def process_single_url_strategy(
    url: str,
    timeout: int,
    use_browser: bool,
    session: Optional[aiohttp.ClientSession],
    playwright_instance: Optional[Any],
    browser_context: Optional[BrowserContext
]) -> Tuple[str, List[str], str]:
    """处理单个 URL，根据策略选择获取方式并提取节点。"""
    content = None
    status = "失败"
    extracted_nodes = []

    try:
        if use_browser and playwright_instance and browser_context:
            content = await fetch_with_browser(playwright_instance, url, timeout, browser_context)
            if content:
                extracted_nodes = extract_nodes(content)
                status = "成功 (Browser)"
            else:
                logger.warning(f"Playwright 未能获取内容，尝试回退到 aiohttp: {url}")
                if session:
                    content = await fetch_with_aiohttp(session, url, timeout)
                    if content:
                        extracted_nodes = extract_nodes(content)
                        status = "成功 (HTTP 回退)"
                else:
                    logger.error("aiohttp session 未初始化，无法回退。")
        elif session:
            content = await fetch_with_aiohttp(session, url, timeout)
            if content:
                extracted_nodes = extract_nodes(content)
                status = "成功 (HTTP)"
        else:
            logger.error(f"没有可用的内容获取策略 (URL: {url})")
            status = "失败 (无策略)"

    except Exception as e:
        logger.error(f"处理 URL {url} 时发生未预期错误: {e}")
        status = "失败 (异常)"

    return url, extracted_nodes, status


async def process_urls(
    urls: List[str], max_concurrency: int, timeout: int, use_browser: bool
) -> Dict[str, List[str]]:
    """并发处理 URL 列表，提取代理节点。"""
    url_to_nodes: Dict[str, List[str]] = defaultdict(list)
    url_statuses: Dict[str, str] = {} # 记录每个 URL 的处理状态
    semaphore = asyncio.Semaphore(max_concurrency)
    
    playwright_instance = None
    browser = None
    browser_context = None
    session = None

    try:
        if use_browser:
            playwright_instance = await async_playwright().start()
            browser = await playwright_instance.chromium.launch(headless=True) # 生产环境建议 headless=True
            browser_context = await browser.new_context(user_agent=UA.random) # 创建上下文以复用
            logger.info("Playwright 浏览器已启动。")
        
        session = aiohttp.ClientSession() # 创建一个 session 以复用连接
        logger.info("aiohttp 客户端会话已启动。")

        async def worker(url: str):
            async with semaphore:
                source_url_domain = urllib.parse.urlparse(url).netloc or url # 用于日志和分组
                url, extracted_nodes, status = await process_single_url_strategy(
                    url, timeout, use_browser, session, playwright_instance, browser_context
                )
                url_to_nodes[source_url_domain].extend(extracted_nodes)
                url_statuses[source_url_domain] = status
                logger.info(f"处理完成 {len(extracted_nodes)} 个节点来自 {url}")

        tasks = [worker(url) for url in urls]
        await asyncio.gather(*tasks)

    finally:
        if session:
            await session.close()
            logger.info("aiohttp 客户端会话已关闭。")
        if browser_context:
            await browser_context.close()
            logger.info("Playwright 浏览器上下文已关闭。")
        if browser:
            await browser.close()
            logger.info("Playwright 浏览器已关闭。")
        if playwright_instance:
            await playwright_instance.stop()
            logger.info("Playwright 实例已停止。")
    
    return url_to_nodes, url_statuses

def save_nodes_to_files(url_to_nodes: Dict[str, List[str]], output_dir: str):
    """将提取到的节点保存到以域名命名的文件中。"""
    os.makedirs(output_dir, exist_ok=True)
    for url_domain, nodes in url_to_nodes.items():
        if nodes:
            sanitized_filename = sanitize_filename_from_url(url_domain)
            output_path = os.path.join(output_dir, sanitized_filename)
            try:
                content = '\n'.join(nodes)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
                logger.info(f"保存 {len(nodes)} 个节点到 {output_path} ({file_size_mb:.2f} MB)")
            except Exception as e:
                logger.error(f"保存节点到文件 '{output_path}' 失败: {e}")
        else:
            logger.info(f"源 {url_domain} 未提取到节点，跳过保存。")

def write_stats_csv(url_node_counts: Dict[str, int], url_statuses: Dict[str, str], stats_output_path: str):
    """将统计信息写入 CSV 文件。"""
    try:
        os.makedirs(os.path.dirname(stats_output_path), exist_ok=True)
        with open(stats_output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Source_URL', 'Nodes_Found', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for url_domain, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True):
                status = url_statuses.get(url_domain, "未知")
                writer.writerow({
                    'Source_URL': url_domain,
                    'Nodes_Found': count,
                    'Status': status
                })
        logger.info(f"统计信息已保存到 {stats_output_path}")
    except Exception as e:
        logger.error(f"写入统计 CSV 文件失败: {e}")

async def main():
    parser = argparse.ArgumentParser(description="从 URL 列表中提取代理节点。")
    parser.add_argument('--sources', type=str, default=DEFAULT_SOURCES_FILE,
                        help=f"包含代理源 URL 的文件路径 (默认为 {DEFAULT_SOURCES_FILE})")
    parser.add_argument('--nodes-output-dir', type=str, default=DEFAULT_NODES_OUTPUT_DIR,
                        help=f"保存提取到的节点的目录 (默认为 {DEFAULT_NODES_OUTPUT_DIR})")
    parser.add_argument('--stats-output', type=str, default=DEFAULT_STATS_FILE,
                        help=f"保存统计信息的 CSV 文件路径 (默认为 {DEFAULT_STATS_FILE})")
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY,
                        help=f"最大并发请求数 (默认为 {DEFAULT_MAX_CONCURRENCY})")
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f"请求超时时间 (秒) (默认为 {DEFAULT_TIMEOUT})")
    parser.add_argument('--use-browser', action='store_true',
                        help="使用 Playwright 浏览器渲染 JavaScript 内容")

    args = parser.parse_args()

    # 验证输入参数
    if not os.path.exists(args.sources):
        logger.error(f"错误: 源文件 '{args.sources}' 不存在。")
        return
    if args.max_concurrency <= 0:
        logger.error(f"错误: 最大并发数必须大于 0。")
        return
    if args.timeout <= 0:
        logger.error(f"错误: 超时时间必须大于 0。")
        return

    logger.info(f"正在从 '{args.sources}' 加载代理源...")
    urls_to_process: List[str] = []
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    urls_to_process.append(stripped_line)
    except Exception as e:
        logger.error(f"加载源文件失败: {e}")
        return

    if not urls_to_process:
        logger.warning("没有找到要处理的 URL。")
        return

    logger.info(f"共找到 {len(urls_to_process)} 个代理源。")
    logger.info(f"启动节点提取过程，最大并发数: {args.max_concurrency}, 超时: {args.timeout}s, {'使用浏览器' if args.use_browser else '不使用浏览器'}。")

    start_time = datetime.now()
    url_to_nodes, url_statuses = await process_urls(urls_to_process, args.max_concurrency, args.timeout, args.use_browser)
    end_time = datetime.now()
    
    total_extracted_nodes = sum(len(nodes) for nodes in url_to_nodes.values())
    unique_extracted_nodes_set = set()
    for nodes_list in url_to_nodes.values():
        unique_extracted_nodes_set.update(nodes_list)
    total_unique_extracted_nodes = len(unique_extracted_nodes_set)


    logger.info(f"所有源处理完成。总耗时: {(end_time - start_time).total_seconds():.2f} 秒。")
    logger.info(f"总共提取到 {total_extracted_nodes} 个节点 (其中 {total_unique_extracted_nodes} 个唯一节点)。")

    logger.info(f"正在保存节点到 '{args.nodes_output_dir}'...")
    save_nodes_to_files(url_to_nodes, args.nodes_output_dir)

    logger.info(f"正在生成统计信息到 '{args.stats_output}'...")
    url_node_counts = {url_domain: len(nodes) for url_domain, nodes in url_to_nodes.items()}
    write_stats_csv(url_node_counts, url_statuses, args.stats_output)

    logger.info("所有任务完成。")

if __name__ == "__main__":
    asyncio.run(main())
