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
DEFAULT_CHUNK_SIZE_MB = 5  # 优化: 默认分片大小调整为 5 MB
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

# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='代理节点提取和去重工具')
    parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'包含源 URL 的输入文件路径 (默认为: {DEFAULT_SOURCES_FILE})')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_FILE, help=f'提取到的节点输出文件路径 (默认为: {DEFAULT_OUTPUT_FILE})')
    parser.add_argument('--stats-output', default=DEFAULT_STATS_FILE, help=f'节点统计数据输出文件路径 (默认为: {DEFAULT_STATS_FILE})')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认为: {DEFAULT_MAX_CONCURRENCY})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认为: {DEFAULT_TIMEOUT})')
    parser.add_argument('--chunk-size-mb', type=int, default=DEFAULT_CHUNK_SIZE_MB, help=f'每个分片文件的最大大小（MB） (默认为: {DEFAULT_CHUNK_SIZE_MB})')
    parser.add_argument('--use-browser', action='store_true', help='当HTTP请求失败时，尝试使用无头浏览器（Playwright）')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    """解码 Base64 字符串，并修复可能存在的填充问题，清理非 Base64 字符。"""
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
    """编码字符串为 URL 安全的 Base64 格式。"""
    try:
        encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
        return encoded_bytes.decode('utf-8').rstrip('=')
    except Exception as e:
        logger.warning(f"Base64 编码失败: {data[:50]}... 错误: {e}")
        return data

def clean_html_tags(text: str) -> str:
    """从字符串中移除所有 HTML/XML 标签及其内容，包括注释，并清理多余空格和特定 HTML 片段。"""
    if not isinstance(text, str) or not text:
        return ""
    
    soup = BeautifulSoup(text, 'html.parser')
    
    # 移除注释
    for element in soup(text=lambda text: isinstance(text, Comment)):
        element.extract()
    
    # 获取纯文本内容
    clean_text = soup.get_text(separator=' ', strip=True)
    
    # 进一步清理常见的 HTML 实体或多余的空格
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    
    # 移除可能残留在 URL 或节点末尾的特定 HTML 标签片段 (即使 BeautifulSoup 已经处理过，以防万一)
    # 这些标签通常不会有内部文本，它们直接附加在节点信息后
    clean_text = re.sub(r'<\/?(?:pre|button|span|p|br)[^>]*>', '', clean_text, flags=re.IGNORECASE)
    
    # 移除任何剩余的、看起来像畸形标签的字符或 HTML 实体
    clean_text = re.sub(r'&#\d+;', '', clean_text) # 数字 HTML 实体
    clean_text = re.sub(r'&\w+;', '', clean_text) # 命名 HTML 实体
    
    return clean_text


def normalize_node_url(url: str) -> str:
    """规范化节点 URL 以提高去重效率，保持关键参数一致。"""
    try:
        protocol, _, rest = url.partition('://')
        if not protocol or protocol.lower() not in NODE_PATTERNS:
            logger.debug(f"无法识别协议或不支持的协议: {url}")
            return url

        parsed_url = urllib.parse.urlparse(url)
        protocol_lower = protocol.lower()

        if protocol_lower == 'vmess':
            config_b64 = rest
            config_json = decode_base64(config_b64)
            if not config_json:
                logger.debug(f"VMess 配置Base64解码失败: {url}")
                return url
            try:
                config = json.loads(config_json)
            except json.JSONDecodeError as e:
                logger.debug(f"VMess 配置 JSON 解析失败: {e} for {config_json[:min(50, len(config_json))]}...")
                return url

            ordered_keys = [
                'v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'tls',
                'sni', 'host', 'path', 'serviceName', 'alpn', 'fp', 'allowInsecure',
                'maxEarlyData', 'earlyDataHeader', 'mode', 'method', 'scy'
            ]
            clean_config = {}
            for k in ordered_keys:
                if k in config and config[k] is not None:
                    if k == 'ps':
                        clean_config[k] = urllib.parse.unquote(str(config[k]))
                    elif k in ['port', 'aid']:
                        try:
                            clean_config[k] = int(config[k])
                        except (ValueError, TypeError):
                            clean_config[k] = 0 if k == 'aid' else 0
                    elif k == 'alpn' and isinstance(config[k], list):
                        clean_config[k] = ','.join(sorted(config[k]))
                    else:
                        clean_config[k] = config[k]
            
            if 'ps' not in clean_config: clean_config['ps'] = ''
            final_config_to_encode = {k: v for k, v in clean_config.items() if not (k == 'aid' and v == 0) and not (k == 'v' and v == '2')}
            return f"vmess://{encode_base64(json.dumps(final_config_to_encode, ensure_ascii=False, sort_keys=True))}"
        
        elif protocol_lower == 'ssr':
            try:
                decoded_ssr_full = decode_base64(rest)
                if not decoded_ssr_full:
                    logger.debug(f"SSR Base64解码失败: {url}")
                    return url
                
                core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr_full)
                if not core_part_match:
                    raise ValueError("SSR 链接核心部分解析失败")
                core_part = core_part_match.group(1)
                
                parts = core_part.split(':')
                if len(parts) < 6:
                    raise ValueError(f"SSR 核心部分参数不足，预期6个，实际{len(parts)}")
                
                host, port, protocol_name, method, obfs_name = parts[0:5]
                password_encoded_val = parts[5].split('/')[0].split('?')[0].split('#')[0]
                
                full_url_tail = core_part_match.group(2)
                parsed_tail = urllib.parse.urlparse(full_url_tail)
                query_params_raw = urllib.parse.parse_qs(parsed_tail.query)
                fragment_raw = parsed_tail.fragment

                clean_params = {}
                for k in sorted(query_params_raw.keys()):
                    val = query_params_raw[k][0] if isinstance(query_params_raw[k], list) else query_params_raw[k]
                    if k in ['protoparam', 'obfsparam', 'group']:
                        decoded_val = decode_base64(val)
                        if decoded_val:
                            clean_params[k] = encode_base64(decoded_val)
                        else:
                            clean_params[k] = encode_base64(val)
                    else:
                        clean_params[k] = urllib.parse.quote(urllib.parse.unquote(val), safe='')
                
                query_string = urllib.parse.urlencode(clean_params, quote_via=urllib.parse.quote)
                remark_decoded = decode_base64(fragment_raw) if fragment_raw else ''
                remark_encoded = encode_base64(remark_decoded) if remark_decoded else ''
                
                normalized_core = f"{host}:{port}:{protocol_name}:{method}:{obfs_name}:{password_encoded_val}"
                if query_string:
                    normalized_core += f"/?{query_string}"
                if remark_encoded:
                    normalized_core += f"#{remark_encoded}"
                
                return f"ssr://{encode_base64(normalized_core)}"
            except Exception as e:
                logger.debug(f"SSR 链接规范化失败 ('{url}')：{e}", exc_info=True)
                return url
        else:
            auth_part = ''
            if parsed_url.username or parsed_url.password:
                auth_user = parsed_url.username if parsed_url.username else ''
                auth_pass = parsed_url.password if parsed_url.password else ''
                auth_part = f"{urllib.parse.quote(urllib.parse.unquote(auth_user), safe='')}:{urllib.parse.quote(urllib.parse.unquote(auth_pass), safe='')}@"
            
            host_port_raw = parsed_url.netloc
            if '@' in host_port_raw:
                host_port_raw = host_port_raw.split('@', 1)[-1]
            host_port = host_port_raw.lower()
            
            query_params = urllib.parse.parse_qs(parsed_url.query)
            sorted_query_params = {}
            for k in sorted(query_params.keys()):
                val = query_params[k][0] if isinstance(query_params[k], list) else query_params[k]
                sorted_query_params[k] = urllib.parse.quote(urllib.parse.unquote(val), safe='')
            
            query_string = urllib.parse.urlencode(sorted_query_params, quote_via=urllib.parse.quote)
            if query_string:
                query_string = '?' + query_string
            
            fragment = urllib.parse.unquote(parsed_url.fragment)
            if fragment:
                fragment = '#' + urllib.parse.quote(fragment, safe='')
            
            return f"{protocol_lower}://{auth_part}{host_port}{query_string}{fragment}"
    except Exception as e:
        logger.debug(f"规范化 URL '{url}' 失败: {e}", exc_info=True)
        return url

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 代理配置字典转换为标准 URL 格式。"""
    proxy_type = proxy.get('type', '').lower()
    name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', f"{proxy_type}_node").strip()), safe='')
    server = proxy.get('server')
    port = proxy.get('port')
    
    if not all([server, port, proxy_type]):
        logger.debug(f"Clash 代理 {proxy.get('name', '未知')} 缺少核心信息，跳过: {proxy}")
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
        
        config: Dict[str, Any] = {
            "v": "2",
            "ps": urllib.parse.unquote(name),
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
                config["host"] = sni 
                config["sni"] = sni
            if proxy.get('skip-cert-verify'):
                config["allowInsecure"] = 1
            if proxy.get('alpn'):
                config["alpn"] = ",".join(proxy['alpn']) if isinstance(proxy['alpn'], list) else proxy['alpn']
            if proxy.get('client-fingerprint'):
                config["fp"] = proxy['client-fingerprint']
            if proxy.get('security'):
                config["scy"] = proxy['security']

        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            config["path"] = ws_opts.get('path', '/')
            if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
                config['host'] = ws_opts['headers']['Host']
            elif ws_opts.get('host'):
                config['host'] = ws_opts['host']
            if ws_opts.get('max-early-data'): config['maxEarlyData'] = ws_opts['max-early-data']
            if ws_opts.get('early-data-header'): config['earlyDataHeader'] = ws_opts['early-data-header']
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            config["serviceName"] = grpc_opts.get('grpc-service-name', '')
            if grpc_opts.get('mode'): config["mode"] = grpc_opts['mode']
        elif network == 'http':
            http_opts = proxy.get('http-opts', {})
            if http_opts.get('method'):
                config['method'] = http_opts['method']
            if http_opts.get('headers'):
                for header_key, header_value in http_opts['headers'].items():
                    if header_key.lower() == 'host':
                        config['host'] = header_value[0] if isinstance(header_value, list) else header_value
                        break
        final_config = {k: v for k, v in config.items() if v is not None and v != '' and not (k == 'aid' and v == 0) and not (k == 'v' and v == '2')}
        
        try:
            return f"vmess://{encode_base64(json.dumps(final_config, ensure_ascii=False, sort_keys=True))}"
        except Exception as e:
            logger.debug(f"VMess 配置 JSON 编码失败，节点：{name}。错误：{e}", exc_info=True)
            return None

    elif proxy_type == 'trojan':
        password = proxy.get('password')
        tls_enabled = proxy.get('tls', False)
        if not all([password, tls_enabled]):
            logger.debug(f"Trojan 代理 {name} 缺少密码或未启用 TLS: {proxy}")
            return None
        params = []
        sni = proxy.get('servername') or proxy.get('host') or server
        if sni: params.append(f"sni={urllib.parse.quote(sni, safe='')}")
        if proxy.get('alpn'): params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']) if isinstance(proxy['alpn'], list) else proxy['alpn'], safe='')}")
        if proxy.get('client-fingerprint'): params.append(f"fp={urllib.parse.quote(proxy['client-fingerprint'], safe='')}")
        if proxy.get('skip-cert-verify'): params.append("allowInsecure=1")
        if not proxy.get('udp', True): params.append("udp=false")
        
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
        tls_enabled = proxy.get('tls', False)
        if not uuid_val:
            logger.debug(f"VLESS 代理 {name} 缺少 UUID: {proxy}")
            return None
        params: Dict[str, Any] = {"type": network}
        if tls_enabled:
            params['security'] = 'tls'
            sni = proxy.get('servername') or proxy.get('host') or server
            if sni: params['sni'] = sni
            if proxy.get('alpn'): params['alpn'] = ",".join(proxy['alpn']) if isinstance(proxy['alpn'], list) else proxy['alpn']
            if proxy.get('client-fingerprint'): params['fp'] = proxy['client-fingerprint']
            if proxy.get('skip-cert-verify'): params['allowInsecure'] = '1'
            if proxy.get('flow'): params['flow'] = proxy['flow']
            if proxy.get('reality-opts'):
                reality_opts = proxy.get('reality-opts')
                if reality_opts.get('publicKey'): params['pbk'] = reality_opts['publicKey']
                if reality_opts.get('shortId'): params['sid'] = reality_opts['shortId']
                if reality_opts.get('spiderX'): params['spx'] = reality_opts['spiderX']
                if reality_opts.get('dest'): params['dest'] = reality_opts['dest']
                if reality_opts.get('serverName'): params['serverName'] = reality_opts['serverName']
        
        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            params['path'] = ws_opts.get('path', '/')
            if 'headers' in ws_opts and 'host' in ws_opts['headers']:
                params['host'] = ws_opts['headers']['host']
            elif ws_opts.get('host'):
                params['host'] = ws_opts['host']
            if ws_opts.get('max-early-data'): params['maxEarlyData'] = ws_opts['max-early-data']
            if ws_opts.get('early-data-header'): params['earlyDataHeader'] = ws_opts['early-data-header']
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            params['serviceName'] = grpc_opts.get('grpc-service-name', '')
            if grpc_opts.get('mode'): params['mode'] = grpc_opts['mode']
        
        final_params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urllib.parse.urlencode(final_params, quote_via=urllib.parse.quote)
        return f"vless://{uuid_val}@{server}:{port}?{query_string}#{name}"

    elif proxy_type == 'hysteria2' or proxy_type == 'hy2':
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
            params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']) if isinstance(proxy['alpn'], list) else proxy['alpn'], safe='')}")
        if proxy.get('obfs'):
            params.append(f"obfs={proxy['obfs']}")
            if proxy.get('obfs-password'):
                params.append(f"obfsParam={urllib.parse.quote(proxy['obfs-password'], safe='')}")
        params_str = '&'.join(params) if params else ''
        return f"hysteria2://{password}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"
    
    elif proxy_type == 'tuic':
        uuid_val = proxy.get('uuid')
        password = proxy.get('password')
        if not all([uuid_val, password, server, port]):
            logger.debug(f"TUIC 代理 {name} 缺少 UUID、密码、服务器或端口: {proxy}")
            return None
        params = []
        if proxy.get('version'): params.append(f"version={proxy['version']}")
        if proxy.get('udp-relay-mode'): params.append(f"udp_relay_mode={proxy['udp-relay-mode']}")
        if proxy.get('enable-sni', True):
            if proxy.get('sni'): params.append(f"sni={urllib.parse.quote(proxy['sni'], safe='')}")
            else: params.append(f"sni={server}")
        if proxy.get('skip-cert-verify', False): params.append("insecure=1")
        if proxy.get('alpn'): params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']) if isinstance(proxy['alpn'], list) else proxy['alpn'], safe='')}")
        if proxy.get('disable-udp-relay', False): params.append("disable_udp_relay=true")
        if proxy.get('reduce-rtt'): params.append("reduce_rtt=true")
        if proxy.get('heartbeat-interval'): params.append(f"heartbeat_interval={proxy['heartbeat-interval']}")
        params_str = '&'.join(params) if params else ''
        return f"tuic://{uuid_val}:{password}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"

    elif proxy_type == 'ssr':
        password = proxy.get('password', '')
        cipher = proxy.get('cipher', 'auto')
        protocol = proxy.get('protocol', 'origin')
        obfs = proxy.get('obfs', 'plain')
        obfs_param = proxy.get('obfs-param', '')
        protocol_param = proxy.get('protocol-param', '')
        group = proxy.get('group', '')
        
        password_b64 = encode_base64(password)
        remark_b64 = encode_base64(urllib.parse.unquote(name))
        
        ssr_core = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{password_b64}"
        params_list = []
        if protocol_param: params_list.append(f"protoparam={encode_base64(protocol_param)}")
        if obfs_param: params_list.append(f"obfsparam={encode_base64(obfs_param)}")
        if group: params_list.append(f"group={encode_base64(group)}")
        
        query_string = "&".join(params_list)
        if query_string:
            ssr_core += f"/?{query_string}"
        
        if remark_b64:
            ssr_core += f"#{remark_b64}"
        
        return f"ssr://{encode_base64(ssr_core)}"

    elif proxy_type == 'snell':
        psk = proxy.get('psk', '')
        if not all([psk, server, port]):
            logger.debug(f"Snell 代理 {name} 缺少 PSK、服务器或端口: {proxy}")
            return None
        
        params = []
        if proxy.get('version'): params.append(f"version={proxy['version']}")
        if proxy.get('obfs'): params.append(f"obfs={proxy['obfs']}")
        if proxy.get('obfs-host'): params.append(f"obfs-host={urllib.parse.quote(proxy['obfs-host'], safe='')}")
        
        params_str = '&'.join(params) if params else ''
        return f"snell://{urllib.parse.quote(psk, safe='')}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"
    
    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}")
    return None

def extract_nodes(content: str, decode_depth: int = 0) -> List[str]:
    """从内容中提取代理节点，支持多种格式。"""
    nodes_found = set()
    
    if not content or decode_depth > MAX_BASE64_DECODE_DEPTH:
        return []

    # 优化: 对原始内容进行初步清理，以防后续正则和BeautifulSoup处理更顺畅
    cleaned_initial_content = clean_html_tags(content)
    
    # 优先处理直接的节点模式匹配
    for pattern_key, pattern_val in NODE_PATTERNS.items():
        # 对清理后的内容进行正则匹配
        matches = re.findall(pattern_val, cleaned_initial_content, re.MULTILINE | re.IGNORECASE)
        for node in matches:
            # 再次清理单个节点，以防万一
            cleaned_node = clean_html_tags(node) 
            nodes_found.add(normalize_node_url(cleaned_node))

    try:
        soup = BeautifulSoup(content, 'html.parser') # 使用原始内容进行HTML解析
        for tag in soup.find_all(True):
            for attr in ['href', 'src', 'data-url', 'data-node', 'data-config', 'data-link', 'data-href', 'content']:
                if attr in tag.attrs and tag.attrs[attr]:
                    link_val = tag.attrs[attr].strip()
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(link_val)
                    if b64_match:
                        decoded_attr = decode_base64(b64_match.group(1))
                        if decoded_attr:
                            # 优化: 对解码后的内容进行清理再递归
                            nodes_found.update(extract_nodes(clean_html_tags(decoded_attr), decode_depth + 1))
                    
                    # 优化: 对直接匹配到的链接值进行清理
                    if re.match(COMBINED_REGEX_PATTERN, link_val, re.IGNORECASE):
                        nodes_found.add(normalize_node_url(clean_html_tags(link_val)))
        
        # 处理 HTML 注释中的内容
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment).strip()
            # 优化: 对注释文本进行清理再进行正则匹配
            cleaned_comment_text = clean_html_tags(comment_text)
            
            if re.search(COMBINED_REGEX_PATTERN, cleaned_comment_text, re.MULTILINE | re.IGNORECASE):
                for pattern_val in NODE_PATTERNS.values():
                    matches = re.findall(pattern_val, cleaned_comment_text, re.MULTILINE | re.IGNORECASE)
                    for node in matches:
                        nodes_found.add(normalize_node_url(clean_html_tags(node))) # 优化: 对匹配到的节点进行清理
            
            base64_matches = BASE64_REGEX_LOOSE.findall(cleaned_comment_text) # 优化: 在清理后的注释文本中查找Base64
            for b64_match_tuple in base64_matches:
                b64_str = b64_match_tuple[0]
                decoded_comment_content = decode_base64(b64_str)
                if decoded_comment_content:
                    nodes_found.update(extract_nodes(clean_html_tags(decoded_comment_content), decode_depth + 1)) # 优化: 对解码内容清理再递归

    except Exception as e:
        logger.debug(f"HTML 解析失败: {e}", exc_info=True)

    # 处理 JavaScript 变量
    js_variable_matches = JS_VAR_REGEX.findall(cleaned_initial_content) # 优化: 在清理后的内容中查找JS变量
    for match_group in js_variable_matches:
        js_val = match_group if isinstance(match_group, str) else match_group[0]
        if re.match(COMBINED_REGEX_PATTERN, js_val, re.IGNORECASE):
            nodes_found.add(normalize_node_url(clean_html_tags(js_val))) # 优化: 对JS变量值进行清理
        elif BASE64_REGEX_LOOSE.fullmatch(js_val):
            decoded_js_var = decode_base64(js_val)
            if decoded_js_var:
                nodes_found.update(extract_nodes(clean_html_tags(decoded_js_var), decode_depth + 1)) # 优化: 对解码内容清理再递归
    
    # 处理 JavaScript 函数调用
    js_func_call_matches = JS_FUNC_CALL_REGEX.findall(cleaned_initial_content) # 优化: 在清理后的内容中查找JS函数调用
    for match_group in js_func_call_matches:
        b64_str_in_func = match_group if isinstance(match_group, str) else match_group[0]
        decoded_func_param = decode_base64(b64_str_in_func)
        if decoded_func_param:
            nodes_found.update(extract_nodes(clean_html_tags(decoded_func_param), decode_depth + 1)) # 优化: 对解码内容清理再递归

    try:
        yaml_content = yaml.safe_load(content) # 使用原始内容进行YAML解析
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    # 优化: 对转换后的节点URL进行清理
                    cleaned_url_node = clean_html_tags(url_node)
                    if any(re.match(pattern, cleaned_url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                        nodes_found.add(normalize_node_url(cleaned_url_node))
        elif isinstance(yaml_content, list):
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item:
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node:
                        # 优化: 对转换后的节点URL进行清理
                        cleaned_url_node = clean_html_tags(url_node)
                        if any(re.match(pattern, cleaned_url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                            nodes_found.add(normalize_node_url(cleaned_url_node))
        if isinstance(yaml_content, (dict, list)):
            iterable_content = yaml_content.values() if isinstance(yaml_content, dict) else yaml_content
            for value in iterable_content:
                if isinstance(value, str):
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(value)
                    if b64_match:
                        decoded_sub_content = decode_base64(b64_match.group(1))
                        if decoded_sub_content:
                            nodes_found.update(extract_nodes(clean_html_tags(decoded_sub_content), decode_depth + 1)) # 优化: 对解码内容清理再递归
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败: {e}", exc_info=True)
    except Exception as e:
        logger.debug(f"YAML 内容处理中发生意外错误: {e}", exc_info=True)

    try:
        json_content = json.loads(content) # 使用原始内容进行JSON解析
        if isinstance(json_content, list):
            for config_dict in json_content:
                if isinstance(config_dict, dict) and config_dict.get('v') == '2' and config_dict.get('id'):
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
                        "alpn": config_dict.get('alpn').split(',') if isinstance(config_dict.get('alpn'), str) else config_dict.get('alpn'),
                        "skip-cert-verify": config_dict.get('allowInsecure') == 1,
                        "client-fingerprint": config_dict.get('fp'),
                        "security": config_dict.get('scy')
                    }
                    if config_dict.get('net') == 'ws':
                        clash_vmess_proxy['ws-opts'] = {'path': config_dict.get('path', '/'), 'headers': {'Host': config_dict.get('host')} if config_dict.get('host') else {}}
                    elif config_dict.get('net') == 'grpc':
                        clash_vmess_proxy['grpc-opts'] = {'grpc-service-name': config_dict.get('serviceName', ''), 'mode': config_dict.get('mode')}
                    url_node = convert_clash_proxy_to_url(clash_vmess_proxy)
                    if url_node:
                        # 优化: 对转换后的节点URL进行清理
                        cleaned_url_node = clean_html_tags(url_node)
                        if any(re.match(pattern, cleaned_url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                            nodes_found.add(normalize_node_url(cleaned_url_node))
                elif isinstance(config_dict, dict) and 'protocol' in config_dict and 'settings' in config_dict:
                    protocol_type = config_dict['protocol'].lower()
                    if protocol_type in [p for p in NODE_PATTERNS.keys()]:
                        outbound_settings = config_dict['settings'].get('vnext', [{}])[0] if protocol_type in ['vmess', 'vless'] else config_dict['settings']
                        users = outbound_settings.get('users', [{}])
                        for user_config in users:
                            stream_settings = config_dict.get('streamSettings', {})
                            proxy_cfg: Dict[str, Any] = {
                                "type": protocol_type,
                                "name": user_config.get('id', user_config.get('email', f"{protocol_type}_node")),
                                "server": outbound_settings.get('address') or user_config.get('address'),
                                "port": outbound_settings.get('port') or user_config.get('port'),
                            }
                            if protocol_type == 'vmess':
                                proxy_cfg.update({
                                    "uuid": user_config.get('id'),
                                    "alterId": user_config.get('alterId', 0),
                                    "cipher": user_config.get('security', 'auto'),
                                })
                            elif protocol_type == 'vless':
                                proxy_cfg.update({
                                    "uuid": user_config.get('id'),
                                    "flow": user_config.get('flow'),
                                })
                            elif protocol_type == 'trojan':
                                proxy_cfg.update({
                                    "password": user_config.get('password'),
                                })
                            network = stream_settings.get('network', 'tcp')
                            proxy_cfg['network'] = network
                            security = stream_settings.get('security')
                            proxy_cfg['tls'] = (security == 'tls')
                            if security == 'tls':
                                tls_settings = stream_settings.get('tlsSettings', {})
                                proxy_cfg['servername'] = tls_settings.get('serverName')
                                proxy_cfg['alpn'] = tls_settings.get('alpn')
                                proxy_cfg['skip-cert-verify'] = tls_settings.get('allowInsecure', False)
                                proxy_cfg['client-fingerprint'] = tls_settings.get('fingerprint')
                                if tls_settings.get('realitySettings'):
                                    reality_settings = tls_settings['realitySettings']
                                    proxy_cfg['reality-opts'] = {
                                        "publicKey": reality_settings.get('publicKey'),
                                        "shortId": reality_settings.get('shortId'),
                                        "spiderX": reality_settings.get('spiderX'),
                                        "dest": reality_settings.get('dest'),
                                        "serverName": reality_settings.get('serverName')
                                    }
                            if network == 'ws':
                                ws_settings = stream_settings.get('wsSettings', {})
                                proxy_cfg['ws-opts'] = {
                                    'path': ws_settings.get('path', '/'),
                                    'headers': ws_settings.get('headers', {})
                                }
                            elif network == 'grpc':
                                grpc_settings = stream_settings.get('grpcSettings', {})
                                proxy_cfg['grpc-opts'] = {
                                    'grpc-service-name': grpc_settings.get('serviceName', ''),
                                    'mode': grpc_settings.get('mode')
                                }
                            elif network == 'kcp':
                                kcp_settings = stream_settings.get('kcpSettings', {})
                                proxy_cfg['kcp-opts'] = {
                                    'mtu': kcp_settings.get('mtu', 1350),
                                    'tti': kcp_settings.get('tti', 50),
                                    'uplinkCapacity': kcp_settings.get('uplinkCapacity', 12),
                                    'downlinkCapacity': kcp_settings.get('downlinkCapacity', 100),
                                    'congestion': kcp_settings.get('congestion', False),
                                    'readBufferSize': kcp_settings.get('readBufferSize', 2),
                                    'writeBufferSize': kcp_settings.get('writeBufferSize', 2),
                                    'header': kcp_settings.get('header', {}).get('type', 'none'),
                                    'seed': kcp_settings.get('seed', '')
                                }
                            elif network == 'quic':
                                quic_settings = stream_settings.get('quicSettings', {})
                                proxy_cfg['quic-opts'] = {
                                    'security': quic_settings.get('security', 'none'),
                                    'key': quic_settings.get('key', ''),
                                    'header': quic_settings.get('header', {}).get('type', 'none')
                                }
                            url_node = convert_clash_proxy_to_url(proxy_cfg)
                            if url_node:
                                # 优化: 对转换后的节点URL进行清理
                                cleaned_url_node = clean_html_tags(url_node)
                                if any(re.match(pattern, cleaned_url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                                    nodes_found.add(normalize_node_url(cleaned_url_node))
        elif isinstance(json_content, dict) and 'proxies' in json_content:
            for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    # 优化: 对转换后的节点URL进行清理
                    cleaned_url_node = clean_html_tags(url_node)
                    if any(re.match(pattern, cleaned_url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                        nodes_found.add(normalize_node_url(cleaned_url_node))
        if isinstance(json_content, (dict, list)):
            iterable_content = json_content.values() if isinstance(json_content, dict) else json_content
            for value in iterable_content:
                if isinstance(value, str):
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(value)
                    if b64_match:
                        decoded_sub_content = decode_base64(b64_match.group(1))
                        if decoded_sub_content:
                            nodes_found.update(extract_nodes(clean_html_tags(decoded_sub_content), decode_depth + 1)) # 优化: 对解码内容清理再递归
    except json.JSONDecodeError as e:
        logger.debug(f"JSON 解析失败: {e}", exc_info=True)
    except Exception as e:
        logger.debug(f"JSON 内容处理中发生意外错误: {e}", exc_info=True)

    if decode_depth < MAX_BASE64_DECODE_DEPTH:
        base64_candidates = BASE64_REGEX_LOOSE.findall(cleaned_initial_content) # 优化: 在清理后的内容中查找Base64
        for b64_candidate_tuple in base64_candidates:
            b64_str = b64_candidate_tuple[0]
            if len(b64_str) < 50:
                continue
            decoded_content_full = decode_base64(b64_str)
            if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != content:
                nodes_found.update(extract_nodes(clean_html_tags(decoded_content_full), decode_depth + 1)) # 优化: 对解码内容清理再递归

    final_filtered_nodes = [
        node for node in nodes_found if any(re.match(pattern, node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()) and len(node) > 20
    ]
    return sorted(list(final_filtered_nodes))

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3, backoff_factor: float = 0.5):
    """带重试机制的 HTTP GET 请求。"""
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=timeout, headers={'User-Agent': UA.random}) as response:
                response.raise_for_status()  # 检查 HTTP 错误状态
                content_type = response.headers.get('Content-Type', '').lower()
                if 'charset=' in content_type:
                    charset = content_type.split('charset=')[-1].strip()
                    if charset:
                        return await response.text(encoding=charset, errors='ignore')
                return await response.text(errors='ignore')
        except aiohttp.ClientError as e:
            logger.warning(f"获取 {url} 失败 (尝试 {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
    logger.error(f"多次尝试后获取 {url} 失败。")
    return None

async def fetch_with_browser(url: str, timeout: int) -> Optional[str]:
    """使用无头浏览器获取网页内容。"""
    logger.info(f"尝试使用浏览器获取 {url}")
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            await page.goto(url, timeout=timeout * 1000)  # Playwright timeout is in milliseconds
            content = await page.content()
            await browser.close()
            logger.info(f"成功使用浏览器获取 {url}")
            return content
    except Exception as e:
        logger.error(f"使用浏览器获取 {url} 失败: {e}")
        return None

async def process_source(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    use_browser: bool,
    unique_nodes: Set[str],
    url_counts: Dict[str, int],
    failed_urls: Set[str],
    semaphore: asyncio.Semaphore
):
    """处理单个源 URL，提取并去重节点。"""
    async with semaphore:
        logger.info(f"正在处理来源: {url}")
        content = await fetch_with_retry(session, url, timeout)
        
        if not content and use_browser:
            content = await fetch_with_browser(url, timeout)

        if content:
            extracted = extract_nodes(content)
            new_nodes_count = 0
            for node in extracted:
                if node not in unique_nodes:
                    unique_nodes.add(node)
                    new_nodes_count += 1
            url_counts[url] = len(extracted)  # 记录该 URL 提取到的节点总数
            logger.info(f"从 {url} 提取到 {len(extracted)} 个节点，其中 {new_nodes_count} 个是新节点。")
        else:
            failed_urls.add(url)
            url_counts[url] = 0
            logger.error(f"无法从 {url} 获取内容。")

async def main():
    args = setup_argparse()

    sources_file_path = args.sources
    output_file_path = args.output
    stats_output_path = args.stats_output
    max_concurrency = args.max_concurrency
    timeout = args.timeout
    chunk_size_mb = args.chunk_size_mb
    use_browser = args.use_browser

    # 确保输出目录存在
    output_dir = os.path.dirname(output_file_path)
    os.makedirs(output_dir, exist_ok=True)

    sources = []
    try:
        with open(sources_file_path, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        logger.error(f"源文件未找到: {sources_file_path}")
        return
    except Exception as e:
        logger.error(f"读取源文件时发生错误: {e}")
        return

    unique_nodes: Set[str] = set()
    url_counts: Dict[str, int] = defaultdict(int)
    failed_urls: Set[str] = set()
    semaphore = asyncio.Semaphore(max_concurrency)

    connector = aiohttp.TCPConnector(limit=max_concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            process_source(session, url, timeout, use_browser, unique_nodes, url_counts, failed_urls, semaphore)
            for url in sources
        ]
        await asyncio.gather(*tasks)

    # --- 节点去重和保存 ---
    sorted_unique_nodes = sorted(list(unique_nodes))
    total_nodes_found = len(sorted_unique_nodes)
    logger.info(f"共找到 {total_nodes_found} 个唯一节点。")

    if not sorted_unique_nodes:
        logger.info("没有找到任何节点，跳过文件保存。")
        # --- 统计数据保存为 CSV ---
        stats_output_dir = os.path.dirname(stats_output_path)
        os.makedirs(stats_output_dir, exist_ok=True)
        try:
            with open(stats_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Source_URL', 'Nodes_Found', 'Status']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                sorted_url_counts = sorted(url_counts.items())
                for url, count in sorted_url_counts:
                    status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点")
                    writer.writerow({'Source_URL': url, 'Nodes_Found': count, 'Status': status})
            logger.info(f"节点统计数据已保存到 {stats_output_path}")
        except Exception as e:
            logger.error(f"保存节点统计数据时发生错误: {e}")
        return

    # 分片保存逻辑
    chunk_size_bytes = chunk_size_mb * 1024 * 1024
    current_node_idx = 0
    file_count = 0

    while current_node_idx < total_nodes_found:
        file_count += 1
        output_path = os.path.join(output_dir, f"nodes_part_{file_count:03d}.txt")
        
        nodes_for_current_file = []
        current_file_size = 0
        
        for i in range(current_node_idx, total_nodes_found):
            node_line = sorted_unique_nodes[i] + '\n'
            node_size = len(node_line.encode('utf-8'))
            
            if current_file_size + node_size > chunk_size_bytes and nodes_for_current_file:
                # 如果添加当前节点会超出最大文件大小，并且当前文件已有内容，则停止添加
                break
            
            nodes_for_current_file.append(node_line)
            current_file_size += node_size
            
        end_node_idx = current_node_idx + len(nodes_for_current_file)
        
        if nodes_for_current_file:
            content_to_write = "".join(nodes_for_current_file)
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content_to_write)
                file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
                logger.info(f"已将 {len(nodes_for_current_file)} 个节点保存到 {output_path} ({file_size_mb:.2f} MB)")
                current_node_idx = end_node_idx
            except Exception as e:
                logger.error(f"保存分片文件 '{output_path}' 时发生错误: {e}")
                current_node_idx = end_node_idx
                continue

    # --- 统计数据保存为 CSV ---
    stats_output_path = args.stats_output
    stats_output_dir = os.path.dirname(stats_output_path)
    os.makedirs(stats_output_dir, exist_ok=True)

    try:
        with open(stats_output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Source_URL', 'Nodes_Found', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            sorted_url_counts = sorted(url_counts.items())
            for url, count in sorted_url_counts:
                status = "成功" if count > 0 else ("失败" if url in failed_urls else "无节点")
                writer.writerow({'Source_URL': url, 'Nodes_Found': count, 'Status': status})
        logger.info(f"节点统计数据已保存到 {stats_output_path}")
    except Exception as e:
        logger.error(f"保存节点统计数据时发生错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())
