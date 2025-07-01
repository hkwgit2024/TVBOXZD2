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
from typing import List, Dict, Set, Optional, Any
from datetime import datetime
from bs4 import BeautifulSoup, Comment
from fake_useragent import UserAgent
from playwright.async_api import async_playwright, Page, BrowserContext # 引入 Playwright

# --- 配置 ---
LOG_FILE = 'proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_OUTPUT_FILE = 'data/nodes.txt' # 基础输出文件名，分片时会加上后缀
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20
MAX_BASE64_DECODE_DEPTH = 3 # 限制Base64递归解码的深度
UA = UserAgent() # 初始化 UserAgent

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
# 注意：这里不再包含 (?i) 标志，它会在 re.compile 时统一添加
# 已禁用 HTTP 和 SOCKS5 代理的提取
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
    # 'http': r'https?://[^\s#]+(?:#[^\n]*)?', # 已禁用 HTTP/HTTPS 代理提取
    # 'socks5': r'socks5://[^\s#]+(?:#[^\n]*)?', # 已禁用 Socks5 代理提取
}
COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values())

# 更强大的 Base64 正则表达式，考虑更复杂的 Base64 片段
# 注意：这里移除了 (?i) 标志，由 re.compile 统一处理 IGNORECASE
BASE64_RAW_PATTERN = r'(?:b64|base64|data:application\/octet-stream;base64,)?\s*["\']?((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))["\']?\s*'
BASE64_REGEX_LOOSE = re.compile(
    BASE64_RAW_PATTERN,
    re.MULTILINE | re.IGNORECASE # 在这里统一添加 IGNORECASE
)

# 正则表达式用于从 JavaScript 变量和函数调用中提取可能的节点字符串
# 确保所有拼接的模式都是原始字符串，外部统一添加标志
JS_VAR_REGEX = re.compile(r'(?:var|let|const)\s+[\w]+\s*=\s*["\'](' + COMBINED_REGEX_PATTERN + r'|' + BASE64_RAW_PATTERN + r')["\']', re.MULTILINE | re.IGNORECASE)
JS_FUNC_CALL_REGEX = re.compile(r'(?:atob|decodeURIComponent)\s*\(\s*["\']?(' + BASE64_RAW_PATTERN + r')["\']?\s*\)', re.MULTILINE | re.IGNORECASE)


# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='代理节点提取和去重工具')
    parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'包含源 URL 的输入文件路径 (默认为: {DEFAULT_SOURCES_FILE})')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_FILE, help=f'提取到的节点输出文件路径 (默认为: {DEFAULT_OUTPUT_FILE})')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认为: {DEFAULT_MAX_CONCURRENCY})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认为: {DEFAULT_TIMEOUT})')
    parser.add_argument('--use-browser', action='store_true', help='当HTTP请求失败时，尝试使用无头浏览器（Playwright）')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    """解码 Base64 字符串，并修复可能存在的填充问题，清理非 Base64 字符。"""
    try:
        # 移除所有非 Base64 字符 (包括空格、换行符、HTML 实体等可能干扰字符)
        cleaned_data = re.sub(r'[^A-Za-z0-9+/=]', '', data)
        # URL 安全 Base64 转换
        cleaned_data = cleaned_data.replace('-', '+').replace('_', '/')
        # 添加缺失的填充字符
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
        return data # 编码失败则返回原数据

def normalize_node_url(url: str) -> str:
    """规范化节点 URL 以提高去重效率，保持关键参数一致。"""
    try:
        protocol, _, rest = url.partition('://')
        if not protocol or protocol.lower() not in NODE_PATTERNS:
            logger.debug(f"无法识别协议或不支持的协议: {url}")
            return url # 如果不是已知协议，不进行规范化

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

            # 定义一个固定顺序的键列表，用于规范化 JSON 结构
            ordered_keys = [
                'v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'tls',
                'sni', 'host', 'path', 'serviceName', 'alpn', 'fp', 'allowInsecure',
                'maxEarlyData', 'earlyDataHeader', 'mode', 'method', 'scy'
            ]
            clean_config = {}
            for k in ordered_keys:
                if k in config and config[k] is not None:
                    if k == 'ps': # 确保名称解码
                        clean_config[k] = urllib.parse.unquote(str(config[k]))
                    elif k in ['port', 'aid']: # 确保是整数
                        try:
                            clean_config[k] = int(config[k])
                        except (ValueError, TypeError):
                            clean_config[k] = 0 if k == 'aid' else 0 # 默认值
                            logger.debug(f"VMess 字段 '{k}' 类型转换失败: {config[k]}")
                    elif k == 'alpn' and isinstance(config[k], list): # 确保 alpn 是字符串逗号分隔
                        clean_config[k] = ','.join(sorted(config[k]))
                    else:
                        clean_config[k] = config[k]
            
            # 确保 ps 存在
            if 'ps' not in clean_config: clean_config['ps'] = ''
            # 移除默认的 aid=0 和 v=2，减少冗余
            final_config_to_encode = {k: v for k, v in clean_config.items() if not (k == 'aid' and v == 0) and not (k == 'v' and v == '2')}
            
            return f"vmess://{encode_base64(json.dumps(final_config_to_encode, ensure_ascii=False, sort_keys=True))}"
        
        elif protocol_lower == 'ssr':
            try:
                decoded_ssr_full = decode_base64(rest)
                if not decoded_ssr_full:
                    logger.debug(f"SSR Base64解码失败: {url}")
                    return url
                
                # 分割核心部分和参数部分
                core_part_match = re.match(r'([^/?#]+)(.*)', decoded_ssr_full)
                if not core_part_match:
                    raise ValueError("SSR 链接核心部分解析失败")
                core_part = core_part_match.group(1)
                
                # host:port:protocol:method:obfs:password_base64
                parts = core_part.split(':')
                if len(parts) < 6:
                    raise ValueError(f"SSR 核心部分参数不足，预期6个，实际{len(parts)}")
                
                host, port, protocol_name, method, obfs_name = parts[0:5]
                password_encoded_val = parts[5].split('/')[0].split('?')[0].split('#')[0] # Get password before any URL query/fragment

                # Parse URL query and fragment (remarks)
                full_url_tail = core_part_match.group(2) # Contains ?params#remarks
                parsed_tail = urllib.parse.urlparse(full_url_tail)
                
                query_params_raw = urllib.parse.parse_qs(parsed_tail.query)
                fragment_raw = parsed_tail.fragment

                clean_params = {}
                # Parameters to decode and re-encode: protoparam, obfsparam, group
                # Ensure consistent key order and encoding/decoding
                for k in sorted(query_params_raw.keys()):
                    val = query_params_raw[k][0] if isinstance(query_params_raw[k], list) else query_params_raw[k]
                    # Specific SSR params might be base64 encoded
                    if k in ['protoparam', 'obfsparam', 'group']:
                        decoded_val = decode_base64(val)
                        if decoded_val:
                            clean_params[k] = encode_base64(decoded_val) # Re-encode for consistency
                        else:
                            clean_params[k] = encode_base64(val) # Fallback if decoding fails
                    else:
                        clean_params[k] = urllib.parse.quote(urllib.parse.unquote(val), safe='')
                
                query_string = urllib.parse.urlencode(clean_params, quote_via=urllib.parse.quote)
                
                # Remark might be Base64 encoded
                remark_decoded = decode_base64(fragment_raw) if fragment_raw else ''
                remark_encoded = encode_base64(remark_decoded) if remark_decoded else ''

                # Reconstruct SSR link's core part
                normalized_core = f"{host}:{port}:{protocol_name}:{method}:{obfs_name}:{password_encoded_val}"
                
                # Concatenate query parameters and remark
                if query_string:
                    normalized_core += f"/?{query_string}"
                if remark_encoded:
                    normalized_core += f"#{remark_encoded}"
                
                return f"ssr://{encode_base64(normalized_core)}"
            except Exception as e:
                logger.debug(f"SSR 链接规范化失败 ('{url}')：{e}", exc_info=True)
                return url
        else:
            # 通用协议规范化 (ss, trojan, vless, hysteria2, hy2, tuic, snell, http, socks5)
            # 注意：如果 NODE_PATTERNS 中移除了 http/socks5，此处也自然不会处理它们
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
            "ps": urllib.parse.unquote(name), # 确保 Clash name 解码
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
        # MKCP/QUIC/HTTP/DS... (Clash 对这些直接支持不直接转换)

        final_config = {k: v for k, v in config.items() if v is not None and v != '' and not (k == 'aid' and v == 0) and not (k == 'v' and v == '2')}
        
        try:
            return f"vmess://{encode_base64(json.dumps(final_config, ensure_ascii=False, sort_keys=True))}" # Sort keys for consistency
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
                reality_opts = proxy['reality-opts']
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
    
    # elif proxy_type in ['http', 'socks5']: # 简单的 HTTP/SOCKS5 代理 (已禁用)
    #     auth_str = ""
    #     if proxy.get('username') and proxy.get('password'):
    #         auth_str = f"{urllib.parse.quote(proxy['username'], safe='')}:{urllib.parse.quote(proxy['password'], safe='')}@"
    #     return f"{proxy_type}://{auth_str}{server}:{port}#{name}"

    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}")
    return None

def extract_nodes(content: str, decode_depth: int = 0) -> List[str]:
    """
    从内容中提取代理节点，支持多种格式。
    """
    nodes_found = set()
    
    if not content or decode_depth > MAX_BASE64_DECODE_DEPTH:
        return []

    # 统一换行符
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # 策略 1: 直接匹配标准订阅链接
    for pattern_key, pattern_val in NODE_PATTERNS.items():
        # 这里使用 re.IGNORECASE 是因为 NODE_PATTERNS 中的值本身不带 (?i)
        matches = re.findall(pattern_val, content, re.MULTILINE | re.IGNORECASE)
        for node in matches:
            nodes_found.add(normalize_node_url(node))
            # 已经禁用了HTTP/SOCKS5的NODE_PATTERNS，所以此处的短链接过滤不再针对它们
            # 如果将来重新启用，需要考虑短链接误报问题
            # if pattern_key in ['http', 'socks5'] and len(node) < 30: # 避免短链接污染
            #     logger.debug(f"可能误报的短HTTP/SOCKS链接: {node}")

    # 策略 2: 增强 HTML 解析 (使用 BeautifulSoup)
    try:
        soup = BeautifulSoup(content, 'html.parser')
        
        # 检查所有标签的 href, src, data-* 属性
        for tag in soup.find_all(True):
            for attr in ['href', 'src', 'data-url', 'data-node', 'data-config', 'data-link', 'data-href', 'content']: # content for meta tags
                if attr in tag.attrs and tag.attrs[attr]:
                    link_val = tag.attrs[attr].strip()
                    
                    # 尝试解码 Base64 属性值
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(link_val) # BASE64_REGEX_LOOSE 已包含 IGNORECASE
                    if b64_match:
                        decoded_attr = decode_base64(b64_match.group(1)) # 取捕获组1
                        if decoded_attr:
                            nodes_found.update(extract_nodes(decoded_attr, decode_depth + 1))
                    
                    # 检查属性值是否是直接的节点链接
                    # 再次使用 COMBINED_REGEX_PATTERN 并手动添加 IGNORECASE
                    if re.match(COMBINED_REGEX_PATTERN, link_val, re.IGNORECASE):
                        nodes_found.add(normalize_node_url(link_val))
        
        # 检查 HTML 注释中的内容
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment).strip()
            # 尝试在注释中匹配节点链接
            if re.search(COMBINED_REGEX_PATTERN, comment_text, re.MULTILINE | re.IGNORECASE):
                for pattern_val in NODE_PATTERNS.values():
                    matches = re.findall(pattern_val, comment_text, re.MULTILINE | re.IGNORECASE)
                    for node in matches:
                        nodes_found.add(normalize_node_url(node))
            # 尝试在注释中匹配 Base64 字符串
            base64_matches = BASE64_REGEX_LOOSE.findall(comment_text) # BASE64_REGEX_LOOSE 已包含 IGNORECASE
            for b64_match_tuple in base64_matches:
                b64_str = b64_match_tuple[0]
                decoded_comment_content = decode_base64(b64_str)
                if decoded_comment_content:
                    nodes_found.update(extract_nodes(decoded_comment_content, decode_depth + 1))

    except Exception as e:
        logger.debug(f"HTML 解析失败: {e}", exc_info=True)

    # 策略 3: 尝试从 JavaScript 变量和函数调用中提取
    # JS_VAR_REGEX 和 JS_FUNC_CALL_REGEX 已经包含了正确的标志
    js_variable_matches = JS_VAR_REGEX.findall(content)
    for match_group in js_variable_matches:
        js_val = match_group if isinstance(match_group, str) else match_group[0]
        if re.match(COMBINED_REGEX_PATTERN, js_val, re.IGNORECASE): # 确认是节点链接
            nodes_found.add(normalize_node_url(js_val))
        elif BASE64_REGEX_LOOSE.fullmatch(js_val): # 确认是 Base64 字符串
            decoded_js_var = decode_base64(js_val)
            if decoded_js_var:
                nodes_found.update(extract_nodes(decoded_js_var, decode_depth + 1))
    
    # 提取 JS 函数调用中的 Base64 字符串 (atob, decodeURIComponent)
    js_func_call_matches = JS_FUNC_CALL_REGEX.findall(content)
    for match_group in js_func_call_matches:
        b64_str_in_func = match_group if isinstance(match_group, str) else match_group[0]
        decoded_func_param = decode_base64(b64_str_in_func)
        if decoded_func_param:
            nodes_found.update(extract_nodes(decoded_func_param, decode_depth + 1))


    # 策略 4: 尝试 YAML (Clash) 配置解析
    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    # 再次检查转换后的节点是否符合当前启用的协议类型
                    if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                        nodes_found.add(normalize_node_url(url_node))
        elif isinstance(yaml_content, list): # 有些订阅直接是代理列表
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item:
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node:
                        if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                            nodes_found.add(normalize_node_url(url_node))
        # 递归检查 YAML 中的字符串值是否是 Base64 编码的订阅
        if isinstance(yaml_content, (dict, list)):
            iterable_content = yaml_content.values() if isinstance(yaml_content, dict) else yaml_content
            for value in iterable_content:
                if isinstance(value, str):
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(value)
                    if b64_match:
                        decoded_sub_content = decode_base64(b64_match.group(1))
                        if decoded_sub_content:
                            nodes_found.update(extract_nodes(decoded_sub_content, decode_depth + 1))
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败: {e}", exc_info=True)
    except Exception as e:
        logger.debug(f"YAML 内容处理中发生意外错误: {e}", exc_info=True)


    # 策略 5: 尝试 JSON 解析 (Vmess/Clash/V2Ray 原生配置或其他 JSON 结构)
    try:
        json_content = json.loads(content)
        if isinstance(json_content, list):
            for config_dict in json_content:
                # 尝试作为 Vmess JSON (兼容 V2Ray JSON config for VMess)
                if isinstance(config_dict, dict) and config_dict.get('v') == '2' and config_dict.get('id'):
                    clash_vmess_proxy = {
                        "type": "vmess", "name": config_dict.get('ps', 'vmess_node'), "server": config_dict.get('add'),
                        "port": config_dict.get('port'), "uuid": config_dict.get('id'), "alterId": config_dict.get('aid', 0),
                        "cipher": config_dict.get('type', 'auto'), "network": config_dict.get('net', 'tcp'),
                        "tls": config_dict.get('tls') == 'tls', "servername": config_dict.get('sni') or config_dict.get('host'),
                        "alpn": config_dict.get('alpn').split(',') if isinstance(config_dict.get('alpn'), str) else config_dict.get('alpn'),
                        "skip-cert-verify": config_dict.get('allowInsecure') == 1, "client-fingerprint": config_dict.get('fp'),
                        "security": config_dict.get('scy')
                    }
                    if config_dict.get('net') == 'ws':
                        clash_vmess_proxy['ws-opts'] = {'path': config_dict.get('path', '/'), 'headers': {'Host': config_dict.get('host')} if config_dict.get('host') else {}}
                    elif config_dict.get('net') == 'grpc':
                        clash_vmess_proxy['grpc-opts'] = {'grpc-service-name': config_dict.get('serviceName', ''), 'mode': config_dict.get('mode')}
                    
                    url_node = convert_clash_proxy_to_url(clash_vmess_proxy)
                    if url_node:
                        if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                            nodes_found.add(normalize_node_url(url_node))
                # 尝试作为 V2Ray/Xray 原生出站代理配置
                elif isinstance(config_dict, dict) and 'protocol' in config_dict and 'settings' in config_dict:
                    protocol_type = config_dict['protocol'].lower()
                    # 仅处理当前 NODE_PATTERNS 中支持的协议类型
                    if protocol_type in [p for p in NODE_PATTERNS.keys() if p not in ['http', 'socks5']]:
                        outbound_settings = config_dict['settings'].get('vnext', [{}])[0] if protocol_type in ['vmess', 'vless'] else config_dict['settings']
                        users = outbound_settings.get('users', [{}])
                        
                        for user_config in users:
                            stream_settings = config_dict.get('streamSettings', {})
                            
                            proxy_cfg: Dict[str, Any] = {
                                "type": protocol_type,
                                "name": user_config.get('id', user_config.get('email', f"{protocol_type}_node")), # V2Ray name fallback
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
                            # 禁用 HTTP/SOCKS 处理，所以这里不添加它们
                            # elif protocol_type == 'socks':
                            #     proxy_cfg.update({
                            #         "username": user_config.get('username'),
                            #         # ...
                            #     })
                            # elif protocol_type == 'http':
                            #     proxy_cfg.update({
                            #         "username": user_config.get('username'),
                            #         # ...
                            #     })

                            # Stream Settings parsing
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
                                if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                                    nodes_found.add(normalize_node_url(url_node))

        elif isinstance(json_content, dict) and 'proxies' in json_content: # 可能是 Clash YAML 转换为 JSON
            for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    if any(re.match(pattern, url_node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()):
                        nodes_found.add(normalize_node_url(url_node))
        # 递归检查 JSON 中的字符串值是否是 Base64 编码的订阅
        if isinstance(json_content, (dict, list)):
            iterable_content = json_content.values() if isinstance(json_content, dict) else json_content
            for value in iterable_content:
                if isinstance(value, str):
                    b64_match = BASE64_REGEX_LOOSE.fullmatch(value)
                    if b64_match:
                        decoded_sub_content = decode_base64(b64_match.group(1))
                        if decoded_sub_content:
                            nodes_found.update(extract_nodes(decoded_sub_content, decode_depth + 1))
    except json.JSONDecodeError as e:
        logger.debug(f"JSON 解析失败: {e}", exc_info=True)
    except Exception as e:
        logger.debug(f"JSON 内容处理中发生意外错误: {e}", exc_info=True)


    # 策略 6: 尝试对整个内容进行 Base64 解码，然后再次应用以上策略
    if decode_depth < MAX_BASE64_DECODE_DEPTH:
        base64_candidates = BASE64_REGEX_LOOSE.findall(content)
        for b64_candidate_tuple in base64_candidates:
            b64_str = b64_candidate_tuple[0] # Take the captured group
            if len(b64_str) < 50: # Avoid decoding very short strings
                continue
            decoded_content_full = decode_base64(b64_str)
            if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != content:
                nodes_found.update(extract_nodes(decoded_content_full, decode_depth + 1))

    final_filtered_nodes = [
        node for node in nodes_found 
        if any(re.match(pattern, node, re.IGNORECASE) for pattern in NODE_PATTERNS.values()) 
        and len(node) > 20 # 过滤掉过短的无效匹配
    ]
    return sorted(list(final_filtered_nodes))


async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3, backoff_factor: float = 1.0) -> str:
    """带重试机制地获取 URL 内容，并使用随机 User-Agent 和 Referer。"""
    headers = {
        'User-Agent': UA.random,
        'Referer': url # 伪造 Referer
    }
    for attempt in range(retries):
        try:
            logger.debug(f"尝试获取 URL ({attempt + 1}/{retries}): {url} (User-Agent: {headers['User-Agent']})")
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientError as e: # 统一捕获 aiohttp 客户端错误
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，HTTP/网络错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
        except asyncio.TimeoutError:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，请求超时")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
        except Exception as e: # 捕获其他所有意外错误
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，未知错误: {e}", exc_info=True)
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
    logger.warning(f"在 {retries} 次尝试后未能成功获取 URL: {url}")
    return ""

async def fetch_with_browser(browser_context: BrowserContext, url: str, timeout: int) -> str:
    """使用 Playwright 无头浏览器获取页面内容。"""
    page: Page = await browser_context.new_page()
    page.set_default_timeout(timeout * 1000) # Playwright uses milliseconds
    try:
        logger.info(f"尝试使用浏览器获取 URL: {url}")
        # 在这里可以添加更多的导航选项，例如等待网络空闲
        await page.goto(url, wait_until="networkidle") 
        content = await page.content()
        logger.info(f"成功使用浏览器获取 URL: {url}")
        return content
    except Exception as e:
        logger.warning(f"使用浏览器获取 URL {url} 失败: {e}", exc_info=True)
        return ""
    finally:
        await page.close()


async def process_single_url_strategy(session: aiohttp.ClientSession, url: str, timeout: int, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> Set[str]:
    """尝试获取并处理单个 URL，返回提取到的节点集合。"""
    content = await fetch_with_retry(session, url, timeout)
    
    if not content and use_browser and browser_context:
        content = await fetch_with_browser(browser_context, url, timeout)

    if content:
        return set(extract_nodes(content))
    return set()

async def process_domain(session: aiohttp.ClientSession, domain: str, timeout: int, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set, use_browser: bool, browser_context: Optional[BrowserContext] = None) -> None:
    """处理单个域名，先尝试 http，再尝试 https，并更新结果字典。"""
    nodes_from_domain = set()
    http_url = f"http://{domain}"
    https_url = f"https://{domain}" 
    
    async with semaphore:
        logger.info(f"正在获取: {http_url}")
        http_nodes = await process_single_url_strategy(session, http_url, timeout, use_browser, browser_context)
        
        if http_nodes:
            nodes_from_domain.update(http_nodes)
            url_node_counts[http_url] = len(http_nodes)
            logger.info(f"从 {http_url} 提取到 {len(http_nodes)} 个节点。")
        else:
            url_node_counts[http_url] = 0
            logger.info(f"HTTP 失败或无节点，尝试获取: {https_url}")
            https_nodes = await process_single_url_strategy(session, https_url, timeout, use_browser, browser_context)
            
            if https_nodes:
                nodes_from_domain.update(https_nodes)
                url_node_counts[https_url] = len(https_nodes)
                logger.info(f"从 {https_url} 提取到 {len(https_nodes)} 个节点。")
            else:
                url_node_counts[https_url] = 0
                failed_urls.add(http_url) # 如果https也失败，则记录原始http url为失败
                failed_urls.add(https_url) # 也记录https url为失败
                logger.warning(f"HTTP 和 HTTPS 均未能从 {domain} 提取到节点。")
    
    return nodes_from_domain

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int, use_browser: bool) -> tuple[List[str], Dict, Set]:
    """并发处理去重后的域名，优先尝试 http，失败后尝试 https。"""
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int)
    failed_urls = set()
    all_nodes_collected = set()
    
    browser_context: Optional[BrowserContext] = None
    playwright_instance = None # To manage playwright instance

    if use_browser:
        logger.info("初始化无头浏览器 (Playwright)...")
        try:
            playwright_instance = await async_playwright().start()
            browser = await playwright_instance.chromium.launch() # You can choose chromium, firefox, or webkit
            browser_context = await browser.new_context(
                user_agent=UA.random,
                ignore_https_errors=True,
                viewport={'width': 1280, 'height': 720} # 模拟常见浏览器视口
            )
            # You can add more context options here, like cookies, permissions etc.
        except Exception as e:
            logger.error(f"初始化 Playwright 失败: {e}. 将不使用浏览器模式。", exc_info=True)
            use_browser = False # Disable browser mode if initialization fails
            if playwright_instance:
                # 确保在异常情况下也能正确停止 Playwright
                try:
                    await playwright_instance.stop()
                except Exception as stop_e:
                    logger.error(f"停止 Playwright 实例时发生错误: {stop_e}")


    async with aiohttp.ClientSession() as session:
        tasks = []
        for domain in domains:
            tasks.append(process_domain(session, domain, timeout, semaphore, url_node_counts, failed_urls, use_browser, browser_context))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for nodes_or_exception in results:
            if isinstance(nodes_or_exception, set):
                all_nodes_collected.update(nodes_or_exception)
            elif isinstance(nodes_or_exception, Exception):
                logger.error(f"处理域名时发生未捕获的异常: {nodes_or_exception}", exc_info=True)

    if browser_context:
        try:
            await browser_context.close()
            await browser.close() # 关闭浏览器实例
        except Exception as e:
            logger.error(f"关闭浏览器上下文或实例时发生错误: {e}")
        finally:
            if playwright_instance:
                try:
                    await playwright_instance.stop()
                except Exception as e:
                    logger.error(f"停止 Playwright 实例时发生错误: {e}")

    final_unique_nodes = set()
    for node in all_nodes_collected:
        final_unique_nodes.add(normalize_node_url(node))
            
    return sorted(list(final_unique_nodes)), url_node_counts, failed_urls

# --- 主程序 ---

def main():
    """主函数，负责程序的整体流程。"""
    global args
    args = setup_argparse()
    
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls_raw = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"源文件 '{args.sources}' 未找到。请确保文件存在。")
        return
    
    unique_domains = set()
    for url in urls_raw:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        if not domain and parsed.path: # Try to extract domain from path if no netloc (e.g., just "example.com")
            # 尝试从看似是域名的路径中提取域名
            domain_match = re.match(r'^(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}(?::\d{1,5})?)(?:/.*)?$', parsed.path)
            if domain_match:
                domain = domain_match.group(1).split('/')[0] # 确保只取域名部分
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

    start_time = datetime.now()
    logger.info(f"开始处理 {len(unique_domains)} 个唯一域名...")
    
    unique_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(unique_domains, args.max_concurrency, args.timeout, args.use_browser))
    
    total_nodes_extracted = len(unique_nodes)
    report_lines = [
        f"--- 报告 ---",
        f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒",
        f"总共提取到 {total_nodes_extracted} 个唯一节点。",
        "\n每个源 URL 的节点提取数量:"
    ]
    report_lines.append("{:<70} {:<15} {:<10}".format("源URL", "找到的节点数", "状态"))
    report_lines.append("-" * 95)
    
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
    
    # --- 新增的分片保存逻辑 ---
    output_dir = os.path.dirname(args.output)
    output_filename_base = os.path.splitext(os.path.basename(args.output))[0]
    os.makedirs(output_dir, exist_ok=True)

    # 估算每个节点链接的平均长度，从而估算每文件可以容纳的节点数量
    # 假设平均每个节点链接大约 80 字节（这是一个保守的估计，实际可能更长或更短）
    # GitHub 文件限制 100 MB = 100 * 1024 * 1024 字节
    # 为了安全起见，每个文件目标大小设置为 90 MB
    target_file_size_mb = 90
    target_file_size_bytes = target_file_size_mb * 1024 * 1024
    
    # 一个粗略的估计：假设平均每个节点占用 80 字节
    avg_node_length_bytes = 80 
    # 计算每个文件理论上应该包含的最大节点数量
    max_nodes_per_file = target_file_size_bytes // avg_node_length_bytes

    if total_nodes_extracted == 0:
        logger.info("没有提取到任何节点，跳过保存。")
        return
        
    if total_nodes_extracted <= max_nodes_per_file:
        # 如果总节点数未超过单个文件限制，则保存为单个文件
        output_path = os.path.join(output_dir, f"{output_filename_base}.txt")
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(unique_nodes))
            logger.info(f"已将 {total_nodes_extracted} 个节点保存到 {output_path}")
        except Exception as e:
            logger.error(f"保存节点到 '{output_path}' 时发生错误: {e}")
    else:
        # 进行分片保存
        logger.info(f"节点总数 {total_nodes_extracted} 超过单文件限制，将进行分片保存。")
        
        # 第一次尝试：计算一个粗略的每文件行数
        estimated_lines_per_file = max_nodes_per_file # 初始估计
        
        # 如果节点数量非常庞大，我们最好设定一个最低行数，避免文件碎片化太严重
        min_lines_per_file = 10000 # 至少每个文件包含 1 万行节点

        # 确保 estimated_lines_per_file 不会太小
        if estimated_lines_per_file < min_lines_per_file:
            estimated_lines_per_file = min_lines_per_file
        
        # 计算需要多少个文件
        num_files = (total_nodes_extracted + estimated_lines_per_file - 1) // estimated_lines_per_file
        logger.info(f"预计将分为 {num_files} 个文件，每个文件大约 {estimated_lines_per_file} 行。")

        current_file_idx = 0
        current_node_idx = 0

        while current_node_idx < total_nodes_extracted:
            current_file_idx += 1
            # 确定当前文件的结束索引
            end_node_idx = min(current_node_idx + estimated_lines_per_file, total_nodes_extracted)
            
            # 获取当前文件的节点列表
            nodes_for_current_file = unique_nodes[current_node_idx:end_node_idx]
            
            # 构建输出文件名，例如 data/nodes_part_001.txt
            output_path = os.path.join(output_dir, f"{output_filename_base}_part_{current_file_idx:03d}.txt")
            
            try:
                content_to_write = '\n'.join(nodes_for_current_file)
                # 检查写入内容的大小，如果超过目标大小，则动态减少当前文件的节点数
                while len(content_to_write.encode('utf-8')) > target_file_size_bytes and len(nodes_for_current_file) > 1:
                    logger.warning(f"文件 '{output_path}' 内容过大 ({len(content_to_write.encode('utf-8')) / (1024*1024):.2f} MB)，尝试减少行数。")
                    # 每次减少 10% 的行数，直到满足条件或只剩一行
                    nodes_for_current_file = nodes_for_current_file[:int(len(nodes_for_current_file) * 0.9)]
                    content_to_write = '\n'.join(nodes_for_current_file)
                    end_node_idx = current_node_idx + len(nodes_for_current_file)
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content_to_write)
                
                logger.info(f"已将 {len(nodes_for_current_file)} 个节点保存到 {output_path} ({len(content_to_write.encode('utf-8')) / (1024*1024):.2f} MB)。")
                
                current_node_idx = end_node_idx # 更新索引到下一个文件的起始位置

            except Exception as e:
                logger.error(f"保存节点到 '{output_path}' 时发生错误: {e}")
                # 如果单个文件写入失败，尝试跳过这部分节点，继续处理剩余的
                current_node_idx = end_node_idx 
                break # 或者根据需要选择是跳过还是中断

if __name__ == '__main__':
    main()
