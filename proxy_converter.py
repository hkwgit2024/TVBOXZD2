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
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
import socket
import ssl
import gzip
import math

# --- 配置 ---
LOG_FILE = 'proxy_converter.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DEFAULT_SOURCES_FILE = 'sources.list'
DEFAULT_OUTPUT_FILE = 'data/nodes.txt'
DEFAULT_MAX_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20
DEFAULT_VALIDATE_TIMEOUT = 5
MAX_BASE64_DECODE_DEPTH = 3  # 限制Base64递归解码的深度
DEFAULT_MAX_FILE_SIZE_MB = 90  # 默认最大文件大小（MB），留10MB余量
DEFAULT_NODES_PER_FILE = 5000  # 默认每文件节点数

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

# 支持的节点协议及其正则表达式模式
NODE_PATTERNS = {
    'ss': r'ss://[^\s#]+(?:#[^\n]*)?',
    'vmess': r'vmess://[^\s]+',
    'trojan': r'trojan://[^\s#]+(?:#[^\n]*)?',
    'vless': r'vless://[^\s#]+(?:#[^\n]*)?',
    'hysteria2': r'hysteria2://[^\s#]+(?:#[^\n]*)?',
}
COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values())

# Base64 字符串正则表达式
BASE64_REGEX = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'

# --- 辅助函数 ---

def setup_argparse() -> argparse.Namespace:
    """解析命令行参数，新增分片参数。"""
    parser = argparse.ArgumentParser(description='代理节点提取、去重和验证工具')
    parser.add_argument('--sources', default=DEFAULT_SOURCES_FILE, help=f'输入文件路径 (默认: {DEFAULT_SOURCES_FILE})')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_FILE, help=f'输出文件路径前缀 (默认: {DEFAULT_OUTPUT_FILE})')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY, help=f'最大并发请求数 (默认: {DEFAULT_MAX_CONCURRENCY})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'请求超时时间（秒） (默认: {DEFAULT_TIMEOUT})')
    parser.add_argument('--validate', action='store_true', help='是否验证节点有效性 (默认启用)')
    parser.add_argument('--validate-timeout', type=int, default=DEFAULT_VALIDATE_TIMEOUT, help=f'节点验证超时时间（秒） (默认: {DEFAULT_VALIDATE_TIMEOUT})')
    parser.add_argument('--output-format', choices=['text', 'base64', 'gzip'], default='gzip', help='输出格式: text, base64 或 gzip (默认: gzip)')
    parser.add_argument('--max-file-size', type=float, default=DEFAULT_MAX_FILE_SIZE_MB, help=f'每个输出文件的最大大小（MB） (默认: {DEFAULT_MAX_FILE_SIZE_MB})')
    parser.add_argument('--nodes-per-file', type=int, default=DEFAULT_NODES_PER_FILE, help=f'每个文件的最大节点数 (默认: {DEFAULT_NODES_PER_FILE})')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    """解码 Base64 字符串，修复填充问题并验证格式。"""
    try:
        data = data.strip().replace('-', '+').replace('_', '/')
        padding = len(data) % 4
        if padding:
            data += '=' * (4 - padding)
        if not re.fullmatch(BASE64_REGEX, data):
            logger.debug(f"无效的 Base64 字符串: {data[:50]}...")
            return ""
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"Base64 解码错误: {e}")
        return ""

def encode_base64(data: str) -> str:
    """编码字符串为 URL 安全的 Base64 格式。"""
    encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8').rstrip('=')

def generate_deduplication_key(node: str) -> Optional[str]:
    """生成节点的去重键，基于核心字段以识别重复节点。"""
    try:
        parsed = urllib.parse.urlparse(node)
        protocol = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if protocol == 'vmess':
            config_json = decode_base64(parsed.netloc)
            if not config_json:
                return None
            try:
                config = json.loads(config_json)
                key_fields = [
                    config.get('add', ''),
                    str(config.get('port', '')),
                    config.get('id', ''),
                    config.get('net', ''),
                    config.get('tls', ''),
                    config.get('sni', ''),
                    config.get('host', ''),
                    config.get('path', ''),
                    config.get('type', '')
                ]
                return f"vmess://{':'.join(map(str, key_fields))}"
            except json.JSONDecodeError:
                return None
        else:
            auth = parsed.username or ''
            host_port = netloc.split('@')[-1] if '@' in netloc else netloc
            key_params = []
            for param in sorted(query_params.keys()):
                if param in ['sni', 'type', 'security', 'flow', 'alpn']:
                    key_params.append(f"{param}={query_params[param][0]}")
            return f"{protocol}://{auth}@{host_port}:{'|'.join(key_params)}"
    except Exception as e:
        logger.debug(f"生成去重键失败: {node}, 错误: {e}")
        return None

def normalize_node_url(url: str) -> str:
    """规范化节点 URL，统一格式以便去重。"""
    try:
        protocol, _, rest = url.partition('://')
        if not protocol or protocol not in NODE_PATTERNS:
            logger.debug(f"不支持的协议或无效 URL: {url}")
            return url

        if protocol == 'vmess':
            if not re.fullmatch(BASE64_REGEX, rest):
                logger.debug(f"VMess URL 的 Base64 部分无效: {url}")
                return url
            config_json = decode_base64(rest)
            if not config_json:
                return url
            try:
                config = json.loads(config_json)
            except json.JSONDecodeError as e:
                logger.debug(f"VMess 配置 JSON 解析失败: {url}, 错误: {e}")
                return url
            ordered_keys = [
                'v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'tls',
                'sni', 'host', 'path', 'serviceName', 'alpn', 'fp', 'allowInsecure',
                'maxEarlyData', 'earlyDataHeader', 'mode', 'method', 'scy'
            ]
            clean_config = {k: config.get(k) for k in ordered_keys if config.get(k) is not None}
            if 'v' not in clean_config: clean_config['v'] = '2'
            if 'aid' in clean_config: clean_config['aid'] = int(clean_config['aid'])
            if 'port' in clean_config: clean_config['port'] = int(clean_config['port'])
            if 'ps' not in clean_config: clean_config['ps'] = ''
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}"
        else:
            parsed_url = urllib.parse.urlparse(url)
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
            return f"{protocol}://{auth_part}{host_port}{query_string}{fragment}"
    except Exception as e:
        logger.debug(f"规范化 URL '{url}' 失败: {e}", exc_info=True)
        return url

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 代理配置转换为标准 URL 格式。"""
    proxy_type = proxy.get('type', '').lower()
    name = urllib.parse.quote(urllib.parse.unquote(proxy.get('name', f"{proxy_type}_node").strip()), safe='')
    server = proxy.get('server')
    port = proxy.get('port')

    if not all([server, port, proxy_type]):
        logger.debug(f"缺少 Clash 代理 {name} 的核心信息: {proxy}")
        return None
    try:
        port = int(port)
        if port <= 0 or port > 65535:
            raise ValueError("端口号超出有效范围")
    except (TypeError, ValueError):
        logger.debug(f"Clash 代理 {name} 的端口无效: {port}")
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
                params.append(f"v2ray-plugin-path={urllib.parse.quote( plugin_opts.get('path', ''), safe='')}")
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
            "ps": urllib.parse.unquote(name),
            "add": server,
            "port": port,
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
                config["alpn"] = ",".join(proxy['alpn'])
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
            return f"vmess://{encode_base64(json.dumps(final_config, ensure_ascii=False))}"
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
        if proxy.get('alpn'): params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']), safe='')}")
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
        return f"trojan://{urllib.parse.quote(password, safe='')}@{server}:{port}{query_string}#{name}"

    elif proxy_type == 'vless':
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
            if sni: params['sni'] = sni
            if proxy.get('alpn'): params['alpn'] = ",".join(proxy['alpn'])
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
        return f"vless://{urllib.parse.quote(uuid_val, safe='')}@{server}:{port}?{query_string}#{name}"

    elif proxy_type == 'hysteria2':
        password = proxy.get('password', '')
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
        return f"hysteria2://{urllib.parse.quote(password, safe='')}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"

    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}")
    return None

async def validate_node(node: str, timeout: int) -> bool:
    """验证节点是否可以通过简单的 TCP 连接测试。"""
    try:
        parsed = urllib.parse.urlparse(node)
        if not parsed.netloc:
            return False
        host_port = parsed.netloc.split('@')[-1]
        host, port_str = host_port.split(':') if ':' in host_port else (host_port, '80')
        port = int(port_str)
        
        if parsed.scheme in ['trojan', 'vless', 'hysteria2'] or 'tls=true' in parsed.query.lower():
            context = ssl.create_default_context()
            if 'allowInsecure=1' in parsed.query:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{host}:{port}", ssl=context, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    return response.status < 400
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
    except (asyncio.TimeoutError, socket.gaierror, aiohttp.ClientError, ValueError) as e:
        logger.debug(f"节点验证失败: {node}, 错误: {e}")
        return False

def extract_nodes(content: str, decode_depth: int = 0, seen_keys: Set[str] = None) -> Tuple[List[str], Set[str]]:
    """从内容中提取代理节点，支持去重键。"""
    if seen_keys is None:
        seen_keys = set()
    nodes_found = set()
    
    if not content or decode_depth > MAX_BASE64_DECODE_DEPTH:
        return [], seen_keys

    content = content.replace('\r\n', '\n').replace('\r', '\n')
    content = re.sub(r'<[^>]*>', '', content)
    content = re.sub(r'/\*[\s\S]*?\*/', '', content)
    content = re.sub(r'//.*', '', content)
    content = '\n'.join([line.strip() for line in content.split('\n') if line.strip()])

    for pattern in NODE_PATTERNS.values():
        matches = re.findall(pattern, content, re.MULTILINE)
        for node in matches:
            dedup_key = generate_deduplication_key(node)
            if dedup_key and dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                nodes_found.add(normalize_node_url(node))
    
    quoted_link_matches = re.findall(rf'["\']({COMBINED_REGEX_PATTERN})["\']', content)
    for link in quoted_link_matches:
        if any(re.match(pattern, link) for pattern in NODE_PATTERNS.values()):
            dedup_key = generate_deduplication_key(link)
            if dedup_key and dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                nodes_found.add(normalize_node_url(link))

    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    dedup_key = generate_deduplication_key(url_node)
                    if dedup_key and dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        nodes_found.add(normalize_node_url(url_node))
        elif isinstance(yaml_content, list):
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item:
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node:
                        dedup_key = generate_deduplication_key(url_node)
                        if dedup_key and dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            nodes_found.add(normalize_node_url(url_node))
        if isinstance(yaml_content, (dict, list)):
            for value in (yaml_content.values() if isinstance(yaml_content, dict) else yaml_content):
                if isinstance(value, str) and re.fullmatch(BASE64_REGEX, value) and len(value) > 50:
                    decoded_sub_content = decode_base64(value)
                    if decoded_sub_content:
                        sub_nodes, seen_keys = extract_nodes(decoded_sub_content, decode_depth + 1, seen_keys)
                        nodes_found.update(sub_nodes)
    except yaml.YAMLError:
        pass

    try:
        json_content = json.loads(content)
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
                        "alpn": config_dict.get('alpn').split(',') if config_dict.get('alpn') else None,
                        "skip-cert-verify": config_dict.get('allowInsecure') == 1,
                        "client-fingerprint": config_dict.get('fp'),
                        "security": config_dict.get('scy')
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
                        dedup_key = generate_deduplication_key(url_node)
                        if dedup_key and dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            nodes_found.add(normalize_node_url(url_node))
        elif isinstance(json_content, dict) and 'proxies' in json_content:
            for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    dedup_key = generate_deduplication_key(url_node)
                    if dedup_key and dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        nodes_found.add(normalize_node_url(url_node))
        if isinstance(json_content, (dict, list)):
            for value in (json_content.values() if isinstance(json_content, dict) else json_content):
                if isinstance(value, str) and re.fullmatch(BASE64_REGEX, value) and len(value) > 50:
                    decoded_sub_content = decode_base64(value)
                    if decoded_sub_content:
                        sub_nodes, seen_keys = extract_nodes(decoded_sub_content, decode_depth + 1, seen_keys)
                        nodes_found.update(sub_nodes)
    except json.JSONDecodeError:
        pass

    if decode_depth < MAX_BASE64_DECODE_DEPTH:
        decoded_content_full = decode_base64(content)
        if decoded_content_full and len(decoded_content_full) > 20 and decoded_content_full != content:
            sub_nodes, seen_keys = extract_nodes(decoded_content_full, decode_depth + 1, seen_keys)
            nodes_found.update(sub_nodes)

    final_filtered_nodes = [
        node for node in nodes_found 
        if any(re.match(pattern, node) for pattern in NODE_PATTERNS.values()) 
        and len(node) > 20
    ]
    return sorted(list(final_filtered_nodes)), seen_keys

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: int, retries: int = 3, backoff_factor: float = 1.0) -> str:
    """带重试机制地获取 URL 内容，区分错误类型。"""
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientConnectionError as e:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，连接错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
        except aiohttp.ClientResponseError as e:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，响应错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
        except asyncio.TimeoutError:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: 请求超时")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
    logger.warning(f"在 {retries} 次尝试后未能成功获取 URL: {url}")
    return ""

async def process_single_url_strategy(session: aiohttp.ClientSession, url: str, timeout: int) -> Tuple[Set[str], Set[str]]:
    """处理单个 URL，提取节点并返回去重键。"""
    content = await fetch_with_retry(session, url, timeout)
    if content:
        nodes, seen_keys = extract_nodes(content)
        return set(nodes), seen_keys
    return set(), set()

async def process_domain(session: aiohttp.ClientSession, domain: str, timeout: int, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set) -> Tuple[Set[str], Set[str]]:
    """处理单个域名，优先尝试 http，失败后尝试 https。"""
    nodes_from_domain = set()
    seen_keys = set()
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"

    async with semaphore:
        logger.info(f"正在获取: {http_url}")
        http_nodes, http_keys = await process_single_url_strategy(session, http_url, timeout)
        
        if http_nodes:
            nodes_from_domain.update(http_nodes)
            seen_keys.update(http_keys)
            url_node_counts[http_url] = len(http_nodes)
            logger.info(f"从 {http_url} 提取到 {len(http_nodes)} 个节点。")
        else:
            url_node_counts[http_url] = 0
            logger.info(f"HTTP 失败，尝试获取: {https_url}")
            https_nodes, https_keys = await process_single_url_strategy(session, https_url, timeout)
            
            if https_nodes:
                nodes_from_domain.update(https_nodes)
                seen_keys.update(https_keys)
                url_node_counts[https_url] = len(https_nodes)
                logger.info(f"从 {https_url} 提取到 {len(https_nodes)} 个节点。")
            else:
                url_node_counts[https_url] = 0
                failed_urls.add(http_url)
                failed_urls.add(https_url)
                logger.warning(f"HTTP 和 HTTPS 均未能从 {domain} 提取到节点。")
    
    return nodes_from_domain, seen_keys

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int, validate: bool, validate_timeout: int) -> tuple[List[str], Dict, Set]:
    """并发处理域名，提取并可选验证节点。"""
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int)
    failed_urls = set()
    all_nodes_collected = set()
    all_seen_keys = set()
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for domain in domains:
            tasks.append(process_domain(session, domain, timeout, semaphore, url_node_counts, failed_urls))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple):
                nodes, keys = result
                all_nodes_collected.update(nodes)
                all_seen_keys.update(keys)

    # 去重并规范化
    final_unique_nodes = set()
    dedup_keys = set()
    for node in all_nodes_collected:
        dedup_key = generate_deduplication_key(node)
        if dedup_key and dedup_key not in dedup_keys:
            dedup_keys.add(dedup_key)
            normalized = normalize_node_url(node)
            if normalized != node:
                logger.debug(f"节点规范化: {node} -> {normalized}")
            final_unique_nodes.add(normalized)

    # 可选验证节点
    valid_nodes = []
    if validate:
        logger.info(f"开始验证 {len(final_unique_nodes)} 个节点的有效性...")
        async with aiohttp.ClientSession() as session:
            tasks = [validate_node(node, validate_timeout) for node in final_unique_nodes]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            valid_nodes = [node for node, valid in zip(final_unique_nodes, results) if valid]
            logger.info(f"验证完成，{len(valid_nodes)}/{len(final_unique_nodes)} 个节点有效。")
    else:
        valid_nodes = list(final_unique_nodes)

    return sorted(valid_nodes), url_node_counts, failed_urls

def save_nodes(nodes: List[str], output_prefix: str, output_format: str, max_file_size_mb: float, nodes_per_file: int) -> List[Tuple[str, int]]:
    """将节点保存到分片文件，确保每个文件不超过指定大小或节点数。"""
    output_files = []
    max_file_size_bytes = max_file_size_mb * 1024 * 1024  # 转换为字节
    nodes_str = '\n'.join(nodes)
    total_size = len(nodes_str.encode('utf-8'))
    
    if not nodes:
        logger.info("无节点可保存。")
        return output_files

    # 估算单个节点的平均大小
    avg_node_size = total_size / len(nodes) if nodes else 1
    nodes_per_chunk = min(nodes_per_file, int(max_file_size_bytes / avg_node_size) + 1)
    num_chunks = math.ceil(len(nodes) / nodes_per_chunk)

    logger.info(f"将节点分割为 {num_chunks} 个文件，每文件最多 {nodes_per_chunk} 个节点或 {max_file_size_mb} MB。")

    for i in range(num_chunks):
        start_idx = i * nodes_per_chunk
        end_idx = min((i + 1) * nodes_per_chunk, len(nodes))
        chunk_nodes = nodes[start_idx:end_idx]
        chunk_str = '\n'.join(chunk_nodes)
        chunk_size = len(chunk_str.encode('utf-8'))

        # 确保分片不超过最大文件大小
        if chunk_size > max_file_size_bytes:
            logger.warning(f"分片 {i+1} 大小 {chunk_size/1024/1024:.2f} MB 超过限制，尝试进一步分割...")
            sub_nodes_per_file = int(nodes_per_chunk * max_file_size_bytes / chunk_size)
            sub_chunks = math.ceil(len(chunk_nodes) / sub_nodes_per_file)
            for j in range(sub_chunks):
                sub_start = j * sub_nodes_per_file
                sub_end = min((j + 1) * sub_nodes_per_file, len(chunk_nodes))
                sub_chunk_nodes = chunk_nodes[sub_start:sub_end]
                sub_chunk_str = '\n'.join(sub_chunk_nodes)
                file_suffix = f"_part{i+1}_{j+1}"
                save_single_chunk(sub_chunk_str, output_prefix, file_suffix, output_format, output_files, len(sub_chunk_nodes))
        else:
            file_suffix = f"_part{i+1}"
            save_single_chunk(chunk_str, output_prefix, file_suffix, output_format, output_files, len(chunk_nodes))

    return output_files

def save_single_chunk(chunk_str: str, output_prefix: str, file_suffix: str, output_format: str, output_files: List[Tuple[str, int]]) -> None:
    """保存单个分片到文件。"""
    base, ext = os.path.splitext(output_prefix)
    if output_format == 'gzip' and not ext.endswith('.gz'):
        output_file = f"{base}{file_suffix}.txt.gz"
    else:
        output_file = f"{base}{file_suffix}{ext or '.txt'}"

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        if output_format == 'base64':
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(encode_base64(chunk_str))
        elif output_format == 'gzip':
            with gzip.open(output_file, 'wt', encoding='utf-8') as f:
                f.write(chunk_str)
        else:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(chunk_str)
        file_size = os.path.getsize(output_file) / 1024 / 1024
        logger.info(f"保存 {len(chunk_str.splitlines())} 个节点到 {output_file}，大小 {file_size:.2f} MB")
        output_files.append((output_file, len(chunk_str.splitlines())))
    except Exception as e:
        logger.error(f"保存分片到 '{output_file}' 时发生错误: {e}")

def main():
    """主函数，负责整体流程。"""
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
        if not domain and parsed.path:
            domain_match = re.match(r'^(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}(?::\d{1,5})?)$', parsed.path)
            if domain_match:
                domain = domain_match.group(1).split('/')[0]
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
    
    unique_nodes, url_node_counts, failed_urls = asyncio.run(
        process_urls(unique_domains, args.max_concurrency, args.timeout, args.validate, args.validate_timeout)
    )
    
    # 统计每种协议的节点数量
    protocol_counts = defaultdict(int)
    for node in unique_nodes:
        protocol = node.split('://')[0]
        protocol_counts[protocol] += 1

    # 生成报告
    report_lines = [
        f"--- 报告 ---",
        f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒",
        f"总共提取到 {len(unique_nodes)} 个唯一节点。",
        f"协议分布：{', '.join([f'{proto}: {count}' for proto, count in protocol_counts.items()])}",
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
    
    # 保存节点到分片文件
    output_files = save_nodes(unique_nodes, args.output, args.output_format, args.max_file_size, args.nodes_per_file)
    
    # 添加分片信息到报告
    report_lines.append("\n输出文件：")
    report_lines.append("{:<70} {:<15}".format("文件路径", "节点数"))
    report_lines.append("-" * 85)
    for file_path, node_count in output_files:
        file_size = os.path.getsize(file_path) / 1024 / 1024
        report_lines.append(f"{file_path:<70} {node_count:<15} ({file_size:.2f} MB)")
    
    report_lines.append("\n--- 报告结束 ---")
    for line in report_lines:
        logger.info(line)

if __name__ == '__main__':
    main()
