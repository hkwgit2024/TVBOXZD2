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
import uuid # 用于 VMess 默认 UUID，虽然实际节点会有自己的 UUID
from collections import defaultdict
from typing import List, Dict, Set, Optional
from datetime import datetime

# 配置日志系统，将日志输出到文件和控制台
logging.basicConfig(
    level=logging.INFO, # 默认日志级别为 INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_converter.log', encoding='utf-8'), # 日志文件，确保支持中文
        logging.StreamHandler() # 控制台输出
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
    # 可以根据需要添加其他协议的模式，例如 WireGuard, Tuic 等
}
# 组合所有协议模式，用于在文本中查找
COMBINED_REGEX_PATTERN = "|".join(NODE_PATTERNS.values())

def setup_argparse() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='代理节点提取和转换工具')
    parser.add_argument('--sources', default='sources.list', help='包含源 URL 的输入文件路径')
    parser.add_argument('--output', default='data/nodes.txt', help='提取到的节点输出文件路径')
    parser.add_argument('--clash-output', default='data/clash.yaml', help='Clash YAML 配置输出文件路径')
    parser.add_argument('--max-concurrency', type=int, default=50, help='最大并发请求数')
    parser.add_argument('--timeout', type=int, default=20, help='请求超时时间（秒）')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    """解码 Base64 字符串，并修复可能存在的填充问题。"""
    try:
        # 移除空白符，并替换 URL 安全的字符
        data = data.strip().replace('-', '+').replace('_', '/')
        # 添加 Base64 填充符
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

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """
    将 Clash 代理配置字典转换为标准 URL 格式。
    这是一个核心功能，需要尽可能精确地映射 Clash 配置到标准 URL 参数。
    如果转换失败或不支持该类型，则返回 None。
    """
    proxy_type = proxy.get('type', '').lower()
    # 节点名称，确保进行 URL 编码
    name = urllib.parse.quote(proxy.get('name', f"{proxy_type}_node").strip(), safe='')

    server = proxy.get('server')
    port = proxy.get('port')
    
    if not all([server, port, proxy_type]): # 检查必需的核心信息
        logger.debug(f"缺少 Clash 代理 {name} 的核心信息: {proxy}")
        return None

    if proxy_type == 'ss':
        cipher = proxy.get('cipher')
        password = proxy.get('password')
        plugin = proxy.get('plugin')
        plugin_opts = proxy.get('plugin-opts', {})

        if not all([cipher, password]):
            logger.debug(f"SS 代理 {name} 缺少加密方法或密码: {proxy}")
            return None

        # SS 认证信息：method:password
        auth = encode_base64(f"{cipher}:{password}")
        
        params = []
        if plugin:
            # SS 插件处理，根据常见插件和其参数进行映射
            if plugin == 'obfs' and 'mode' in plugin_opts:
                params.append(f"plugin={plugin}")
                params.append(f"obfs-host={urllib.parse.quote(plugin_opts.get('host', ''))}")
                params.append(f"obfs-mode={plugin_opts['mode']}")
            elif plugin == 'v2ray-plugin': # V2ray-plugin 兼容性处理
                params.append(f"plugin={plugin}")
                params.append(f"v2ray-plugin-mode={plugin_opts.get('mode', 'websocket')}")
                params.append(f"v2ray-plugin-host={urllib.parse.quote(plugin_opts.get('host', ''))}")
                params.append(f"v2ray-plugin-path={urllib.parse.quote(plugin_opts.get('path', ''))}")
                if plugin_opts.get('tls'): params.append("v2ray-plugin-tls=true")
                if plugin_opts.get('skip-cert-verify'): params.append("v2ray-plugin-skip-cert-verify=true")
                if plugin_opts.get('mux'): params.append("v2ray-plugin-mux=true")
            # 其他 SS 插件类型可以在这里添加
        
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
            "ps": urllib.parse.unquote(name), # VMess JSON 中的名称不应 URL 编码
            "add": server,
            "port": port,
            "id": uuid_val,
            "aid": proxy.get('alterId', 0),
            "net": network,
            "type": proxy.get('cipher', 'auto'), # Clash 的 type 字段有时映射到 VMess 的加密方式
        }
        
        # TLS 相关选项
        if tls_enabled:
            config["tls"] = "tls"
            sni = proxy.get('servername') or proxy.get('host')
            if sni:
                config["host"] = sni # VMess JSON 中的 host 字段通常用于 SNI/Host header
                config["sni"] = sni
            
            if proxy.get('skip-cert-verify'):
                config["allowInsecure"] = 1
            if proxy.get('alpn'):
                config["alpn"] = ",".join(proxy['alpn'])
            if proxy.get('client-fingerprint'):
                config["fp"] = proxy['client-fingerprint']

        # 网络传输方式特定选项
        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            config["path"] = ws_opts.get('path', '/')
            if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
                config['host'] = ws_opts['headers']['Host']
            elif 'host' in ws_opts:
                config['host'] = ws_opts['host']
            if ws_opts.get('max-early-data'): config['maxEarlyData'] = ws_opts['max-early-data']
            if ws_opts.get('early-data-header'): config['earlyDataHeader'] = ws_opts['early-data-header']
            
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            config["serviceName"] = grpc_opts.get('grpc-service-name', '')
            if grpc_opts.get('mode'): config["mode"] = grpc_opts['mode'] # gun/multi-mode
            
        elif network == 'http':
            http_opts = proxy.get('http-opts', {})
            if http_opts.get('method'):
                config['method'] = http_opts['method']
            if http_opts.get('headers'):
                for header_key, header_value in http_opts['headers'].items():
                    if header_key.lower() == 'host':
                        config['host'] = header_value[0] if isinstance(header_value, list) else header_value
                        break
        
        # 清理空值和 None 值，确保 JSON 简洁有效
        clean_config = {k: v for k, v in config.items() if v is not None and v != ''}
        # 确保 'ps' (节点名称) 存在且不为空
        if not clean_config.get('ps'):
            clean_config['ps'] = urllib.parse.unquote(name)
        
        try:
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False))}"
        except Exception as e:
            logger.debug(f"VMess 配置 JSON 编码失败，节点：{name}。错误：{e}")
            return None

    elif proxy_type == 'trojan':
        password = proxy.get('password')
        tls_enabled = proxy.get('tls', False) # Trojan 通常需要 TLS
        
        if not all([password, tls_enabled]):
            logger.debug(f"Trojan 代理 {name} 缺少密码或未启用 TLS: {proxy}")
            return None
        
        params = []
        # SNI 优先使用 'servername'，其次 'host'，最后是 'server'
        sni = proxy.get('servername') or proxy.get('host') or server
        if sni: params.append(f"sni={urllib.parse.quote(sni)}")
        
        if proxy.get('alpn'): params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']))}")
        if proxy.get('client-fingerprint'): params.append(f"fp={urllib.parse.quote(proxy['client-fingerprint'])}")
        if proxy.get('skip-cert-verify'): params.append("allowInsecure=1") # Trojan URL 中为 allowInsecure
        if proxy.get('udp', True): params.append("udp=true") # 默认 UDP 支持

        # 网络传输方式选项 (例如 WebSocket, gRPC)，Trojan URL 中也通过查询参数体现
        network = proxy.get('network')
        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            params.append(f"type=ws")
            params.append(f"path={urllib.parse.quote(ws_opts.get('path', '/'))}")
            if 'headers' in ws_opts and 'host' in ws_opts['headers']:
                params.append(f"host={urllib.parse.quote(ws_opts['headers']['host'])}")
            elif 'host' in ws_opts:
                params.append(f"host={urllib.parse.quote(ws_opts['host'])}")
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            params.append(f"type=grpc")
            params.append(f"serviceName={urllib.parse.quote(grpc_opts.get('grpc-service-name', ''))}")
            if grpc_opts.get('mode'): params.append(f"mode={urllib.parse.quote(grpc_opts['mode'])}")
            
        query_string = "?" + "&".join(params) if params else ""
        return f"trojan://{password}@{server}:{port}{query_string}#{name}"

    elif proxy_type == 'vless':
        uuid_val = proxy.get('uuid')
        network = proxy.get('network', 'tcp')
        tls_enabled = proxy.get('tls', False)
        
        if not uuid_val:
            logger.debug(f"VLESS 代理 {name} 缺少 UUID: {proxy}")
            return None
        
        params = {
            "type": network # 网络传输类型是 VLESS 必需参数
        }
        
        # TLS 相关选项
        if tls_enabled:
            params['security'] = 'tls'
            sni = proxy.get('servername') or proxy.get('host') or server
            if sni: params['sni'] = sni
            
            if proxy.get('alpn'): params['alpn'] = ",".join(proxy['alpn'])
            if proxy.get('client-fingerprint'): params['fp'] = proxy['client-fingerprint']
            if proxy.get('skip-cert-verify'): params['allowInsecure'] = '1'
            if proxy.get('flow'): params['flow'] = proxy['flow'] # VLESS flow

        # 网络传输方式特定选项
        if network == 'ws':
            ws_opts = proxy.get('ws-opts', {})
            params['path'] = ws_opts.get('path', '/')
            if 'headers' in ws_opts and 'host' in ws_opts['headers']:
                params['host'] = ws_opts['headers']['host']
            elif 'host' in ws_opts:
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
            params.append(f"sni={urllib.parse.quote(proxy['sni'])}")
        if proxy.get('skip-cert-verify', False):
            params.append("insecure=1") # Hysteria2 URL 中为 insecure
        if proxy.get('fast-open', False):
            params.append("fastopen=1")
        if proxy.get('up', 0): # 上行带宽
            params.append(f"up_mbps={proxy['up']}")
        if proxy.get('down', 0): # 下行带宽
            params.append(f"down_mbps={proxy['down']}")
        if proxy.get('alpn'):
            params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']))}")
        if proxy.get('obfs'): # 混淆方式
            params.append(f"obfs={proxy['obfs']}")
            if proxy.get('obfs-password'):
                params.append(f"obfsParam={urllib.parse.quote(proxy['obfs-password'])}")

        params_str = '&'.join(params) if params else ''
        return f"hysteria2://{password}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"
        
    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}")
    return None

def parse_url_to_clash_proxy(url: str) -> Optional[Dict]:
    """
    将标准订阅 URL 解析回 Clash 代理配置字典。
    这是 convert_clash_proxy_to_url 的逆向操作，用于生成完整的 Clash YAML。
    """
    try:
        if url.startswith('ss://'):
            # SS 链接格式: ss://auth@server:port[?params]#name
            match = re.match(r'ss://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', url)
            if not match: return None
            auth_b64, server, port, query_str, name = match.groups()
            
            auth_decoded = decode_base64(auth_b64)
            if ':' not in auth_decoded: return None # 认证信息不正确
            cipher, password = auth_decoded.split(':', 1) # 只分割一次

            proxy = {
                'type': 'ss',
                'name': urllib.parse.unquote(name or f"ss_{server}_{port}"),
                'server': server,
                'port': int(port),
                'cipher': cipher,
                'password': password,
                'udp': True # Clash SS 默认 UDP 支持
            }
            # 解析查询参数以获取插件信息
            if query_str:
                params = urllib.parse.parse_qs(query_str)
                plugin_type = params.get('plugin', [None])[0]
                if plugin_type == 'obfs':
                    proxy['plugin'] = 'obfs'
                    proxy['plugin-opts'] = {
                        'mode': params.get('obfs-mode', ['http'])[0],
                        'host': urllib.parse.unquote(params.get('obfs-host', [''])[0])
                    }
                elif plugin_type == 'v2ray-plugin':
                    proxy['plugin'] = 'v2ray-plugin'
                    plugin_opts = {
                        'mode': params.get('v2ray-plugin-mode', ['websocket'])[0],
                        'host': urllib.parse.unquote(params.get('v2ray-plugin-host', [''])[0]),
                        'path': urllib.parse.unquote(params.get('v2ray-plugin-path', [''])[0]),
                    }
                    if params.get('v2ray-plugin-tls', ['false'])[0].lower() == 'true': plugin_opts['tls'] = True
                    if params.get('v2ray-plugin-skip-cert-verify', ['false'])[0].lower() == 'true': plugin_opts['skip-cert-verify'] = True
                    if params.get('v2ray-plugin-mux', ['false'])[0].lower() == 'true': plugin_opts['mux'] = True
                    proxy['plugin-opts'] = plugin_opts
            return proxy

        elif url.startswith('vmess://'):
            # VMess 链接格式: vmess://base64_encoded_json
            config_b64 = url[8:]
            config_json = decode_base64(config_b64)
            if not config_json: return None
            
            config = json.loads(config_json)
            proxy = {
                'type': 'vmess',
                'name': config.get('ps', 'unnamed'),
                'server': config.get('add'),
                'port': int(config.get('port')),
                'uuid': config.get('id'),
                'alterId': config.get('aid', 0),
                'network': config.get('net', 'tcp'),
                'cipher': config.get('type', 'auto'), # VMess JSON 的 type 有时是加密方式
                'tls': config.get('tls', 'none').lower() == 'tls',
                'udp': True # Clash VMess 默认 UDP 支持
            }

            # TLS 相关的额外配置
            if proxy['tls']:
                if config.get('host'): proxy['servername'] = config['host'] # VMess host often maps to Clash servername
                if config.get('sni'): proxy['servername'] = config['sni'] # SNI might be separate
                if config.get('allowInsecure', 0) == 1: proxy['skip-cert-verify'] = True
                if config.get('alpn'): proxy['alpn'] = config['alpn'].split(',')
                if config.get('fp'): proxy['client-fingerprint'] = config['fp']

            # 网络传输方式特定配置
            if proxy['network'] == 'ws':
                proxy['ws-opts'] = {
                    'path': config.get('path', '/'),
                    'headers': {'Host': config.get('host', '')}
                }
            elif proxy['network'] == 'grpc':
                proxy['grpc-opts'] = {
                    'grpc-service-name': config.get('serviceName', ''),
                    'mode': config.get('mode', '')
                }
            elif proxy['network'] == 'http':
                proxy['http-opts'] = {
                    'method': config.get('method', 'GET'),
                    'headers': {'Host': [config.get('host', '')]} # Clash http headers are lists
                }
            return proxy

        elif url.startswith('trojan://'):
            # Trojan 链接格式: trojan://password@server:port[?params]#name
            match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', url)
            if not match: return None
            password, server, port, query_str, name = match.groups()

            proxy = {
                'type': 'trojan',
                'name': urllib.parse.unquote(name or f"trojan_{server}_{port}"),
                'server': server,
                'port': int(port),
                'password': password,
                'tls': True, # Trojan 链接通常隐含 TLS
                'udp': True # Clash Trojan 默认 UDP 支持
            }
            if query_str:
                params = urllib.parse.parse_qs(query_str)
                if params.get('sni'): proxy['servername'] = urllib.parse.unquote(params['sni'][0])
                if params.get('alpn'): proxy['alpn'] = params['alpn'][0].split(',')
                if params.get('fp'): proxy['client-fingerprint'] = params['fp'][0]
                if params.get('allowInsecure', ['0'])[0] == '1': proxy['skip-cert-verify'] = True

                # 网络传输方式
                network_type = params.get('type', [None])[0]
                if network_type == 'ws':
                    proxy['network'] = 'ws'
                    proxy['ws-opts'] = {
                        'path': urllib.parse.unquote(params.get('path', ['/'])[0]),
                        'headers': {'host': urllib.parse.unquote(params.get('host', [''])[0])}
                    }
                elif network_type == 'grpc':
                    proxy['network'] = 'grpc'
                    proxy['grpc-opts'] = {
                        'grpc-service-name': urllib.parse.unquote(params.get('serviceName', [''])[0]),
                        'mode': urllib.parse.unquote(params.get('mode', [''])[0])
                    }
            return proxy

        elif url.startswith('vless://'):
            # VLESS 链接格式: vless://uuid@server:port[?params]#name
            match = re.match(r'vless://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', url)
            if not match: return None
            uuid_val, server, port, query_str, name = match.groups()

            proxy = {
                'type': 'vless',
                'name': urllib.parse.unquote(name or f"vless_{server}_{port}"),
                'server': server,
                'port': int(port),
                'uuid': uuid_val,
                'udp': True # Clash VLESS 默认 UDP 支持
            }
            if query_str:
                params = urllib.parse.parse_qs(query_str)
                # TLS & Security
                if params.get('security', ['none'])[0].lower() == 'tls': proxy['tls'] = True
                if params.get('sni'): proxy['servername'] = urllib.parse.unquote(params['sni'][0])
                if params.get('alpn'): proxy['alpn'] = params['alpn'][0].split(',')
                if params.get('fp'): proxy['client-fingerprint'] = params['fp'][0]
                if params.get('allowInsecure', ['0'])[0] == '1': proxy['skip-cert-verify'] = True
                if params.get('flow'): proxy['flow'] = params['flow'][0]

                # Network Type
                network_type = params.get('type', ['tcp'])[0]
                proxy['network'] = network_type

                if network_type == 'ws':
                    proxy['ws-opts'] = {
                        'path': urllib.parse.unquote(params.get('path', ['/'])[0]),
                        'headers': {'host': urllib.parse.unquote(params.get('host', [''])[0])}
                    }
                elif network_type == 'grpc':
                    proxy['grpc-opts'] = {
                        'grpc-service-name': urllib.parse.unquote(params.get('serviceName', [''])[0]),
                        'mode': urllib.parse.unquote(params.get('mode', [''])[0])
                    }
            return proxy
        
        elif url.startswith('hysteria2://'):
            # Hysteria2 链接格式: hysteria2://password@server:port[?params]#name
            match = re.match(r'hysteria2://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', url)
            if not match: return None
            password, server, port, query_str, name = match.groups()

            proxy = {
                'type': 'hysteria2',
                'name': urllib.parse.unquote(name or f"hysteria2_{server}_{port}"),
                'server': server,
                'port': int(port),
                'password': password,
                'udp': True # Hysteria2 默认 UDP 支持
            }
            if query_str:
                params = urllib.parse.parse_qs(query_str)
                if params.get('sni'): proxy['sni'] = urllib.parse.unquote(params['sni'][0])
                if params.get('insecure', ['0'])[0] == '1': proxy['skip-cert-verify'] = True
                if params.get('fastopen', ['0'])[0] == '1': proxy['fast-open'] = True
                if params.get('up_mbps'): proxy['up'] = int(params['up_mbps'][0])
                if params.get('down_mbps'): proxy['down'] = int(params['down_mbps'][0])
                if params.get('alpn'): proxy['alpn'] = params['alpn'][0].split(',')
                if params.get('obfs'): proxy['obfs'] = params['obfs'][0]
                if params.get('obfsParam'): proxy['obfs-password'] = urllib.parse.unquote(params['obfsParam'][0])
            return proxy

        # TODO: 添加其他协议（如 WireGuard, Tuic 等）的逆向解析逻辑
        
        logger.debug(f"不支持的 URL 协议或解析失败: {url}")
        return None
    except Exception as e:
        logger.debug(f"解析 URL {url} 到 Clash 代理时发生错误: {e}")
        return None

def extract_nodes(content: str) -> List[str]:
    """
    从各种内容格式中提取代理节点。
    此函数会尝试所有可能的解析策略（直接匹配、HTML 属性、YAML、Base64 解码后内容），
    并汇总所有找到的有效节点 URL。
    """
    nodes_found = set() # 使用 set 自动去重

    # 预处理内容，统一换行符
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # --- 策略 1: 尝试从内容中直接匹配标准订阅链接 ---
    # 无论内容是什么格式，只要能直接匹配到标准链接就提取
    for pattern in NODE_PATTERNS.values():
        matches = re.findall(pattern, content, re.MULTILINE)
        for node in matches:
            nodes_found.add(node)
    
    # --- 策略 2: 尝试从 HTML 属性中提取订阅链接 (例如 onclick 属性) ---
    # 查找被单引号或双引号包裹的、符合任何订阅链接模式的字符串。
    # 这可以捕获 <button onclick='copyToClipboard("trojan://...")'> 这样的链接
    html_link_matches = re.findall(rf'["\']({COMBINED_REGEX_PATTERN})["\']', content)
    for link in html_link_matches:
        # 对提取到的链接再次进行有效性验证，确保它确实是一个协议链接
        for pattern in NODE_PATTERNS.values():
            if re.match(pattern, link):
                nodes_found.add(link)
                break # 找到匹配，跳到下一个提取到的链接

    # --- 策略 3: 尝试 YAML 解析 (用于 Clash 配置文件) ---
    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    nodes_found.add(url_node)
        elif isinstance(yaml_content, list): # 有些订阅是直接的代理列表
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item: # 假设是代理字典
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node: nodes_found.add(url_node)
            
    except yaml.YAMLError:
        pass # 不是 YAML 格式，继续

    # --- 策略 4: 尝试 JSON 解析 (用于 VMess 或其他 JSON 格式的订阅) ---
    try:
        json_content = json.loads(content)
        if isinstance(json_content, list): # 可能是 VMess 列表
            for config_dict in json_content:
                if isinstance(config_dict, dict) and config_dict.get('v') == '2' and config_dict.get('id'):
                    # 尝试将 VMess JSON 直接转为 URL
                    url_node = convert_clash_proxy_to_url({'type': 'vmess', **config_dict})
                    if url_node:
                        nodes_found.add(url_node)
                # 如果是其他协议的 JSON 格式，可能需要更多判断
        elif isinstance(json_content, dict) and 'proxies' in json_content: # 可能是 Clash JSON
             for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node: nodes_found.add(url_node)
    except json.JSONDecodeError:
        pass # 不是 JSON 格式，继续

    # --- 策略 5: 尝试 Base64 解码，然后再次尝试解析 ---
    decoded_content = decode_base64(content)
    if decoded_content and len(decoded_content) > 20:
        # 对解码后的内容再次执行所有提取策略 (但避免无限递归)
        # 提取直链
        for pattern in NODE_PATTERNS.values():
            matches = re.findall(pattern, decoded_content, re.MULTILINE)
            for node in matches:
                nodes_found.add(node)
        
        # 尝试 YAML
        try:
            yaml_content_decoded = yaml.safe_load(decoded_content)
            if isinstance(yaml_content_decoded, dict) and 'proxies' in yaml_content_decoded:
                for proxy_dict in yaml_content_decoded['proxies']:
                    url_node = convert_clash_proxy_to_url(proxy_dict)
                    if url_node: nodes_found.add(url_node)
            elif isinstance(yaml_content_decoded, list):
                for item in yaml_content_decoded:
                    if isinstance(item, dict) and 'type' in item:
                        url_node = convert_clash_proxy_to_url(item)
                        if url_node: nodes_found.add(url_node)
        except yaml.YAMLError:
            pass
        
        # 尝试 JSON
        try:
            json_content_decoded = json.loads(decoded_content)
            if isinstance(json_content_decoded, list):
                for config_dict in json_content_decoded:
                    if isinstance(config_dict, dict) and config_dict.get('v') == '2' and config_dict.get('id'):
                        url_node = convert_clash_proxy_to_url({'type': 'vmess', **config_dict})
                        if url_node: nodes_found.add(url_node)
            elif isinstance(json_content_decoded, dict) and 'proxies' in json_content_decoded:
                 for proxy_dict in json_content_decoded['proxies']:
                    url_node = convert_clash_proxy_to_url(proxy_dict)
                    if url_node: nodes_found.add(url_node)
        except json.JSONDecodeError:
            pass

    # 最终过滤：确保所有提取到的都是有效的订阅 URL，并且长度合理
    # 过滤掉一些可能是代码片段或无效的短字符串
    final_filtered_nodes = []
    for node in nodes_found:
        is_valid_url_pattern = False
        for pattern in NODE_PATTERNS.values():
            if re.match(pattern, node):
                is_valid_url_pattern = True
                break
        
        if is_valid_url_pattern and len(node) > 20: # 长度限制，避免误报短字符串
            final_filtered_nodes.append(node)
    
    # 返回列表，方便后续排序
    return final_filtered_nodes

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, retries: int = 3, backoff_factor: float = 1.0) -> str:
    """带重试机制地获取 URL 内容。"""
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=args.timeout)) as response:
                response.raise_for_status() # 对 4xx/5xx 响应抛出异常
                return await response.text()
        except aiohttp.ClientError as e:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt)) # 指数退避
    logger.error(f"在 {retries} 次尝试后未能成功获取 URL: {url}")
    return ""

async def fetch_url_nodes_task(session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set) -> List[str]:
    """从单个 URL 获取并提取节点的异步任务。"""
    async with semaphore: # 使用信号量控制并发
        logger.info(f"正在处理 URL: {url}")
        try:
            content = await fetch_with_retry(session, url)
            if not content:
                failed_urls.add(url)
                url_node_counts[url] = 0
                logger.warning(f"未能获取内容或内容为空，URL: {url}")
                return []
            
            nodes = extract_nodes(content)
            url_node_counts[url] = len(nodes)
            if nodes:
                logger.info(f"从 {url} 中提取到 {len(nodes)} 个有效节点。")
            else:
                logger.info(f"从 {url} 中未提取到有效节点。")
            return nodes
        except Exception as e:
            logger.error(f"处理 URL {url} 时发生未知错误: {e}")
            failed_urls.add(url)
            return []

async def process_urls(urls: List[str], max_concurrency: int) -> tuple[List[str], Dict, Set]:
    """并发处理多个 URL。"""
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int) # 每个 URL 对应的节点数量
    failed_urls = set() # 获取失败的 URL 集合
    all_extracted_nodes = [] # 存储所有提取到的节点（可能有重复）
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url_nodes_task(session, url, semaphore, url_node_counts, failed_urls) for url in urls]
        # 使用 return_exceptions=True 确保即使有任务失败，其他任务也能继续
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for nodes_or_exception in results:
            if isinstance(nodes_or_exception, list): # 成功返回节点列表
                all_extracted_nodes.extend(nodes_or_exception)
            else:
                # 异常已在 fetch_url_nodes_task 中处理和记录，此处跳过
                pass 
                
    # 去重所有提取到的节点
    unique_nodes = list(dict.fromkeys(all_extracted_nodes)) # Python 3.7+ 保持插入顺序的去重方法
    return unique_nodes, url_node_counts, failed_urls

def generate_clash_config(nodes: List[str]) -> Dict:
    """
    根据提取到的节点 URL 生成 Clash YAML 配置。
    此函数会尝试将所有支持的 URL 协议逆向解析为 Clash 字典格式。
    """
    proxies_clash_format = []
    for node_url in nodes:
        clash_proxy = parse_url_to_clash_proxy(node_url)
        if clash_proxy:
            proxies_clash_format.append(clash_proxy)
        else:
            logger.debug(f"未能将节点 URL 转换为 Clash 代理格式: {node_url}")
            
    # Clash 配置文件的基本结构
    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'redir-port': 7892,
        'mixed-port': 7893,
        'mode': 'rule',
        'log-level': 'info',
        'allow-lan': True,
        'bind-address': '*',
        'external-controller': '127.0.0.1:9090',
        'secret': '',
        'dns': {
            'enable': True,
            'ipv6': False,
            'listen': '0.0.0.0:53',
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'default-nameserver': [
                '114.114.114.114',
                '223.5.5.5',
                '8.8.8.8'
            ],
            'nameserver': [
                'https://dns.google/dns-query',
                'tls://dns.google'
            ],
            'fallback': [],
            'fallback-filter': {
                'geoip': True,
                'geoip-code': 'CN',
                'ipcidr': [
                    '240.0.0.0/4'
                ]
            }
        },
        'proxies': proxies_clash_format, # 放置转换后的代理
        'proxy-groups': [
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['♻️ 自动选择', 'DIRECT'] + [p['name'] for p in proxies_clash_format if 'name' in p]
            },
            {
                'name': '♻️ 自动选择',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'proxies': [p['name'] for p in proxies_clash_format if 'name' in p]
            },
            {
                'name': 'DIRECT',
                'type': 'direct'
            }
        ],
        'rules': [
            'GEOIP,CN,DIRECT',
            'MATCH,🚀 节点选择'
        ]
    }
    return clash_config

def main():
    """主函数，负责程序的整体流程。"""
    global args # 将 args 设置为全局变量，以便在异步函数中访问
    args = setup_argparse()
    
    # 读取 URL 列表
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"源文件 {args.sources} 未找到。请确保文件存在。")
        return
    
    # 处理 URL 并提取节点
    start_time = datetime.now()
    logger.info(f"开始处理 {len(urls)} 个 URL...")
    
    # 运行异步主流程
    unique_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(urls, args.max_concurrency))
    
    # 对提取到的节点进行排序
    unique_nodes.sort()
    
    # --- 生成并打印报告 ---
    total_nodes_extracted = len(unique_nodes)
    report_lines = [
        f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒",
        f"总共提取到 {total_nodes_extracted} 个唯一节点。",
        "\n每个 URL 的节点提取数量:"
    ]
    # 格式化表格头部
    report_lines.append("{:<70} {:<15} {:<10}".format("URL", "找到的节点数", "状态"))
    report_lines.append("-" * 95)
    
    # 按找到的节点数降序排序，并添加到报告
    sorted_url_counts = sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True)
    for url, count in sorted_url_counts:
        status = "成功" if count > 0 else "无节点"
        report_lines.append(f"{url:<70} {count:<15} {status:<10}")
    
    if failed_urls:
        report_lines.append("\n获取失败的 URL:")
        report_lines.extend(sorted(list(failed_urls))) # 对失败的 URL 也进行排序
    
    # 将报告打印到控制台
    for line in report_lines:
        logger.info(line)
    
    # --- 保存节点到文件 ---
    # 确保输出目录存在
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_nodes))
        logger.info(f"已将 {total_nodes_extracted} 个节点保存到 {args.output}")
    except Exception as e:
        logger.error(f"保存节点到 {args.output} 时发生错误: {e}")
    
    # --- 保存 Clash 配置到文件 ---
    # 确保 Clash 输出目录存在
    os.makedirs(os.path.dirname(args.clash_output), exist_ok=True)
    clash_config = generate_clash_config(unique_nodes)
    try:
        with open(args.clash_output, 'w', encoding='utf-8') as f:
            yaml.safe_dump(clash_config, f, allow_unicode=True, indent=2, sort_keys=False) # 保持顺序，美化输出
        logger.info(f"已将 Clash 配置保存到 {args.clash_output}")
    except Exception as e:
        logger.error(f"保存 Clash 配置到 {args.clash_output} 时发生错误: {e}")

if __name__ == '__main__':
    main()
