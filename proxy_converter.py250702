
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

# 配置日志系统，将日志输出到文件和控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_converter.log', encoding='utf-8'),
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

def setup_argparse() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='代理节点提取和去重工具')
    parser.add_argument('--sources', default='sources.list', help='包含源 URL 的输入文件路径')
    parser.add_argument('--output', default='data/nodes.txt', help='提取到的节点输出文件路径')
    parser.add_argument('--max-concurrency', type=int, default=50, help='最大并发请求数')
    parser.add_argument('--timeout', type=int, default=20, help='请求超时时间（秒）')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    """解码 Base64 字符串，并修复可能存在的填充问题。"""
    try:
        data = data.strip().replace('-', '+').replace('_', '/')
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
    """规范化节点 URL 以提高去重效率。"""
    try:
        protocol = url.split('://', 1)[0]
        if protocol not in NODE_PATTERNS:
            return url

        if protocol == 'vmess':
            config_b64 = url[8:]
            config_json = decode_base64(config_b64)
            if not config_json:
                return url
            config = json.loads(config_json)
            clean_config = {
                'v': config.get('v', '2'),
                'ps': config.get('ps', ''),
                'add': config.get('add', ''),
                'port': config.get('port', ''),
                'id': config.get('id', ''),
                'aid': config.get('aid', 0),
                'net': config.get('net', 'tcp'),
                'type': config.get('type', 'none'),
                'tls': config.get('tls', ''),
                'sni': config.get('sni', ''),
                'host': config.get('host', ''),
                'path': config.get('path', ''),
                'serviceName': config.get('serviceName', '')
            }
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False, sort_keys=True))}"
        
        else:
            match = re.match(rf'{protocol}://([^@]+@)?([^?]+)(\?[^#]*)?(#.*)?', url)
            if not match:
                return url
            auth, host_port, query, name = match.groups()
            auth = auth or ''
            query = query or ''
            name = urllib.parse.unquote(name[1:]) if name else ''
            if query:
                params = urllib.parse.parse_qs(query[1:])
                sorted_params = {k: params[k][0] for k in sorted(params.keys())}
                query = '?' + urllib.parse.urlencode(sorted_params, quote_via=urllib.parse.quote)
            host_port = host_port.lower()
            return f"{protocol}://{auth}{host_port}{query}{'#' + urllib.parse.quote(name) if name else ''}"
    except Exception as e:
        logger.debug(f"规范化 URL {url} 失败: {e}")
        return url

def extract_nodes(content: str) -> List[str]:
    """从内容中提取代理节点，并进行去重优化。"""
    nodes_found = set()
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # 策略 1: 直接匹配标准订阅链接
    for pattern in NODE_PATTERNS.values():
        matches = re.findall(pattern, content, re.MULTILINE)
        for node in matches:
            normalized_node = normalize_node_url(node)
            nodes_found.add(normalized_node)
    
    # 策略 2: 从 HTML 属性中提取订阅链接
    html_link_matches = re.findall(rf'["\']({COMBINED_REGEX_PATTERN})["\']', content)
    for link in html_link_matches:
        for pattern in NODE_PATTERNS.values():
            if re.match(pattern, link):
                normalized_node = normalize_node_url(link)
                nodes_found.add(normalized_node)
                break

    # 策略 3: 尝试 YAML 解析
    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy_dict in yaml_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    normalized_node = normalize_node_url(url_node)
                    nodes_found.add(normalized_node)
        elif isinstance(yaml_content, list):
            for item in yaml_content:
                if isinstance(item, dict) and 'type' in item:
                    url_node = convert_clash_proxy_to_url(item)
                    if url_node:
                        normalized_node = normalize_node_url(url_node)
                        nodes_found.add(normalized_node)
    except yaml.YAMLError:
        pass

    # 策略 4: 尝试 JSON 解析
    try:
        json_content = json.loads(content)
        if isinstance(json_content, list):
            for config_dict in json_content:
                if isinstance(config_dict, dict) and config_dict.get('v') == '2' and config_dict.get('id'):
                    url_node = convert_clash_proxy_to_url({'type': 'vmess', **config_dict})
                    if url_node:
                        normalized_node = normalize_node_url(url_node)
                        nodes_found.add(normalized_node)
        elif isinstance(json_content, dict) and 'proxies' in json_content:
            for proxy_dict in json_content['proxies']:
                url_node = convert_clash_proxy_to_url(proxy_dict)
                if url_node:
                    normalized_node = normalize_node_url(url_node)
                    nodes_found.add(normalized_node)
    except json.JSONDecodeError:
        pass

    # 策略 5: 尝试 Base64 解码
    decoded_content = decode_base64(content)
    if decoded_content and len(decoded_content) > 20:
        for pattern in NODE_PATTERNS.values():
            matches = re.findall(pattern, decoded_content, re.MULTILINE)
            for node in matches:
                normalized_node = normalize_node_url(node)
                nodes_found.add(normalized_node)
        
        try:
            yaml_content_decoded = yaml.safe_load(decoded_content)
            if isinstance(yaml_content_decoded, dict) and 'proxies' in yaml_content_decoded:
                for proxy_dict in yaml_content_decoded['proxies']:
                    url_node = convert_clash_proxy_to_url(proxy_dict)
                    if url_node:
                        normalized_node = normalize_node_url(url_node)
                        nodes_found.add(normalized_node)
            elif isinstance(yaml_content_decoded, list):
                for item in yaml_content_decoded:
                    if isinstance(item, dict) and 'type' in item:
                        url_node = convert_clash_proxy_to_url(item)
                        if url_node:
                            normalized_node = normalize_node_url(url_node)
                            nodes_found.add(normalized_node)
        except yaml.YAMLError:
            pass
        
        try:
            json_content_decoded = json.loads(decoded_content)
            if isinstance(json_content_decoded, list):
                for config_dict in json_content_decoded:
                    if isinstance(config_dict, dict) and config_dict.get('v') == '2' and config_dict.get('id'):
                        url_node = convert_clash_proxy_to_url({'type': 'vmess', **config_dict})
                        if url_node:
                            normalized_node = normalize_node_url(url_node)
                            nodes_found.add(normalized_node)
            elif isinstance(json_content_decoded, dict) and 'proxies' in json_content_decoded:
                for proxy_dict in json_content_decoded['proxies']:
                    url_node = convert_clash_proxy_to_url(proxy_dict)
                    if url_node:
                        normalized_node = normalize_node_url(url_node)
                        nodes_found.add(normalized_node)
        except json.JSONDecodeError:
            pass

    # 修复 SyntaxError
    final_filtered_nodes = [node for node in nodes_found if any(re.match(pattern, node) for pattern in NODE_PATTERNS.values()) and len(node) > 20]
    return sorted(final_filtered_nodes)

def convert_clash_proxy_to_url(proxy: Dict) -> Optional[str]:
    """将 Clash 代理配置字典转换为标准 URL 格式。"""
    proxy_type = proxy.get('type', '').lower()
    name = urllib.parse.quote(proxy.get('name', f"{proxy_type}_node").strip(), safe='')
    server = proxy.get('server')
    port = proxy.get('port')
    
    if not all([server, port, proxy_type]):
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
        auth = encode_base64(f"{cipher}:{password}")
        params = []
        if plugin:
            if plugin == 'obfs' and 'mode' in plugin_opts:
                params.append(f"plugin={plugin}")
                params.append(f"obfs-host={urllib.parse.quote(plugin_opts.get('host', ''))}")
                params.append(f"obfs-mode={plugin_opts['mode']}")
            elif plugin == 'v2ray-plugin':
                params.append(f"plugin={plugin}")
                params.append(f"v2ray-plugin-mode={plugin_opts.get('mode', 'websocket')}")
                params.append(f"v2ray-plugin-host={urllib.parse.quote(plugin_opts.get('host', ''))}")
                params.append(f"v2ray-plugin-path={urllib.parse.quote(plugin_opts.get('path', ''))}")
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
        clean_config = {k: v for k, v in config.items() if v is not None and v != ''}
        if not clean_config.get('ps'):
            clean_config['ps'] = urllib.parse.unquote(name)
        try:
            return f"vmess://{encode_base64(json.dumps(clean_config, ensure_ascii=False))}"
        except Exception as e:
            logger.debug(f"VMess 配置 JSON 编码失败，节点：{name}。错误：{e}")
            return None

    elif proxy_type == 'trojan':
        password = proxy.get('password')
        tls_enabled = proxy.get('tls', False)
        if not all([password, tls_enabled]):
            logger.debug(f"Trojan 代理 {name} 缺少密码或未启用 TLS: {proxy}")
            return None
        params = []
        sni = proxy.get('servername') or proxy.get('host') or server
        if sni: params.append(f"sni={urllib.parse.quote(sni)}")
        if proxy.get('alpn'): params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']))}")
        if proxy.get('client-fingerprint'): params.append(f"fp={urllib.parse.quote(proxy['client-fingerprint'])}")
        if proxy.get('skip-cert-verify'): params.append("allowInsecure=1")
        if proxy.get('udp', True): params.append("udp=true")
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
        params = {"type": network}
        if tls_enabled:
            params['security'] = 'tls'
            sni = proxy.get('servername') or proxy.get('host') or server
            if sni: params['sni'] = sni
            if proxy.get('alpn'): params['alpn'] = ",".join(proxy['alpn'])
            if proxy.get('client-fingerprint'): params['fp'] = proxy['client-fingerprint']
            if proxy.get('skip-cert-verify'): params['allowInsecure'] = '1'
            if proxy.get('flow'): params['flow'] = proxy['flow']
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
            params.append("insecure=1")
        if proxy.get('fast-open', False):
            params.append("fastopen=1")
        if proxy.get('up', 0):
            params.append(f"up_mbps={proxy['up']}")
        if proxy.get('down', 0):
            params.append(f"down_mbps={proxy['down']}")
        if proxy.get('alpn'):
            params.append(f"alpn={urllib.parse.quote(','.join(proxy['alpn']))}")
        if proxy.get('obfs'):
            params.append(f"obfs={proxy['obfs']}")
            if proxy.get('obfs-password'):
                params.append(f"obfsParam={urllib.parse.quote(proxy['obfs-password'])}")
        params_str = '&'.join(params) if params else ''
        return f"hysteria2://{password}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"
        
    logger.debug(f"不支持的代理类型或无法转换的代理: {proxy_type} - {proxy}")
    return None

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, retries: int = 3, backoff_factor: float = 1.0) -> str:
    """带重试机制地获取 URL 内容。"""
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=args.timeout)) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientError as e:
            logger.debug(f"尝试 {attempt + 1}/{retries} 失败，URL: {url}，错误: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
    logger.error(f"在 {retries} 次尝试后未能成功获取 URL: {url}")
    return ""

async def process_domain(session: aiohttp.ClientSession, domain: str, timeout: int, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set) -> Set[str]:
    """处理单个域名，先尝试 http，再尝试 https"""
    nodes = set()
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"

    # 优先尝试 http
    logger.info(f"尝试访问 HTTP: {http_url}")
    content = await fetch_with_retry(session, http_url)
    if content:
        nodes.update(extract_nodes(content))
        url_node_counts[http_url] = len(nodes)
        logger.info(f"从 {http_url} 提取到 {len(nodes)} 个节点")
        return nodes

    # http 失败，尝试 https
    logger.info(f"HTTP 失败，尝试 HTTPS: {https_url}")
    content = await fetch_with_retry(session, https_url)
    if content:
        nodes.update(extract_nodes(content))
        url_node_counts[https_url] = len(nodes)
        logger.info(f"从 {https_url} 提取到 {len(nodes)} 个节点")
    else:
        failed_urls.add(http_url)
        failed_urls.add(https_url)
        url_node_counts[http_url] = 0
        url_node_counts[https_url] = 0
        logger.warning(f"HTTP 和 HTTPS 均失败: {domain}")
    
    return nodes

async def process_urls(domains: Set[str], max_concurrency: int, timeout: int) -> tuple[List[str], Dict, Set]:
    """并发处理去重后的域名，优先尝试 http，失败后尝试 https"""
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int)
    failed_urls = set()
    all_nodes = set()
    
    async with aiohttp.ClientSession() as session:
        tasks = [process_domain(session, domain, timeout, semaphore, url_node_counts, failed_urls) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for nodes_or_exception in results:
            if isinstance(nodes_or_exception, set):
                all_nodes.update(nodes_or_exception)
    
    return sorted(list(all_nodes)), url_node_counts, failed_urls

def main():
    """主函数，负责程序的整体流程。"""
    global args
    args = setup_argparse()
    
    # 读取 URL 列表
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"源文件 {args.sources} 未找到。请确保文件存在。")
        return
    
    # 去重域名
    unique_domains = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path  # 提取域名（包括端口）
        unique_domains.add(domain)
    
    # 处理 URL 并提取节点
    start_time = datetime.now()
    logger.info(f"开始处理 {len(unique_domains)} 个唯一域名...")
    
    unique_nodes, url_node_counts, failed_urls = asyncio.run(process_urls(unique_domains, args.max_concurrency, args.timeout))
    
    # 生成报告
    total_nodes_extracted = len(unique_nodes)
    report_lines = [
        f"处理完成，耗时 {(datetime.now() - start_time).total_seconds():.2f} 秒",
        f"总共提取到 {total_nodes_extracted} 个唯一节点。",
        "\n每个 URL 的节点提取数量:"
    ]
    report_lines.append("{:<70} {:<15} {:<10}".format("URL", "找到的节点数", "状态"))
    report_lines.append("-" * 95)
    
    sorted_url_counts = sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True)
    for url, count in sorted_url_counts:
        status = "成功" if count > 0 else "无节点"
        report_lines.append(f"{url:<70} {count:<15} {status:<10}")
    
    if failed_urls:
        report_lines.append("\n获取失败的 URL:")
        report_lines.extend(sorted(list(failed_urls)))
    
    for line in report_lines:
        logger.info(line)
    
    # 保存节点到文件
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_nodes))
        logger.info(f"已将 {total_nodes_extracted} 个节点保存到 {args.output}")
    except Exception as e:
        logger.error(f"保存节点到 {args.output} 时发生错误: {e}")

if __name__ == '__main__':
    main()
