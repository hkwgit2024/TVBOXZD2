# -*- coding: utf-8 -*-
import os
import requests
from urllib.parse import urlparse, parse_qs
import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import argparse
import re
import yaml
import json
import csv
import hashlib
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志
logging.basicConfig(filename='error.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 请求头
headers = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/91.0.4472.124 Safari/537.36'
    ),
    'Accept-Encoding': 'gzip, deflate'
}

# 命令行参数解析
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源和节点解析")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功数量")
parser.add_argument('--timeout', type=int, default=30, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.yaml', help="输出文件路径")
parser.add_argument('--no-proxy-groups', action='store_true', default=True, help="不生成 proxy-groups 部分，仅输出 proxies")
args = parser.parse_args()

# 全局变量
MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
TEMP_MERGED_NODES_RAW_FILE = 'temp_merged_nodes_raw.txt'
STATISTICS_FILE = 'data/url_statistics.csv'
SUCCESS_URLS_FILE = 'data/successful_urls.txt'
FAILED_URLS_FILE = 'data/failed_urls.txt'

# 定义删除关键词
DELETE_KEYWORDS = [
    '剩余流量', '套餐到期', '流量', '到期', '过期', '免费', '试用', '体验', '限时', '限制',
    '已用', '可用', '不足', '到期时间', '倍率', '返利', '充值', '续费', '用量', '订阅'
]

def is_valid_url(url):
    """验证URL格式是否合法，仅接受 http 或 https 方案"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def is_valid_ip_address(host):
    """验证是否为有效的 IPv4 或 IPv6 地址"""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        try:
            if host.startswith('[') and host.endswith(']'):
                ipaddress.ip_address(host[1:-1])
                return True
            return False
        except ValueError:
            return False

def get_url_list_from_remote(url_source):
    """从给定的公开网址获取 URL 列表"""
    try:
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url_source, headers=headers, timeout=10)
        response.raise_for_status()
        text_content = response.text.strip()
        raw_urls = [line.strip() for line in text_content.splitlines() if line.strip()]
        print(f"从 {url_source} 获取到 {len(raw_urls)} 个URL")
        return raw_urls
    except Exception as e:
        logging.error(f"获取URL列表失败: {url_source} - {e}")
        return []

def parse_content_to_nodes(content):
    """从文本内容中解析出节点"""
    if not content:
        return []

    found_nodes = []
    processed_content = content

    # 1. 尝试 Base64 解码
    try:
        decoded_bytes = base64.b64decode(content)
        processed_content = decoded_bytes.decode('utf-8')
        logging.info("内容成功 Base64 解码。")
    except Exception:
        pass

    # 2. 尝试 YAML 解析
    try:
        parsed_data = yaml.safe_load(processed_content)
        if isinstance(parsed_data, dict) and 'proxies' in parsed_data and isinstance(parsed_data['proxies'], list):
            for proxy_entry in parsed_data['proxies']:
                if isinstance(proxy_entry, dict):
                    if 'name' in proxy_entry and not isinstance(proxy_entry['name'], str):
                        proxy_entry['name'] = str(proxy_entry['name'])
                    found_nodes.append(proxy_entry)
                elif isinstance(proxy_entry, str) and any(proxy_entry.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    found_nodes.append(proxy_entry.strip())
            logging.info("内容成功解析为 Clash YAML。")
        elif isinstance(parsed_data, list):
            for item in parsed_data:
                if isinstance(item, str):
                    found_nodes.append(item.strip())
                elif isinstance(item, dict):
                    if 'name' in item and not isinstance(item['name'], str):
                        item['name'] = str(item['name'])
                    found_nodes.append(item)
            logging.info("内容成功解析为 YAML 列表。")
    except yaml.YAMLError:
        pass
    except Exception as e:
        logging.error(f"YAML 解析失败: {e}")
        pass

    # 3. 通过正则表达式提取节点
    node_pattern = re.compile(
        r'(vmess://\S+|'
        r'trojan://\S+|'
        r'ss://\S+|'
        r'ssr://\S+|'
        r'vless://\S+|'
        r'hy://\S+|'
        r'hy2://\S+|'
        r'hysteria://\S+|'
        r'hysteria2://\S+)'
    )
    
    matches = node_pattern.findall(content)
    for match in matches:
        found_nodes.append(match.strip())
    
    if content != processed_content:
        matches_decoded = node_pattern.findall(processed_content)
        for match in matches_decoded:
            found_nodes.append(match.strip())

    return found_nodes

def fetch_and_parse_url(url):
    """
    获取URL内容并解析出节点。
    返回 (节点列表, 是否成功, 错误信息, 状态码)
    """
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))

    try:
        logging.debug(f"开始请求 URL: {url}")
        resp = session.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text.strip()
        
        if len(content) < 10:
            logging.warning(f"获取到内容过短，可能无效: {url}")
            return [], False, "内容过短", resp.status_code
        
        nodes = parse_content_to_nodes(content)
        logging.debug(f"URL {url} 解析到 {len(nodes)} 个节点")
        return nodes, True, None, resp.status_code
    except requests.exceptions.Timeout:
        logging.error(f"请求超时: {url}")
        return [], False, "请求超时", None
    except requests.exceptions.ConnectionError as e:
        logging.error(f"连接失败: {url} - {e}")
        return [], False, f"连接失败: {e}", None
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP错误: {url} - {e}")
        return [], False, f"HTTP错误: {e}", None
    except requests.exceptions.RequestException as e:
        logging.error(f"请求失败: {url} - {e}")
        return [], False, f"请求失败: {e}", None
    except Exception as e:
        logging.error(f"处理URL异常: {url} - {e}")
        return [], False, f"未知异常: {e}", None

def write_statistics_to_csv(statistics_data, filename):
    """将统计数据写入CSV文件"""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量', '状态', '错误信息', '状态码']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in statistics_data:
            writer.writerow(row)
    print(f"统计数据已保存至：{filename}")

def write_urls_to_file(urls, filename):
    """将URL列表写入文件"""
    with open(filename, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(url + '\n')
    print(f"URL列表已保存至：{filename}")

def clean_node_name(name, index=None):
    """清理节点名称"""
    if not isinstance(name, str):
        name = str(name)

    cleaned_name = name.strip()
    cleaned_name = re.sub(r'【[^】]*?(流量|到期|过期|充值|续费)[^】]*】', '', cleaned_name)
    cleaned_name = re.sub(r'\[[^]]*?(流量|到期|过期|充值|续费)[^\]]*\]', '', cleaned_name)
    cleaned_name = re.sub(r'\([^)]*?(流量|到期|过期|充值|续费)[^)]*\)', '', cleaned_name)
    cleaned_name = re.sub(r'（[^）]*?(流量|到期|过期|充值|续费)[^）]*）', '', cleaned_name)

    redundant_keywords_to_remove = [
        r'\d+%', r'\d{4}-\d{2}-\d{2}', r'\d{2}-\d{2}', r'x\d+',
        r'秒杀', r'活动', r'新年', r'福利', r'VIP\d*', r'Pro', r'Lite', r'Plus',
        r'自动', r'手动', r'自选',
        r'(\d+\.\d+kbps)', r'(\d+\.\d+mbps)', r'(\d+kbps)', r'(\d+mbps)',
        r'\\n', r'\\r', r'\d+\.\d+G|\d+G',
    ]

    for keyword in redundant_keywords_to_remove:
        cleaned_name = re.sub(keyword, ' ', cleaned_name, flags=re.IGNORECASE).strip()

    cleaned_name = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9\s\.\-_@#|]', ' ', cleaned_name)
    cleaned_name = re.sub(r'\s+', ' ', cleaned_name).strip()

    region_map = {
        '香港': 'HK', '台湾': 'TW', '日本': 'JP', '新加坡': 'SG', '美国': 'US', '英国': 'UK',
        '德国': 'DE', '韩国': 'KR', '马来': 'MY', '泰国': 'TH', '菲律宾': 'PH', '越南': 'VN',
        '印尼': 'ID', '印度': 'IN', '澳洲': 'AU', '加拿大': 'CA', '俄罗斯': 'RU', '巴西': 'BR',
        '意大利': 'IT', '荷兰': 'NL', '中国': 'CN'
    }
    for full_name, short_name in region_map.items():
        cleaned_name = cleaned_name.replace(full_name, short_name)

    meaningful_keywords = ['IPLC', 'IEPL', '专线', '中转', '直连']
    preserved_info = []
    for keyword in meaningful_keywords:
        if keyword.lower() in cleaned_name.lower():
            preserved_info.append(keyword)
    
    node_number_match = re.search(r'(?<!\d)\d{1,2}(?!\d)|Node\d{1,2}', cleaned_name, re.IGNORECASE)
    if node_number_match:
        preserved_info.append(node_number_match.group(0))

    if not cleaned_name or len(cleaned_name) <= 3:
        cleaned_name = 'Node'
        if any(region in name for region in region_map.values()):
            for region in region_map.values():
                if region in name:
                    cleaned_name = region
                    break
        if preserved_info:
            cleaned_name += ' ' + ' '.join(preserved_info)

    if index is not None:
        cleaned_name += f"-{index:02d}"

    if len(cleaned_name) > 80:
        cleaned_name = cleaned_name[:80].rstrip() + '...'

    return cleaned_name if cleaned_name else f"Node-{index:02d}" if index is not None else "Unknown Node"

def _generate_node_fingerprint(node):
    """为节点生成唯一指纹，覆盖所有关键字段以确保去重准确"""
    if isinstance(node, dict):
        node_type = node.get('type', '').lower()
        fingerprint_data = {
            'type': node_type,
            'server': node.get('server', ''),
            'port': str(node.get('port', '')),
            'network': node.get('network', ''),
            'tls': str(node.get('tls', False)).lower(),
            'skip-cert-verify': str(node.get('skip-cert-verify', False)).lower(),
            'servername': node.get('servername', '') or node.get('sni', '') or node.get('host', ''),
            'flow': node.get('flow', ''),
        }

        if node_type == 'vless':
            fingerprint_data.update({
                'uuid': node.get('uuid', '') or node.get('id', ''),
                'ws-path': node.get('ws-opts', {}).get('path', '') if node.get('ws-opts') else '',
                'ws-headers': json.dumps(node.get('ws-opts', {}).get('headers', {}), sort_keys=True) if node.get('ws-opts') else '',
                'grpc-serviceName': node.get('grpc-opts', {}).get('serviceName', '') if node.get('grpc-opts') else '',
            })
        elif node_type == 'trojan':
            fingerprint_data.update({
                'password': node.get('password', ''),
                'sni': node.get('sni', '') or node.get('host', ''),
            })
        elif node_type == 'vmess':
            fingerprint_data.update({
                'uuid': node.get('uuid', '') or node.get('id', ''),
                'alterId': str(node.get('alterId', '') or node.get('aid', '')),
                'cipher': node.get('cipher', ''),
                'ws-path': node.get('ws-opts', {}).get('path', '') if node.get('ws-opts') else '',
                'ws-headers': json.dumps(node.get('ws-opts', {}).get('headers', {}), sort_keys=True) if node.get('ws-opts') else '',
            })
        elif node_type == 'ss':
            fingerprint_data.update({
                'cipher': node.get('cipher', ''),
                'password': node.get('password', ''),
            })
        elif node_type in ['hysteria', 'hysteria2', 'hy', 'hy2']:
            fingerprint_data.update({
                'password': node.get('password', '') or node.get('auth_str', ''),
                'obfs': node.get('obfs', ''),
                'obfs-password': node.get('obfs-password', ''),
                'alpn': ','.join(node.get('alpn', [])),
                'protocol': node.get('protocol', ''),
            })

        normalized_data = {k: str(v).lower().strip() if v is not None else '' for k, v in fingerprint_data.items()}
        stable_json = json.dumps(normalized_data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(stable_json.encode('utf-8')).hexdigest()

    elif isinstance(node, str):
        try:
            if not any(node.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                logging.warning(f"无效的节点协议: {node[:50]}...")
                return None

            parsed_url = urlparse(node)
            scheme = parsed_url.scheme.lower()
            netloc = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            query_params = parse_qs(parsed_url.query)

            host = netloc.split(':')[0] if ':' in netloc else netloc
            port = netloc.split(':')[1] if ':' in netloc else ''
            if is_valid_ip_address(host) and host.startswith('[') and host.endswith(']'):
                host = host[1:-1]
            elif not is_valid_ip_address(host) and not re.match(r'^[a-zA-Z0-9\-\.]+$', host):
                logging.warning(f"无效的主机名: {host} in {node[:50]}...")
                return None

            fingerprint_parts = [
                scheme,
                host,
                port,
                path,
            ]

            normalized_query_params = {}
            for k, v in query_params.items():
                normalized_query_params[k.lower()] = str(v[0]).lower().strip()

            if scheme == 'vless':
                fingerprint_parts.extend([
                    parsed_url.username or '',
                    normalized_query_params.get('type', ''),
                    normalized_query_params.get('security', ''),
                    normalized_query_params.get('sni', '') or normalized_query_params.get('host', ''),
                    normalized_query_params.get('path', ''),
                    json.dumps(normalized_query_params.get('headers', {}), sort_keys=True),
                    normalized_query_params.get('flow', ''),
                    normalized_query_params.get('serviceName', '')
                ])
            elif scheme == 'trojan':
                fingerprint_parts.extend([
                    parsed_url.username or '',
                    normalized_query_params.get('type', ''),
                    normalized_query_params.get('sni', '') or normalized_query_params.get('host', ''),
                    normalized_query_params.get('allowInsecure', ''),
                ])
            elif scheme == 'vmess':
                try:
                    decoded = base64.b64decode(node[len("vmess://"):]).decode('utf-8')
                    config = json.loads(decoded)
                    fingerprint_parts.extend([
                        config.get('id', ''),
                        str(config.get('aid', '')),
                        config.get('net', ''),
                        config.get('tls', ''),
                        config.get('sni', '') or config.get('host', ''),
                        config.get('path', ''),
                        json.dumps(config.get('headers', {}), sort_keys=True),
                    ])
                except Exception:
                    pass
            elif scheme == 'ss':
                fingerprint_parts.extend([
                    parsed_url.username or '',
                    normalized_query_params.get('plugin', ''),
                ])

            sorted_query_keys = sorted(normalized_query_params.keys())
            for k in sorted_query_keys:
                if k not in ['name', 'ps', 'remarks', 'info', 'usage', 'expire', 'ud', 'up', 'dn', 'package', 'nodeName', 'nodeid', 'ver']:
                    fingerprint_parts.append(f"{k}={normalized_query_params[k]}")

            return hashlib.sha256("".join(fingerprint_parts).encode('utf-8')).hexdigest()
        except Exception as e:
            logging.warning(f"生成URL节点指纹失败: {node[:50]}... - {e}")
            return None
    return None

def deduplicate_and_standardize_nodes(raw_nodes_list):
    """对节点进行去重和标准化"""
    unique_node_fingerprints = set()
    final_clash_proxies = []

    for idx, node in enumerate(raw_nodes_list):
        clash_proxy_dict = None
        node_raw_name = ""

        if isinstance(node, dict):
            clash_proxy_dict = node
            node_raw_name = str(node.get('name', ''))
        elif isinstance(node, str):
            try:
                parsed_url = urlparse(node)
                node_raw_name = str(parsed_url.fragment)
                if not any(node.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    logging.warning(f"跳过无效协议的节点: {node[:50]}...")
                    continue
                host = parsed_url.hostname or ''
                if host and not (is_valid_ip_address(host) or re.match(r'^[a-zA-Z0-9\-\.]+$', host)):
                    logging.warning(f"跳过无效主机名的节点: {host} in {node[:50]}...")
                    continue

                if node.startswith("vmess://"):
                    decoded = base64.b64decode(node[len("vmess://"):].encode('utf-8')).decode('utf-8')
                    config = json.loads(decoded)
                    clash_proxy_dict = {
                        'name': str(config.get('ps', 'VMess Node')),
                        'type': 'vmess',
                        'server': config.get('add'),
                        'port': int(config.get('port')),
                        'uuid': config.get('id'),
                        'alterId': int(config.get('aid', 0)),
                        'cipher': 'auto',
                        'network': config.get('net'),
                        'tls': True if config.get('tls') == 'tls' else False,
                        'skip-cert-verify': True if config.get('scy') == 'true' else False,
                        'servername': config.get('sni') or config.get('host'),
                        'ws-opts': {'path': config.get('path', '/'), 'headers': {'Host': config.get('host')}} if config.get('net') == 'ws' else None,
                        'grpc-opts': {'serviceName': config.get('path', '')} if config.get('net') == 'grpc' else None,
                    }
                elif node.startswith("trojan://"):
                    parsed = urlparse(node)
                    password = parsed.username
                    server = parsed.hostname
                    port = parsed.port
                    query = parse_qs(parsed.query)
                    clash_proxy_dict = {
                        'name': str(parsed.fragment or 'Trojan Node'),
                        'type': 'trojan',
                        'server': server,
                        'port': port,
                        'password': password,
                        'network': query.get('type', ['tcp'])[0],
                        'tls': True,
                        'skip-cert-verify': query.get('allowInsecure', ['0'])[0] == '1',
                        'sni': query.get('sni', [server])[0]
                    }
                elif node.startswith("ss://"):
                    decoded_part = node[len("ss://"):].split('#', 1)[0]
                    try:
                        decoded_info = base64.b64decode(decoded_part.encode('utf-8')).decode('utf-8')
                        parts = decoded_info.split('@', 1)
                        method_password = parts[0].split(':', 1)
                        method = method_password[0]
                        password = method_password[1] if len(method_password) > 1 else ''
                        server_port = parts[1].split(':', 1)
                        server = server_port[0]
                        port = int(server_port[1])
                        clash_proxy_dict = {
                            'name': str(parsed_url.fragment or 'SS Node'),
                            'type': 'ss',
                            'server': server,
                            'port': port,
                            'cipher': method,
                            'password': password,
                        }
                    except Exception as e:
                        logging.warning(f"SS节点解析失败: {node[:50]}... - {e}")
                        clash_proxy_dict = None
                elif node.startswith("vless://"):
                    parsed = urlparse(node)
                    uuid = parsed.username
                    server = parsed.hostname
                    port = parsed.port
                    query = parse_qs(parsed.query)
                    clash_proxy_dict = {
                        'name': str(parsed.fragment or 'VLESS Node'),
                        'type': 'vless',
                        'server': server,
                        'port': port,
                        'uuid': uuid,
                        'network': query.get('type', ['tcp'])[0],
                        'tls': True if query.get('security', [''])[0] == 'tls' else False,
                        'skip-cert-verify': query.get('flow', [''])[0] == 'xtls-rprx-direct',
                        'servername': query.get('sni', [server])[0],
                        'flow': query.get('flow', [''])[0],
                        'ws-opts': {'path': query.get('path', ['/'])[0], 'headers': {'Host': query.get('host', [''])[0]}} if query.get('type', [''])[0] == 'ws' else None,
                        'grpc-opts': {'serviceName': query.get('serviceName', [''])[0]} if query.get('type', [''])[0] == 'grpc' else None,
                    }
                elif node.startswith("hysteria://") or node.startswith("hy://"):
                    parsed = urlparse(node)
                    server = parsed.hostname
                    port = parsed.port
                    query = parse_qs(parsed.query)
                    clash_proxy_dict = {
                        'name': str(parsed.fragment or 'Hysteria Node'),
                        'type': 'hysteria',
                        'server': server,
                        'port': port,
                        'auth_str': query.get('auth', [''])[0],
                        'alpn': query.get('alpn', [''])[0].split(','),
                        'network': query.get('protocol', ['udp'])[0],
                        'skip-cert-verify': query.get('insecure', ['0'])[0] == '1',
                        'sni': query.get('peer', [server])[0]
                    }
                    if not clash_proxy_dict['alpn']:
                        del clash_proxy_dict['alpn']
                elif node.startswith("hysteria2://") or node.startswith("hy2://"):
                    parsed = urlparse(node)
                    password = parsed.username
                    server = parsed.hostname
                    port = parsed.port
                    query = parse_qs(parsed.query)
                    clash_proxy_dict = {
                        'name': str(parsed.fragment or 'Hysteria2 Node'),
                        'type': 'hysteria2',
                        'server': server,
                        'port': port,
                        'password': password,
                        'obfs': query.get('obfs', [''])[0],
                        'obfs-password': query.get('obfsParam', [''])[0],
                        'tls': True,
                        'skip-cert-verify': query.get('insecure', ['0'])[0] == '1',
                        'sni': query.get('sni', [server])[0],
                        'alpn': query.get('alpn', [''])[0].split(',')
                    }
                    if not clash_proxy_dict['obfs']:
                        del clash_proxy_dict['obfs']
                    if not clash_proxy_dict['obfs-password']:
                        del clash_proxy_dict['obfs-password']
                    if not clash_proxy_dict['alpn']:
                        del clash_proxy_dict['alpn']
            except Exception as e:
                logging.warning(f"URL节点转换为Clash字典失败: {node[:50]}... - {e}")
                clash_proxy_dict = None

        if clash_proxy_dict:
            name_to_check = str(node_raw_name or clash_proxy_dict.get('name', ''))
            should_delete_node = False
            for keyword in DELETE_KEYWORDS:
                try:
                    if keyword.lower() in name_to_check.lower():
                        logging.info(f"节点 '{name_to_check}' 包含删除关键词 '{keyword}'，已跳过。")
                        should_delete_node = True
                        break
                except AttributeError as e:
                    logging.error(f"检查删除关键词时出错: name_to_check={name_to_check}, type={type(name_to_check)}, node={clash_proxy_dict.get('name', 'Unknown')} - {e}")
                    should_delete_node = True
                    break
            if should_delete_node:
                continue

            server = clash_proxy_dict.get('server', '')
            if server and not (is_valid_ip_address(server) or re.match(r'^[a-zA-Z0-9\-\.]+$', server)):
                logging.warning(f"跳过无效服务器地址的节点: {server} in {clash_proxy_dict.get('name', 'Unknown')}")
                continue

            clash_proxy_dict['name'] = clean_node_name(
                clash_proxy_dict.get('name', f"{clash_proxy_dict.get('type', 'Unknown')} {clash_proxy_dict.get('server', '')}:{clash_proxy_dict.get('port', '')}"),
                index=idx + 1
            )

            # 清理冗余字段
            if clash_proxy_dict.get('ws-opts') == {'path': '', 'headers': {}} or clash_proxy_dict.get('ws-opts') is None:
                clash_proxy_dict.pop('ws-opts', None)
            if clash_proxy_dict.get('grpc-opts') == {'serviceName': ''} or clash_proxy_dict.get('grpc-opts') is None:
                clash_proxy_dict.pop('grpc-opts', None)
            if clash_proxy_dict.get('flow') == '':
                clash_proxy_dict.pop('flow', None)

            fingerprint = _generate_node_fingerprint(clash_proxy_dict)
            if fingerprint and fingerprint not in unique_node_fingerprints:
                unique_node_fingerprints.add(fingerprint)
                final_clash_proxies.append(clash_proxy_dict)
            else:
                logging.debug(f"重复节点（按指纹）：{clash_proxy_dict.get('name', '')} - {fingerprint}")

    return final_clash_proxies

# --- 主程序流程 ---

URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")

if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。无法获取订阅链接。")
    exit(1)

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
os.makedirs(os.path.dirname(STATISTICS_FILE), exist_ok=True)

raw_urls_from_source = get_url_list_from_remote(URL_SOURCE)

urls_to_fetch = set()
url_statistics = []
successful_urls = []
failed_urls = []
all_parsed_nodes_raw = []

print("\n--- 预处理原始URL/字符串列表 ---")
for entry in raw_urls_from_source:
    if is_valid_url(entry):
        urls_to_fetch.add(entry)
    else:
        print(f"发现非HTTP/HTTPS条目，尝试直接解析: {entry[:80]}...")
        parsed_nodes = parse_content_to_nodes(entry)
        if parsed_nodes:
            all_parsed_nodes_raw.extend(parsed_nodes)
            stat_entry = {'URL': entry, '节点数量': len(parsed_nodes), '状态': '直接解析成功', '错误信息': '', '状态码': None}
            url_statistics.append(stat_entry)
            successful_urls.append(entry)
        else:
            stat_entry = {'URL': entry, '节点数量': 0, '状态': '直接解析失败', '错误信息': '非URL且无法解析为节点', '状态码': None}
            url_statistics.append(stat_entry)
            failed_urls.append(entry)

print("\n--- 阶段一：获取并合并所有订阅链接中的节点 ---")
total_urls_to_process_via_http = len(urls_to_fetch)

if total_urls_to_process_via_http > 0:
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls_to_fetch}
        for future in tqdm(as_completed(future_to_url), total=total_urls_to_process_via_http, desc="通过HTTP/HTTPS请求并解析节点", mininterval=1.0):
            url = future_to_url[future]
            nodes, success, error_message, status_code = future.result()

            stat_entry = {
                'URL': url,
                '节点数量': len(nodes),
                '状态': '成功' if success else '失败',
                '错误信息': error_message if error_message else '',
                '状态码': status_code
            }
            url_statistics.append(stat_entry)

            if success:
                successful_urls.append(url)
                all_parsed_nodes_raw.extend(nodes)
                print(f"成功处理 URL: {url}, 节点数: {len(nodes)}, 状态码: {status_code}")
            else:
                failed_urls.append(url)
                print(f"失败 URL: {url}, 错误: {error_message}")

            if len(all_parsed_nodes_raw) >= MAX_SUCCESS * 2:
                print("已收集足够节点，提前终止请求")
                executor._threads.clear()
                break

final_unique_clash_proxies = deduplicate_and_standardize_nodes(all_parsed_nodes_raw)

with open(TEMP_MERGED_NODES_RAW_FILE, 'w', encoding='utf-8') as temp_file:
    for node in final_unique_clash_proxies:
        temp_file.write(json.dumps(node, ensure_ascii=False) + '\n')

print(f"\n阶段一完成。合并到 {len(final_unique_clash_proxies)} 个唯一Clash代理字典，已保存至 {TEMP_MERGED_NODES_RAW_FILE}")

write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE)

print("\n--- 阶段二：输出最终 Clash YAML 配置 ---")

if not OUTPUT_FILE.endswith(('.yaml', '.yml')):
    OUTPUT_FILE = os.path.splitext(OUTPUT_FILE)[0] + '.yaml'

proxies_to_output = final_unique_clash_proxies[:MAX_SUCCESS]

clash_config = {
    'proxies': proxies_to_output
}

success_count = len(proxies_to_output)

try:
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
        yaml.dump(clash_config, out_file, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"最终 Clash YAML 配置已保存至：{OUTPUT_FILE}")
except Exception as e:
    logging.error(f"写入最终 Clash YAML 文件失败: {e}")
    print(f"错误：写入最终 Clash YAML 文件失败: {e}")

if os.path.exists(TEMP_MERGED_NODES_RAW_FILE):
    os.remove(TEMP_MERGED_NODES_RAW_FILE)
    print(f"已删除临时文件：{TEMP_MERGED_NODES_RAW_FILE}")

print("\n" + "=" * 50)
print("最终结果：")
print(f"原始来源总条目数：{len(raw_urls_from_source)}")
print(f"其中需要HTTP/HTTPS请求的订阅链接数：{len(urls_to_fetch)}")
print(f"其中直接解析的非URL字符串数：{len(raw_urls_from_source) - len(urls_to_fetch)}")
print(f"成功处理的URL/字符串总数：{len(successful_urls)}")
print(f"失败的URL/字符串总数：{len(failed_urls)}")
print(f"初步聚合的原始节点数（去重和过滤前）：{len(all_parsed_nodes_raw)}")
print(f"去重、标准化和过滤后的唯一Clash代理数：{len(final_unique_clash_proxies)}")
print(f"最终输出到Clash YAML文件的节点数：{success_count}")
if len(final_unique_clash_proxies) > 0:
    print(f"最终有效内容率（相对于去重过滤后）：{success_count/len(final_unique_clash_proxies):.1%}")
if success_count < MAX_SUCCESS:
    print("警告：未能达到目标数量，原始列表可能有效URL/节点不足，或部分URL获取失败。")
print(f"结果文件已保存至：{OUTPUT_FILE}")
print(f"统计数据已保存至：{STATISTICS_FILE}")
print(f"成功URL列表已保存至：{SUCCESS_URLS_FILE}")
print(f"失败URL列表已保存至：{FAILED_URLS_FILE}")
print("=" * 50)
