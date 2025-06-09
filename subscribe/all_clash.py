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
from collections import defaultdict
import random

# 配置日志
logging.basicConfig(
    filename='error.log',
    level=logging.INFO,  # 减少DEBUG日志，提高性能
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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
parser.add_argument('--timeout', type=int, default=30, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.yaml', help="输出文件路径")
args = parser.parse_args()

# 全局变量
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

# 预编译正则表达式，提高性能
region_pattern = re.compile(r'\b(HK|TW|JP|SG|US|UK|DE|KR|MY|TH|PH|VN|ID|IN|AU|CA|RU|BR|IT|NL|CN|AE|AD|KZ)\b', re.IGNORECASE)
provider_pattern = re.compile(r'\b(AWS|Amazon|Akamai|Oracle|Alibaba|Google|Tencent|Vultr|OVH|DigitalOcean|Core Labs|Cloudflare)\b', re.IGNORECASE)
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
        logging.info(f"从 {url_source} 获取到 {len(raw_urls)} 个URL")
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
    """清理节点名称，增强地区和提供商解析"""
    if not isinstance(name, str):
        name = str(name)

    cleaned_name = name.strip()

    # 删除无关信息
    cleaned_name = re.sub(r'【[^】]*?(流量|到期|过期|充值|续费)[^】]*】', '', cleaned_name)
    cleaned_name = re.sub(r'\[[^]]*?(流量|到期|过期|充值|续费)[^\]]*\]', '', cleaned_name)
    cleaned_name = re.sub(r'\([^)]*?(流量|到期|过期|充值|续费)[^)]*\)', '', cleaned_name)
    cleaned_name = re.sub(r'（[^）]*?(流量|到期|过期|充值|续费)[^）]*）', '', cleaned_name)

    redundant_keywords = [
        r'\d+%', r'\d{4}-\d{2}-\d{2}', r'\d{2}-\d{2}', r'x\d+',
        r'秒杀', r'活动', r'新年', r'福利', r'VIP\d*', r'Pro', r'Lite', r'Plus',
        r'自动', r'手动', r'自选', r'(\d+\.\d+kbps)', r'(\d+\.\d+mbps)', r'(\d+kbps)', r'(\d+mbps)',
        r'\\n', r'\\r', r'\d+\.\d+G|\d+G',
    ]
    for keyword in redundant_keywords:
        cleaned_name = re.sub(keyword, ' ', cleaned_name, flags=re.IGNORECASE).strip()

    cleaned_name = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9\s\.\-_@#|]', ' ', cleaned_name)
    cleaned_name = re.sub(r'\s+', ' ', cleaned_name).strip()

    # 地区和提供商映射
    region_map = {
        '香港': 'HK', '台湾': 'TW', '日本': 'JP', '新加坡': 'SG', '美国': 'US', '英国': 'UK',
        '德国': 'DE', '韩国': 'KR', '马来西亚': 'MY', '泰国': 'TH', '菲律宾': 'PH', '越南': 'VN',
        '印尼': 'ID', '印度': 'IN', '澳大利亚': 'AU', '加拿大': 'CA', '俄罗斯': 'RU', '巴西': 'BR',
        '意大利': 'IT', '荷兰': 'NL', '中国': 'CN', '阿联酋': 'AE', '安道尔': 'AD', '哈萨克斯坦': 'KZ'
    }
    provider_map = {
        'Amazon': 'AWS', 'Oracle': 'Oracle', 'Alibaba': 'Alibaba', 'Google': 'Google',
        'Tencent': 'Tencent', 'Vultr': 'Vultr', 'OVH': 'OVH', 'DigitalOcean': 'DO',
        'Akamai': 'Akamai', 'Core Labs': 'CoreLabs', 'Cloudflare': 'CF'
    }

    # 提取地区和提供商
    region = None
    provider = None
    region_match = region_pattern.search(cleaned_name)
    provider_match = provider_pattern.search(cleaned_name)
    if region_match:
        region = region_match.group(0).upper()
    if provider_match:
        provider = provider_match.group(0).title()
        for full_name, short_name in provider_map.items():
            if full_name.lower() in provider.lower():
                provider = short_name
                break

    # 保留关键信息
    meaningful_keywords = ['IPLC', 'IEPL', '专线', '中转', '直连']
    preserved_info = [kw for kw in meaningful_keywords if kw.lower() in cleaned_name.lower()]
    
    node_number_match = re.search(r'(?<!\d)\d{1,2}(?!\d)|Node\d{1,2}', cleaned_name, re.IGNORECASE)
    if node_number_match:
        preserved_info.append(node_number_match.group(0))

    # 构建名称
    parts = []
    if region:
        parts.append(region)
    if provider:
        parts.append(provider)
    if preserved_info:
        parts.append('_'.join(preserved_info))
    if not parts:
        parts.append('Node')
    if index is not None:
        parts.append(f"{index:02d}")
    
    cleaned_name = '-'.join(parts)
    
    if len(cleaned_name) > 80:
        cleaned_name = cleaned_name[:80].rstrip() + '...'

    return cleaned_name if cleaned_name else f"Node-{index:02d}" if index is not None else "Unknown Node"

def _generate_node_fingerprint(node):
    """为节点生成唯一指纹，简化字段以减少重复"""
    def normalize_value(value):
        return '' if value is None else str(value).lower().strip()

    if isinstance(node, dict):
        fingerprint_data = {
            'type': normalize_value(node.get('type')),
            'server': normalize_value(node.get('server')),
            'port': normalize_value(node.get('port')),
            'network': normalize_value(node.get('network')),
            'tls': normalize_value(node.get('tls')),
            'sni': normalize_value(node.get('sni') or node.get('host')),
        }
        stable_json = json.dumps(fingerprint_data, sort_keys=True, ensure_ascii=False)
        fingerprint = hashlib.sha256(stable_json.encode('utf-8')).hexdigest()
        return fingerprint

    elif isinstance(node, str):
        try:
            if not any(node.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                return None
            parsed_url = urlparse(node)
            scheme = parsed_url.scheme.lower()
            netloc = parsed_url.netloc.lower()
            host = netloc.split(':')[0] if ':' in netloc else netloc
            port = netloc.split(':')[1] if ':' in netloc else ''
            if is_valid_ip_address(host) and host.startswith('[') and host.endswith(']'):
                host = host[1:-1]
            elif not is_valid_ip_address(host) and not re.match(r'^[a-zA-Z0-9\-\.]+$', host):
                return None
            fingerprint_parts = [scheme, host, port]
            fingerprint = hashlib.sha256(''.join(fingerprint_parts).encode('utf-8')).hexdigest()
            return fingerprint
        except Exception:
            return None

    return None

def deduplicate_and_standardize_nodes(raw_nodes_list):
    """去重逻辑，输出所有唯一节点，保持多样性"""
    unique_node_fingerprints = set()
    grouped_nodes = defaultdict(list)

    logging.info(f"去重前节点数: {len(raw_nodes_list)}")

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
                    continue
                host = parsed_url.hostname or ''
                if host and not (is_valid_ip_address(host) or re.match(r'^[a-zA-Z0-9\-\.]+$', host)):
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
                    if clash_proxy_dict.get('ws-opts') == {'path': '/', 'headers': {'Host': ''}}:
                        clash_proxy_dict['ws-opts'] = None
                    if clash_proxy_dict.get('grpc-opts') == {'serviceName': ''}:
                        clash_proxy_dict['grpc-opts'] = None
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
                    except Exception:
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
                    if clash_proxy_dict.get('ws-opts') == {'path': '/', 'headers': {'Host': ''}}:
                        clash_proxy_dict['ws-opts'] = None
                    if clash_proxy_dict.get('grpc-opts') == {'serviceName': ''}:
                        clash_proxy_dict['grpc-opts'] = None
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
                        'server': parsed_url,
                        'port': 'port',
                        'password': password,
                        'obfs': query.get('obfs', [''])[0],
                        'obfs-password': query.get('password', [''])[0],
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
            # 过滤包含删除关键词的节点
            if any(keyword.lower() in node_raw_name.lower() for keyword in DELETE_KEYWORDS:
                continue

            server = clash_proxy_dict.get('server', '')
            if server and not (is_valid_ip_address(server) or re.match(r'^[a-zA-Z0-9\-\.]+$', server)):
                logging.warning(f"忽略无效服务器地址的节点: {server}")
                continue

            # 提取地区和提供商
            region = 'Unknown'
            provider = 'Unknown'
            region_match = region_pattern.search(node_raw_name)
            provider_match = provider_pattern.search(node_raw_name)
            if region_match:
                region = region_match.group(0).upper()
            if provider_match:
                provider = provider_match.group(0).title()

            # 清理节点名称
            clash_proxy_dict['name'] = clean_node_name(node_raw_name, idx + 1)

            # 生成指纹并去重
            fingerprint = _generate_node_fingerprint(clash_proxy_dict)
            if fingerprint and fingerprint not in unique_node_fingerprints:
                unique_node_fingerprints.add(fingerprint)
                group_key = (region, provider, clash_proxy_dict.get('type', 'Unknown'))
                grouped_nodes[group_key].append(clash_proxy_dict)

    # 动态分配所有唯一节点，保持多样性
    final_clash_proxies = []
    region_counts = defaultdict(int)
    protocol_counts = defaultdict(int)

    # 按地区和协议排序，确保多样性
    sorted_groups = sorted(grouped_nodes.items(), key=lambda x: len(x[1]), reverse=True)
    
    for (region, provider, protocol), nodes in sorted_groups:
        # 随机选择一个代表性节点（可扩展为按质量排序）
        selected = random.choice(nodes)
        final_clash_proxies.append(selected)
        region_counts[region] += 1
        protocol_counts[protocol.lower()] += 1

    logging.info(f"去重后节点数：{len(final_clash_proxies)}")
    logging.info(f"地区分布：{dict(region_counts)}")
    logging.info(f"协议分布：{dict(protocol_counts)}")
    return final_clash_proxies

# 主程序流程
URL_SOURCE = os.environ.get('URL_SOURCE')
print(f"调试信息 - 读取到的 URL 来源：{source: {URL_SOURCE}")

if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。无法获取订阅链接。")
    logging.error("未设置 URL_SOURCE 环境变量")
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
        print(f"发现非HTTP/HTTPS条目，尝试直接解析：{entry[:80]}...")
        parsed_nodes = parse_content_to_nodes(entry.strip())
        if parsed_nodes:
            all_parsed_nodes_raw.extend(parsed_nodes)
            stat_entry = {'URL': 'entry['URL'], '节点数量': len(parsed_nodes)}, 'Status': 'Success', 'Error Message': 'Directly parsed successfully'}, 'Status Code': None}
            url_statistics.append(stat_entry)
            successful_urls.append(entry)
        else:
            stat_entry = {'entry: 'URL', 'failed_urls': 0}, 'Status': 'Failed', 'Error Message': '非URL且无法解析为节点'}, 'Status Code': None}
            url_statistics.append(stat_entry)
            failed_urls.append(entry)

print("\n--- 阶段 1：获取并合并所有订阅链接中的节点 ---")
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

final_clash_proxies = deduplicate_and_standardize_nodes(all_parsed_nodes_raw)

with open(TEMP_MERGED_NODES_RAW_FILE, 'w', encoding='utf-8') as f:
    for node in final_clash_proxies:
        if isinstance(node, dict):
            f.write(json.dumps(node, ensure_ascii=False) + '\n')
        else:
            f.write(str(node).strip() + '\n')

print(f"\n阶段一完成。合并到 {len(final_clash_proxies)} 个唯一Clash代理字典，保存至 {TEMP_MERGED_NODES_RAW_FILE}")

write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE))

print("\n--- 阶段二：输出最终 Clash YAML 配置 ---")
if not OUTPUT_FILE.endswith(('.yaml', '.yml')):
    OUTPUT_FILE = os.path.splitext(OUTPUT_FILE)[0] + '.yaml'

proxies_to_output = final_clash_proxies  # 输出所有唯一节点

proxy_names_in_group = []
for node in proxies_to_output:
    if isinstance(node, dict) and 'name' in node:
        proxy_names_in_group.append(node['name'])
    else:
        proxy_names_in_group.append(f"{node.get('type', 'Unknown')} {node.get('server', '')}")

clash_config = {
    'proxies': proxies_to_output,
    'proxy-groups': [
        {
            'name': '🚖 节点选择',
            'type': 'select',
            'proxies': ['DIRECT'] + proxy_names_in_group
        },
        {
            'name': '♻️ 自动选择',
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'proxies': proxy_names_in_group
        }
    ],
    'rules': [
        'MATCH', '🚖 节点选择'
    ]
}

success_count = len(proxies_to_output)

try:
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
        yaml.dump(clash_config, out_file, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"最终 Clash YAML 配置已保存至：{OUTPUT_FILE}")

except Exception as e:
    logging.error(f"写入最终 Clash YAML 文件失败: {e}")
    print(f"错误：写入最终 Clash YAML 文件失败: {str(e)}")

if os.path.exists(TEMP_MERGED_NODES_RAW_FILE):
    os.remove(TEMP_MERGED_NODES_RAW_FILE)
    print(f"已删除临时文件：{TEMP_MERGED_NODES_RAW_FILE}")

print("\n" + "="*50)
print("最终结果：")
print(f"原始来源总条目数：{len(raw_urls_from_source}")
print(f"其中需要HTTP/HTTPS请求的订阅链接数：{len(urls_to_fetch)}")
print(f"其中直接解析的非URL字符串数：{len(raw_urls_from_source) - len(urls_to_fetch)}")
print(f"成功处理的URL/字符串总数：{len(successful_urls)}")
print(f"失败的URL/字符串总数：{len(failed_urls)}")
print(f"初步聚合的原始节点数（去重和过滤前）：{len(all_failed_urls_raw)}")
print(f"去重、标准化和过滤后的节点数：{len(final_clash_proxies)}")
print(f"最终输出到Clash YAML文件的节点数：{success_count}")
if len(final_clash_proxies) > 0:
    print(f"最终有效内容率（相对于去重过滤后）：{success_count/len(final_clash_proxies):.1%}")
print(f"结果文件已保存至：{OUTPUT_FILE}")
print(f"统计数据已保存至：{STATISTICS_FILE}")
print(f"成功URL列表已保存至：{SUCCESS_URLS_FILE}")
print(f"失败URL列表已保存至：{FAILED_URLS_FILE}")
print("=" * 50)
