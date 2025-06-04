# -*- coding: utf-8 -*-
import os
import requests
from urllib.parse import urlparse, parse_qs, urlencode
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

# 配置日志
logging.basicConfig(filename='error.log', level=logging.ERROR,
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
parser.add_argument('--timeout', type=int, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.yaml', help="输出文件路径")
args = parser.parse_args()

# 全局变量，从命令行参数或默认值获取
MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
TEMP_MERGED_NODES_RAW_FILE = 'temp_merged_nodes_raw.txt'
STATISTICS_FILE = 'data/url_statistics.csv'
SUCCESS_URLS_FILE = 'data/successful_urls.txt'
FAILED_URLS_FILE = 'data/failed_urls.txt'

# 定义如果节点名称包含这些关键词，则直接删除该节点
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
            # 对于 IPv6 地址，检查是否被正确包裹在方括号中
            if host.startswith('[') and host.endswith(']'):
                ipaddress.ip_address(host[1:-1])
                return True
            return False
        except ValueError:
            return False

def get_url_list_from_remote(url_source):
    """从给定的公开网址获取 URL 列表"""
    try:
        response = requests.get(url_source, headers=headers, timeout=10)
        response.raise_for_status()
        text_content = response.text.strip()
        raw_urls = [line.strip() for line in text_content.splitlines() if line.strip()]
        print(f"从 {url_source} 获取到 {len(raw_urls)} 个URL")
        return raw_urls
    except Exception as e:
        logging.error(f"获取URL列表失败: {url_source} - {e}")
        return []

def parse_content_to_nodes(content):
    """
    从文本内容中解析出各种类型的节点。
    返回的节点格式保持原始字符串或字典形式。
    """
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

    # 2. 尝试 YAML 解析 (主要用于 Clash 配置)
    try:
        parsed_data = yaml.safe_load(processed_content)
        if isinstance(parsed_data, dict) and 'proxies' in parsed_data and isinstance(parsed_data['proxies'], list):
            for proxy_entry in parsed_data['proxies']:
                if isinstance(proxy_entry, dict):
                    found_nodes.append(proxy_entry)
                elif isinstance(proxy_entry, str) and any(proxy_entry.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    found_nodes.append(proxy_entry.strip())
            logging.info("内容成功解析为 Clash YAML。")
        elif isinstance(parsed_data, list):
            for item in parsed_data:
                if isinstance(item, str):
                    found_nodes.append(item.strip())
                elif isinstance(item, dict):
                    found_nodes.append(item)
            logging.info("内容成功解析为 YAML 列表。")
    except yaml.YAMLError:
        pass
    except Exception as e:
        logging.error(f"YAML 解析失败: {e}")
        pass

    # 3. 通过正则表达式提取节点（处理明文、非标准格式等）
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
    返回一个元组：(节点列表, 是否成功, 错误信息(如果失败))
    """
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text.strip()
        
        if len(content) < 10:
            logging.warning(f"获取到内容过短，可能无效: {url}")
            return [], False, "内容过短"
        
        nodes = parse_content_to_nodes(content)
        return nodes, True, None
    except requests.exceptions.Timeout:
        logging.error(f"请求超时: {url}")
        return [], False, "请求超时"
    except requests.exceptions.RequestException as e:
        logging.error(f"请求失败: {url} - {e}")
        return [], False, f"请求失败: {e}"
    except Exception as e:
        logging.error(f"处理URL异常: {url} - {e}")
        return [], False, f"未知异常: {e}"

def write_statistics_to_csv(statistics_data, filename):
    """将统计数据写入CSV文件"""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量', '状态', '错误信息']
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

def clean_node_name(name):
    """
    清理节点名称，移除冗余信息，只保留核心关键字。
    """
    if not isinstance(name, str):
        return str(name)

    cleaned_name = name.strip()

    # 1. 移除各种括号及其内部内容 (包括全角和半角)
    cleaned_name = re.sub(r'【[^】]*】', '', cleaned_name)
    cleaned_name = re.sub(r'\[[^\]]*\]', '', cleaned_name)
    cleaned_name = re.sub(r'\([^\)]*\)', '', cleaned_name)
    cleaned_name = re.sub(r'（[^）]*）', '', cleaned_name)
    cleaned_name = re.sub(r'\{[^}]*\}', '', cleaned_name)
    cleaned_name = re.sub(r'＜[^＞]*＞', '', cleaned_name)
    cleaned_name = re.sub(r'<[^>]*>', '', cleaned_name)

    # 2. 移除常见的冗余关键词（不包含在 DELETE_KEYWORDS 中的）
    redundant_keywords_to_remove = [
        r'\[\d+\]', # [1], [2] 这种序号
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', # IP地址
        r'x\d+', # x1, x2 等倍率标识
        r'\d+%', # 100% 这种百分比
        r'\d{4}-\d{2}-\d{2}', # 日期 YYYY-MM-DD
        r'\d{2}-\d{2}', # 日期 MM-DD
        r'IPLC', r'IEPL', r'NAT', r'UDP', r'TCP', r'隧道', r'直连', r'中转', r'回国',
        r'线路', r'入口', r'出口', r'节点', r'负载均衡', r'普通', r'优质', r'高级', r'超清',
        r'秒杀', r'活动', r'新年', r'福利', r'VIP', r'VIP\d+', r'Pro', r'Lite', r'Plus',
        r'SS', r'SSR', r'VMESS', r'VLESS', r'TROJAN', r'HYSTERIA', r'HYSTERIA2', r'HY', r'HY2', # 协议名
        r'自动', r'手动', r'自选', r'香港', r'台湾', r'日本', r'韩国', r'新加坡', r'美国', r'英国', r'德国',
        r'France', r'Canada', r'Australia', r'Russia', r'Brazil', r'India', r'UAE',
        r'HK', r'TW', r'JP', r'KR', r'SG', r'US', r'UK', r'DE', r'FR', r'CA', r'AU', r'RU', r'BR', r'IN', r'AE',
        r'地区', r'城市', r'编号', r'序号', r'数字', r'号', r'服', r'群', r'组', r'专线', r'加速',
        r'(\d+ms)', # 100ms 这种延迟标记
        r'(\d+\.\d+kbps)', r'(\d+\.\d+mbps)', r'(\d+kbps)', r'(\d+mbps)', # 速度标记
        r'\\n', r'\\r', # 换行符
        r'\d+\.\d+G|\d+G', # 流量信息
        r'\[\d+\]' # 再次去除数字在方括号内
    ]

    for keyword in redundant_keywords_to_remove:
        cleaned_name = re.sub(keyword, ' ', cleaned_name, flags=re.IGNORECASE).strip()

    # 3. 移除特殊字符（只保留汉字、字母、数字、点、横线、下划线、空格）
    cleaned_name = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9\s\.\-_]', ' ', cleaned_name)

    # 4. 合并多个空格为一个，并去除首尾空格
    cleaned_name = re.sub(r'\s+', ' ', cleaned_name).strip()

    # 5. 常见缩写或变体的标准化
    cleaned_name = cleaned_name.replace('香港', 'HK').replace('台湾', 'TW').replace('日本', 'JP').replace('新加坡', 'SG')
    cleaned_name = cleaned_name.replace('美国', 'US').replace('英国', 'UK').replace('德国', 'DE').replace('韩国', 'KR')
    cleaned_name = cleaned_name.replace('马来', 'MY').replace('泰国', 'TH').replace('菲律宾', 'PH').replace('越南', 'VN')
    cleaned_name = cleaned_name.replace('印尼', 'ID').replace('印度', 'IN').replace('澳洲', 'AU').replace('加拿大', 'CA')
    cleaned_name = cleaned_name.replace('俄罗斯', 'RU').replace('巴西', 'BR').replace('意大利', 'IT').replace('荷兰', 'NL')
    cleaned_name = cleaned_name.replace('中国', 'CN')

    # 6. 截断过长名称，保留前50个字符
    if len(cleaned_name) > 50:
        cleaned_name = cleaned_name[:50] + '...'

    return cleaned_name if cleaned_name else "Unknown Node"

def _generate_node_fingerprint(node):
    """
    为Clash代理字典或节点链接生成一个唯一的指纹（哈希值）。
    """
    if isinstance(node, dict):
        fingerprint_data = {
            'type': node.get('type'),
            'server': node.get('server'),
            'port': node.get('port'),
        }

        node_type = node.get('type')
        if node_type == 'vmess':
            fingerprint_data['uuid'] = node.get('uuid') or node.get('id')
            fingerprint_data['alterId'] = node.get('alterId') or node.get('aid')
            fingerprint_data['network'] = node.get('network')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['sni'] = node.get('sni') or node.get('host')
            fingerprint_data['path'] = node.get('path')
        elif node_type == 'trojan':
            fingerprint_data['password'] = node.get('password')
            fingerprint_data['network'] = node.get('network')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['sni'] = node.get('sni') or node.get('host')
            fingerprint_data['skip-cert-verify'] = node.get('skip-cert-verify')
        elif node_type == 'ss':
            fingerprint_data['cipher'] = node.get('cipher')
            fingerprint_data['password'] = node.get('password')
        elif node_type == 'vless':
            fingerprint_data['uuid'] = node.get('uuid') or node.get('id')
            fingerprint_data['network'] = node.get('network')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['sni'] = node.get('sni') or node.get('host')
            fingerprint_data['path'] = node.get('path')
            fingerprint_data['flow'] = node.get('flow')
        elif node_type in ['hysteria', 'hysteria2', 'hy', 'hy2']:
            fingerprint_data['password'] = node.get('password')
            fingerprint_data['obfs'] = node.get('obfs')
            fingerprint_data['obfs-password'] = node.get('obfs-password')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['sni'] = node.get('sni') or node.get('host')
            fingerprint_data['alpn'] = node.get('alpn')
            fingerprint_data['skip-cert-verify'] = node.get('skip-cert-verify')

        normalized_data = {k: str(v).lower().strip() if v is not None else '' for k, v in fingerprint_data.items()}
        stable_json = json.dumps(normalized_data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(stable_json.encode('utf-8')).hexdigest()
    elif isinstance(node, str):
        try:
            # 验证节点是否为有效的协议 URL
            if not any(node.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                logging.warning(f"无效的节点协议: {node[:50]}...")
                return None

            parsed_url = urlparse(node)
            scheme = parsed_url.scheme
            netloc = parsed_url.netloc
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            # 验证 netloc 中的主机部分
            host = netloc.split(':')[0] if ':' in netloc else netloc
            if is_valid_ip_address(host) and host.startswith('[') and host.endswith(']'):
                host = host[1:-1]  # 移除 IPv6 地址的方括号
            elif not is_valid_ip_address(host) and not re.match(r'^[a-zA-Z0-9\-\.]+$', host):
                logging.warning(f"无效的主机名: {host} in {node[:50]}...")
                return None

            normalized_query_params = {}
            for k, v in query_params.items():
                normalized_query_params[k.lower()] = str(v[0]).lower().strip()
            
            fingerprint_parts = [
                scheme,
                host.lower(),
                netloc.lower().split(':')[-1] if ':' in netloc else '',
                path.lower()
            ]

            sorted_query_keys = sorted(normalized_query_params.keys())
            for k in sorted_query_keys:
                if k not in ['name', 'ps', 'remarks', 'info', 'flow', 'usage', 'expire', 'ud', 'up', 'dn', 'package', 'nodeName', 'nodeid', 'ver']:
                    fingerprint_parts.append(f"{k}={normalized_query_params[k]}")

            return hashlib.sha256("".join(fingerprint_parts).encode('utf-8')).hexdigest()
        except Exception as e:
            logging.warning(f"生成URL节点指纹失败: {node[:50]}... - {e}")
            return None
    return None

def deduplicate_and_standardize_nodes(raw_nodes_list):
    """
    对混合格式的节点进行去重，标准化为Clash YAML代理字典，并根据关键词过滤。
    返回一个列表，其中包含唯一的、标准化的Clash代理字典。
    """
    unique_node_fingerprints = set()
    final_clash_proxies = []

    for node in raw_nodes_list:
        clash_proxy_dict = None
        node_raw_name = ""  # 用于检查是否包含删除关键词的原始名称

        if isinstance(node, dict):
            clash_proxy_dict = node
            node_raw_name = node.get('name', '')
        elif isinstance(node, str):
            try:
                parsed_url = urlparse(node)
                node_raw_name = parsed_url.fragment  # 提取 # 后面的部分
                # 验证节点协议
                if not any(node.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    logging.warning(f"跳过无效协议的节点: {node[:50]}...")
                    continue

                # 验证主机名或 IP 地址
                host = parsed_url.hostname or ''
                if host and not (is_valid_ip_address(host) or re.match(r'^[a-zA-Z0-9\-\.]+$', host)):
                    logging.warning(f"跳过无效主机名的节点: {host} in {node[:50]}...")
                    continue

                # 尝试将 URL 转换为 Clash 代理字典
                if node.startswith("vmess://"):
                    decoded = base64.b64decode(node[len("vmess://"):].encode('utf-8')).decode('utf-8')
                    config = json.loads(decoded)
                    clash_proxy_dict = {
                        'name': config.get('ps', 'VMess Node'),
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
                        'name': parsed.fragment or 'Trojan Node',
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
                            'name': parsed_url.fragment or 'SS Node',
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
                        'name': parsed.fragment or 'VLESS Node',
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
                        'name': parsed.fragment or 'Hysteria Node',
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
                        'name': parsed.fragment or 'Hysteria2 Node',
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
            # 检查原始名称是否包含删除关键词
            should_delete_node = False
            name_to_check = node_raw_name or clash_proxy_dict.get('name', '')

            for keyword in DELETE_KEYWORDS:
                if keyword.lower() in name_to_check.lower():
                    logging.info(f"节点 '{name_to_check}' 包含删除关键词 '{keyword}'，已跳过。")
                    should_delete_node = True
                    break
            
            if should_delete_node:
                continue

            # 验证服务器地址
            server = clash_proxy_dict.get('server', '')
            if server and not (is_valid_ip_address(server) or re.match(r'^[a-zA-Z0-9\-\.]+$', server)):
                logging.warning(f"跳过无效服务器地址的节点: {server} in {clash_proxy_dict.get('name', 'Unknown')}")
                continue

            # 清理节点名称
            clash_proxy_dict['name'] = clean_node_name(clash_proxy_dict.get('name', f"{clash_proxy_dict.get('type', 'Unknown')} {clash_proxy_dict.get('server', '')}:{clash_proxy_dict.get('port', '')}"))

            # 使用指纹进行去重
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
            stat_entry = {'URL': entry, '节点数量': len(parsed_nodes), '状态': '直接解析成功', '错误信息': ''}
            url_statistics.append(stat_entry)
            successful_urls.append(entry)
        else:
            stat_entry = {'URL': entry, '节点数量': 0, '状态': '直接解析失败', '错误信息': '非URL且无法解析为节点'}
            url_statistics.append(stat_entry)
            failed_urls.append(entry)

print("\n--- 阶段一：获取并合并所有订阅链接中的节点 ---")
total_urls_to_process_via_http = len(urls_to_fetch)

if total_urls_to_process_via_http > 0:
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls_to_fetch}
        for future in tqdm(as_completed(future_to_url), total=total_urls_to_process_via_http, desc="通过HTTP/HTTPS请求并解析节点"):
            url = future_to_url[future]
            nodes, success, error_message = future.result()

            stat_entry = {'URL': url, '节点数量': len(nodes), '状态': '成功' if success else '失败', '错误信息': error_message if error_message else ''}
            url_statistics.append(stat_entry)

            if success:
                successful_urls.append(url)
                all_parsed_nodes_raw.extend(nodes)
            else:
                failed_urls.append(url)

final_unique_clash_proxies = deduplicate_and_standardize_nodes(all_parsed_nodes_raw)

with open(TEMP_MERGED_NODES_RAW_FILE, 'w', encoding='utf-8') as temp_file:
    for node in final_unique_clash_proxies:
        if isinstance(node, dict):
            temp_file.write(json.dumps(node, ensure_ascii=False) + '\n')
        else:
            temp_file.write(node.strip() + '\n')

print(f"\n阶段一完成。合并到 {len(final_unique_clash_proxies)} 个唯一Clash代理字典，已保存至 {TEMP_MERGED_NODES_RAW_FILE}")

write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE)

print("\n--- 阶段二：输出最终 Clash YAML 配置 ---")

if not OUTPUT_FILE.endswith(('.yaml', '.yml')):
    OUTPUT_FILE = os.path.splitext(OUTPUT_FILE)[0] + '.yaml'

proxies_to_output = final_unique_clash_proxies[:MAX_SUCCESS]

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
            'name': '🚀 节点选择',
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
        'MATCH,🚀 节点选择'
    ]
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
