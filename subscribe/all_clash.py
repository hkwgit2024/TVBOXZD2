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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志
# 日志文件名为 error.log，级别设置为 DEBUG，方便调试和问题追溯
logging.basicConfig(filename='error.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 请求头
# 模拟浏览器行为，防止被服务器识别为机器人
headers = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/91.0.4472.124 Safari/537.36'
    ),
    'Accept-Encoding': 'gzip, deflate' # 接受gzip和deflate编码，提高传输效率
}

# 命令行参数解析
# 允许用户通过命令行自定义脚本行为
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源和节点解析")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功数量，达到此数量后脚本可能会提前终止")
parser.add_argument('--timeout', type=int, default=30, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.yaml', help="输出文件路径，生成的Clash YAML配置将保存到此文件")
args = parser.parse_args()

# 全局变量
MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
TEMP_MERGED_NODES_RAW_FILE = 'temp_merged_nodes_raw.txt' # 临时文件，用于存储原始解析到的节点
STATISTICS_FILE = 'data/url_statistics.csv' # 统计文件，记录每个URL的处理结果
SUCCESS_URLS_FILE = 'data/successful_urls.txt' # 成功获取并解析的URL列表
FAILED_URLS_FILE = 'data/failed_urls.txt' # 失败的URL列表

# 定义删除关键词
# 包含这些关键词的节点名称将被跳过，通常是广告、流量信息等
DELETE_KEYWORDS = [
    '剩余流量', '套餐到期', '流量', '到期', '过期', '免费', '试用', '体验', '限时', '限制',
    '已用', '可用', '不足', '到期时间', '倍率', '返利', '充值', '续费', '用量', '订阅'
]

def is_valid_url(url):
    """
    验证URL格式是否合法，仅接受 http 或 https 方案。
    使用 urllib.parse.urlparse 进行解析和验证。
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def is_valid_ip_address(host):
    """
    验证是否为有效的 IPv4 或 IPv6 地址。
    使用 ipaddress 模块进行验证。
    """
    try:
        # 尝试解析为IPv4或IPv6
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # 针对IPv6地址可能带方括号的情况进行额外处理
        try:
            if host.startswith('[') and host.endswith(']'):
                ipaddress.ip_address(host[1:-1])
                return True
            return False
        except ValueError:
            return False

def get_url_list_from_remote(url_source):
    """
    从给定的公开网址获取 URL 列表。
    通常这个url_source会是一个包含订阅链接的文本文件。
    """
    try:
        session = requests.Session()
        # 配置重试策略，处理常见的网络错误和状态码
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url_source, headers=headers, timeout=10)
        response.raise_for_status() # 如果状态码不是2xx，会抛出HTTPError
        text_content = response.text.strip()
        # 将内容按行分割，过滤空行
        raw_urls = [line.strip() for line in text_content.splitlines() if line.strip()]
        print(f"从 {url_source} 获取到 {len(raw_urls)} 个URL或字符串")
        return raw_urls
    except Exception as e:
        logging.error(f"获取URL列表失败: {url_source} - {e}")
        return []

def parse_content_to_nodes(content):
    """
    从文本内容中解析出节点。
    内容可能是Base64编码的，也可能是Clash YAML格式，或者直接是多种协议的URL列表。
    """
    if not content:
        return []

    found_nodes = []
    processed_content = content

    # 1. 尝试 Base64 解码
    # 订阅内容通常是Base64编码的，优先尝试解码
    try:
        decoded_bytes = base64.b64decode(content)
        processed_content = decoded_bytes.decode('utf-8')
        logging.info("内容成功 Base64 解码。")
    except Exception:
        # 如果不是Base64编码，则保持原样
        pass

    # 2. 尝试 YAML 解析
    # 如果是Clash YAML配置，解析其中的proxies部分
    try:
        parsed_data = yaml.safe_load(processed_content)
        if isinstance(parsed_data, dict) and 'proxies' in parsed_data and isinstance(parsed_data['proxies'], list):
            for proxy_entry in parsed_data['proxies']:
                if isinstance(proxy_entry, dict):
                    # 确保name是字符串，以防某些配置中name是数字
                    if 'name' in proxy_entry and not isinstance(proxy_entry['name'], str):
                        proxy_entry['name'] = str(proxy_entry['name'])
                    found_nodes.append(proxy_entry)
                elif isinstance(proxy_entry, str) and any(proxy_entry.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    # 直接是URL字符串形式的节点
                    found_nodes.append(proxy_entry.strip())
            logging.info("内容成功解析为 Clash YAML。")
        elif isinstance(parsed_data, list):
            # 如果解析结果直接是一个列表（例如，某些订阅直接返回节点URL列表）
            for item in parsed_data:
                if isinstance(item, str):
                    found_nodes.append(item.strip())
                elif isinstance(item, dict):
                    if 'name' in item and not isinstance(item['name'], str):
                        item['name'] = str(item['name'])
                    found_nodes.append(item)
            logging.info("内容成功解析为 YAML 列表。")
    except yaml.YAMLError:
        pass # 不是YAML格式，继续尝试其他解析方式
    except Exception as e:
        logging.error(f"YAML 解析失败: {e}")
        pass

    # 3. 通过正则表达式提取节点
    # 尝试从原始内容或解码后的内容中直接匹配节点URL
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
    
    # 检查原始内容
    matches = node_pattern.findall(content)
    for match in matches:
        found_nodes.append(match.strip())
    
    # 如果内容被解码过，再检查解码后的内容
    if content != processed_content:
        matches_decoded = node_pattern.findall(processed_content)
        for match in matches_decoded:
            found_nodes.append(match.strip())

    return found_nodes

def fetch_and_parse_url(url):
    """
    获取URL内容并解析出节点。
    此函数会尝试请求给定的URL，然后调用 parse_content_to_nodes 进行解析。
    返回 (节点列表, 是否成功, 错误信息, 状态码)
    """
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))

    try:
        logging.debug(f"开始请求 URL: {url}")
        resp = session.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status() # 对于 4xx 或 5xx 状态码，抛出异常
        content = resp.text.strip()
        
        if len(content) < 10: # 内容过短可能是无效订阅
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
    """
    清理节点名称，去除多余信息，标准化区域名称，并添加序号。
    这个函数仅用于美化节点名称，不影响去重逻辑。
    """
    if not isinstance(name, str):
        name = str(name)

    cleaned_name = name.strip()

    # 移除包含特定关键词的括号内容，例如“【剩余流量2G】”
    cleaned_name = re.sub(r'【[^】]*?(流量|到期|过期|充值|续费)[^】]*】', '', cleaned_name)
    cleaned_name = re.sub(r'\[[^]]*?(流量|到期|过期|充值|续费)[^\]]*\]', '', cleaned_name)
    cleaned_name = re.sub(r'\([^)]*?(流量|到期|过期|充值|续费)[^)]*\)', '', cleaned_name)
    cleaned_name = re.sub(r'（[^）]*?(流量|到期|过期|充值|续费)[^）]*）', '', cleaned_name)

    # 移除其他冗余关键词或模式
    redundant_keywords_to_remove = [
        r'\d+%', r'\d{4}-\d{2}-\d{2}', r'\d{2}-\d{2}', r'x\d+', # 100%, 日期, x2倍率
        r'秒杀', r'活动', r'新年', r'福利', r'VIP\d*', r'Pro', r'Lite', r'Plus', # 促销词
        r'自动', r'手动', r'自选', # 选择方式
        r'(\d+\.\d+kbps)', r'(\d+\.\d+mbps)', r'(\d+kbps)', r'(\d+mbps)', # 速度信息
        r'\\n', r'\\r', r'\d+\.\d+G|\d+G', # 换行符，流量G数
    ]

    for keyword in redundant_keywords_to_remove:
        cleaned_name = re.sub(keyword, ' ', cleaned_name, flags=re.IGNORECASE).strip()

    # 移除特殊字符，只保留中文、英文、数字、空格和一些常用符号
    cleaned_name = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9\s\.\-_@#|]', ' ', cleaned_name)
    # 合并多个空格为单个空格
    cleaned_name = re.sub(r'\s+', ' ', cleaned_name).strip()

    # 将中文区域名替换为英文简称
    region_map = {
        '香港': 'HK', '台湾': 'TW', '日本': 'JP', '新加坡': 'SG', '美国': 'US', '英国': 'UK',
        '德国': 'DE', '韩国': 'KR', '马来': 'MY', '泰国': 'TH', 'PH': 'PH', '越南': 'VN',
        '印尼': 'ID', '印度': 'IN', '澳洲': 'AU', '加拿大': 'CA', '俄罗斯': 'RU', '巴西': 'BR',
        '意大利': 'IT', '荷兰': 'NL', '中国': 'CN' # 添加中国
    }
    for full_name, short_name in region_map.items():
        cleaned_name = cleaned_name.replace(full_name, short_name)

    # 尝试保留一些有意义的关键词，例如专线信息
    meaningful_keywords = ['IPLC', 'IEPL', '专线', '中转', '直连']
    preserved_info = []
    for keyword in meaningful_keywords:
        if keyword.lower() in cleaned_name.lower():
            preserved_info.append(keyword)
    
    # 尝试保留节点编号
    node_number_match = re.search(r'(?<!\d)\d{1,2}(?!\d)|Node\d{1,2}', cleaned_name, re.IGNORECASE)
    if node_number_match:
        preserved_info.append(node_number_match.group(0))

    # 如果清理后名称过短或为空，尝试使用区域名或默认名称
    if not cleaned_name or len(cleaned_name) <= 3:
        cleaned_name = 'Node'
        # 如果原始名称中包含区域信息，优先使用区域信息
        if any(region in name for region in region_map.values()):
            for region in region_map.values():
                if region in name:
                    cleaned_name = region
                    break
        if preserved_info:
            cleaned_name += ' ' + ' '.join(preserved_info) # 补充保留的信息

    # 添加序号，确保名称唯一性 (在最终输出时再统一添加，这里只是一个通用清理函数)
    # 脚本的实际实现中，序号是在 deduplicate_and_standardize_nodes 中添加的
    if index is not None:
        cleaned_name += f"-{index:02d}"

    # 限制名称长度
    if len(cleaned_name) > 80:
        cleaned_name = cleaned_name[:80].rstrip() + '...'

    return cleaned_name if cleaned_name else f"Node-{index:02d}" if index is not None else "Unknown Node"

def _generate_node_fingerprint(node):
    """
    为节点生成唯一指纹（哈希值）。
    这是去重逻辑的核心。
    改进点：更全面地处理 ws-opts 和 grpc-opts，确保其完整内容影响指纹。
    """
    if isinstance(node, dict):
        # 提取核心参数，这些参数是节点身份的关键
        fingerprint_data = {
            'type': node.get('type'),
            'server': node.get('server'),
            'port': node.get('port'),
        }

        node_type = node.get('type')
        if node_type == 'vmess':
            fingerprint_data['uuid'] = node.get('uuid') or node.get('id')
            fingerprint_data['alterId'] = node.get('alterId') or node.get('aid')
            fingerprint_data['cipher'] = node.get('cipher') # vmess 也有 cipher
            fingerprint_data['network'] = node.get('network')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['servername'] = node.get('servername') or node.get('host') or node.get('sni') # 统一 servername/sni/host
            
            # 改进：将整个 ws-opts 或 grpc-opts 字典进行哈希
            if node.get('ws-opts'):
                # 确保 ws-opts 内部键排序一致，然后哈希整个字典
                ws_opts_str = json.dumps(node['ws-opts'], sort_keys=True, ensure_ascii=False)
                fingerprint_data['ws-opts-hash'] = hashlib.sha256(ws_opts_str.encode('utf-8')).hexdigest()
            if node.get('grpc-opts'):
                grpc_opts_str = json.dumps(node['grpc-opts'], sort_keys=True, ensure_ascii=False)
                fingerprint_data['grpc-opts-hash'] = hashlib.sha256(grpc_opts_str.encode('utf-8')).hexdigest()

        elif node_type == 'trojan':
            fingerprint_data['password'] = node.get('password')
            fingerprint_data['network'] = node.get('network')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['servername'] = node.get('servername') or node.get('sni') or node.get('host')
            fingerprint_data['skip-cert-verify'] = node.get('skip-cert-verify')
            # trojan 也可能有 ws-opts/grpc-opts，但 Clash 配置中通常直接写在 network 下
            # 如果 Clash 配置中 trojan 也有独立的 ws-opts/grpc-opts 字段，此处需增加
            if node.get('ws-opts'):
                ws_opts_str = json.dumps(node['ws-opts'], sort_keys=True, ensure_ascii=False)
                fingerprint_data['ws-opts-hash'] = hashlib.sha256(ws_opts_str.encode('utf-8')).hexdigest()
            if node.get('grpc-opts'):
                grpc_opts_str = json.dumps(node['grpc-opts'], sort_keys=True, ensure_ascii=False)
                fingerprint_data['grpc-opts-hash'] = hashlib.sha256(grpc_opts_str.encode('utf-8')).hexdigest()

        elif node_type == 'ss':
            fingerprint_data['cipher'] = node.get('cipher')
            fingerprint_data['password'] = node.get('password')
            fingerprint_data['plugin'] = node.get('plugin') # SS可能带plugin
            if node.get('plugin-opts'): # 处理plugin-opts
                plugin_opts_str = json.dumps(node['plugin-opts'], sort_keys=True, ensure_ascii=False)
                fingerprint_data['plugin-opts-hash'] = hashlib.sha256(plugin_opts_str.encode('utf-8')).hexdigest()

        elif node_type == 'vless':
            fingerprint_data['uuid'] = node.get('uuid') or node.get('id')
            fingerprint_data['network'] = node.get('network')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['servername'] = node.get('servername') or node.get('sni') or node.get('host')
            fingerprint_data['flow'] = node.get('flow') # VLESS 独有 flow
            fingerprint_data['skip-cert-verify'] = node.get('skip-cert-verify')

            # 改进：将整个 ws-opts 或 grpc-opts 字典进行哈希
            if node.get('ws-opts'):
                ws_opts_str = json.dumps(node['ws-opts'], sort_keys=True, ensure_ascii=False)
                fingerprint_data['ws-opts-hash'] = hashlib.sha256(ws_opts_str.encode('utf-8')).hexdigest()
            if node.get('grpc-opts'):
                grpc_opts_str = json.dumps(node['grpc-opts'], sort_keys=True, ensure_ascii=False)
                fingerprint_data['grpc-opts-hash'] = hashlib.sha256(grpc_opts_str.encode('utf-8')).hexdigest()
            
            # xtls settings for vless
            fingerprint_data['xudp'] = node.get('xudp')
            fingerprint_data['udp-over-tcp'] = node.get('udp-over-tcp')

        elif node_type in ['hysteria', 'hysteria2', 'hy', 'hy2']:
            fingerprint_data['password'] = node.get('password') # Hysteria2 用 password
            fingerprint_data['auth_str'] = node.get('auth_str') # Hysteria 用 auth_str
            fingerprint_data['obfs'] = node.get('obfs')
            fingerprint_data['obfs-password'] = node.get('obfs-password')
            fingerprint_data['tls'] = node.get('tls')
            fingerprint_data['servername'] = node.get('servername') or node.get('sni') or node.get('peer')
            fingerprint_data['alpn'] = sorted(node.get('alpn', [])) # ALPN 列表排序后加入
            fingerprint_data['skip-cert-verify'] = node.get('skip-cert-verify')
            fingerprint_data['protocol'] = node.get('protocol') # Hysteria 可能有 protocol (udp/webrtc)
            fingerprint_data['up'] = node.get('up') # bandwidth
            fingerprint_data['down'] = node.get('down') # bandwidth

        # 将所有指纹数据项标准化为字符串，并转换为小写，去除首尾空白
        # 确保 None 值处理为 ''，使不同表示的空值具有相同指纹
        normalized_data = {k: str(v).lower().strip() if v is not None else '' for k, v in fingerprint_data.items()}
        
        # 将标准化后的数据转换为JSON字符串，并排序键以保证一致性，最后进行SHA256哈希
        stable_json = json.dumps(normalized_data, sort_keys=True, ensure_ascii=False)
        # logging.debug(f"Generated fingerprint JSON for node {node.get('name', 'N/A')}: {stable_json}")
        return hashlib.sha256(stable_json.encode('utf-8')).hexdigest()
    
    elif isinstance(node, str):
        # 对于 URL 字符串形式的节点，直接从 URL 中提取关键信息生成指纹
        try:
            if not any(node.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                logging.warning(f"无效的节点协议: {node[:50]}...")
                return None

            parsed_url = urlparse(node)
            scheme = parsed_url.scheme
            netloc = parsed_url.netloc
            path = parsed_url.path
            # 解析查询参数，并进行标准化
            query_params = parse_qs(parsed_url.query)
            
            host = netloc.split(':')[0] if ':' in netloc else netloc
            if is_valid_ip_address(host) and host.startswith('[') and host.endswith(']'):
                host = host[1:-1] # 移除IPv6地址的方括号
            elif not is_valid_ip_address(host) and not re.match(r'^[a-zA-Z0-9\-\.]+$', host):
                logging.warning(f"无效的主机名: {host} in {node[:50]}...")
                return None

            normalized_query_params = {}
            for k, v in query_params.items():
                # 统一处理查询参数，例如将列表值取第一个，并标准化为小写字符串
                normalized_query_params[k.lower()] = str(v[0]).lower().strip()
            
            # 构建指纹部件列表，这些部件应该是影响节点唯一性的核心参数
            fingerprint_parts = [
                scheme,
                host.lower(),
                # 端口号，确保一致性
                netloc.lower().split(':')[-1] if ':' in netloc else '',
                path.lower()
            ]

            # 排除不影响节点唯一性的查询参数 (如名称、流量信息等)
            # 这些参数通常是动态变化的，不应该作为去重依据
            excluded_keys = ['name', 'ps', 'remarks', 'info', 'flow', 'usage', 'expire', 'ud', 'up', 'dn', 'package', 'nodeName', 'nodeid', 'ver', 'hash', 'group'] # 添加 hash, group
            
            # 将剩余的查询参数按键名排序后加入指纹部件
            sorted_query_keys = sorted(normalized_query_params.keys())
            for k in sorted_query_keys:
                if k not in excluded_keys:
                    fingerprint_parts.append(f"{k}={normalized_query_params[k]}")

            # 对所有部件进行哈希
            fingerprint_str = "".join(fingerprint_parts)
            # logging.debug(f"Generated fingerprint string for URL {node[:50]}: {fingerprint_str}")
            return hashlib.sha256(fingerprint_str.encode('utf-8')).hexdigest()
        except Exception as e:
            logging.warning(f"生成URL节点指纹失败: {node[:50]}... - {e}")
            return None
    return None

def deduplicate_and_standardize_nodes(raw_nodes_list):
    """
    对节点进行去重和标准化。
    将各种原始节点格式转换为统一的Clash代理字典格式，并基于指纹进行去重。
    """
    unique_node_fingerprints = set()
    final_clash_proxies = []

    for idx, node in enumerate(raw_nodes_list):
        clash_proxy_dict = None
        node_raw_name = "" # 用于保留原始名称以进行关键词检查

        if isinstance(node, dict):
            # 如果已经是字典格式，直接使用
            clash_proxy_dict = node
            node_raw_name = str(node.get('name', '')) # 获取原始名称
        elif isinstance(node, str):
            # 如果是URL字符串，尝试解析为Clash字典格式
            try:
                parsed_url = urlparse(node)
                # 提取原始节点名称（通常在URL片段中）
                node_raw_name = str(parsed_url.fragment or '') 
                
                # 检查协议是否有效
                if not any(node.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    logging.warning(f"跳过无效协议的节点: {node[:50]}...")
                    continue
                
                # 检查主机名是否有效
                host = parsed_url.hostname or ''
                if host and not (is_valid_ip_address(host) or re.match(r'^[a-zA-Z0-9\-\.]+$', host)):
                    logging.warning(f"跳过无效主机名的节点: {host} in {node[:50]}...")
                    continue

                # 根据协议类型进行解析并转换为Clash字典格式
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
                        'cipher': config.get('scy', 'auto'), # vmess 也有 scy 字段表示加密方式
                        'network': config.get('net'),
                        'tls': True if config.get('tls') == 'tls' else False,
                        'skip-cert-verify': True if config.get('scy') == 'true' else False, # Clash scy 和 skip-cert-verify 行为有差异，这里只作为参考
                        'servername': config.get('sni') or config.get('host') or config.get('add'), # sni/host/add 优先级
                    }
                    if config.get('net') == 'ws':
                        clash_proxy_dict['ws-opts'] = {
                            'path': config.get('path', '/'),
                            'headers': {'Host': config.get('host') or config.get('add')} # Host 为空时使用 add
                        }
                        if clash_proxy_dict['ws-opts']['headers']['Host'] == '': # 如果Host还是空，则删除headers
                             del clash_proxy_dict['ws-opts']['headers']['Host']
                             if not clash_proxy_dict['ws-opts']['headers']: # 如果headers为空，则删除headers
                                 del clash_proxy_dict['ws-opts']['headers']
                        if clash_proxy_dict['ws-opts']['path'] == '/' and not clash_proxy_dict['ws-opts'].get('headers'): # 如果path和headers都为空，则删除ws-opts
                            clash_proxy_dict['ws-opts'] = None
                    if config.get('net') == 'grpc':
                        clash_proxy_dict['grpc-opts'] = {
                            'serviceName': config.get('path', '')
                        }
                        if clash_proxy_dict['grpc-opts']['serviceName'] == '':
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
                        'servername': query.get('sni', [server])[0]
                    }
                    # Trojan协议也可能通过查询参数携带ws或grpc信息
                    if query.get('type', [''])[0] == 'ws':
                        clash_proxy_dict['ws-opts'] = {
                            'path': query.get('path', ['/'])[0],
                            'headers': {'Host': query.get('host', [''])[0]}
                        }
                        if clash_proxy_dict['ws-opts']['headers']['Host'] == '':
                             del clash_proxy_dict['ws-opts']['headers']['Host']
                             if not clash_proxy_dict['ws-opts']['headers']:
                                 del clash_proxy_dict['ws-opts']['headers']
                        if clash_proxy_dict['ws-opts']['path'] == '/' and not clash_proxy_dict['ws-opts'].get('headers'):
                            clash_proxy_dict['ws-opts'] = None
                    if query.get('type', [''])[0] == 'grpc':
                        clash_proxy_dict['grpc-opts'] = {
                            'serviceName': query.get('serviceName', [''])[0]
                        }
                        if clash_proxy_dict['grpc-opts']['serviceName'] == '':
                            clash_proxy_dict['grpc-opts'] = None

                elif node.startswith("ss://"):
                    decoded_part = node[len("ss://"):].split('#', 1)[0]
                    try:
                        # SS链接可能包含Base64编码的用户信息
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
                        # 处理 SS 插件
                        if 'plugin' in parsed_url.query:
                            query_params = parse_qs(parsed_url.query)
                            clash_proxy_dict['plugin'] = query_params.get('plugin', [''])[0]
                            plugin_opts = query_params.get('plugin_opts', [''])[0]
                            if plugin_opts:
                                clash_proxy_dict['plugin-opts'] = {}
                                for opt in plugin_opts.split(';'):
                                    if '=' in opt:
                                        k, v = opt.split('=', 1)
                                        clash_proxy_dict['plugin-opts'][k] = v
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
                        'skip-cert-verify': query.get('flow', [''])[0] == 'xtls-rprx-direct' or query.get('allowInsecure', ['0'])[0] == '1',
                        'servername': query.get('sni', [server])[0],
                        'flow': query.get('flow', [''])[0],
                        'xudp': query.get('xudp', [''])[0] == '1', # xudp
                        'udp-over-tcp': query.get('udp_over_tcp', [''])[0] == 'true', # udp-over-tcp
                    }
                    if query.get('type', [''])[0] == 'ws':
                        clash_proxy_dict['ws-opts'] = {
                            'path': query.get('path', ['/'])[0],
                            'headers': {'Host': query.get('host', [''])[0]}
                        }
                        if clash_proxy_dict['ws-opts']['headers']['Host'] == '':
                             del clash_proxy_dict['ws-opts']['headers']['Host']
                             if not clash_proxy_dict['ws-opts']['headers']:
                                 del clash_proxy_dict['ws-opts']['headers']
                        if clash_proxy_dict['ws-opts']['path'] == '/' and not clash_proxy_dict['ws-opts'].get('headers'):
                            clash_proxy_dict['ws-opts'] = None
                    if query.get('type', [''])[0] == 'grpc':
                        clash_proxy_dict['grpc-opts'] = {
                            'serviceName': query.get('serviceName', [''])[0]
                        }
                        if clash_proxy_dict['grpc-opts']['serviceName'] == '':
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
                        'auth_str': query.get('auth', [''])[0], # Hysteria 1 用 auth_str
                        'alpn': query.get('alpn', [''])[0].split(','),
                        'network': query.get('protocol', ['udp'])[0],
                        'skip-cert-verify': query.get('insecure', ['0'])[0] == '1',
                        'servername': query.get('peer', [server])[0],
                        'up': int(query.get('up_mbps', ['0'])[0]),
                        'down': int(query.get('down_mbps', ['0'])[0])
                    }
                    if not clash_proxy_dict['alpn'] or clash_proxy_dict['alpn'] == ['']: # 确保 alpn 非空
                        del clash_proxy_dict['alpn']
                    if clash_proxy_dict['up'] == 0: del clash_proxy_dict['up']
                    if clash_proxy_dict['down'] == 0: del clash_proxy_dict['down']
                    
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
                        'servername': query.get('sni', [server])[0],
                        'alpn': query.get('alpn', [''])[0].split(',')
                    }
                    if not clash_proxy_dict['obfs']: del clash_proxy_dict['obfs']
                    if not clash_proxy_dict['obfs-password']: del clash_proxy_dict['obfs-password']
                    if not clash_proxy_dict['alpn'] or clash_proxy_dict['alpn'] == ['']:
                        del clash_proxy_dict['alpn']

            except Exception as e:
                logging.warning(f"URL节点转换为Clash字典失败: {node[:50]}... - {e}")
                clash_proxy_dict = None

        if clash_proxy_dict:
            # 检查节点名称是否包含删除关键词
            name_to_check = str(node_raw_name or clash_proxy_dict.get('name', '')) # 优先使用原始名称进行检查
            
            should_delete_node = False
            for keyword in DELETE_KEYWORDS:
                try:
                    if keyword.lower() in name_to_check.lower():
                        logging.info(f"节点 '{name_to_check}' 包含删除关键词 '{keyword}'，已跳过。")
                        should_delete_node = True
                        break
                except AttributeError as e: # 防止 name_to_check 不是字符串
                    logging.error(f"检查删除关键词时出错: name_to_check={name_to_check}, type={type(name_to_check)}, node={clash_proxy_dict.get('name', 'Unknown')} - {e}")
                    should_delete_node = True
                    break
            
            if should_delete_node:
                continue

            # 检查服务器地址是否有效
            server = clash_proxy_dict.get('server', '')
            if server and not (is_valid_ip_address(server) or re.match(r'^[a-zA-Z0-9\-\.]+$', server)):
                logging.warning(f"跳过无效服务器地址的节点: {server} in {clash_proxy_dict.get('name', 'Unknown')}")
                continue

            # 生成指纹并进行去重
            fingerprint = _generate_node_fingerprint(clash_proxy_dict)
            if fingerprint and fingerprint not in unique_node_fingerprints:
                unique_node_fingerprints.add(fingerprint)
                # 清理节点名称，并添加序号
                clash_proxy_dict['name'] = clean_node_name(
                    clash_proxy_dict.get('name', f"{clash_proxy_dict.get('type', 'Unknown')} {clash_proxy_dict.get('server', '')}:{clash_proxy_dict.get('port', '')}"),
                    index=len(final_clash_proxies) + 1 # 使用当前已收集到的节点数量作为序号
                )
                final_clash_proxies.append(clash_proxy_dict)
            else:
                logging.debug(f"重复节点（按指纹）：{clash_proxy_dict.get('name', '')} - {fingerprint}")

    return final_clash_proxies

# --- 主程序流程 ---

# 从环境变量中获取 URL_SOURCE
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")

if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。请设置一个包含订阅链接的远程文本文件URL。")
    exit(1)

# 创建输出目录
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
os.makedirs(os.path.dirname(STATISTICS_FILE), exist_ok=True)

# 阶段一：获取原始URL/字符串列表
raw_urls_from_source = get_url_list_from_remote(URL_SOURCE)

urls_to_fetch = set() # 需要通过HTTP/HTTPS请求的URL
url_statistics = [] # 用于记录处理统计
successful_urls = [] # 成功处理的URL列表
failed_urls = [] # 失败的URL列表
all_parsed_nodes_raw = [] # 所有解析到的原始节点（未去重和标准化）

print("\n--- 预处理原始URL/字符串列表 ---")
for entry in raw_urls_from_source:
    if is_valid_url(entry):
        # 如果是有效的HTTP/HTTPS URL，加入待请求列表
        urls_to_fetch.add(entry)
    else:
        # 如果不是有效的URL，尝试直接解析其内容（可能是Base64编码的节点列表或Clash配置片段）
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

print("\n--- 阶段一：并行获取并合并所有订阅链接中的节点 ---")
total_urls_to_process_via_http = len(urls_to_fetch)

if total_urls_to_process_via_http > 0:
    # 使用线程池并行请求URL，提高效率
    # max_workers=16 是一个常用值，可以根据网络和CPU情况调整
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls_to_fetch}
        # tqdm 用于显示进度条
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

            # 提前终止机制：如果已收集到足够多的原始节点（MAX_SUCCESS的两倍，考虑到去重损失），则停止请求
            if len(all_parsed_nodes_raw) >= MAX_SUCCESS * 2:
                print(f"已收集足够原始节点 ({len(all_parsed_nodes_raw)})，达到 MAX_SUCCESS * 2，提前终止后续请求。")
                # 显式关闭线程池中的线程
                executor._threads.clear() 
                break

# 对所有收集到的原始节点进行去重和标准化
final_unique_clash_proxies = deduplicate_and_standardize_nodes(all_parsed_nodes_raw)

# 将去重后的原始节点（字典形式）写入临时文件，方便调试
with open(TEMP_MERGED_NODES_RAW_FILE, 'w', encoding='utf-8') as temp_file:
    for node in final_unique_clash_proxies:
        if isinstance(node, dict):
            temp_file.write(json.dumps(node, ensure_ascii=False) + '\n')
        else: # 理论上到这里都应该是dict了，以防万一
            temp_file.write(str(node).strip() + '\n') # 确保写入的是字符串

print(f"\n阶段一完成。合并到 {len(final_unique_clash_proxies)} 个唯一Clash代理字典，已保存至 {TEMP_MERGED_NODES_RAW_FILE}")

# 写入统计数据和URL列表
write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE)

print("\n--- 阶段二：输出最终 Clash YAML 配置 ---")

# 确保输出文件是 .yaml 或 .yml 扩展名
if not OUTPUT_FILE.endswith(('.yaml', '.yml')):
    OUTPUT_FILE = os.path.splitext(OUTPUT_FILE)[0] + '.yaml'

# 取出最多 MAX_SUCCESS 个节点进行输出
proxies_to_output = final_unique_clash_proxies[:MAX_SUCCESS]

# 构建代理组的名称列表
proxy_names_in_group = []
for node in proxies_to_output:
    if isinstance(node, dict) and 'name' in node:
        proxy_names_in_group.append(node['name'])
    else:
        # 兜底处理，确保即使没有name也能添加到组
        proxy_names_in_group.append(f"{node.get('type', 'Unknown')} {node.get('server', '')}")

# 构建最终的Clash配置字典
clash_config = {
    'proxies': proxies_to_output,
    'proxy-groups': [
        {
            'name': '🚀 节点选择', # 手动选择节点组
            'type': 'select',
            'proxies': ['DIRECT'] + proxy_names_in_group # 包含直连选项
        },
        {
            'name': '♻️ 自动选择', # 自动测速选择最佳节点组
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204', # Google的无内容响应页面，常用于测速
            'interval': 300, # 测速间隔300秒
            'proxies': proxy_names_in_group
        }
        # 可以根据需要添加更多的代理组和规则
    ],
    'rules': [
        # 例如：
        # 'DOMAIN-SUFFIX,google.com,♻️ 自动选择',
        # 'GEOIP,CN,DIRECT',
        'MATCH,🚀 节点选择' # 默认规则，所有未匹配的流量走节点选择组
    ]
}

success_count = len(proxies_to_output)

# 将Clash配置写入YAML文件
try:
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
        # allow_unicode=True 确保中文正确编码
        # default_flow_style=False 确保输出为块样式，提高可读性
        # sort_keys=False 保持字典插入顺序（对于proxies和proxy-groups很重要）
        yaml.dump(clash_config, out_file, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"最终 Clash YAML 配置已保存至：{OUTPUT_FILE}")
except Exception as e:
    logging.error(f"写入最终 Clash YAML 文件失败: {e}")
    print(f"错误：写入最终 Clash YAML 文件失败: {e}")

# 清理临时文件
if os.path.exists(TEMP_MERGED_NODES_RAW_FILE):
    os.remove(TEMP_MERGED_NODES_RAW_FILE)
    print(f"已删除临时文件：{TEMP_MERGED_NODES_RAW_FILE}")

# 打印最终运行摘要
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
    print(f"警告：未能达到目标数量 {MAX_SUCCESS}，原始列表可能有效URL/节点不足，或部分URL获取失败。")
print(f"结果文件已保存至：{OUTPUT_FILE}")
print(f"统计数据已保存至：{STATISTICS_FILE}")
print(f"成功URL列表已保存至：{SUCCESS_URLS_FILE}")
print(f"失败URL列表已保存至：{FAILED_URLS_FILE}")
print("=" * 50)
