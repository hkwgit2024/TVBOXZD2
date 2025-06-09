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

# 定义常见占位符 UUID/密码，这些不会作为唯一性判断依据
COMMON_UUID_PLACEHOLDERS = [
    "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1", # 你提供的示例中的占位符
    "00000000-0000-0000-0000-000000000000",
    "d23b3208-d01d-40d3-b1d6-fe1e48edcb74" # 常见的伪造UUID
    # 可以根据观察到的其他常见占位符补充
]

# 定义常见占位符密码
COMMON_PASSWORD_PLACEHOLDERS = [
    "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1", # 你提供的示例中的占位符
    "password", "123456", "000000", "test", "demo", "free"
    # 可以根据观察到的其他常见占位符补充
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
        r'ssr://\S+|' # SSR 也是 URL 形式
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
        '意大利': 'IT', '荷兰': 'NL', '中国': 'CN', '深圳': 'SZ', '上海': 'SH', '北京': 'BJ',
        '广州': 'GZ', '杭州': 'HZ' # 增加一些城市简称
    }
    for full_name, short_name in region_map.items():
        cleaned_name = cleaned_name.replace(full_name, short_name)

    # 尝试保留一些有意义的关键词，例如专线信息
    meaningful_keywords = ['IPLC', 'IEPL', '专线', '中转', '直连', 'CDN']
    preserved_info = []
    for keyword in meaningful_keywords:
        if keyword.lower() in cleaned_name.lower():
            preserved_info.append(keyword)
    
    # 尝试保留节点编号
    node_number_match = re.search(r'(?<!\d)(?:[Nn]ode|Server)?\s?(\d{1,3})(?!\d)', cleaned_name) # 匹配 Node1, Server 2, 123
    if node_number_match:
        preserved_info.append(node_number_match.group(1))

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
        # 确保序号格式一致，例如两位数
        cleaned_name += f"-{index:03d}" # 更改为三位数序号

    # 限制名称长度
    if len(cleaned_name) > 80:
        cleaned_name = cleaned_name[:80].rstrip() + '...'

    return cleaned_name if cleaned_name else f"Node-{index:03d}" if index is not None else "Unknown Node"

def _normalize_dict_for_fingerprint(data):
    """
    递归地标准化字典，以便生成稳定的指纹。
    - 键转换为小写
    - 值去除首尾空白
    - 移除 None 或空字符串的值
    - 列表进行排序
    - 嵌套字典递归处理
    """
    if not isinstance(data, dict):
        return data # 非字典类型直接返回

    normalized = {}
    for k, v in data.items():
        if isinstance(v, dict):
            normalized_v = _normalize_dict_for_fingerprint(v)
            if normalized_v: # 只有非空字典才保留
                normalized[k.lower()] = normalized_v
        elif isinstance(v, list):
            # 对列表元素进行标准化并排序
            normalized_list = sorted([str(item).lower().strip() for item in v if str(item).strip()])
            if normalized_list: # 只有非空列表才保留
                normalized[k.lower()] = normalized_list
        elif v is not None and str(v).strip() != '': # 忽略 None 和空字符串
            # 统一布尔值表示
            if isinstance(v, bool):
                normalized[k.lower()] = str(v).lower()
            else:
                normalized[k.lower()] = str(v).lower().strip()
    return normalized

def _get_node_core_params(node_dict):
    """
    从标准化的Clash节点字典中提取核心参数集，用于生成指纹。
    这是去重逻辑的核心，旨在忽略非核心或动态变化的参数。
    """
    core_params = {
        'type': node_dict.get('type'),
        'server': node_dict.get('server'),
        'port': node_dict.get('port'),
    }

    node_type = node_dict.get('type')

    # 处理 servername/sni：如果与 server 不同，则加入，否则忽略
    servername = node_dict.get('servername') or node_dict.get('sni')
    if servername and str(servername).lower().strip() != str(node_dict.get('server', '')).lower().strip():
        core_params['servername'] = servername

    # 处理 skip-cert-verify, 统一为布尔值
    if node_dict.get('skip-cert-verify') is not None:
        core_params['skip-cert-verify'] = bool(node_dict['skip-cert-verify'])
    elif node_type in ['trojan', 'vless', 'vmess', 'hysteria', 'hysteria2'] and node_dict.get('tls'):
         # 对于开启TLS的节点，如果明确指定 skip-cert-verify=False，则认为证书验证是严格的，否则默认为True
        core_params['skip-cert-verify'] = bool(node_dict.get('skip-cert-verify', False))


    # 协议特定参数
    if node_type == 'vmess':
        uuid = node_dict.get('uuid') or node_dict.get('id')
        if uuid and str(uuid).lower() not in COMMON_UUID_PLACEHOLDERS:
            core_params['uuid'] = uuid
        core_params['alterId'] = int(node_dict.get('alterId', 0) or node_dict.get('aid', 0)) # alterId 影响连接
        core_params['cipher'] = node_dict.get('cipher') # VMess 的加密方式
        core_params['network'] = node_dict.get('network')
        core_params['tls'] = bool(node_dict.get('tls')) # VMess 的 tls
        
        # 处理 ws-opts
        ws_opts = node_dict.get('ws-opts')
        if isinstance(ws_opts, dict):
            standardized_ws_opts = {}
            # 只有当 path 不为 '/' 或存在有意义的 headers 时才加入
            if ws_opts.get('path') and ws_opts['path'] != '/':
                standardized_ws_opts['path'] = ws_opts['path']
            if ws_opts.get('headers') and isinstance(ws_opts['headers'], dict):
                # 对 headers 字典进行标准化：键小写，值小写并去空白
                standardized_headers = {k.lower(): str(v).lower().strip() for k, v in ws_opts['headers'].items() if str(v).strip()}
                if standardized_headers:
                    standardized_ws_opts['headers'] = standardized_headers
            if standardized_ws_opts:
                core_params['ws-opts'] = standardized_ws_opts

        # 处理 grpc-opts
        grpc_opts = node_dict.get('grpc-opts')
        if isinstance(grpc_opts, dict) and grpc_opts.get('serviceName'):
            core_params['grpc-opts'] = {'serviceName': grpc_opts['serviceName']} # 只关心 serviceName

    elif node_type == 'trojan':
        password = node_dict.get('password')
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        core_params['network'] = node_dict.get('network')
        core_params['tls'] = bool(node_dict.get('tls'))
        
        # Trojan 可能有 ws-opts/grpc-opts
        ws_opts = node_dict.get('ws-opts')
        if isinstance(ws_opts, dict):
            standardized_ws_opts = {}
            if ws_opts.get('path') and ws_opts['path'] != '/':
                standardized_ws_opts['path'] = ws_opts['path']
            if ws_opts.get('headers') and isinstance(ws_opts['headers'], dict):
                standardized_headers = {k.lower(): str(v).lower().strip() for k, v in ws_opts['headers'].items() if str(v).strip()}
                if standardized_headers:
                    standardized_ws_opts['headers'] = standardized_headers
            if standardized_ws_opts:
                core_params['ws-opts'] = standardized_ws_opts
        
        grpc_opts = node_dict.get('grpc-opts')
        if isinstance(grpc_opts, dict) and grpc_opts.get('serviceName'):
            core_params['grpc-opts'] = {'serviceName': grpc_opts['serviceName']}

    elif node_type == 'ss':
        core_params['cipher'] = node_dict.get('cipher')
        password = node_dict.get('password')
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        
        # 处理 plugin 和 plugin-opts
        if node_dict.get('plugin'):
            core_params['plugin'] = node_dict['plugin']
            if node_dict.get('plugin-opts'):
                # 对 plugin-opts 字典进行标准化
                standardized_plugin_opts = {k.lower(): str(v).lower().strip() for k, v in node_dict['plugin-opts'].items() if str(v).strip()}
                if standardized_plugin_opts:
                    core_params['plugin-opts'] = standardized_plugin_opts

    elif node_type == 'vless':
        uuid = node_dict.get('uuid') or node_dict.get('id')
        if uuid and str(uuid).lower() not in COMMON_UUID_PLACEHOLDERS:
            core_params['uuid'] = uuid
        core_params['network'] = node_dict.get('network')
        core_params['tls'] = bool(node_dict.get('tls'))
        # 只有非空字符串才加入 flow
        if node_dict.get('flow') and node_dict['flow'] != '':
            core_params['flow'] = node_dict['flow']
        
        core_params['xudp'] = bool(node_dict.get('xudp'))
        core_params['udp-over-tcp'] = bool(node_dict.get('udp-over-tcp'))

        # 处理 ws-opts
        ws_opts = node_dict.get('ws-opts')
        if isinstance(ws_opts, dict):
            standardized_ws_opts = {}
            if ws_opts.get('path') and ws_opts['path'] != '/':
                standardized_ws_opts['path'] = ws_opts['path']
            if ws_opts.get('headers') and isinstance(ws_opts['headers'], dict):
                standardized_headers = {k.lower(): str(v).lower().strip() for k, v in ws_opts['headers'].items() if str(v).strip()}
                if standardized_headers:
                    standardized_ws_opts['headers'] = standardized_headers
            if standardized_ws_opts:
                core_params['ws-opts'] = standardized_ws_opts
        
        # 处理 grpc-opts
        grpc_opts = node_dict.get('grpc-opts')
        if isinstance(grpc_opts, dict) and grpc_opts.get('serviceName'):
            core_params['grpc-opts'] = {'serviceName': grpc_opts['serviceName']}
            
    elif node_type in ['hysteria', 'hy']:
        password = node_dict.get('password') # Hysteria 使用 password
        auth_str = node_dict.get('auth_str') # Hysteria 也可能使用 auth_str
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        elif auth_str and str(auth_str).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['auth_str'] = auth_str
        
        core_params['network'] = node_dict.get('protocol', 'udp') # Hysteria 的 protocol 字段
        core_params['tls'] = bool(node_dict.get('tls'))

        alpn_list = [a.strip().lower() for a in node_dict.get('alpn', []) if a.strip()]
        if alpn_list:
            core_params['alpn'] = sorted(alpn_list) # ALPN 列表排序

    elif node_type in ['hysteria2', 'hy2']:
        password = node_dict.get('password')
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        
        core_params['obfs'] = node_dict.get('obfs')
        core_params['obfs-password'] = node_dict.get('obfs-password')
        core_params['tls'] = bool(node_dict.get('tls'))

        alpn_list = [a.strip().lower() for a in node_dict.get('alpn', []) if a.strip()]
        if alpn_list:
            core_params['alpn'] = sorted(alpn_list) # ALPN 列表排序

    # 对整个核心参数字典进行标准化，去除空值等
    return _normalize_dict_for_fingerprint(core_params)

def _generate_stable_fingerprint_from_params(params_dict):
    """
    将标准化的核心参数字典转换为稳定的JSON字符串，并计算SHA256指纹。
    """
    if not params_dict:
        return None

    # 确保JSON序列化是稳定的（键排序，非ASCII字符保留）
    stable_json = json.dumps(params_dict, sort_keys=True, ensure_ascii=False)
    # logging.debug(f"Fingerprint JSON: {stable_json}") # 用于调试
    return hashlib.sha256(stable_json.encode('utf-8')).hexdigest()

def deduplicate_and_standardize_nodes(raw_nodes_list):
    """
    对节点进行去重和标准化。
    将各种原始节点格式转换为统一的Clash代理字典格式，并基于核心参数指纹进行去重。
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
                protocol_scheme = parsed_url.scheme.lower()
                if not any(protocol_scheme == p for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    logging.warning(f"跳过无效协议的节点: {node[:50]}...")
                    continue
                
                # 检查主机名是否有效
                host = parsed_url.hostname or ''
                if host and not (is_valid_ip_address(host) or re.match(r'^[a-zA-Z0-9\-\.]+$', host)):
                    logging.warning(f"跳过无效主机名的节点: {host} in {node[:50]}...")
                    continue

                # 根据协议类型进行解析并转换为Clash字典格式
                if protocol_scheme == "vmess":
                    decoded = base64.b64decode(node[len("vmess://"):].encode('utf-8')).decode('utf-8')
                    config = json.loads(decoded)
                    
                    clash_proxy_dict = {
                        'name': str(config.get('ps', 'VMess Node')),
                        'type': 'vmess',
                        'server': config.get('add'),
                        'port': int(config.get('port')),
                        'uuid': config.get('id'),
                        'alterId': int(config.get('aid', 0)),
                        'cipher': config.get('scy', 'auto'), 
                        'network': config.get('net'),
                        'tls': (config.get('tls') == 'tls'),
                        'skip-cert-verify': (config.get('scy', 'false') == 'true'), # scy 字段在某些工具中也表示 skip-cert-verify
                        'servername': config.get('sni') or config.get('host') or config.get('add'),
                    }
                    # ws-opts
                    if config.get('net') == 'ws':
                        ws_opts = {}
                        if config.get('path') and config['path'] != '/':
                            ws_opts['path'] = config['path']
                        if config.get('host'):
                            ws_opts['headers'] = {'Host': config['host']}
                        if ws_opts:
                            clash_proxy_dict['ws-opts'] = ws_opts
                    # grpc-opts
                    if config.get('net') == 'grpc':
                        grpc_opts = {}
                        if config.get('path'):
                            grpc_opts['serviceName'] = config['path']
                        if grpc_opts:
                            clash_proxy_dict['grpc-opts'] = grpc_opts
                    
                elif protocol_scheme == "trojan":
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
                        'skip-cert-verify': (query.get('allowInsecure', ['0'])[0] == '1'),
                        'servername': query.get('sni', [server])[0]
                    }
                    if query.get('type', [''])[0] == 'ws':
                        ws_opts = {}
                        if query.get('path', [''])[0] and query['path'][0] != '/':
                            ws_opts['path'] = query['path'][0]
                        if query.get('host', [''])[0]:
                            ws_opts['headers'] = {'Host': query['host'][0]}
                        if ws_opts:
                            clash_proxy_dict['ws-opts'] = ws_opts
                    if query.get('type', [''])[0] == 'grpc':
                        grpc_opts = {}
                        if query.get('serviceName', [''])[0]:
                            grpc_opts['serviceName'] = query['serviceName'][0]
                        if grpc_opts:
                            clash_proxy_dict['grpc-opts'] = grpc_opts

                elif protocol_scheme == "ss":
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
                        query_params = parse_qs(parsed_url.query)
                        if 'plugin' in query_params:
                            clash_proxy_dict['plugin'] = query_params.get('plugin', [''])[0]
                            plugin_opts_str = query_params.get('plugin_opts', [''])[0]
                            if plugin_opts_str:
                                plugin_opts = {}
                                for opt in plugin_opts_str.split(';'):
                                    if '=' in opt:
                                        k, v = opt.split('=', 1)
                                        plugin_opts[k] = v
                                clash_proxy_dict['plugin-opts'] = plugin_opts
                    except Exception as e:
                        logging.warning(f"SS节点解析失败: {node[:50]}... - {e}")
                        clash_proxy_dict = None
                
                elif protocol_scheme == "ssr":
                    # SSR 链接解析更复杂，需要单独处理
                    # SSR 链接格式通常是 ssr://<base64_encoded_info>
                    # <base64_encoded_info> = <server>:<port>:<protocol>:<method>:<obfs>:<password_base64_encoded>/?obfsparam=<obfsparam_base64>&protoparam=<protoparam_base64>&remarks=<remarks_base64>&group=<group_base64>&udp=<udp_enabled>
                    try:
                        decoded_info = base64.b64decode(node[len("ssr://"):].split('#', 1)[0]).decode('utf-8')
                        parts = decoded_info.split(':', 5) # server:port:protocol:method:obfs:password
                        server = parts[0]
                        port = int(parts[1])
                        protocol = parts[2]
                        method = parts[3]
                        obfs = parts[4]
                        password_b64 = parts[5].split('/?', 1)[0]
                        password = base64.b64decode(password_b64.encode('utf-8')).decode('utf-8')

                        clash_proxy_dict = {
                            'name': str(parsed_url.fragment or 'SSR Node'),
                            'type': 'ssr', # Clash 对 SSR 支持可能有限，这里保留
                            'server': server,
                            'port': port,
                            'cipher': method,
                            'password': password,
                            'protocol': protocol,
                            'obfs': obfs
                        }
                        
                        query_params_str = parts[5].split('/?', 1)[1] if '/?' in parts[5] else ''
                        query_params = parse_qs(query_params_str)

                        if 'obfsparam' in query_params:
                            clash_proxy_dict['obfs-param'] = base64.b64decode(query_params['obfsparam'][0].encode('utf-8')).decode('utf-8')
                        if 'protoparam' in query_params:
                            clash_proxy_dict['protocol-param'] = base64.b64decode(query_params['protoparam'][0].encode('utf-8')).decode('utf-8')
                        if 'udp' in query_params:
                            clash_proxy_dict['udp'] = (query_params['udp'][0] == '1')
                        
                        # SSR 的 name 通常在 remarks 中
                        if 'remarks' in query_params:
                             clash_proxy_dict['name'] = base64.b64decode(query_params['remarks'][0].encode('utf-8')).decode('utf-8')
                    except Exception as e:
                        logging.warning(f"SSR节点解析失败: {node[:50]}... - {e}")
                        clash_proxy_dict = None

                elif protocol_scheme == "vless":
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
                        'tls': (query.get('security', [''])[0] == 'tls'),
                        'skip-cert-verify': (query.get('allowInsecure', ['0'])[0] == '1'),
                        'servername': query.get('sni', [server])[0],
                        'xudp': (query.get('xudp', ['0'])[0] == '1'),
                        'udp-over-tcp': (query.get('udp_over_tcp', ['false'])[0] == 'true'),
                    }
                    if query.get('flow', [''])[0]:
                        clash_proxy_dict['flow'] = query['flow'][0]

                    if query.get('type', [''])[0] == 'ws':
                        ws_opts = {}
                        if query.get('path', [''])[0] and query['path'][0] != '/':
                            ws_opts['path'] = query['path'][0]
                        if query.get('host', [''])[0]:
                            ws_opts['headers'] = {'Host': query['host'][0]}
                        if ws_opts:
                            clash_proxy_dict['ws-opts'] = ws_opts
                    if query.get('type', [''])[0] == 'grpc':
                        grpc_opts = {}
                        if query.get('serviceName', [''])[0]:
                            grpc_opts['serviceName'] = query['serviceName'][0]
                        if grpc_opts:
                            clash_proxy_dict['grpc-opts'] = grpc_opts
                        
                elif protocol_scheme in ["hysteria", "hy"]:
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
                        'network': query.get('protocol', ['udp'])[0],
                        'skip-cert-verify': (query.get('insecure', ['0'])[0] == '1'),
                        'servername': query.get('peer', [server])[0],
                        'tls': True # Hysteria 默认带 TLS
                    }
                    alpn_list = [a.strip() for a in query.get('alpn', [''])[0].split(',') if a.strip()]
                    if alpn_list:
                        clash_proxy_dict['alpn'] = alpn_list
                    if query.get('up_mbps', ['0'])[0] != '0':
                        clash_proxy_dict['up'] = int(query['up_mbps'][0])
                    if query.get('down_mbps', ['0'])[0] != '0':
                        clash_proxy_dict['down'] = int(query['down_mbps'][0])
                    
                elif protocol_scheme in ["hysteria2", "hy2"]:
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
                        'tls': True,
                        'skip-cert-verify': (query.get('insecure', ['0'])[0] == '1'),
                        'servername': query.get('sni', [server])[0],
                    }
                    if query.get('obfs', [''])[0]:
                        clash_proxy_dict['obfs'] = query['obfs'][0]
                    if query.get('obfsParam', [''])[0]:
                        clash_proxy_dict['obfs-password'] = query['obfsParam'][0]
                    alpn_list = [a.strip() for a in query.get('alpn', [''])[0].split(',') if a.strip()]
                    if alpn_list:
                        clash_proxy_dict['alpn'] = alpn_list

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
            core_params = _get_node_core_params(clash_proxy_dict)
            fingerprint = _generate_stable_fingerprint_from_params(core_params)
            
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
        else:
            logging.debug(f"无法转换为Clash字典的原始节点或URL: {str(node)[:80]}...")

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
            # 这里的判断条件可以根据实际情况调整，比如 len(all_parsed_nodes_raw) > MAX_SUCCESS * 1.5 
            # 也可以直接不设置提前终止，等待所有URL处理完毕
            if len(all_parsed_nodes_raw) >= MAX_SUCCESS * 2:
                print(f"已收集足够原始节点 ({len(all_parsed_nodes_raw)})，达到 MAX_SUCCESS * 2，提前终止后续请求。")
                # 显式关闭线程池中的线程
                executor.shutdown(wait=True, cancel_futures=True) # 确保所有任务被取消并线程关闭
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
        # 这种情况通常不应该发生，因为 clean_node_name 会确保有名称
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
        },
        {
            'name': '📈 手动排序', # 增加一个按ping排序的组，方便手动选择
            'type': 'select',
            'proxies': ['DIRECT'] + sorted(proxy_names_in_group) # 按名称排序
        },
        # 增加一些常见的策略组
        {
            'name': '🌍 国外流量',
            'type': 'select',
            'proxies': ['♻️ 自动选择', '🚀 节点选择']
        },
        {
            'name': '🪜 漏网之鱼',
            'type': 'select',
            'proxies': ['♻️ 自动选择', '🚀 节点选择', 'DIRECT']
        },
        {
            'name': '🛑 广告拦截',
            'type': 'select',
            'proxies': ['REJECT', 'DIRECT']
        },
        {
            'name': '📢 其他',
            'type': 'select',
            'proxies': ['DIRECT', '♻️ 自动选择']
        }
    ],
    'rules': [
        # 添加一些基础规则
        'DOMAIN-SUFFIX,cn,DIRECT',
        'GEOIP,CN,DIRECT',
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
