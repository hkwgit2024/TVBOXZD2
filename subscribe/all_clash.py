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

# Configure logging
# Log file named error.log, level set to DEBUG for easier debugging and tracing
logging.basicConfig(filename='error.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Request headers
# Simulate browser behavior to prevent being identified as a bot
headers = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/91.0.4472.124 Safari/537.36'
    ),
    'Accept-Encoding': 'gzip, deflate' # Accept gzip and deflate encoding for better transfer efficiency
}

# Command-line argument parsing
# Allows user to customize script behavior via command line
parser = argparse.ArgumentParser(description="URL content fetching script, supporting multiple URL sources and node parsing")
parser.add_argument('--max_success', type=int, default=99999, help="Target number of successful nodes. Script may terminate early if this is reached.")
parser.add_argument('--timeout', type=int, default=30, help="Request timeout in seconds.")
parser.add_argument('--output', type=str, default='data/all_clash.yaml', help="Output file path for the generated Clash YAML configuration.")
args = parser.parse_args()

# Global variables
MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
TEMP_MERGED_NODES_RAW_FILE = 'temp_merged_nodes_raw.txt' # Temporary file to store raw parsed nodes
STATISTICS_FILE = 'data/url_statistics.csv' # Statistics file for recording URL processing results
SUCCESS_URLS_FILE = 'data/successful_urls.txt' # List of successfully fetched and parsed URLs
FAILED_URLS_FILE = 'data/failed_urls.txt' # List of failed URLs

# Define keywords for deletion
# Nodes with names containing these keywords will be skipped, typically ads or traffic info
DELETE_KEYWORDS = [
    '剩余流量', '套餐到期', '流量', '到期', '过期', '免费', '试用', '体验', '限时', '限制',
    '已用', '可用', '不足', '到期时间', '倍率', '返利', '充值', '续费', '用量', '订阅',
    '广告', '通知', '公告', '过期', '无效', '测试', '失效', '故障', '维护'
]

# Define common placeholder UUIDs/passwords, these will not be used for uniqueness
COMMON_UUID_PLACEHOLDERS = [
    "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1", # Example placeholder
    "00000000-0000-0000-0000-000000000000",
    "d23b3208-d01d-40d3-b1d6-fe1e48edcb74", # Common fake UUID
    "f1c97c11-9a74-4b5b-bc3c-c9f56475653b" # Another common placeholder
]

# Define common placeholder passwords
COMMON_PASSWORD_PLACEHOLDERS = [
    "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1", # Example placeholder
    "password", "123456", "000000", "test", "demo", "free", "admin", "guest"
]


def is_valid_url(url):
    """
    Validates URL format, only accepts http or https schemes.
    Uses urllib.parse.urlparse for parsing and validation.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def is_valid_ip_address(host):
    """
    Validates if it's a valid IPv4 or IPv6 address.
    Uses ipaddress module for validation.
    """
    try:
        # Try parsing as IPv4 or IPv6
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Extra handling for IPv6 addresses that might be enclosed in square brackets
        try:
            if host.startswith('[') and host.endswith(']'):
                ipaddress.ip_address(host[1:-1])
                return True
            return False
        except ValueError:
            return False

def get_url_list_from_remote(url_source):
    """
    Fetches a list of URLs from a given public URL.
    Typically, url_source will be a text file containing subscription links.
    """
    try:
        session = requests.Session()
        # Configure retry strategy for common network errors and status codes
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url_source, headers=headers, timeout=10)
        response.raise_for_status() # Raises HTTPError for 4xx/5xx status codes
        text_content = response.text.strip()
        # Split content by lines, filter out empty lines
        raw_urls = [line.strip() for line in text_content.splitlines() if line.strip()]
        print(f"Fetched {len(raw_urls)} URLs or strings from {url_source}")
        return raw_urls
    except Exception as e:
        logging.error(f"Failed to fetch URL list: {url_source} - {e}")
        return []

def parse_content_to_nodes(content):
    """
    Parses nodes from text content.
    Content can be Base64 encoded, Clash YAML format, or a direct list of various protocol URLs.
    """
    if not content:
        return []

    found_nodes = []
    processed_content = content

    # 1. Try Base64 decoding
    # Subscription content is often Base64 encoded, prioritize decoding
    try:
        decoded_bytes = base64.b64decode(content)
        processed_content = decoded_bytes.decode('utf-8')
        logging.debug("Content successfully Base64 decoded.")
    except Exception:
        # If not Base64 encoded, keep as is
        pass

    # 2. Try YAML parsing
    # If it's a Clash YAML configuration, parse the 'proxies' section
    try:
        parsed_data = yaml.safe_load(processed_content)
        if isinstance(parsed_data, dict) and 'proxies' in parsed_data and isinstance(parsed_data['proxies'], list):
            for proxy_entry in parsed_data['proxies']:
                if isinstance(proxy_entry, dict):
                    # Ensure name is a string, in case some configs have numeric names
                    if 'name' in proxy_entry and not isinstance(proxy_entry['name'], str):
                        proxy_entry['name'] = str(proxy_entry['name'])
                    found_nodes.append(proxy_entry)
                elif isinstance(proxy_entry, str) and any(proxy_entry.startswith(p + '://') for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    # Nodes directly as URL strings
                    found_nodes.append(proxy_entry.strip())
            logging.debug("Content successfully parsed as Clash YAML.")
        elif isinstance(parsed_data, list):
            # If the parsing result is directly a list (e.g., some subscriptions return a list of node URLs directly)
            for item in parsed_data:
                if isinstance(item, str):
                    found_nodes.append(item.strip())
                elif isinstance(item, dict):
                    if 'name' in item and not isinstance(item['name'], str):
                        item['name'] = str(item['name'])
                    found_nodes.append(item)
            logging.debug("Content successfully parsed as YAML list.")
    except yaml.YAMLError:
        pass # Not YAML format, continue trying other parsing methods
    except Exception as e:
        logging.error(f"YAML parsing failed: {e}")
        pass

    # 3. Extract nodes using regex
    # Try to match node URLs directly from original or decoded content
    node_pattern = re.compile(
        r'(vmess://\S+|'
        r'trojan://\S+|'
        r'ss://\S+|'
        r'ssr://\S+|' # SSR is also URL format
        r'vless://\S+|'
        r'hy://\S+|'
        r'hy2://\S+|'
        r'hysteria://\S+|'
        r'hysteria2://\S+)'
    )
    
    # Check original content
    matches = node_pattern.findall(content)
    for match in matches:
        found_nodes.append(match.strip())
    
    # If content was decoded, check decoded content again
    if content != processed_content:
        matches_decoded = node_pattern.findall(processed_content)
        for match in matches_decoded:
            found_nodes.append(match.strip())

    return found_nodes

def fetch_and_parse_url(url):
    """
    Fetches URL content and parses nodes.
    This function tries to request the given URL, then calls parse_content_to_nodes for parsing.
    Returns (list of nodes, success status, error message, status code)
    """
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))

    try:
        logging.debug(f"Starting request for URL: {url}")
        resp = session.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status() # Raise an exception for 4xx or 5xx status codes
        content = resp.text.strip()
        
        if len(content) < 10: # Content too short might be an invalid subscription
            logging.warning(f"Content too short, might be invalid: {url}")
            return [], False, "Content too short", resp.status_code
            
        nodes = parse_content_to_nodes(content)
        logging.debug(f"URL {url} parsed {len(nodes)} nodes")
        return nodes, True, None, resp.status_code
    except requests.exceptions.Timeout:
        logging.error(f"Request timed out: {url}")
        return [], False, "Request timed out", None
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection failed: {url} - {e}")
        return [], False, f"Connection failed: {e}", None
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error: {url} - {e}")
        return [], False, f"HTTP error: {e}", None
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {url} - {e}")
        return [], False, f"Unknown request error: {e}", None
    except Exception as e:
        logging.error(f"Exception processing URL: {url} - {e}")
        return [], False, f"Unknown exception: {e}", None

def write_statistics_to_csv(statistics_data, filename):
    """Writes statistics data to a CSV file"""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', 'Node Count', 'Status', 'Error Message', 'Status Code']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in statistics_data:
            writer.writerow(row)
    print(f"Statistics saved to: {filename}")

def write_urls_to_file(urls, filename):
    """Writes a list of URLs to a file"""
    with open(filename, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(url + '\n')
    print(f"URL list saved to: {filename}")

def clean_node_name(name, index=None):
    """
    Cleans node names, removes redundant information, standardizes region names, and adds an index.
    This function is only for beautifying node names and does not affect the deduplication logic.
    """
    if not isinstance(name, str):
        name = str(name)

    cleaned_name = name.strip()

    # Remove content in parentheses containing specific keywords (e.g., "[Remaining Traffic 2G]")
    cleaned_name = re.sub(r'【[^】]*?(流量|到期|过期|充值|续费)[^】]*】', '', cleaned_name)
    cleaned_name = re.sub(r'\[[^]]*?(流量|到期|过期|充值|续费)[^\]]*\]', '', cleaned_name)
    cleaned_name = re.sub(r'\([^)]*?(流量|到期|过期|充值|续费)[^)]*\)', '', cleaned_name)
    cleaned_name = re.sub(r'（[^）]*?(流量|到期|过期|充值|续费)[^）]*）', '', cleaned_name)

    # Remove other redundant keywords or patterns
    redundant_keywords_to_remove = [
        r'\d+%', r'\d{4}-\d{2}-\d{2}', r'\d{2}-\d{2}', r'x\d+', # 100%, date, x2 multiplier
        r'秒杀', r'活动', r'新年', r'福利', r'VIP\d*', r'Pro', r'Lite', r'Plus', # Promotional terms
        r'自动', r'手动', r'自选', # Selection methods
        r'(\d+\.\d+kbps)', r'(\d+\.\d+mbps)', r'(\d+kbps)', r'(\d+mbps)', # Speed info
        r'\\n', r'\\r', r'\d+\.\d+G|\d+G', # Newline characters, traffic GB
        r'[Nn]ode\d*', r'[Ss]erver\d*', # Remove generic "NodeX", "ServerX" as they are replaced by index
        r'\[.*?\]', r'\(.*?\)', r'【.*?】', r'（.*?）' # Remove any remaining bracketed content
    ]

    for keyword in redundant_keywords_to_remove:
        cleaned_name = re.sub(keyword, ' ', cleaned_name, flags=re.IGNORECASE).strip()

    # Remove special characters, keep only Chinese, English, numbers, spaces, and some common symbols
    cleaned_name = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9\s\.\-_@#|]', ' ', cleaned_name)
    # Merge multiple spaces into a single space
    cleaned_name = re.sub(r'\s+', ' ', cleaned_name).strip()

    # Map Chinese region names to English abbreviations
    region_map = {
        '香港': 'HK', '台湾': 'TW', '日本': 'JP', '新加坡': 'SG', '美国': 'US', '英国': 'UK',
        '德国': 'DE', '韩国': 'KR', '马来': 'MY', '泰国': 'TH', 'PH': 'PH', '越南': 'VN',
        '印尼': 'ID', '印度': 'IN', '澳洲': 'AU', '加拿大': 'CA', '俄罗斯': 'RU', '巴西': 'BR',
        '意大利': 'IT', '荷兰': 'NL', '中国': 'CN', '深圳': 'SZ', '上海': 'SH', '北京': 'BJ',
        '广州': 'GZ', '杭州': 'HZ', '阿根廷': 'AR', '法国': 'FR', '瑞士': 'CH', '芬兰': 'FI',
        '爱尔兰': 'IE', '瑞典': 'SE', '挪威': 'NO', '丹麦': 'DK', '比利时': 'BE', '奥地利': 'AT',
        '西班牙': 'ES', '葡萄牙': 'PT', '希腊': 'GR', '以色列': 'IL', '土耳其': 'TR', '南非': 'ZA',
        '埃及': 'EG', '迪拜': 'AE', '阿联酋': 'AE', '加拿大': 'CA', '墨西哥': 'MX', '哥伦比亚': 'CO',
        '智利': 'CL', '秘鲁': 'PE', '新西兰': 'NZ', '菲律宾': 'PH'
    }
    for full_name, short_name in region_map.items():
        cleaned_name = cleaned_name.replace(full_name, short_name)
        # Also handle partial matches if full_name is part of a longer string
        cleaned_name = re.sub(re.escape(full_name) + r'(\S*)', short_name + r'\1', cleaned_name, flags=re.IGNORECASE)


    # Try to retain some meaningful keywords, like dedicated line info
    meaningful_keywords = ['IPLC', 'IEPL', '专线', '中转', '直连', 'CDN', 'AZURE', 'AWS', 'GCP', 'Oracle', 'HKBN']
    preserved_info = []
    for keyword in meaningful_keywords:
        if keyword.lower() in cleaned_name.lower():
            preserved_info.append(keyword)
    
    # If cleaned name is too short or empty, try to use region name or default name
    if not cleaned_name or len(cleaned_name) <= 3:
        initial_name_part = 'Node'
        # If original name contains region info, prioritize using it
        found_region = False
        for region in region_map.values():
            if region.lower() in name.lower():
                initial_name_part = region
                found_region = True
                break
        
        if not found_region and any(region in name for region in region_map.keys()):
             for full_name, short_name in region_map.items():
                if full_name in name:
                    initial_name_part = short_name
                    break
        
        cleaned_name = initial_name_part

    # Append preserved info if any
    if preserved_info:
        # Ensure we don't duplicate info if it's already in the cleaned name
        unique_preserved_info = []
        for info in preserved_info:
            if info.lower() not in cleaned_name.lower():
                unique_preserved_info.append(info)
        if unique_preserved_info:
            cleaned_name += ' ' + ' '.join(unique_preserved_info)

    # Limit name length
    if len(cleaned_name) > 80:
        cleaned_name = cleaned_name[:80].rstrip() + '...'

    # Add index (this happens in the main loop for final proxies)
    if index is not None:
        cleaned_name += f"-{index:03d}" # Three-digit index

    return cleaned_name if cleaned_name else f"Node-{index:03d}" if index is not None else "Unknown Node"

def _normalize_dict_for_fingerprint(data):
    """
    Recursively normalizes a dictionary for stable fingerprint generation.
    - Keys are converted to lowercase.
    - Values are stripped of leading/trailing whitespace.
    - None, empty strings, and default boolean `False` values are removed (unless explicitly `True`).
    - Lists are sorted after their elements are normalized.
    - Nested dictionaries are processed recursively.
    """
    if not isinstance(data, dict):
        # Handle non-dictionary types directly, ensuring consistent string representation
        if isinstance(data, bool):
            return str(data).lower()
        if data is None or str(data).strip() == '':
            return None # Treat None and empty string as same for removal
        return str(data).lower().strip() # Convert everything to stripped lowercase string

    normalized = {}
    for k, v in data.items():
        if isinstance(v, dict):
            normalized_v = _normalize_dict_for_fingerprint(v)
            if normalized_v: # Only keep non-empty dictionaries
                normalized[k.lower()] = normalized_v
        elif isinstance(v, list):
            # Normalize and sort list elements
            normalized_list = sorted([_normalize_dict_for_fingerprint(item) for item in v if _normalize_dict_for_fingerprint(item) is not None])
            if normalized_list: # Only keep non-empty lists
                normalized[k.lower()] = normalized_list
        elif v is not None:
            # Handle booleans explicitly: False is a default, only True should be considered distinct if not default
            if isinstance(v, bool):
                if v is True: # Only include explicit True in fingerprint
                    normalized[k.lower()] = "true"
            elif str(v).strip() != '': # Ignore empty strings after strip
                normalized[k.lower()] = str(v).lower().strip()
    return normalized

def _get_node_core_params(node_dict):
    """
    Extracts a set of core parameters from a standardized Clash node dictionary for fingerprinting.
    This is the core of the deduplication logic, designed to ignore non-core or dynamically changing parameters.
    """
    core_params = {
        'type': node_dict.get('type'),
        'server': node_dict.get('server'),
        'port': node_dict.get('port'),
    }

    node_type = node_dict.get('type')

    # Handle servername/sni: if different from server, include; otherwise, ignore
    servername = node_dict.get('servername') or node_dict.get('sni')
    # Compare after stripping and lowercasing to handle subtle differences
    if servername and str(servername).lower().strip() != str(node_dict.get('server', '')).lower().strip():
        core_params['servername'] = servername

    # Handle tls and skip-cert-verify consistently
    # If TLS is enabled, skip-cert-verify=False is default for strict verification
    # Only include skip-cert-verify=True if explicitly set
    tls_enabled = bool(node_dict.get('tls'))
    core_params['tls'] = tls_enabled
    if tls_enabled and bool(node_dict.get('skip-cert-verify')) is True:
        core_params['skip-cert-verify'] = True # Only include if it's explicitly True


    # Protocol-specific parameters
    if node_type == 'vmess':
        uuid = node_dict.get('uuid') or node_dict.get('id')
        if uuid and str(uuid).lower() not in COMMON_UUID_PLACEHOLDERS:
            core_params['uuid'] = uuid
        # AlterId 0 is often default, only include if non-zero
        alter_id = int(node_dict.get('alterId', 0) or node_dict.get('aid', 0))
        if alter_id != 0:
            core_params['alterId'] = alter_id
        
        # Cipher should be included as it affects security/compatibility
        if node_dict.get('cipher'):
            core_params['cipher'] = node_dict['cipher']
        
        core_params['network'] = node_dict.get('network')
        
        # Process ws-opts
        ws_opts = node_dict.get('ws-opts')
        if isinstance(ws_opts, dict):
            standardized_ws_opts = {}
            # Only include path if not default '/'
            if ws_opts.get('path') and ws_opts['path'] != '/':
                standardized_ws_opts['path'] = str(ws_opts['path']).lower().strip()
            if ws_opts.get('headers') and isinstance(ws_opts['headers'], dict):
                # Standardize headers: keys to lowercase, values to lowercase and stripped, then sort by key
                standardized_headers = {k.lower(): str(v).lower().strip() for k, v in ws_opts['headers'].items() if str(v).strip()}
                if standardized_headers:
                    # Sort headers by key to ensure consistent representation
                    standardized_ws_opts['headers'] = dict(sorted(standardized_headers.items()))
            if standardized_ws_opts:
                core_params['ws-opts'] = standardized_ws_opts

        # Process grpc-opts
        grpc_opts = node_dict.get('grpc-opts')
        if isinstance(grpc_opts, dict) and grpc_opts.get('serviceName'):
            core_params['grpc-opts'] = {'serviceName': str(grpc_opts['serviceName']).lower().strip()}

    elif node_type == 'trojan':
        password = node_dict.get('password')
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        core_params['network'] = node_dict.get('network')
        
        # Trojan might have ws-opts/grpc-opts
        ws_opts = node_dict.get('ws-opts')
        if isinstance(ws_opts, dict):
            standardized_ws_opts = {}
            if ws_opts.get('path') and ws_opts['path'] != '/':
                standardized_ws_opts['path'] = str(ws_opts['path']).lower().strip()
            if ws_opts.get('headers') and isinstance(ws_opts['headers'], dict):
                standardized_headers = {k.lower(): str(v).lower().strip() for k, v in ws_opts['headers'].items() if str(v).strip()}
                if standardized_headers:
                    standardized_ws_opts['headers'] = dict(sorted(standardized_headers.items()))
            if standardized_ws_opts:
                core_params['ws-opts'] = standardized_ws_opts
        
        grpc_opts = node_dict.get('grpc-opts')
        if isinstance(grpc_opts, dict) and grpc_opts.get('serviceName'):
            core_params['grpc-opts'] = {'serviceName': str(grpc_opts['serviceName']).lower().strip()}

    elif node_type == 'ss':
        if node_dict.get('cipher'):
            core_params['cipher'] = node_dict['cipher']
        password = node_dict.get('password')
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        
        # Process plugin and plugin-opts
        if node_dict.get('plugin'):
            core_params['plugin'] = str(node_dict['plugin']).lower().strip()
            if node_dict.get('plugin-opts'):
                # Standardize plugin-opts dictionary
                standardized_plugin_opts = {k.lower(): str(v).lower().strip() for k, v in node_dict['plugin-opts'].items() if str(v).strip()}
                if standardized_plugin_opts:
                    # Sort plugin-opts by key
                    core_params['plugin-opts'] = dict(sorted(standardized_plugin_opts.items()))

    elif node_type == 'vless':
        uuid = node_dict.get('uuid') or node_dict.get('id')
        if uuid and str(uuid).lower() not in COMMON_UUID_PLACEHOLDERS:
            core_params['uuid'] = uuid
        core_params['network'] = node_dict.get('network')
        
        # Only include non-empty flow
        if node_dict.get('flow') and node_dict['flow'] != '':
            core_params['flow'] = str(node_dict['flow']).lower().strip()
        
        if bool(node_dict.get('xudp')) is True:
            core_params['xudp'] = True
        if bool(node_dict.get('udp-over-tcp')) is True:
            core_params['udp-over-tcp'] = True

        # Process ws-opts
        ws_opts = node_dict.get('ws-opts')
        if isinstance(ws_opts, dict):
            standardized_ws_opts = {}
            if ws_opts.get('path') and ws_opts['path'] != '/':
                standardized_ws_opts['path'] = str(ws_opts['path']).lower().strip()
            if ws_opts.get('headers') and isinstance(ws_opts['headers'], dict):
                standardized_headers = {k.lower(): str(v).lower().strip() for k, v in ws_opts['headers'].items() if str(v).strip()}
                if standardized_headers:
                    standardized_ws_opts['headers'] = dict(sorted(standardized_headers.items()))
            if standardized_ws_opts:
                core_params['ws-opts'] = standardized_ws_opts
        
        # Process grpc-opts
        grpc_opts = node_dict.get('grpc-opts')
        if isinstance(grpc_opts, dict) and grpc_opts.get('serviceName'):
            core_params['grpc-opts'] = {'serviceName': str(grpc_opts['serviceName']).lower().strip()}
            
    elif node_type in ['hysteria', 'hy']:
        password = node_dict.get('password') # Hysteria uses password
        auth_str = node_dict.get('auth_str') # Hysteria can also use auth_str
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        elif auth_str and str(auth_str).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['auth_str'] = auth_str
        
        # protocol for Hysteria
        if node_dict.get('protocol'):
            core_params['network'] = str(node_dict['protocol']).lower().strip()
        
        # ALPN list needs to be sorted and lowercased
        alpn_list = [a.strip().lower() for a in node_dict.get('alpn', []) if a.strip()]
        if alpn_list:
            core_params['alpn'] = sorted(alpn_list)
        
        # Exclude up/down bandwidth from fingerprint as they are often dynamic
        # if node_dict.get('up') is not None:
        #     core_params['up'] = int(node_dict['up'])
        # if node_dict.get('down') is not None:
        #     core_params['down'] = int(node_dict['down'])

    elif node_type in ['hysteria2', 'hy2']:
        password = node_dict.get('password')
        if password and str(password).lower() not in COMMON_PASSWORD_PLACEHOLDERS:
            core_params['password'] = password
        
        if node_dict.get('obfs'):
            core_params['obfs'] = str(node_dict['obfs']).lower().strip()
        if node_dict.get('obfs-password'):
            core_params['obfs-password'] = str(node_dict['obfs-password']).lower().strip()

        # ALPN list needs to be sorted and lowercased
        alpn_list = [a.strip().lower() for a in node_dict.get('alpn', []) if a.strip()]
        if alpn_list:
            core_params['alpn'] = sorted(alpn_list)

    # Normalize the entire core_params dictionary to remove empty values etc.
    return _normalize_dict_for_fingerprint(core_params)

def _generate_stable_fingerprint_from_params(params_dict):
    """
    Converts the standardized core parameters dictionary into a stable JSON string and calculates its SHA256 fingerprint.
    """
    if not params_dict:
        return None

    # Ensure JSON serialization is stable (sorted keys, preserve non-ASCII chars)
    # Use indent=None and separators=(',', ':') to get a compact, stable representation
    stable_json = json.dumps(params_dict, sort_keys=True, ensure_ascii=False, indent=None, separators=(',', ':'))
    # logging.debug(f"Fingerprint JSON: {stable_json}") # For debugging
    return hashlib.sha256(stable_json.encode('utf-8')).hexdigest()

def deduplicate_and_standardize_nodes(raw_nodes_list):
    """
    Deduplicates and standardizes nodes.
    Converts various raw node formats into a unified Clash proxy dictionary format,
    and deduplicates based on a core parameter fingerprint.
    """
    unique_node_fingerprints = set()
    final_clash_proxies = []

    for idx, node in enumerate(raw_nodes_list):
        clash_proxy_dict = None
        node_raw_name = "" # To preserve original name for keyword checking

        if isinstance(node, dict):
            # If already a dictionary, use it directly
            clash_proxy_dict = node
            node_raw_name = str(node.get('name', '')) # Get original name
        elif isinstance(node, str):
            # If it's a URL string, try to parse it into Clash dictionary format
            try:
                parsed_url = urlparse(node)
                # Extract original node name (usually in URL fragment)
                node_raw_name = str(parsed_url.fragment or '') 
                
                # Check if protocol is valid
                protocol_scheme = parsed_url.scheme.lower()
                if not any(protocol_scheme == p for p in ["vmess", "trojan", "ss", "ssr", "vless", "hy", "hy2", "hysteria", "hysteria2"]):
                    logging.warning(f"Skipping node with invalid protocol: {node[:50]}...")
                    continue
                
                # Check if hostname is valid
                host = parsed_url.hostname or ''
                if host and not (is_valid_ip_address(host) or re.match(r'^[a-zA-Z0-9\-\.]+$', host)):
                    logging.warning(f"Skipping node with invalid hostname: {host} in {node[:50]}...")
                    continue

                # Parse and convert to Clash dictionary format based on protocol type
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
                        'skip-cert-verify': (config.get('scy', 'false') == 'true'), # scy field can also mean skip-cert-verify
                        'servername': config.get('sni') or config.get('host') or config.get('add'),
                    }
                    # ws-opts
                    if config.get('net') == 'ws':
                        ws_opts = {}
                        if config.get('path'):
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
                        if query.get('path', [''])[0]:
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
                        # SS link format: ss://base64_encoded_method:password@server:port#name
                        # Handle potential base64 padding issues
                        decoded_part_padded = decoded_part + '=' * (-len(decoded_part) % 4)
                        decoded_info = base64.b64decode(decoded_part_padded.encode('utf-8')).decode('utf-8')
                        
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
                        logging.warning(f"SS node parsing failed: {node[:50]}... - {e}")
                        clash_proxy_dict = None
                
                elif protocol_scheme == "ssr":
                    # SSR link format: ssr://<base64_encoded_info>
                    # <base64_encoded_info> = <server>:<port>:<protocol>:<method>:<obfs>:<password_base64_encoded>/?obfsparam=<obfsparam_base64>&protoparam=<protoparam_base64>&remarks=<remarks_base64>&group=<group_base64>&udp=<udp_enabled>
                    try:
                        decoded_info_b64 = node[len("ssr://"):].split('#', 1)[0]
                        # Handle potential base64 padding issues for SSR
                        decoded_info_b64_padded = decoded_info_b64 + '=' * (-len(decoded_info_b64) % 4)
                        decoded_info = base64.b64decode(decoded_info_b64_padded.encode('utf-8')).decode('utf-8')
                        
                        # Split by ':', the password part contains '?' for query params
                        parts = decoded_info.split(':', 5) 
                        server = parts[0]
                        port = int(parts[1])
                        protocol = parts[2]
                        method = parts[3]
                        obfs = parts[4]
                        
                        # Split password part from query string
                        password_b64_part = parts[5].split('/?', 1)[0]
                        password = base64.b64decode(password_b64_part + '=' * (-len(password_b64_part) % 4)).decode('utf-8')

                        clash_proxy_dict = {
                            'name': str(parsed_url.fragment or 'SSR Node'),
                            'type': 'ssr', # Clash may have limited SSR support, keep it here
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
                            obfs_param_b64 = query_params['obfsparam'][0]
                            clash_proxy_dict['obfs-param'] = base64.b64decode(obfs_param_b64 + '=' * (-len(obfs_param_b64) % 4)).decode('utf-8')
                        if 'protoparam' in query_params:
                            proto_param_b64 = query_params['protoparam'][0]
                            clash_proxy_dict['protocol-param'] = base64.b64decode(proto_param_b64 + '=' * (-len(proto_param_b64) % 4)).decode('utf-8')
                        if 'udp' in query_params:
                            clash_proxy_dict['udp'] = (query_params['udp'][0] == '1')
                        
                        # SSR name is typically in remarks
                        if 'remarks' in query_params:
                             remarks_b64 = query_params['remarks'][0]
                             clash_proxy_dict['name'] = base64.b64decode(remarks_b64 + '=' * (-len(remarks_b64) % 4)).decode('utf-8')
                    except Exception as e:
                        logging.warning(f"SSR node parsing failed: {node[:50]}... - {e}")
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
                        if query.get('path', [''])[0]:
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
                        'tls': True # Hysteria defaults to TLS
                    }
                    alpn_list = [a.strip() for a in query.get('alpn', [''])[0].split(',') if a.strip()]
                    if alpn_list:
                        clash_proxy_dict['alpn'] = alpn_list
                    # IMPORTANT: Exclude bandwidth limits from fingerprint
                    # if query.get('up_mbps', ['0'])[0] != '0':
                    #     clash_proxy_dict['up'] = int(query['up_mbps'][0])
                    # if query.get('down_mbps', ['0'])[0] != '0':
                    #     clash_proxy_dict['down'] = int(query['down_mbps'][0])
                    
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
                logging.warning(f"URL node conversion to Clash dictionary failed: {node[:80]}... - {e}")
                clash_proxy_dict = None

        if clash_proxy_dict:
            # Check if node name contains deletion keywords
            name_to_check = str(node_raw_name or clash_proxy_dict.get('name', '')) # Prioritize original name for checking
            
            should_delete_node = False
            for keyword in DELETE_KEYWORDS:
                try:
                    if keyword.lower() in name_to_check.lower():
                        logging.info(f"Node '{name_to_check}' contains deletion keyword '{keyword}', skipped.")
                        should_delete_node = True
                        break
                except AttributeError as e: # Prevent name_to_check from not being a string
                    logging.error(f"Error checking deletion keywords: name_to_check={name_to_check}, type={type(name_to_check)}, node={clash_proxy_dict.get('name', 'Unknown')} - {e}")
                    should_delete_node = True
                    break
            
            if should_delete_node:
                continue

            # Check if server address is valid
            server = clash_proxy_dict.get('server', '')
            if server and not (is_valid_ip_address(server) or re.match(r'^[a-zA-Z0-9\-\.]+$', server)):
                logging.warning(f"Skipping node with invalid server address: {server} in {clash_proxy_dict.get('name', 'Unknown')}")
                continue

            # Generate fingerprint and deduplicate
            core_params = _get_node_core_params(clash_proxy_dict)
            fingerprint = _generate_stable_fingerprint_from_params(core_params)
            
            if fingerprint and fingerprint not in unique_node_fingerprints:
                unique_node_fingerprints.add(fingerprint)
                # Clean node name and add index
                clash_proxy_dict['name'] = clean_node_name(
                    clash_proxy_dict.get('name', f"{clash_proxy_dict.get('type', 'Unknown')} {clash_proxy_dict.get('server', '')}:{clash_proxy_dict.get('port', '')}"),
                    index=len(final_clash_proxies) + 1 # Use current number of collected nodes as index
                )
                final_clash_proxies.append(clash_proxy_dict)
            else:
                logging.debug(f"Duplicate node (by fingerprint): {clash_proxy_dict.get('name', '')} - {fingerprint}")
        else:
            logging.debug(f"Raw node or URL could not be converted to Clash dictionary: {str(node)[:80]}...")

    return final_clash_proxies

# --- Main program flow ---

# Get URL_SOURCE from environment variable
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"Debug Info - URL_SOURCE value read: {URL_SOURCE}")

if not URL_SOURCE:
    print("Error: Environment variable 'URL_SOURCE' is not set. Please set a URL to a remote text file containing subscription links.")
    exit(1)

# Create output directories
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
os.makedirs(os.path.dirname(STATISTICS_FILE), exist_ok=True)

# Phase One: Get raw URL/string list
raw_urls_from_source = get_url_list_from_remote(URL_SOURCE)

urls_to_fetch = set() # URLs to be fetched via HTTP/HTTPS
url_statistics = [] # For recording processing statistics
successful_urls = [] # List of successfully processed URLs
failed_urls = [] # List of failed URLs
all_parsed_nodes_raw = [] # All parsed raw nodes (before deduplication and standardization)

print("\n--- Preprocessing Raw URL/String List ---")
for entry in raw_urls_from_source:
    if is_valid_url(entry):
        # If it's a valid HTTP/HTTPS URL, add to the list to be requested
        urls_to_fetch.add(entry)
    else:
        # If it's not a valid URL, try to parse its content directly (might be Base64 encoded node list or Clash config fragment)
        print(f"Found non-HTTP/HTTPS entry, attempting direct parsing: {entry[:80]}...")
        parsed_nodes = parse_content_to_nodes(entry)
        if parsed_nodes:
            all_parsed_nodes_raw.extend(parsed_nodes)
            stat_entry = {'URL': entry, 'Node Count': len(parsed_nodes), 'Status': 'Direct Parse Success', 'Error Message': '', 'Status Code': None}
            url_statistics.append(stat_entry)
            successful_urls.append(entry)
        else:
            stat_entry = {'URL': entry, 'Node Count': 0, 'Status': 'Direct Parse Failed', 'Error Message': 'Not a URL and could not be parsed as node', 'Status Code': None}
            url_statistics.append(stat_entry)
            failed_urls.append(entry)

print("\n--- Phase One: Fetching and Merging Nodes from All Subscription Links in Parallel ---")
total_urls_to_process_via_http = len(urls_to_fetch)

if total_urls_to_process_via_http > 0:
    # Use a thread pool for parallel URL requests to improve efficiency
    # max_workers=16 is a common value, can be adjusted based on network and CPU
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls_to_fetch}
        # tqdm for progress bar
        for future in tqdm(as_completed(future_to_url), total=total_urls_to_process_via_http, desc="Fetching and parsing nodes via HTTP/HTTPS", mininterval=1.0):
            url = future_to_url[future]
            nodes, success, error_message, status_code = future.result()

            stat_entry = {
                'URL': url,
                'Node Count': len(nodes),
                'Status': 'Success' if success else 'Failed',
                'Error Message': error_message if error_message else '',
                'Status Code': status_code
            }
            url_statistics.append(stat_entry)

            if success:
                successful_urls.append(url)
                all_parsed_nodes_raw.extend(nodes)
                print(f"Successfully processed URL: {url}, Nodes: {len(nodes)}, Status Code: {status_code}")
            else:
                failed_urls.append(url)
                print(f"Failed URL: {url}, Error: {error_message}")

            # Early termination mechanism: if enough raw nodes are collected (e.g., 2 times MAX_SUCCESS, considering deduplication loss), stop further requests
            # The condition here can be adjusted, e.g., len(all_parsed_nodes_raw) > MAX_SUCCESS * 1.5
            # Alternatively, you can disable early termination and wait for all URLs to be processed
            if len(all_parsed_nodes_raw) >= MAX_SUCCESS * 2:
                print(f"Enough raw nodes collected ({len(all_parsed_nodes_raw)}), reaching MAX_SUCCESS * 2, terminating remaining requests early.")
                # Explicitly shut down threads in the thread pool
                executor.shutdown(wait=True, cancel_futures=True) # Ensure all tasks are cancelled and threads are closed
                break

# Deduplicate and standardize all collected raw nodes
final_unique_clash_proxies = deduplicate_and_standardize_nodes(all_parsed_nodes_raw)

# Write deduplicated raw nodes (in dictionary form) to a temporary file for debugging
with open(TEMP_MERGED_NODES_RAW_FILE, 'w', encoding='utf-8') as temp_file:
    for node in final_unique_clash_proxies:
        if isinstance(node, dict):
            temp_file.write(json.dumps(node, ensure_ascii=False) + '\n')
        else: # Theoretically, all should be dicts by now, but for safety
            temp_file.write(str(node).strip() + '\n') # Ensure strings are written

print(f"\nPhase One complete. Merged into {len(final_unique_clash_proxies)} unique Clash proxy dictionaries, saved to {TEMP_MERGED_NODES_RAW_FILE}")

# Write statistics and URL lists
write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE)

print("\n--- Phase Two: Outputting Final Clash YAML Configuration ---")

# Ensure output file has .yaml or .yml extension
if not OUTPUT_FILE.endswith(('.yaml', '.yml')):
    OUTPUT_FILE = os.path.splitext(OUTPUT_FILE)[0] + '.yaml'

# Take at most MAX_SUCCESS nodes for output
proxies_to_output = final_unique_clash_proxies[:MAX_SUCCESS]

# Build list of proxy names for proxy groups
proxy_names_in_group = []
for node in proxies_to_output:
    if isinstance(node, dict) and 'name' in node:
        proxy_names_in_group.append(node['name'])
    else:
        # Fallback to ensure it's added to the group even without a name
        # This shouldn't happen usually, as clean_node_name ensures a name
        proxy_names_in_group.append(f"{node.get('type', 'Unknown')} {node.get('server', '')}")

# Build final Clash configuration dictionary
clash_config = {
    'proxies': proxies_to_output,
    'proxy-groups': [
        {
            'name': '🚀 节点选择', # Manual node selection group
            'type': 'select',
            'proxies': ['DIRECT'] + proxy_names_in_group # Include direct connection option
        },
        {
            'name': '♻️ 自动选择', # Auto-test and select best node group
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204', # Google's no-content response page, often used for speed testing
            'interval': 300, # Test interval 300 seconds
            'proxies': proxy_names_in_group
        },
        {
            'name': '📈 手动排序', # Add a group for manual sorting by ping for convenience
            'type': 'select',
            'proxies': ['DIRECT'] + sorted(proxy_names_in_group) # Sort by name
        },
        # Add some common policy groups
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
        # Add some basic rules
        'DOMAIN-SUFFIX,cn,DIRECT',
        'GEOIP,CN,DIRECT',
        'MATCH,🚀 节点选择' # Default rule: all unmatched traffic goes through the node selection group
    ]
}

success_count = len(proxies_to_output)

# Write Clash configuration to YAML file
try:
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
        # allow_unicode=True ensures Chinese characters are correctly encoded
        # default_flow_style=False ensures block style output for readability
        # sort_keys=False maintains dictionary insertion order (important for proxies and proxy-groups)
        yaml.dump(clash_config, out_file, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"Final Clash YAML configuration saved to: {OUTPUT_FILE}")
except Exception as e:
    logging.error(f"Failed to write final Clash YAML file: {e}")
    print(f"Error: Failed to write final Clash YAML file: {e}")

# Clean up temporary file
if os.path.exists(TEMP_MERGED_NODES_RAW_FILE):
    os.remove(TEMP_MERGED_NODES_RAW_FILE)
    print(f"Temporary file deleted: {TEMP_MERGED_NODES_RAW_FILE}")

# Print final run summary
print("\n" + "=" * 50)
print("Final Results:")
print(f"Total raw entries from source: {len(raw_urls_from_source)}")
print(f"  HTTP/HTTPS subscriptions to fetch: {len(urls_to_fetch)}")
print(f"  Directly parsed non-URL strings: {len(raw_urls_from_source) - len(urls_to_fetch)}")
print(f"Total successfully processed URLs/strings: {len(successful_urls)}")
print(f"Total failed URLs/strings: {len(failed_urls)}")
print(f"Total raw nodes merged (before deduplication and filtering): {len(all_parsed_nodes_raw)}")
print(f"Unique Clash proxies after deduplication, standardization, and filtering: {len(final_unique_clash_proxies)}")
print(f"Nodes output to final Clash YAML file: {success_count}")
if len(final_unique_clash_proxies) > 0:
    print(f"Final effective content rate (relative to deduplicated filtered): {success_count/len(final_unique_clash_proxies):.1%}")
if success_count < MAX_SUCCESS:
    print(f"Warning: Failed to reach target quantity {MAX_SUCCESS}. Original list might lack sufficient valid URLs/nodes, or some URLs failed to fetch.")
print(f"Result file saved to: {OUTPUT_FILE}")
print(f"Statistics saved to: {STATISTICS_FILE}")
print(f"Successful URL list saved to: {SUCCESS_URLS_FILE}")
print(f"Failed URL list saved to: {FAILED_URLS_FILE}")
print("=" * 50)
