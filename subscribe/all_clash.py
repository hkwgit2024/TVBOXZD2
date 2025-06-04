import os
import sys
import argparse
import yaml
import requests
import base64
import re
from urllib.parse import urlparse, unquote
from tqdm import tqdm
import datetime
import ipaddress # For IPv6 validation
import json # For handling JSON-based subscriptions (like V2ray-N base64)

# --- Configuration ---
# 输出文件路径
OUTPUT_FILE = os.path.join("data", "all_clash.yaml")
# 错误日志文件路径
ERROR_LOG_FILE = "error.log"
# URL 统计文件路径
URL_STATISTICS_FILE = os.path.join("data", "url_statistics.csv")
# 成功处理的URL列表
SUCCESSFUL_URLS_FILE = os.path.join("data", "successful_urls.txt")
# 失败处理的URL列表
FAILED_URLS_FILE = os.path.join("data", "failed_urls.txt")

# 最大节点名称长度
MAX_NODE_NAME_LENGTH = 60

# --- Helper Functions ---

def ensure_directory_exists(file_path):
    """确保文件所在的目录存在。"""
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

def log_error(message):
    """记录错误信息到日志文件和标准错误输出。"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message, file=sys.stderr)
    ensure_directory_exists(ERROR_LOG_FILE) # Ensure directory for log file
    with open(ERROR_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(full_message + "\n")

def _safe_base64_decode(data):
    """安全地进行 Base64 解码，处理填充错误。"""
    for i in range(4):
        try:
            return base64.b64decode(data + '=' * i).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            continue
    raise ValueError("Invalid Base64 string after padding attempts")

def _is_valid_ipv6(ip_str):
    """检查字符串是否是有效的 IPv6 地址。"""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False

def _clean_node_name(name):
    """
    清理节点名称：
    1. URL解码。
    2. 删除特定无用前缀（如官网地址）。
    3. 删除括号内的标签（如【VIP】）。
    4. 去除多余空格。
    5. 截断过长的名称。
    """
    if not isinstance(name, str):
        return str(name) # 确保是字符串

    # 1. URL解码
    decoded_name = unquote(name)

    # 2. 删除特定无用前缀（例如官网地址或广告语）
    # 匹配 "官网地址: " 或 "官网:" 开头，后跟任意非空格字符直到下一个空格或行尾
    decoded_name = re.sub(r'(?:官网地址|官网|机场官网|订阅地址|节点来源)[:：\s]*\S*', '', decoded_name, flags=re.IGNORECASE).strip()
    # 移除可能存在的其他广告或水印
    decoded_name = re.sub(r'@[a-zA-Z0-9_-]+', '', decoded_name).strip() # 例如 @YouTube
    decoded_name = re.sub(r'由\s*@\s*\S+\s*提供', '', decoded_name).strip() # 例如 由 @xxx 提供
    decoded_name = re.sub(r'tg[@_]\S+', '', decoded_name, flags=re.IGNORECASE).strip() # 例如 tg@xxx
    decoded_name = re.sub(r'[\s]*\S+_\s*Official', '', decoded_name, flags=re.IGNORECASE).strip() # 例如 xxx_Official

    # 3. 删除各种括号及其中内容，这些通常是标签或额外信息
    decoded_name = re.sub(r'[【\[\(\{][^【\[\(\{】\]\)\}]*[】\]\)\}]', '', decoded_name).strip()
    # 删除特殊字符，可能在名称中误出现，但不应删除正常的标点符号
    decoded_name = re.sub(r'[^\w\s\-\._()#@&=+/]', '', decoded_name).strip() # 保留一些常用字符

    # 4. 去除多余空格
    cleaned_name = re.sub(r'\s+', ' ', decoded_name).strip()

    # 5. 截断过长的名称
    if len(cleaned_name) > MAX_NODE_NAME_LENGTH:
        cleaned_name = cleaned_name[:MAX_NODE_NAME_LENGTH - 3] + "..."

    return cleaned_name or "Unnamed Node" # 如果清理后为空，则使用默认名称

def _generate_node_fingerprint(node):
    """
    生成节点的唯一指纹，用于去重。
    考虑 Clash 字典和 URL 字符串两种形式。
    """
    if isinstance(node, dict):
        # Clash 字典形式
        unique_parts = []
        for key in ['type', 'server', 'port', 'uuid', 'password', 'cipher', 'network', 'tls', 'udp', 'path', 'host', 'sni']:
            if key in node:
                unique_parts.append(str(node[key]))
        return "#".join(unique_parts)
    elif isinstance(node, str):
        # URL 字符串形式
        try:
            parsed_url = urlparse(node)
            # 对 URL 进行标准化，去除 fragments (name) 和 query parameters (extra config)
            # 仅保留协议、用户名、密码、主机、端口和路径
            standardized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            return standardized_url
        except Exception:
            return node # 如果解析失败，直接用原始字符串作为指纹
    return str(node) # 兜底

# --- Clash Proxy Parsers ---

def _parse_vmess(url_str):
    """解析 Vmess URL 为 Clash 代理字典。"""
    try:
        # Vmess URL 的格式是 vmess://base64encoded_json
        if not url_str.startswith("vmess://"):
            return None
        encoded_data = url_str[len("vmess://"):]
        decoded_json = _safe_base64_decode(encoded_data)
        vmess_data = json.loads(decoded_json)

        node = {
            'name': _clean_node_name(vmess_data.get('ps', 'Unnamed Vmess Node')),
            'type': 'vmess',
            'server': vmess_data.get('add'),
            'port': int(vmess_data.get('port')),
            'uuid': vmess_data.get('id'),
            'alterId': int(vmess_data.get('aid', 0)),
            'cipher': vmess_data.get('scy', 'auto'), # scy for security, fallback to 'auto'
            'network': vmess_data.get('net', 'tcp'),
            'tls': vmess_data.get('tls', '') == 'tls',
            'skip-cert-verify': vmess_data.get('allowInsecure', '0') == '1',
            'udp': True # Vmess 默认支持 UDP
        }

        if node['network'] == 'ws':
            node['ws-opts'] = {
                'path': vmess_data.get('path', '/'),
                'headers': {'Host': vmess_data.get('host', node['server'])}
            }
        elif node['network'] == 'grpc':
            node['grpc-opts'] = {
                'serviceName': vmess_data.get('path', ''), # Vmess grpc path is serviceName
                'overrideAuthority': vmess_data.get('host', '') # Vmess grpc host is authority
            }
        
        if node['tls'] and vmess_data.get('sni'):
            node['servername'] = vmess_data['sni']
        elif node['tls']:
             # Fallback to host or server if sni is not explicitly provided for TLS
            node['servername'] = vmess_data.get('host', node['server'])


        # Remove null or empty options if they don't apply to the network type
        if node['network'] != 'ws':
            node.pop('ws-opts', None)
        if node['network'] != 'grpc':
            node.pop('grpc-opts', None)
        if not node.get('tls'):
            node.pop('servername', None)
            node.pop('skip-cert-verify', None)

        return node
    except Exception as e:
        log_error(f"Failed to parse Vmess URL '{url_str[:50]}...': {e}")
        return None

def _parse_ss(url_str):
    """解析 ShadowSocks URL 为 Clash 代理字典。"""
    try:
        if not url_str.startswith("ss://"):
            return None

        # SS URL 格式: ss://[base64-encoded-userinfo@]server:port[#name]
        parts = url_str[len("ss://"):].split('#', 1)
        # 获取名称，并进行解码
        name = _clean_node_name(unquote(parts[1])) if len(parts) > 1 else 'Unnamed SS Node'
        core_part = parts[0]

        # 分离用户认证信息 (如果有) 和服务器信息
        user_info_raw = None
        server_port_part = core_part
        if '@' in core_part:
            user_info_raw, server_port_part = core_part.split('@', 1)

        cipher = "auto"
        password = ""
        if user_info_raw:
            try:
                decoded_user_info = _safe_base64_decode(user_info_raw)
                cipher, password = decoded_user_info.split(':', 1)
            except Exception as e:
                # Fallback if userinfo is not base64 or malformed
                # Some SS links have non-base64 userinfo (e.g., direct cipher:password)
                if ':' in user_info_raw:
                    cipher, password = user_info_raw.split(':', 1)
                else:
                    log_error(f"Could not decode SS user info for '{url_str[:50]}...': {e}")
                    return None # Invalid user info, skip
        
        server, port_str = server_port_part.rsplit(':', 1)
        port = int(port_str)

        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': cipher,
            'password': password,
            'udp': True # SS 默认支持 UDP
        }
    except Exception as e:
        log_error(f"Failed to parse SS URL '{url_str[:50]}...': {e}")
        return None

def _parse_trojan(url_str):
    """解析 Trojan URL 为 Clash 代理字典。"""
    try:
        if not url_str.startswith("trojan://"):
            return None

        # Trojan URL 格式: trojan://password@server:port[?params][#name]
        parts = url_str[len("trojan://"):].split('#', 1)
        name = _clean_node_name(unquote(parts[1])) if len(parts) > 1 else 'Unnamed Trojan Node'
        
        main_part = parts[0]
        password_server_part, params_str = main_part.split('?', 1) if '?' in main_part else (main_part, '')

        password, server_port_part = password_server_part.split('@', 1)
        server, port_str = server_port_part.rsplit(':', 1)
        port = int(port_str)

        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value

        node = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'network': params.get('type', 'tcp'), # Clash uses 'network' not 'type' for this
            'tls': True, # Trojan inherently uses TLS
            'skip-cert-verify': params.get('allowInsecure', '0') == '1',
            'udp': True # Trojan 默认支持 UDP
        }
        if 'sni' in params:
            node['sni'] = params['sni']
        elif 'host' in params: # Fallback to host if sni not present, though sni is more common for trojan
             node['sni'] = params['host']
        else: # If neither sni nor host, use server as sni
            node['sni'] = server

        if node['network'] == 'ws':
            node['ws-opts'] = {
                'path': params.get('path', '/'),
                'headers': {'Host': params.get('host', node['server'])}
            }
        elif node['network'] == 'grpc':
            node['grpc-opts'] = {
                'serviceName': params.get('serviceName', ''),
                'overrideAuthority': params.get('authority', '')
            }

        # Remove null or empty options if they don't apply to the network type
        if node['network'] != 'ws':
            node.pop('ws-opts', None)
        if node['network'] != 'grpc':
            node.pop('grpc-opts', None)
        if not node.get('tls'): # Should not happen for trojan but for robustness
            node.pop('servername', None)
            node.pop('skip-cert-verify', None)
            node.pop('sni', None) # SNI only for TLS

        return node
    except Exception as e:
        log_error(f"Failed to parse Trojan URL '{url_str[:50]}...': {e}")
        return None

def _parse_hysteria2(url_str):
    """解析 Hysteria2 URL 为 Clash 代理字典。"""
    try:
        if not url_str.startswith("hysteria2://"):
            return None
        
        # hysteria2://password@server:port?param=value#name
        parts = url_str[len("hysteria2://"):].split('#', 1)
        name = _clean_node_name(unquote(parts[1])) if len(parts) > 1 else 'Unnamed Hysteria2 Node'

        main_part = parts[0]
        password_server_part, params_str = main_part.split('?', 1) if '?' in main_part else (main_part, '')

        password, server_port_part = password_server_part.split('@', 1)
        server, port_str = server_port_part.rsplit(':', 1)
        port = int(port_str)

        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
        
        node = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'tls': True,
            'skip-cert-verify': params.get('insecure', '0') == '1',
            'udp': True # Hysteria2 supports UDP by default
        }

        # Hysteria2 specific parameters
        if 'sni' in params:
            node['sni'] = params['sni']
        else: # Default to server as sni
            node['sni'] = server

        # ALPN
        if 'alpn' in params:
            node['alpn'] = [params['alpn']]
        
        # Fast Open, Mux, Obfs, Obfs-password not directly supported by Clash Hysteria2 type,
        # but the script should handle what Clash supports.
        
        return node
    except Exception as e:
        log_error(f"Failed to parse Hysteria2 URL '{url_str[:50]}...': {e}")
        return None

# --- Main Logic Functions ---

def fetch_subscriptions(url_source, timeout):
    """
    从 URL_SOURCE 获取订阅内容。
    URL_SOURCE 可以是单个 URL 字符串或包含多个 URL 的文件路径。
    """
    urls_to_fetch = []
    if os.path.exists(url_source):
        with open(url_source, 'r', encoding='utf-8') as f:
            urls_to_fetch = [line.strip() for line in f if line.strip()]
    else:
        urls_to_fetch = [url_source]

    all_raw_data = []
    successful_urls = []
    failed_urls = []
    
    total_urls = len(urls_to_fetch)
    print(f"开始获取 {total_urls} 个订阅链接...")

    for url in tqdm(urls_to_fetch, desc="获取订阅", unit="URL"):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()  # 检查 HTTP 错误
            all_raw_data.append(response.text)
            successful_urls.append(url)
        except requests.exceptions.RequestException as e:
            log_error(f"Failed to fetch URL '{url}': {e}")
            failed_urls.append(url)
    
    # 写入成功和失败的URL
    ensure_directory_exists(SUCCESSFUL_URLS_FILE)
    with open(SUCCESSFUL_URLS_FILE, 'w', encoding='utf-8') as f:
        for u in successful_urls:
            f.write(u + '\n')
    ensure_directory_exists(FAILED_URLS_FILE)
    with open(FAILED_URLS_FILE, 'w', encoding='utf-8') as f:
        for u in failed_urls:
            f.write(u + '\n')

    return all_raw_data, successful_urls, failed_urls

def parse_nodes_from_data(raw_data):
    """
    解析原始订阅数据，尝试识别 Clash YAML 或 Base64 编码的 URL 列表。
    返回所有解析出的原始节点（可能是字典或URL字符串）。
    """
    all_nodes_raw = []
    # 确保 data/ 目录存在，以便写入 YAML 文件
    ensure_directory_exists(OUTPUT_FILE)
    
    for content in tqdm(raw_data, desc="解析内容", unit="文件"):
        try:
            # 尝试作为 Clash YAML 解析
            parsed_yaml = yaml.safe_load(content)
            if isinstance(parsed_yaml, dict) and 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
                all_nodes_raw.extend(parsed_yaml['proxies'])
                continue

            # 尝试 Base64 解码，然后解析每行
            decoded_content = _safe_base64_decode(content)
            lines = decoded_content.splitlines()
            for line in lines:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    all_nodes_raw.append(stripped_line)
        except (ValueError, yaml.YAMLError, json.JSONDecodeError, UnicodeDecodeError) as e:
            log_error(f"Failed to parse content (not YAML or Base64 URLs) for some data: {e}. Content starts with: {content[:100]}")
            # 如果是 HTML，可能是 Cloudflare 挑战，直接跳过
            if "<html" in content.lower() or "cloudflare" in content.lower():
                log_error("Content appears to be HTML/Cloudflare challenge, skipping.")
                continue
            # 否则，可能是无法识别的格式，直接将其作为原始字符串添加，留待后续处理
            all_nodes_raw.append(content) # Fallback: add raw content for potential other parsers (though unlikely)
    return all_nodes_raw

def deduplicate_and_standardize_nodes(all_parsed_nodes_raw):
    """
    去重并标准化所有节点为 Clash 字典格式。
    处理各种 URL 协议和已有的 Clash 字典。
    """
    unique_clash_proxies = {} # 使用指纹作为键进行去重

    # Vmess, SS, Trojan, Hysteria2 等 URL 解析器映射
    url_parsers = {
        'vmess': _parse_vmess,
        'ss': _parse_ss,
        'trojan': _parse_trojan,
        'hysteria2': _parse_hysteria2,
        # 可以根据需要添加其他协议的解析器
    }

    for node_raw in tqdm(all_parsed_nodes_raw, desc="标准化节点", unit="节点"):
        clash_proxy = None

        if isinstance(node_raw, dict):
            # 已经是 Clash 字典格式，进行清理和标准化名称
            if 'name' in node_raw:
                node_raw['name'] = _clean_node_name(node_raw['name'])
            else:
                node_raw['name'] = _clean_node_name(f"{node_raw.get('type', 'unknown')}-{node_raw.get('server', 'unknown')}")
            clash_proxy = node_raw
        elif isinstance(node_raw, str):
            # 尝试解析 URL 字符串
            try:
                parsed_url = urlparse(node_raw)
            except (ValueError, TypeError) as e:
                # 捕获 ValueError (如 Invalid IPv6 URL) 和 TypeError (如果 node 不是字符串)
                log_error(f"Skipping invalid URL/node format '{node_raw[:50]}...': {e}")
                continue  # 跳过当前无效节点，继续处理下一个

            scheme = parsed_url.scheme
            if scheme in url_parsers:
                clash_proxy = url_parsers[scheme](node_raw)
            else:
                log_error(f"Unsupported URL scheme '{scheme}' for node: {node_raw[:50]}...")
        else:
            log_error(f"Unsupported node type: {type(node_raw)} for node: {node_raw}")

        if clash_proxy:
            fingerprint = _generate_node_fingerprint(clash_proxy)
            if fingerprint not in unique_clash_proxies:
                unique_clash_proxies[fingerprint] = clash_proxy
            else:
                # 如果名称更干净或更具体，可以更新
                existing_name = unique_clash_proxies[fingerprint].get('name')
                new_name = clash_proxy.get('name')
                if new_name and (not existing_name or len(new_name) < len(existing_name)):
                    unique_clash_proxies[fingerprint]['name'] = new_name


    return list(unique_clash_proxies.values())

def save_clash_config(proxies, output_file, max_success_nodes):
    """将处理后的代理节点保存为 Clash YAML 格式。"""
    
    # 限制保存的节点数量
    proxies_to_save = proxies[:max_success_nodes]

    clash_config = {
        'proxies': proxies_to_save,
        # 可以添加其他 Clash 配置，例如 proxy-groups, rules 等
        # 'proxy-groups': [...],
        # 'rules': [...]
    }
    
    ensure_directory_exists(output_file)
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"成功保存 {len(proxies_to_save)} 个节点到 {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Fetch and process proxy subscriptions for Clash.")
    parser.add_argument('--output', type=str, default=OUTPUT_FILE,
                        help=f"Output Clash YAML file path. Default: {OUTPUT_FILE}")
    parser.add_argument('--url_source', type=str,
                        help="URL of the subscription, or path to a file containing multiple URLs. "
                             "Defaults to environment variable URL_SOURCE if not provided.")
    parser.add_argument('--timeout', type=int, default=60,
                        help="Timeout for fetching subscriptions in seconds. Default: 60.")
    parser.add_argument('--max_success', type=int, default=99999,
                        help="Maximum number of successful nodes to include in the output. Default: 99999.")

    args = parser.parse_args()

    # 获取 URL_SOURCE，优先使用命令行参数，其次是环境变量
    url_source = args.url_source or os.getenv('URL_SOURCE')
    if not url_source:
        print("Error: No URL source provided. Use --url_source or set URL_SOURCE environment variable.", file=sys.stderr)
        sys.exit(1)

    print(f"开始从源 '{url_source}' 获取代理节点...")

    # 1. 获取订阅内容
    raw_data, successful_urls, failed_urls = fetch_subscriptions(url_source, args.timeout)
    print(f"成功获取 {len(successful_urls)} 个 URL，失败 {len(failed_urls)} 个 URL。")

    # 2. 解析原始数据中的节点
    all_parsed_nodes_raw = parse_nodes_from_data(raw_data)
    print(f"原始数据中解析出 {len(all_parsed_nodes_raw)} 个节点（去重前）。")

    # 3. 去重并标准化节点
    final_unique_clash_proxies = deduplicate_and_standardize_nodes(all_parsed_nodes_raw)
    print(f"去重和标准化后，得到 {len(final_unique_clash_proxies)} 个唯一节点。")

    # 4. 保存为 Clash YAML 格式
    save_clash_config(final_unique_clash_proxies, args.output, args.max_success)
    print("脚本运行完毕。")

    # 记录 URL 统计信息
    with open(URL_STATISTICS_FILE, 'w', encoding='utf-8') as f:
        f.write("Status,URL\n")
        for u in successful_urls:
            f.write(f"Success,{u}\n")
        for u in failed_urls:
            f.write(f"Failed,{u}\n")

if __name__ == "__main__":
    main()
