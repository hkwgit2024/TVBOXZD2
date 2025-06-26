import requests
import base64
import re
import os
import urllib.parse
import json
import logging
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Tuple
import hashlib

# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 配置 ---
CONFIG = {
    "NODE_URLS": [
        "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
    ],
    "OUTPUT_FILE": "data/sub.txt",
    "DOWNLOAD_TIMEOUT": 60,
    "MAX_WORKERS": 5  # 并行下载线程数
}

# --- 数据结构 ---
ParsedNode = namedtuple(
    'ParsedNode',
    ['protocol', 'address', 'port', 'user_id', 'password', 'encryption', 'name',
     'remark', 'network', 'tls', 'sni', 'obfs', 'raw_link']
)

# --- 辅助函数 ---
def decode_base64_url(data: str) -> Optional[str]:
    """解码 URL-safe Base64 字符串，处理填充并增强容错性。"""
    data = data.strip().replace(' ', '').replace('\n', '').replace('\r', '')
    if not re.fullmatch(r'^[a-zA-Z0-9+/=\-_]+$', data):
        return None
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError):
        return None

# --- 协议解析器 ---
def parse_vmess(node_string: str, parsed_url: urllib.parse.ParseResult) -> Optional[ParsedNode]:
    """解析 VMess 协议链接。"""
    vmess_data_encoded = parsed_url.netloc + parsed_url.path.lstrip('/')
    decoded_json_str = decode_base64_url(vmess_data_encoded)
    if not decoded_json_str:
        logger.debug(f"VMess base64 decode failed: {node_string[:100]}...")
        return None
    try:
        vmess_config = json.loads(decoded_json_str)
        return ParsedNode(
            protocol="vmess",
            address=vmess_config.get('add'),
            port=vmess_config.get('port'),
            user_id=vmess_config.get('id'),
            password=None,
            encryption=vmess_config.get('scy'),
            name=vmess_config.get('ps') or urllib.parse.unquote(parsed_url.fragment),
            remark=vmess_config.get('ps'),
            network=vmess_config.get('net'),
            tls='tls' if vmess_config.get('tls') == 'tls' else None,
            sni=vmess_config.get('host'),
            obfs=None,
            raw_link=node_string
        )
    except json.JSONDecodeError:
        logger.debug(f"VMess JSON decode error: {decoded_json_str[:100]}...")
        return None

def parse_vless(node_string: str, parsed_url: urllib.parse.ParseResult) -> Optional[ParsedNode]:
    """解析 VLESS 协议链接。"""
    auth_addr_port_str = parsed_url.netloc
    query_params = urllib.parse.parse_qs(parsed_url.query)
    user_id = None
    address = None
    port = None

    if '@' in auth_addr_port_str:
        user_id, addr_port_str = auth_addr_port_str.split('@', 1)
    else:
        addr_port_str = auth_addr_port_str
        user_id = query_params.get('uuid', [None])[0]
        if not user_id:
            logger.debug(f"VLESS missing UUID: {node_string[:100]}...")
            return None

    if ':' in addr_port_str:
        address, port_str = addr_port_str.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            logger.debug(f"VLESS invalid port '{port_str}': {node_string[:100]}...")
            return None
    else:
        address = addr_port_str
        logger.debug(f"VLESS missing port: {node_string[:100]}...")
        return None

    return ParsedNode(
        protocol="vless",
        address=address,
        port=port,
        user_id=user_id,
        password=None,
        encryption=None,
        name=urllib.parse.unquote(parsed_url.fragment),
        remark=None,
        network=query_params.get('type', [None])[0],
        tls=query_params.get('security', [None])[0],
        sni=query_params.get('sni', [None])[0],
        obfs=None,
        raw_link=node_string
    )

def parse_trojan(node_string: str, parsed_url: urllib.parse.ParseResult) -> Optional[ParsedNode]:
    """解析 Trojan 协议链接。"""
    full_auth_addr_port_str = parsed_url.netloc + parsed_url.path
    query_params = urllib.parse.parse_qs(parsed_url.query)
    password = None
    address = None
    port = None

    if '@' in full_auth_addr_port_str:
        password, addr_port_str = full_auth_addr_port_str.split('@', 1)
    else:
        addr_port_str = full_auth_addr_port_str
        logger.debug(f"Trojan missing password: {node_string[:100]}...")
        return None

    if ':' in addr_port_str:
        address, port_str = addr_port_str.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            logger.debug(f"Trojan invalid port '{port_str}': {node_string[:100]}...")
            return None
    else:
        address = addr_port_str
        logger.debug(f"Trojan missing port: {node_string[:100]}...")
        return None

    return ParsedNode(
        protocol="trojan",
        address=address,
        port=port,
        user_id=None,
        password=password,
        encryption=None,
        name=urllib.parse.unquote(parsed_url.fragment),
        remark=None,
        network=None,
        tls=query_params.get('security', [None])[0],
        sni=query_params.get('sni', [None])[0],
        obfs=None,
        raw_link=node_string
    )

def parse_ss(node_string: str, parsed_url: urllib.parse.ParseResult) -> Optional[ParsedNode]:
    """解析 Shadowsocks (SS) 协议链接。"""
    auth_part_raw = parsed_url.netloc
    decoded_auth_part = decode_base64_url(auth_part_raw)
    auth_info = decoded_auth_part if decoded_auth_part else auth_part_raw
    encryption = None
    password = None
    address = parsed_url.hostname
    port = parsed_url.port

    if ':' in auth_info:
        encryption, password = auth_info.split(':', 1)
    else:
        logger.debug(f"SS malformed auth: '{auth_info}': {node_string[:100]}...")
        return None

    if not port and parsed_url.path.strip('/'):
        addr_port_path = parsed_url.path.strip('/')
        if ':' in addr_port_path:
            try:
                path_address, path_port_str = addr_port_path.rsplit(':', 1)
                if not address:
                    address = path_address
                port = int(path_port_str)
            except ValueError:
                logger.debug(f"SS invalid port in path: '{addr_port_path}': {node_string[:100]}...")
                return None
        else:
            if not address:
                address = addr_port_path
                logger.debug(f"SS missing port in path: {node_string[:100]}...")
                return None

    if not address:
        logger.debug(f"SS missing address: {node_string[:100]}...")
        return None

    return ParsedNode(
        protocol="ss",
        address=address,
        port=port,
        user_id=None,
        password=password,
        encryption=encryption,
        name=urllib.parse.unquote(parsed_url.fragment),
        remark=None,
        network=None,
        tls=None,
        sni=None,
        obfs=None,
        raw_link=node_string
    )

def parse_ssr(node_string: str, parsed_url: urllib.parse.ParseResult) -> Optional[ParsedNode]:
    """解析 ShadowsocksR (SSR) 协议链接。"""
    ssr_data_encoded = parsed_url.netloc + parsed_url.path.lstrip('/')
    decoded_ssr_params = decode_base64_url(ssr_data_encoded)
    if not decoded_ssr_params:
        logger.debug(f"SSR base64 decode failed: {node_string[:100]}...")
        return None

    try:
        parts = decoded_ssr_params.split(':')
        if len(parts) < 5:
            logger.debug(f"SSR malformed params: '{decoded_ssr_params[:100]}': {node_string[:100]}...")
            return None

        address = parts[0]
        port = int(parts[1])
        encryption = parts[3]
        obfs = parts[4]
        password = None
        if len(parts) >= 6:
            password_base64_part = parts[5].split('/')[0]
            password = decode_base64_url(password_base64_part) if password_base64_part else None

        return ParsedNode(
            protocol="ssr",
            address=address,
            port=port,
            user_id=None,
            password=password,
            encryption=encryption,
            name=urllib.parse.unquote(parsed_url.fragment),
            remark=None,
            network=None,
            tls=None,
            sni=None,
            obfs=obfs,
            raw_link=node_string
        )
    except (ValueError, IndexError) as e:
        logger.debug(f"SSR parse error '{e}': '{decoded_ssr_params[:100]}': {node_string[:100]}...")
        return None

def parse_hysteria2(node_string: str, parsed_url: urllib.parse.ParseResult) -> Optional[ParsedNode]:
    """解析 Hysteria2 协议链接。"""
    full_auth_addr_port_str = parsed_url.netloc + parsed_url.path
    query_params = urllib.parse.parse_qs(parsed_url.query)
    password = None
    address = None
    port = None

    if '@' in full_auth_addr_port_str:
        password, addr_port_str = full_auth_addr_port_str.split('@', 1)
    else:
        addr_port_str = full_auth_addr_port_str
        logger.debug(f"Hysteria2 missing password: {node_string[:100]}...")
        return None

    if ':' in addr_port_str:
        address, port_str = addr_port_str.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            logger.debug(f"Hysteria2 invalid port '{port_str}': {node_string[:100]}...")
            return None
    else:
        address = addr_port_str
        logger.debug(f"Hysteria2 missing port: {node_string[:100]}...")
        return None

    return ParsedNode(
        protocol="hysteria2",
        address=address,
        port=port,
        user_id=None,
        password=password,
        encryption=None,
        name=urllib.parse.unquote(parsed_url.fragment),
        remark=None,
        network=None,
        tls=None,
        sni=query_params.get('sni', [None])[0],
        obfs=query_params.get('obfs', [None])[0],
        raw_link=node_string
    )

# 协议解析器注册
PROTOCOL_PARSERS = {
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "ssr": parse_ssr,
    "hysteria2": parse_hysteria2
}

def parse_node(node_string: str) -> Optional[ParsedNode]:
    """解析代理协议链接，调用特定协议的解析器。"""
    node_string = node_string.strip()
    if not node_string:
        return None

    try:
        parsed_url = urllib.parse.urlparse(node_string)
        protocol = parsed_url.scheme.lower()
        if protocol not in PROTOCOL_PARSERS:
            logger.debug(f"Unsupported protocol '{protocol}': {node_string[:100]}...")
            return None

        parsed_node = PROTOCOL_PARSERS[protocol](node_string, parsed_url)
        if parsed_node and parsed_node.address and parsed_node.port and 0 < parsed_node.port <= 65535:
            return parsed_node
        logger.debug(f"Missing essential info (address/port): {node_string[:100]}...")
        return None
    except Exception as e:
        logger.error(f"Error parsing node '{node_string[:100]}...': {e}")
        return None

# --- 下载函数 ---
def download_nodes(url: str) -> List[Tuple[str, Optional[str]]]:
    """下载并返回节点行列表。"""
    logger.info(f"Downloading from: {url}")
    try:
        response = requests.get(url, stream=True, timeout=CONFIG["DOWNLOAD_TIMEOUT"])
        response.raise_for_status()
        nodes = []
        for line_bytes in response.iter_lines(chunk_size=8192):
            if line_bytes:
                node_entry = line_bytes.decode('utf-8', errors='ignore').strip()
                if node_entry:
                    decoded = decode_base64_url(node_entry) if re.fullmatch(r'^[a-zA-Z0-9+/=\-_]+$', node_entry) else None
                    nodes.append((node_entry, decoded))
        logger.info(f"Downloaded {len(nodes)} lines from {url}")
        return nodes
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error downloading from {url}: {e}")
        return []

# --- 主逻辑 ---
def main():
    logger.info(f"Starting node processing. Downloading from {len(CONFIG['NODE_URLS'])} sources.")

    # 确保输出目录存在
    output_dir = os.path.dirname(CONFIG["OUTPUT_FILE"])
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    unique_nodes = set()
    processed_links = []
    stats = {"raw_lines": 0, "parsed_nodes": 0, "duplicates": 0, "malformed": 0}

    # 并行下载
    with ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        node_lists = executor.map(download_nodes, CONFIG["NODE_URLS"])

    # 处理节点
    for nodes in node_lists:
        for node_entry, decoded_entry in nodes:
            stats["raw_lines"] += 1
            node_string = decoded_entry or node_entry
            parsed_node = parse_node(node_string)
            if not parsed_node:
                stats["malformed"] += 1
                continue

            # 使用哈希生成唯一键
            node_key = hashlib.sha256(
                "|".join(filter(None, [
                    parsed_node.protocol, parsed_node.address, str(parsed_node.port),
                    parsed_node.user_id, parsed_node.password, parsed_node.encryption,
                    parsed_node.obfs, parsed_node.network, parsed_node.tls, parsed_node.sni
                ])).encode()).hexdigest()

            if node_key not in unique_nodes:
                unique_nodes.add(node_key)
                processed_links.append(parsed_node.raw_link)
                stats["parsed_nodes"] += 1
            else:
                stats["duplicates"] += 1

    # 写入文件
    processed_links.sort()
    try:
        with open(CONFIG["OUTPUT_FILE"], "w", encoding='utf-8') as f:
            f.write("\n".join(processed_links) + "\n")
        logger.info(f"Saved {stats['parsed_nodes']} unique nodes to {CONFIG['OUTPUT_FILE']}")
        logger.info(f"Summary: Raw lines: {stats['raw_lines']}, Parsed: {stats['parsed_nodes']}, "
                   f"Duplicates: {stats['duplicates']}, Malformed: {stats['malformed']}")
    except IOError as e:
        logger.critical(f"Error writing to {CONFIG['OUTPUT_FILE']}: {e}")

if __name__ == "__main__":
    main()
