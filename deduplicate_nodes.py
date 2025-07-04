import requests
import os
import re
import datetime
import urllib.parse
import logging
import base64
import json
import socket
import platform
import subprocess
from urllib.parse import parse_qs
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import argparse

# 配置日志
def setup_logging(debug: bool):
    """根据调试模式配置日志级别"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('node_deduplication.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

class NodeStandardizer:
    """节点标准化器，负责解析和标准化不同协议的节点URL"""
    
    @staticmethod
    def clean_node_url(node_url: str) -> str:
        """清理节点URL，移除不可见字符、多余空格和编码问题"""
        if not node_url:
            return ""
        # 移除控制字符、空格、制表符、换行符等
        node_url = re.sub(r'[\x00-\x1F\x7F\x80-\x9F\s]+', '', node_url).strip().rstrip('/')
        # 多次解码可能的双重URL编码
        for _ in range(3):
            try:
                decoded = urllib.parse.unquote(node_url, errors='ignore')
                if decoded == node_url:
                    break
                node_url = decoded
            except Exception:
                break
        return node_url

    @staticmethod
    def standardize_node_minimal(node_url: str, debug: bool = False) -> tuple[str | None, str, str | None, str | None]:
        """
        标准化节点URL，提取核心信息用于去重，并保留原始节点和主机名/IP。
        返回 (标准化后的节点字符串, 协议类型, 原始节点, 主机名/IP)。
        """
        if not node_url:
            return None, "unknown", None, None

        node_url_cleaned = NodeStandardizer.clean_node_url(node_url)
        match = re.match(r"^(?P<protocol>hysteria2|vmess|trojan|ss|ssr|vless)://(?P<data>.*)", 
                         node_url_cleaned, re.IGNORECASE)
        if not match:
            if debug:
                logging.debug(f"不支持的协议或格式错误: {node_url}")
            return None, "unknown", None, None

        protocol = match.group("protocol").lower()
        data_part = match.group("data")
        host = None

        try:
            core_data = data_part.split('?', 1)[0].split('#', 1)[0]
            core_data_standardized = urllib.parse.unquote_plus(core_data).strip()

            if protocol in ("vmess", "vless"):
                result, host = NodeStandardizer._standardize_vmess_vless(protocol, core_data_standardized, data_part)
            elif protocol in ("trojan", "hysteria2"):
                result, host = NodeStandardizer._standardize_trojan_hysteria2(protocol, core_data_standardized)
            elif protocol == "ss":
                result, host = NodeStandardizer._standardize_ss(core_data_standardized)
            elif protocol == "ssr":
                result, host = NodeStandardizer._standardize_ssr(core_data_standardized)
            else:
                result = None

            if result and debug:
                logging.debug(f"去重键: {result} (原始: {node_url})")
            return result, protocol, node_url, host

        except Exception as e:
            logging.error(f"标准化节点 {node_url} 时发生错误: {e}")
            return None, "unknown", None, None

    @staticmethod
    def _standardize_vmess_vless(protocol: str, core_data: str, full_data: str) -> tuple[str | None, str | None]:
        """处理vmess和vless协议"""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            return None, None
        uuid, address_port = parts
        address = None
        if protocol == "vmess":
            try:
                # 尝试base64解码
                decoded = json.loads(base64.b64decode(uuid + '=' * (-len(uuid) % 4)).decode('utf-8', errors='ignore'))
                uuid = decoded.get('id', '').lower()
                address = decoded.get('add', '').lower()
                port = decoded.get('port', '')
                if NodeStandardizer.is_valid_port(str(port)):
                    return f"{protocol}://{uuid}@{address}:{port}", address
                return None, None
            except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
                # 后备方案：尝试直接解析
                address_parts = address_port.rsplit(':', 1)
                if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
                    address = address_parts[0].lower()
                    return f"{protocol}://{uuid.lower()}@{address_port.lower()}", address
                return None, None
        elif protocol == "vless":
            query = full_data.split('?', 1)[1].split('#', 1)[0] if '?' in full_data else ''
            params = parse_qs(query)
            encryption = params.get('encryption', ['none'])[0].lower()
            transport = params.get('type', ['tcp'])[0].lower()
            security = params.get('security', ['none'])[0].lower()
            flow = params.get('flow', [''])[0].lower()
            sni = params.get('sni', [''])[0].lower()
            fp = params.get('fp', [''])[0].lower()
            address_parts = address_port.rsplit(':', 1)
            if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
                address = address_parts[0].lower()
                return f"{protocol}://{uuid.lower()}@{address_port.lower()}?encryption={encryption}&type={transport}&security={security}&flow={flow}&sni={sni}&fp={fp}", address
            return None, None
        return None, None

    @staticmethod
    def _standardize_trojan_hysteria2(protocol: str, core_data: str) -> tuple[str | None, str | None]:
        """处理trojan和hysteria2协议"""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            return None, None
        password, address_port = parts
        address_parts = address_port.rsplit(':', 1)
        if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
            address = address_parts[0].lower()
            return f"{protocol}://{urllib.parse.quote(password, safe='')}@{address_port.lower()}", address
        return None, None

    @staticmethod
    def _standardize_ss(core_data: str) -> tuple[str | None, str | None]:
        """处理ss协议"""
        if '@' not in core_data or ':' not in core_data.split('@')[0]:
            return None, None
        try:
            auth_info, server_info = core_data.split('@', 1)
            method, password = auth_info.split(':', 1)
            host, port = server_info.rsplit(':', 1)
            if NodeStandardizer.is_valid_port(port):
                return f"ss://{method.lower()}:{urllib.parse.quote(password, safe='')}@{host.lower()}:{port}", host.lower()
            return None, None
        except ValueError:
            logging.debug(f"无法解析SS核心格式: {core_data}")
            return None, None

    @staticmethod
    def _standardize_ssr(core_data: str) -> tuple[str | None, str | None]:
        """处理ssr协议"""
        parts = core_data.split(':')
        if len(parts) < 6:
            return None, None
        try:
            host, port, proto, method, obfs, password = parts[:6]
            password = urllib.parse.unquote_plus(password)
            if NodeStandardizer.is_valid_port(port):
                return f"ssr://{host.lower()}:{port}:{proto.lower()}:{method.lower()}:{obfs.lower()}:{urllib.parse.quote(password, safe='')}", host.lower()
            return None, None
        except ValueError:
            logging.debug(f"无法解析SSR核心格式: {core_data}")
            return None, None

    @staticmethod
    def is_valid_port(port: str) -> bool:
        """验证端口号是否有效"""
        try:
            return 0 < int(port) <= 65535
        except ValueError:
            return False

class NodePinger:
    """节点Ping工具，用于检测节点的连通性"""
    
    @staticmethod
    def ping_host(host: str, count: int = 1, timeout: int = 5) -> bool:
        """
        Ping给定的主机名或IP地址。
        
        Args:
            host (str): 要ping的主机名或IP地址。
            count (int): Ping的次数。
            timeout (int): 每个Ping请求的超时时间（秒）。
            
        Returns:
            bool: 如果至少一次Ping成功则返回True，否则返回False。
        """
        try:
            # 尝试解析域名到IP地址
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            logging.debug(f"无法解析主机名: {host}")
            return False

        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W' # -w for windows in ms, -W for linux in seconds

        try:
            command = ['ping', param, str(count), timeout_param, str(timeout), ip_address]
            process = subprocess.run(command, capture_output=True, text=True, timeout=timeout * count + 2) # 增加一些缓冲时间
            
            if process.returncode == 0:
                logging.debug(f"Ping {host} ({ip_address}) 成功。")
                return True
            else:
                logging.debug(f"Ping {host} ({ip_address}) 失败。错误码: {process.returncode}, 输出: {process.stdout.strip()} {process.stderr.strip()}")
                return False
        except subprocess.TimeoutExpired:
            logging.debug(f"Ping {host} ({ip_address}) 超时。")
            return False
        except Exception as e:
            logging.error(f"Ping {host} ({ip_address}) 时发生错误: {e}")
            return False

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), 
        retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url(url: str) -> requests.Response:
    """带重试机制的URL请求"""
    with requests.Session() as session:
        response = session.get(url, timeout=20, stream=True)
        response.raise_for_status()
        return response

def write_protocol_outputs(nodes: dict, output_dir: str) -> dict:
    """将去重后的节点按协议写入文件，并写入单一文件，返回每个文件的节点数"""
    os.makedirs(output_dir, exist_ok=True)
    protocol_counts = {}
    all_nodes = []

    # 按协议分组写入
    for protocol, node_list in nodes.items():
        if node_list:
            output_file = os.path.join(output_dir, f"{protocol}.txt")
            sorted_nodes = sorted(node_list)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_nodes) + '\n')
            protocol_counts[output_file] = len(sorted_nodes)
            logging.info(f"写入协议文件: {output_file} ({len(sorted_nodes)} 个节点)")
            all_nodes.extend(sorted_nodes)

    # 写入单一文件
    output_all_file = os.path.join(output_dir, 'all.txt')
    with open(output_all_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(all_nodes)) + '\n')
    protocol_counts[output_all_file] = len(all_nodes)
    logging.info(f"写入单一文件: {output_all_file} ({len(all_nodes)} 个节点)")

    return protocol_counts

def download_and_deduplicate_nodes(args):
    """从GitHub Raw链接下载节点数据，标准化并去重后按协议保存，并进行Ping测试"""
    setup_logging(args.debug)
    node_url = args.node_url
    output_dir = args.output_dir
    
    unique_nodes = {}  # 按协议存储原始节点 {protocol: [node1, node2, ...]}
    unique_keys = set()  # 去重键集合
    ping_successful_nodes = [] # Ping成功的节点
    ping_failed_nodes = [] # Ping失败的节点
    
    stats = {
        'download_count': 0,
        'total_nodes_processed': 0,
        'failed_to_standardize_count': 0,
        'invalid_format_count': 0,
        'duplicate_count': 0,
        'protocol_counts': {},
        'output_file_counts': {},
        'ping_success_count': 0,
        'ping_fail_count': 0,
    }
    
    logging.info("--- 开始下载和去重节点 ---")
    start_time = datetime.datetime.now()

    try:
        logging.info(f"正在下载: {node_url}")
        response = fetch_url(node_url)
        stats['download_count'] += 1
        
        nodes_to_ping = [] # 存储 (原始节点, 主机名/IP) 元组

        for line in response.iter_lines(decode_unicode=True):
            node = line.strip()
            if not node:
                continue
            
            stats['total_nodes_processed'] += 1
            minimal_node, protocol, original_node, host = NodeStandardizer.standardize_node_minimal(node, args.debug)
            
            if minimal_node and original_node:
                if minimal_node in unique_keys:
                    stats['duplicate_count'] += 1
                    if args.debug:
                        logging.debug(f"发现重复节点: {minimal_node}")
                else:
                    unique_keys.add(minimal_node)
                    unique_nodes.setdefault(protocol, []).append(original_node)
                    stats['protocol_counts'][protocol] = stats['protocol_counts'].get(protocol, 0) + 1
                    if host: # 如果成功提取到主机名/IP，则添加到待Ping列表
                        nodes_to_ping.append((original_node, host))
            else:
                stats['failed_to_standardize_count'] += 1
                if args.debug:
                    logging.warning(f"无法标准化节点: {node}")

    except requests.exceptions.RequestException as e:
        logging.error(f"下载失败 {node_url}: {e}")
        stats['invalid_format_count'] += 1
    except Exception as e:
        logging.error(f"处理 {node_url} 时发生未知错误: {e}")
        stats['invalid_format_count'] += 1

    # 按协议和单一文件写入
    stats['output_file_counts'] = write_protocol_outputs(unique_nodes, output_dir)

    # 进行节点Ping测试
    logging.info("\n--- 开始节点连通性测试 ---")
    for original_node, host in nodes_to_ping:
        if NodePinger.ping_host(host):
            ping_successful_nodes.append(original_node)
            stats['ping_success_count'] += 1
        else:
            ping_failed_nodes.append(original_node)
            stats['ping_fail_count'] += 1
    
    # 写入Ping结果文件
    os.makedirs(output_dir, exist_ok=True)
    ping_success_file = os.path.join(output_dir, 'ping_successful_nodes.txt')
    with open(ping_success_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(ping_successful_nodes)) + '\n')
    logging.info(f"写入Ping成功节点文件: {ping_success_file} ({len(ping_successful_nodes)} 个节点)")

    ping_fail_file = os.path.join(output_dir, 'ping_failed_nodes.txt')
    with open(ping_fail_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(ping_failed_nodes)) + '\n')
    logging.info(f"写入Ping失败节点文件: {ping_fail_file} ({len(ping_failed_nodes)} 个节点)")


    end_time = datetime.datetime.now()
    duration = end_time - start_time

    # 输出运行摘要
    logging.info("\n==================== 运行摘要 ====================")
    logging.info(f"成功下载的链接数: {stats['download_count']}")
    logging.info(f"处理的节点总数: {stats['total_nodes_processed']}")
    logging.info(f"重复节点数: {stats['duplicate_count']}")
    logging.info(f"无法标准化的节点数: {stats['failed_to_standardize_count']}")
    logging.info(f"格式无效的节点数: {stats['invalid_format_count']}")
    logging.info(f"去重后的有效节点总数: {sum(stats['protocol_counts'].values())}")
    logging.info("协议分布:")
    for protocol, count in sorted(stats['protocol_counts'].items()):
        logging.info(f"  {protocol}: {count}")
    logging.info("输出文件:")
    for output_file, count in sorted(stats['output_file_counts'].items()):
        logging.info(f"  {output_file}: {count} 个节点")
    logging.info(f"Ping成功的节点数: {stats['ping_success_count']}")
    logging.info(f"Ping失败的节点数: {stats['ping_fail_count']}")
    logging.info(f"总耗时: {duration.total_seconds():.2f} 秒")
    logging.info("==============================================")

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Download, deduplicate, and ping proxy nodes.')
    parser.add_argument('--node-url', 
                        default="https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt", 
                        help='URL for the node file')
    parser.add_argument('--output-dir', default='data', help='Output directory')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    download_and_deduplicate_nodes(args)
