import requests
import os
import re
import datetime
import urllib.parse
import logging
import base64
import json
from urllib.parse import parse_qs
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import argparse

# 配置日志
logging.basicConfig(
    level=logging.INFO,
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
        """清理节点URL，移除不可见字符和多余空格"""
        return re.sub(r'[\s\r\n\t]+', '', node_url).strip().rstrip('/')

    @staticmethod
    def standardize_node_minimal(node_url: str) -> tuple[str | None, str]:
        """
        标准化节点URL，提取核心信息用于去重。
        返回 (标准化后的节点字符串, 协议类型)。
        """
        if not node_url:
            return None, "unknown"

        node_url = NodeStandardizer.clean_node_url(node_url)
        match = re.match(r"^(?P<protocol>hysteria2|vmess|trojan|ss|ssr|vless)://(?P<data>.*)", 
                        node_url, re.IGNORECASE)
        if not match:
            logging.debug(f"不支持的协议或格式错误: {node_url}")
            return None, "unknown"

        protocol = match.group("protocol").lower()
        data_part = match.group("data")
        minimal_node_parts = [f"{protocol}://"]

        try:
            core_data = data_part.split('?', 1)[0].split('#', 1)[0]
            core_data_standardized = urllib.parse.unquote_plus(core_data).strip()

            if protocol in ("vmess", "vless"):
                return NodeStandardizer._standardize_vmess_vless(protocol, core_data_standardized, data_part), protocol
            
            elif protocol in ("trojan", "hysteria2"):
                return NodeStandardizer._standardize_trojan_hysteria2(protocol, core_data_standardized), protocol
            
            elif protocol == "ss":
                return NodeStandardizer._standardize_ss(core_data_standardized), protocol
            
            elif protocol == "ssr":
                return NodeStandardizer._standardize_ssr(core_data_standardized), protocol
            
            return None, "unknown"

        except Exception as e:
            logging.error(f"标准化节点 {node_url} 时发生错误: {e}")
            return None, "unknown"

    @staticmethod
    def _standardize_vmess_vless(protocol: str, core_data: str, full_data: str) -> str | None:
        """处理vmess和vless协议"""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            return None
        uuid, address = parts
        if protocol == "vmess":
            try:
                decoded = json.loads(base64.b64decode(uuid + '=' * (-len(uuid) % 4)).decode('utf-8'))
                uuid = decoded.get('id', '').lower()
                address = f"{decoded.get('add', '').lower()}:{decoded.get('port', '')}"
            except (base64.binascii.Error, json.JSONDecodeError):
                pass
        elif protocol == "vless":
            query = full_data.split('?', 1)[1].split('#', 1)[0] if '?' in full_data else ''
            params = parse_qs(query)
            encryption = params.get('encryption', ['none'])[0].lower()
            transport = params.get('type', ['tcp'])[0].lower()
            address_parts = address.rsplit(':', 1)
            if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
                return f"{protocol}://{uuid.lower()}@{address.lower()}?encryption={encryption}&type={transport}"
            return None
        address_parts = address.rsplit(':', 1)
        if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
            return f"{protocol}://{uuid.lower()}@{address.lower()}"
        return None

    @staticmethod
    def _standardize_trojan_hysteria2(protocol: str, core_data: str) -> str | None:
        """处理trojan和hysteria2协议"""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            return None
        password, address = parts
        address_parts = address.rsplit(':', 1)
        if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
            return f"{protocol}://{password}@{address.lower()}"
        return None

    @staticmethod
    def _standardize_ss(core_data: str) -> str | None:
        """处理ss协议"""
        if '@' not in core_data or ':' not in core_data.split('@')[0]:
            return None
        try:
            auth_info, server_info = core_data.split('@', 1)
            method, password = auth_info.split(':', 1)
            host, port = server_info.rsplit(':', 1)
            if NodeStandardizer.is_valid_port(port):
                return f"ss://{method.lower()}:{password}@{host.lower()}:{port}"
            return None
        except ValueError:
            logging.debug(f"无法解析SS核心格式: {core_data}")
            return None

    @staticmethod
    def _standardize_ssr(core_data: str) -> str | None:
        """处理ssr协议"""
        parts = core_data.split(':')
        if len(parts) < 6:
            return None
        try:
            host, port, proto, method, obfs, password = parts[:6]
            password = urllib.parse.unquote_plus(password)
            if NodeStandardizer.is_valid_port(port):
                return f"ssr://{host.lower()}:{port}:{proto.lower()}:{method.lower()}:{obfs.lower()}:{password}"
            return None
        except ValueError:
            logging.debug(f"无法解析SSR核心格式: {core_data}")
            return None

    @staticmethod
    def is_valid_port(port: str) -> bool:
        """验证端口号是否有效"""
        try:
            return 0 < int(port) <= 65535
        except ValueError:
            return False

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), 
       retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url(url: str) -> requests.Response:
    """带重试机制的URL请求"""
    with requests.Session() as session:
        response = session.get(url, timeout=20, stream=True)
        response.raise_for_status()
        return response

def download_and_deduplicate_nodes(args):
    """从GitHub Raw链接下载节点数据，标准化并去重后保存"""
    base_url = args.base_url
    start_index = args.start_index
    end_index = args.end_index
    output_dir = args.output_dir
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_dir, f'all_{timestamp}.txt')
    
    unique_nodes = set()
    stats = {
        'download_count': 0,
        'total_nodes_processed': 0,
        'failed_to_standardize_count': 0,
        'invalid_format_count': 0,
        'duplicate_count': 0,
        'protocol_counts': {}
    }
    
    logging.info("--- 开始下载和去重节点 ---")
    start_time = datetime.datetime.now()
    batch_size = 10000

    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(start_index, end_index + 1):
            file_index = str(i).zfill(3)
            url = f"{base_url}{file_index}.txt"
            
            try:
                logging.info(f"正在下载: {url}")
                response = fetch_url(url)
                stats['download_count'] += 1
                
                for line in response.iter_lines(decode_unicode=True):
                    node = line.strip()
                    if not node:
                        continue
                    
                    stats['total_nodes_processed'] += 1
                    minimal_node, protocol = NodeStandardizer.standardize_node_minimal(node)
                    
                    if minimal_node:
                        if minimal_node in unique_nodes:
                            stats['duplicate_count'] += 1
                            logging.debug(f"发现重复节点: {minimal_node}")
                        else:
                            unique_nodes.add(minimal_node)
                            stats['protocol_counts'][protocol] = stats['protocol_counts'].get(protocol, 0) + 1
                    else:
                        stats['failed_to_standardize_count'] += 1
                        logging.warning(f"无法标准化节点: {node}")

                    if len(unique_nodes) >= batch_size:
                        f.write('\n'.join(sorted(unique_nodes)) + '\n')
                        unique_nodes.clear()

            except requests.exceptions.RequestException as e:
                logging.error(f"下载失败 {url}: {e}")
                stats['invalid_format_count'] += 1
            except Exception as e:
                logging.error(f"处理 {url} 时发生未知错误: {e}")
                stats['invalid_format_count'] += 1

        if unique_nodes:
            f.write('\n'.join(sorted(unique_nodes)) + '\n')

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
    for protocol, count in stats['protocol_counts'].items():
        logging.info(f"  {protocol}: {count}")
    logging.info(f"节点已保存到: {output_file}")
    logging.info(f"总耗时: {duration.total_seconds():.2f} 秒")
    logging.info("==============================================")

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Download and deduplicate proxy nodes.')
    parser.add_argument('--base-url', 
                       default="https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes_part_", 
                       help='Base URL for node files')
    parser.add_argument('--start-index', type=int, default=1, help='Start index for files')
    parser.add_argument('--end-index', type=int, default=199, help='End index for files')
    parser.add_argument('--output-dir', default='data', help='Output directory')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    download_and_deduplicate_nodes(args)
