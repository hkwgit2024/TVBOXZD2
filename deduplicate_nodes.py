import requests
import os
import re
import datetime
import urllib.parse
import logging
import base64
import json
from urllib.parse import urlparse, parse_qs

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
    def standardize_node_minimal(node_url: str) -> str | None:
        """
        标准化明文节点URL，保留核心连接信息，去除非必要参数和备注。
        支持 hysteria2, vmess, trojan, ss, ssr, vless 等协议。
        """
        if not node_url:
            return None

        # 清除空白字符、回车和多余斜杠
        node_url = node_url.strip().rstrip('/')

        # 识别协议 (忽略大小写)
        match = re.match(r"^(?P<protocol>hysteria2|vmess|trojan|ss|ssr|vless)://(?P<data>.*)", 
                        node_url, re.IGNORECASE)
        if not match:
            logging.debug(f"不支持的协议或格式错误: {node_url}")
            return None

        protocol = match.group("protocol").lower()
        data_part = match.group("data")
        minimal_node_parts = [f"{protocol}://"]

        try:
            # 分离核心数据，去除查询参数和备注
            core_data = data_part.split('?', 1)[0].split('#', 1)[0].strip()
            core_data_standardized = urllib.parse.unquote_plus(core_data).strip()

            if protocol in ("vmess", "vless"):
                return NodeStandardizer._standardize_vmess_vless(protocol, core_data_standardized)
            
            elif protocol in ("trojan", "hysteria2"):
                return NodeStandardizer._standardize_trojan_hysteria2(protocol, core_data_standardized)
            
            elif protocol == "ss":
                return NodeStandardizer._standardize_ss(core_data_standardized)
            
            elif protocol == "ssr":
                return NodeStandardizer._standardize_ssr(core_data_standardized)
            
            return None

        except Exception as e:
            logging.error(f"标准化节点 {node_url} 时发生错误: {e}")
            return None

    @staticmethod
    def _standardize_vmess_vless(protocol: str, core_data: str) -> str | None:
        """处理vmess和vless协议"""
        parts = core_data.split('@', 1)
        if len(parts) == 2:
            uuid, address = parts
            if protocol == "vmess":
                try:
                    # vmess可能需要base64解码
                    decoded = json.loads(base64.b64decode(uuid + '=' * (-len(uuid) % 4)).decode('utf-8'))
                    uuid = decoded.get('id', '').lower()
                    address = f"{decoded.get('add', '').lower()}:{decoded.get('port', '')}"
                except (base64.binascii.Error, json.JSONDecodeError):
                    pass  # 如果base64解码失败，保持原样
            return f"{protocol}://{uuid.lower()}@{address.lower()}"
        return f"{protocol}://{core_data.lower()}"

    @staticmethod
    def _standardize_trojan_hysteria2(protocol: str, core_data: str) -> str | None:
        """处理trojan和hysteria2协议"""
        parts = core_data.split('@', 1)
        if len(parts) == 2:
            password, address = parts
            return f"{protocol}://{password}@{address.lower()}"
        return f"{protocol}://{core_data}"

    @staticmethod
    def _standardize_ss(core_data: str) -> str | None:
        """处理ss协议"""
        if '@' in core_data and ':' in core_data.split('@')[0]:
            try:
                auth_info, server_info = core_data.split('@', 1)
                method, password = auth_info.split(':', 1)
                host, port = server_info.rsplit(':', 1)
                return f"ss://{method.lower()}:{password}@{host.lower()}:{port}"
            except ValueError:
                logging.debug(f"无法解析SS核心格式: {core_data}")
                return None
        return None

    @staticmethod
    def _standardize_ssr(core_data: str) -> str | None:
        """处理ssr协议"""
        parts = core_data.split(':')
        if len(parts) >= 6:
            try:
                host, port, proto, method, obfs, password = parts[:6]
                password = urllib.parse.unquote_plus(password)
                return f"ssr://{host.lower()}:{port}:{proto.lower()}:{method.lower()}:{obfs.lower()}:{password}"
            except ValueError:
                logging.debug(f"无法解析SSR核心格式: {core_data}")
                return None
        return None

def download_and_deduplicate_nodes() -> None:
    """
    从GitHub Raw链接下载节点数据，标准化并去重后保存到文件。
    """
    base_url = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes_part_"
    start_index = 1
    end_index = 199
    output_dir = 'data'
    output_file = os.path.join(output_dir, 'all.txt')
    
    unique_nodes = set()
    stats = {
        'download_count': 0,
        'total_nodes_processed': 0,
        'failed_to_standardize_count': 0,
        'invalid_format_count': 0
    }
    
    logging.info("--- 开始下载和去重节点 ---")
    start_time = datetime.datetime.now()

    # 使用流式处理逐行读取，减少内存占用
    for i in range(start_index, end_index + 1):
        file_index = str(i).zfill(3)
        url = f"{base_url}{file_index}.txt"
        
        try:
            logging.info(f"正在下载: {url}")
            response = requests.get(url, timeout=20, stream=True)
            response.raise_for_status()
            stats['download_count'] += 1
            
            for line in response.iter_lines(decode_unicode=True):
                node = line.strip()
                if not node:
                    continue
                
                stats['total_nodes_processed'] += 1
                minimal_node = NodeStandardizer.standardize_node_minimal(node)
                
                if minimal_node:
                    unique_nodes.add(minimal_node)
                else:
                    stats['failed_to_standardize_count'] += 1
                    logging.warning(f"无法标准化节点: {node}")

        except requests.exceptions.RequestException as e:
            logging.error(f"下载失败 {url}: {e}")
        except Exception as e:
            logging.error(f"处理 {url} 时发生未知错误: {e}")
            stats['invalid_format_count'] += 1

    # 保存结果
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for node in sorted(unique_nodes):
            f.write(node + '\n')
    
    end_time = datetime.datetime.now()
    duration = end_time - start_time

    # 输出统计信息
    logging.info("\n--- 运行摘要 ---")
    logging.info(f"成功下载的链接数: {stats['download_count']}")
    logging.info(f"处理的节点总数: {stats['total_nodes_processed']}")
    logging.info(f"无法标准化的节点数: {stats['failed_to_standardize_count']}")
    logging.info(f"格式无效的节点数: {stats['invalid_format_count']}")
    logging.info(f"去重后的有效节点总数: {len(unique_nodes)}")
    logging.info(f"节点已保存到: {output_file}")
    logging.info(f"总耗时: {duration.total_seconds():.2f} 秒")
    logging.info("------------------")

if __name__ == "__main__":
    download_and_deduplicate_nodes()
