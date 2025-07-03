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
    level=logging.INFO, # 生产环境可以设置为 INFO，调试时可以设置为 DEBUG
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('node_deduplication.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class NodeStandardizer:
    """节点标准化器，负责解析和标准化不同协议的节点URL"""

    SUPPORTED_PROTOCOLS = {"hysteria2", "vmess", "trojan", "ss", "ssr", "vless"}

    @staticmethod
    def clean_node_url(node_url: str) -> str:
        """清理节点URL，移除不可见字符和多余空格"""
        # 移除所有空白字符（包括空格、制表符、换行符）并去除首尾空格，最后移除末尾的斜杠
        return re.sub(r'\s+', '', node_url).strip().rstrip('/')

    @staticmethod
    def standardize_node_minimal(node_url: str) -> tuple[str | None, str]:
        """
        标准化节点URL，提取核心信息用于去重。
        返回 (标准化后的节点字符串, 协议类型)。
        """
        if not node_url:
            logging.debug("空节点URL，跳过。")
            return None, "unknown"

        node_url = NodeStandardizer.clean_node_url(node_url)
        
        # 匹配支持的协议
        match = re.match(r"^(?P<protocol>" + "|".join(NodeStandardizer.SUPPORTED_PROTOCOLS) + r")://(?P<data>.*)",
                         node_url, re.IGNORECASE)
        if not match:
            logging.debug(f"不支持的协议或格式错误: {node_url}")
            return None, "unknown"

        protocol = match.group("protocol").lower()
        data_part = match.group("data")

        try:
            # 分离核心数据、查询参数和片段
            core_data_raw, _, query_fragment = data_part.partition('?')
            core_data_raw, _, fragment = core_data_raw.partition('#')
            
            # 对核心数据部分进行URL解码，并去除末尾可能存在的 /
            core_data_standardized = urllib.parse.unquote_plus(core_data_raw).strip().rstrip('/')
            
            query_string = None
            if query_fragment:
                # 重新组合查询字符串，确保正确解析
                if '#' in query_fragment:
                    query_string = query_fragment.split('#', 1)[0]
                else:
                    query_string = query_fragment

            # 将查询参数解析为字典，并标准化键和值
            query_params = NodeStandardizer._normalize_query_params(parse_qs(query_string)) if query_string else {}

            if protocol == "vmess":
                return NodeStandardizer._standardize_vmess(core_data_standardized, query_params), protocol
            
            elif protocol == "vless":
                return NodeStandardizer._standardize_vless(core_data_standardized, query_params), protocol
            
            elif protocol in ("trojan", "hysteria2"):
                return NodeStandardizer._standardize_trojan_hysteria2(protocol, core_data_standardized, query_params), protocol
            
            elif protocol == "ss":
                return NodeStandardizer._standardize_ss(core_data_standardized, query_params), protocol
            
            elif protocol == "ssr":
                return NodeStandardizer._standardize_ssr(core_data_standardized, query_params), protocol
            
            return None, "unknown"

        except Exception as e:
            # 打印详细错误信息，包括堆栈跟踪
            logging.error(f"标准化节点 {node_url} 时发生错误: {e}", exc_info=True)
            return None, "unknown"

    @staticmethod
    def _normalize_query_params(params: dict) -> dict:
        """将查询参数字典标准化，键和值都转换为小写，多值列表转换为排序后的元组。"""
        normalized = {}
        for key, values in params.items():
            key_lower = key.lower()
            # 确保值是列表，并且对值进行排序和标准化
            normalized_values = tuple(sorted([str(v).lower() for v in values]))
            normalized[key_lower] = normalized_values
        return normalized

    @staticmethod
    def _get_param_value(normalized_params: dict, key: str, default: str = '') -> str:
        """从标准化后的查询参数字典中获取指定键的第一个值。"""
        key_lower = key.lower()
        if key_lower in normalized_params and normalized_params[key_lower]:
            return normalized_params[key_lower][0]
        return default

    @staticmethod
    def _standardize_vmess(core_data: str, query_params: dict) -> str | None:
        """处理vmess协议，提取UUID、地址、端口及其他关键参数。"""
        try:
            # VMess 的 core_data 是 base64 编码的 JSON
            decoded_json_str = base64.b64decode(core_data + '=' * (-len(core_data) % 4)).decode('utf-8')
            decoded_data = json.loads(decoded_json_str)
            
            _id = decoded_data.get('id', '').lower()
            add = decoded_data.get('add', '').lower()
            port = str(decoded_data.get('port', '')).lower()
            
            if not (_id and add and NodeStandardizer.is_valid_port(port)):
                logging.debug(f"VMess 核心信息缺失或端口无效: id={_id}, add={add}, port={port}")
                return None
            
            # 提取并标准化其他重要参数
            net = decoded_data.get('net', 'tcp').lower()
            _type = decoded_data.get('type', 'none').lower()
            tls = decoded_data.get('tls', '').lower()
            host = decoded_data.get('host', '').lower()
            path = decoded_data.get('path', '').lower()
            sni = decoded_data.get('sni', '').lower()
            fp = decoded_data.get('fp', '').lower()
            
            # 构建标准化字符串，确保参数顺序一致
            standardized_parts = [
                f"vmess://{_id}@{add}:{port}",
                f"net={net}",
                f"type={_type}",
                f"tls={tls}"
            ]
            if host: standardized_parts.append(f"host={host}")
            if path: standardized_parts.append(f"path={path}")
            if sni: standardized_parts.append(f"sni={sni}")
            if fp: standardized_parts.append(f"fp={fp}")

            # 对标准化后的参数进行排序，以确保相同的节点生成相同的字符串
            sorted_params = sorted(standardized_parts[1:])
            return standardized_parts[0] + '?' + '&'.join(sorted_params)

        except (base64.binascii.Error, json.JSONDecodeError, ValueError) as e:
            logging.debug(f"无法解析VMess核心格式或端口无效: {core_data}. 错误: {e}")
            return None

    @staticmethod
    def _standardize_vless(core_data: str, query_params: dict) -> str | None:
        """处理vless协议，提取UUID、地址、端口及其他关键参数。"""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            logging.debug(f"VLESS 格式错误，缺少 '@' 分隔符: {core_data}")
            return None
        
        uuid, address_port = parts
        uuid = uuid.lower()
        address_parts = address_port.rsplit(':', 1)
        
        if len(address_parts) != 2 or not NodeStandardizer.is_valid_port(address_parts[1]):
            logging.debug(f"VLESS 地址或端口无效: {address_port}")
            return None
            
        address = address_parts[0].lower()
        port = address_parts[1].lower()

        # 提取VLESS特有参数，并赋予默认值，使用标准化后的参数字典
        security = NodeStandardizer._get_param_value(query_params, 'security', 'none').lower()
        flow = NodeStandardizer._get_param_value(query_params, 'flow', '').lower()
        transport_type = NodeStandardizer._get_param_value(query_params, 'type', 'tcp').lower()
        host = NodeStandardizer._get_param_value(query_params, 'host', '').lower()
        path = NodeStandardizer._get_param_value(query_params, 'path', '').lower()
        sni = NodeStandardizer._get_param_value(query_params, 'sni', '').lower()
        fp = NodeStandardizer._get_param_value(query_params, 'fp', '').lower()
        pbk = NodeStandardizer._get_param_value(query_params, 'pbk', '').lower()
        sid = NodeStandardizer._get_param_value(query_params, 'sid', '').lower()
        
        standardized_parts = [
            f"vless://{uuid}@{address}:{port}",
            f"security={security}",
            f"type={transport_type}"
        ]
        if flow: standardized_parts.append(f"flow={flow}")
        if host: standardized_parts.append(f"host={host}")
        if path: standardized_parts.append(f"path={path}")
        if sni: standardized_parts.append(f"sni={sni}")
        if fp: standardized_parts.append(f"fp={fp}")
        if pbk: standardized_parts.append(f"pbk={pbk}")
        if sid: standardized_parts.append(f"sid={sid}")

        sorted_params = sorted(standardized_parts[1:])
        return standardized_parts[0] + '?' + '&'.join(sorted_params)


    @staticmethod
    def _standardize_trojan_hysteria2(protocol: str, core_data: str, query_params: dict) -> str | None:
        """处理trojan和hysteria2协议"""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            logging.debug(f"{protocol} 格式错误，缺少 '@' 分隔符: {core_data}")
            return None
        
        password, address = parts
        address_parts = address.rsplit(':', 1)
        
        if len(address_parts) != 2 or not NodeStandardizer.is_valid_port(address_parts[1]):
            logging.debug(f"{protocol} 地址或端口无效: {address}")
            return None
        
        address_lower = address_parts[0].lower()
        port = address_parts[1] # 端口通常保持字符串形式

        sni = NodeStandardizer._get_param_value(query_params, 'sni', '').lower()
        alpn = NodeStandardizer._get_param_value(query_params, 'alpn', '').lower()
        
        # Hysteria2 特有参数
        obfs = NodeStandardizer._get_param_value(query_params, 'obfs', '').lower()
        obfs_password = NodeStandardizer._get_param_value(query_params, 'obfs-password', '').lower()
        
        standardized_parts = [
            f"{protocol}://{password}@{address_lower}:{port}"
        ]
        if sni: standardized_parts.append(f"sni={sni}")
        if alpn: standardized_parts.append(f"alpn={alpn}")
        if obfs: standardized_parts.append(f"obfs={obfs}")
        if obfs_password: standardized_parts.append(f"obfs-password={obfs_password}")

        sorted_params = sorted(standardized_parts[1:])
        return standardized_parts[0] + ('?' + '&'.join(sorted_params) if sorted_params else '')

    @staticmethod
    def _standardize_ss(core_data: str, query_params: dict) -> str | None:
        """处理ss协议"""
        try:
            decoded_auth_server = core_data
            # SS 核心数据可能是 base64 编码的
            if not ('@' in core_data and ':' in core_data.split('@')[0]):
                try:
                    # 尝试 base64 解码，处理 ss://BASE64_ENCODED_DATA 格式
                    decoded_auth_server = base64.b64decode(core_data + '=' * (-len(core_data) % 4)).decode('utf-8')
                except (base64.binascii.Error, UnicodeDecodeError):
                    logging.debug(f"SS核心数据非base64编码且不符合直接格式: {core_data}")
                    return None
            
            # 格式应为 method:password@server:port
            if '@' not in decoded_auth_server:
                logging.debug(f"SS 格式错误，缺少 '@' 分隔符: {decoded_auth_server}")
                return None

            auth_info, server_info = decoded_auth_server.split('@', 1)
            
            if ':' not in auth_info:
                logging.debug(f"SS 认证信息格式错误，缺少 ':' 分隔符: {auth_info}")
                return None
            method, password = auth_info.split(':', 1)
            
            if ':' not in server_info:
                logging.debug(f"SS 服务器信息格式错误，缺少 ':' 分隔符: {server_info}")
                return None
            host, port = server_info.rsplit(':', 1) # 从右边分割，确保端口是最后一部分

            if NodeStandardizer.is_valid_port(port):
                # 考虑 plugin 参数及其选项
                plugin = NodeStandardizer._get_param_value(query_params, 'plugin', '').lower()
                plugin_opts = NodeStandardizer._get_param_value(query_params, 'plugin-opts', '').lower()

                standardized_parts = [
                    f"ss://{method.lower()}:{password}@{host.lower()}:{port}"
                ]
                if plugin: standardized_parts.append(f"plugin={plugin}")
                if plugin_opts: standardized_parts.append(f"plugin-opts={plugin_opts}")

                sorted_params = sorted(standardized_parts[1:])
                return standardized_parts[0] + ('?' + '&'.join(sorted_params) if sorted_params else '')
            
            logging.debug(f"SS 端口无效: {port}")
            return None
        except ValueError as e:
            logging.debug(f"无法解析SS核心格式: {core_data}. 错误: {e}")
            return None

    @staticmethod
    def _standardize_ssr(core_data: str, query_params: dict) -> str | None:
        """处理ssr协议"""
        # SSR 的 core_data 必须是 base64 编码的
        try:
            # 补齐 base64 编码可能缺少的 padding
            decoded_ssr_data = base64.b64decode(core_data + '=' * (-len(core_data) % 4)).decode('utf-8')
            parts = decoded_ssr_data.split(':')
            
            # SSR 标准格式通常有 6 个主要部分：host:port:protocol:method:obfs:password_base64
            # 后面可能还有 obfsparam_base64/protoparam_base64/?remarks_base64
            if len(parts) < 6:
                logging.debug(f"SSR 核心格式部分不足 6 个: {decoded_ssr_data}")
                return None
            
            host, port, proto, method, obfs_raw, password_raw = parts[:6]
            
            # 对密码和混淆参数进行URL解码
            password = urllib.parse.unquote_plus(password_raw)
            obfs = urllib.parse.unquote_plus(obfs_raw)

            if NodeStandardizer.is_valid_port(port):
                # 获取 obfsparam 和 protoparam，它们可能在路径中，也可能在 query_params 中
                # 优先从 query_params 中获取
                obfsparam = NodeStandardizer._get_param_value(query_params, 'obfsparam', '').lower()
                protoparam = NodeStandardizer._get_param_value(query_params, 'protoparam', '').lower()
                
                # 如果 query_params 中没有，则从路径的剩余部分中解析
                if not obfsparam and len(parts) >= 7:
                    obfsparam = urllib.parse.unquote_plus(parts[6]).lower()
                if not protoparam and len(parts) >= 8:
                    protoparam = urllib.parse.unquote_plus(parts[7]).lower()

                standardized_parts = [
                    f"ssr://{host.lower()}:{port}:{proto.lower()}:{method.lower()}:{obfs.lower()}:{password}"
                ]
                if obfsparam: standardized_parts.append(f"obfsparam={obfsparam}")
                if protoparam: standardized_parts.append(f"protoparam={protoparam}")

                sorted_params = sorted(standardized_parts[1:])
                return standardized_parts[0] + ('?' + '&'.join(sorted_params) if sorted_params else '')
            
            logging.debug(f"SSR 端口无效: {port}")
            return None
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            logging.debug(f"无法解析SSR核心格式或端口无效: {core_data}. 错误: {e}")
            return None

    @staticmethod
    def is_valid_port(port: str) -> bool:
        """验证端口号是否有效"""
        try:
            port_num = int(port)
            return 0 < port_num <= 65535
        except ValueError:
            return False

---

## 节点下载与去重流程

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2),
        retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url(url: str) -> requests.Response:
    """带重试机制的URL请求"""
    with requests.Session() as session:
        response = session.get(url, timeout=20, stream=True)
        response.raise_for_status() # 如果请求失败，会抛出 HTTPError
        return response

def download_and_deduplicate_nodes(args):
    """从GitHub Raw链接下载节点数据，标准化并去重后保存"""
    base_url = args.base_url
    start_index = args.start_index
    end_index = args.end_index
    output_dir = args.output_dir
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_dir, f'all_{timestamp}.txt')
    
    # unique_nodes 存储标准化后的字符串，用于快速查找重复项
    unique_nodes = set() 

    stats = {
        'download_count': 0,
        'total_nodes_processed': 0,
        'failed_to_standardize_count': 0,
        'invalid_format_count': 0, # 用于统计下载失败或解析异常的文件
        'duplicate_count': 0,
        'protocol_counts': {} # 统计每种协议的去重后数量
    }
    
    logging.info("--- 开始下载和去重节点 ---")
    start_time = datetime.datetime.now()
    batch_size = 10000 # 每处理一定数量的节点就写入文件，防止内存过载

    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(start_index, end_index + 1):
            file_index = str(i).zfill(3) # 格式化文件序号为三位数，例如 001, 002
            url = f"{base_url}{file_index}.txt"
            
            try:
                logging.info(f"正在下载: {url}")
                response = fetch_url(url)
                stats['download_count'] += 1
                
                for line in response.iter_lines(decode_unicode=True):
                    node = line.strip()
                    if not node: # 跳过空行
                        continue
                    
                    stats['total_nodes_processed'] += 1
                    minimal_node, protocol = NodeStandardizer.standardize_node_minimal(node)
                    
                    if minimal_node:
                        if minimal_node in unique_nodes:
                            stats['duplicate_count'] += 1
                            logging.debug(f"发现重复节点 (标准化): {minimal_node}, 原始: {node}")
                        else:
                            unique_nodes.add(minimal_node)
                            stats['protocol_counts'][protocol] = stats['protocol_counts'].get(protocol, 0) + 1
                    else:
                        stats['failed_to_standardize_count'] += 1
                        # 对于无法标准化的节点，发出警告，帮助调试
                        logging.warning(f"无法标准化节点，可能格式不正确或不受支持: {node}")

                    # 达到批处理大小，写入文件并清空集合
                    if len(unique_nodes) >= batch_size:
                        logging.debug(f"达到批处理大小 {batch_size}，写入文件并清空缓存。")
                        # 写入时排序，保持输出稳定
                        f.write('\n'.join(sorted(unique_nodes)) + '\n')
                        unique_nodes.clear()

            except requests.exceptions.RequestException as e:
                logging.error(f"下载文件失败 {url}: {e}")
                stats['invalid_format_count'] += 1 # 这里计入下载失败，后续不会处理这些URL
            except Exception as e:
                logging.error(f"处理 {url} 时发生未知错误: {e}", exc_info=True)
                stats['invalid_format_count'] += 1

        # 循环结束后，写入剩余的唯一节点
        if unique_nodes:
            logging.info(f"写入剩余的 {len(unique_nodes)} 个节点。")
            f.write('\n'.join(sorted(unique_nodes)) + '\n')

    end_time = datetime.datetime.now()
    duration = end_time - start_time

    # 输出运行摘要
    logging.info("\n==================== 运行摘要 ====================")
    logging.info(f"成功下载的链接数: {stats['download_count']}")
    logging.info(f"处理的节点总数: {stats['total_nodes_processed']}")
    logging.info(f"重复节点数: {stats['duplicate_count']}")
    logging.info(f"无法标准化的节点数: {stats['failed_to_standardize_count']}")
    logging.info(f"下载或处理过程中出现无效格式/错误的文件数: {stats['invalid_format_count']}")
    logging.info(f"去重后的有效节点总数: {sum(stats['protocol_counts'].values())}") 
    logging.info("协议分布:")
    for protocol, count in stats['protocol_counts'].items():
        logging.info(f"  {protocol}: {count}")
    logging.info(f"节点已保存到: {output_file}")
    logging.info(f"总耗时: {duration.total_seconds():.2f} 秒")
    logging.info("==============================================")

---

## 命令行参数解析

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='下载并去重代理节点。')
    parser.add_argument('--base-url',
                        default="https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes_part_",
                        help='节点文件的基础URL')
    parser.add_argument('--start-index', type=int, default=1, help='文件序号的起始索引')
    parser.add_argument('--end-index', type=int, default=199, help='文件序号的结束索引')
    parser.add_argument('--output-dir', default='data', help='输出目录')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    download_and_deduplicate_nodes(args)
