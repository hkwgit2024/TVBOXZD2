import requests
import base64
import re
import os
import urllib.parse
import json
import logging
from collections import namedtuple

# --- 配置日志 ---
# 默认日志级别为 INFO，只输出重要信息。
# 如果需要详细调试（例如，查看每个被跳过的节点的原因），可以将其改为 logging.DEBUG。
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 常量定义 ---
# 所有要处理的节点源 URL 列表
NODE_URLS = [
    
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
]
# 最终输出的节点文件路径
OUTPUT_FILE = "data/sub.txt"
# 下载每个节点源的超时时间（秒）
DOWNLOAD_TIMEOUT = 60

# 定义一个具名元组来标准化解析后的节点信息
# 并非所有字段都适用于所有协议，未解析到的字段将为 None
ParsedNode = namedtuple(
    'ParsedNode',
    ['protocol', 'address', 'port', 'user_id', 'password', 'encryption', 'name', 
     'remark', 'network', 'tls', 'sni', 'obfs', 'raw_link']
)

# --- 辅助函数：Base64 解码 ---
def decode_base64_url(data: str) -> str | None:
    """
    解码 URL-safe Base64 字符串，处理填充并增强容错性。
    此函数会预过滤不符合 Base64 字符集的字符串，并处理常见的解码错误。
    """
    data = data.strip()
    if not data:
        return None

    # 预过滤：快速排除包含非 Base64 字符的字符串，提高效率。
    # 允许的字符包括大小写字母、数字、+、/、=、-、_
    # Note: re.fullmatch 性能优于循环检查每个字符
    if not re.fullmatch(r'^[a-zA-Z0-9+/=\-_]+$', data):
        logger.debug(f"Base64 quick filter: Data contains non-Base64 chars for '{data[:50]}...'")
        return None

    # 清理：去除可能存在于数据中的空格、换行符等，这些会干扰 Base64 解码。
    data = data.replace(' ', '').replace('\n', '').replace('\r', '')

    try:
        # base64.urlsafe_b64decode 可以处理一些不带或带不完整填充的情况。
        # 避免手动添加复杂的填充逻辑，直接让库处理。
        decoded_bytes = base64.urlsafe_b64decode(data)
        return decoded_bytes.decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        # 捕获 Base64 数据损坏或 UTF-8 解码失败的错误。
        logger.debug(f"Base64 decode error for '{data[:100]}...': {e}")
        return None
    except Exception as e:
        # 捕获其他任何未预料的错误。
        logger.debug(f"Unexpected error during Base64 decode for '{data[:100]}...': {e}")
        return None

# --- 核心解析函数：parse_node ---
def parse_node(node_string: str) -> ParsedNode | None:
    """
    解析各种代理协议链接，提取核心信息。
    此函数旨在提供更健壮的初步解析，即使部分格式不标准也能尝试提取关键数据。
    返回 ParsedNode 对象或 None。
    """
    original_link = node_string.strip()
    if not original_link:
        return None

    # 初始化所有字段为 None
    protocol, address, port, user_id, password, encryption, name, remark, network, tls, sni, obfs = (None,) * 12

    try:
        # 使用 urllib.parse.urlparse 解析 URL
        parsed_url = urllib.parse.urlparse(original_link)
        protocol = parsed_url.scheme.lower()
        
        # 快速过滤掉明显不支持或无效的协议
        supported_protocols = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2'}
        if protocol not in supported_protocols:
            logger.debug(f"Unsupported protocol '{protocol}' for link: {original_link[:100]}...")
            return None

        # 解析 URL 的查询参数和片段 (通常是节点名称)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        fragment = parsed_url.fragment

        # 优先使用 URL 片段作为节点名称
        if fragment:
            name = urllib.parse.unquote(fragment) # 解码 URL 编码的名称

        # --- 各协议特定的解析逻辑 ---
        if protocol == "vmess":
            # VMess: base64(json_config)
            # VMess 链接的主体是 Base64 编码的 JSON 字符串，通常在 netloc 和 path 部分。
            vmess_data_encoded = parsed_url.netloc + parsed_url.path.lstrip('/')
            decoded_json_str = decode_base64_url(vmess_data_encoded)
            if decoded_json_str:
                try:
                    vmess_config = json.loads(decoded_json_str)
                    address = vmess_config.get('add')
                    port = vmess_config.get('port')
                    user_id = vmess_config.get('id')
                    encryption = vmess_config.get('scy') # scy for security method
                    network = vmess_config.get('net')
                    tls = 'tls' if vmess_config.get('tls') == 'tls' else None
                    sni = vmess_config.get('host') # host is often SNI/hostname for WS/HTTP
                    name = name or vmess_config.get('ps') # ps for remark/name
                    remark = vmess_config.get('ps')
                except json.JSONDecodeError:
                    logger.debug(f"VMess JSON decode error for '{decoded_json_str[:100]}' in link {original_link[:100]}...")
            else:
                logger.debug(f"VMess base64 decode failed for link: {original_link[:100]}...")

        elif protocol == "vless":
            # VLESS: uuid@address:port?params#name
            # parsed_url.netloc 可能是 "uuid@address:port" 或 "address:port"
            auth_addr_port_str = parsed_url.netloc

            if '@' in auth_addr_port_str:
                user_id, addr_port_str = auth_addr_port_str.split('@', 1)
            else:
                addr_port_str = auth_addr_port_str
                # 尝试从 query 中获取 UUID (某些VLESS链接可能如此)
                user_id = query_params.get('uuid', [None])[0] 
                if not user_id:
                    logger.debug(f"VLESS link missing UUID in netloc or query: {original_link[:100]}...")

            if ':' in addr_port_str:
                address, port_str = addr_port_str.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"VLESS invalid port '{port_str}' in {original_link[:100]}...")
                    port = None
            else: # 如果没有端口，则整个是地址
                 address = addr_port_str
                 logger.debug(f"VLESS link missing port: {original_link[:100]}...")

            network = query_params.get('type', [None])[0]
            tls = query_params.get('security', [None])[0]
            sni = query_params.get('sni', [None])[0]
            
        elif protocol == "trojan":
            # Trojan: password@address:port?params#name
            # 优化：组合 netloc 和 path，然后手动分割，避免 urllib.parse 误判
            full_auth_addr_port_str = parsed_url.netloc + parsed_url.path # 例如 "password@address:port"

            if '@' in full_auth_addr_port_str:
                password, addr_port_str = full_auth_addr_port_str.split('@', 1)
            else:
                addr_port_str = full_auth_addr_port_str
                logger.debug(f"Trojan link missing password: {original_link[:100]}...")
            
            if ':' in addr_port_str:
                address, port_str = addr_port_str.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"Trojan invalid port '{port_str}' in {original_link[:100]}...")
                    port = None
            else: # 如果没有端口，则整个是地址
                 address = addr_port_str
                 logger.debug(f"Trojan link missing port: {original_link[:100]}...")
            
            tls = query_params.get('security', [None])[0]
            sni = query_params.get('sni', [None])[0]

        elif protocol == "ss":
            # SS: base64(method:password)@address:port#name OR method:password@address:port#name
            # parsed_url.netloc 包含了认证信息 (base64或明文)
            auth_part_raw = parsed_url.netloc

            decoded_auth_part = decode_base64_url(auth_part_raw)
            auth_info = decoded_auth_part if decoded_auth_part else auth_part_raw

            if ':' in auth_info:
                encryption, password = auth_info.split(':', 1)
            else:
                logger.debug(f"SS auth info malformed: '{auth_info}' in {original_link[:100]}...")

            # address:port 可能是 parsed_url.hostname 和 parsed_url.port
            # 或者在某些不规范链接中，也可能在 path 部分
            address = parsed_url.hostname
            if parsed_url.port:
                port = parsed_url.port
            elif parsed_url.path and parsed_url.path.strip('/'): # 兼容 path 里有地址端口的情况
                 addr_port_path = parsed_url.path.strip('/')
                 if ':' in addr_port_path:
                     try:
                         path_address, path_port_str = addr_port_path.rsplit(':', 1)
                         if not address: # 如果 hostname 没提取到，才尝试用 path 的
                            address = path_address
                         if not port:
                            port = int(path_port_str)
                     except ValueError:
                         logger.debug(f"SS invalid port in path: '{addr_port_path}' in {original_link[:100]}...")
                 elif not address: # 如果 path 里只有地址
                    address = addr_port_path
                    logger.debug(f"SS link missing port in path: {original_link[:100]}...")

            if not address:
                logger.debug(f"SS link missing address: {original_link[:100]}...")


        elif protocol == "ssr":
            # SSR: base64(server:port:protocol:method:obfs:password_base64/?params)
            # SSR 链接通常整个 "host/path" 部分都是 Base64 编码的
            ssr_data_encoded = parsed_url.netloc + parsed_url.path.lstrip('/')
            decoded_ssr_params = decode_base64_url(ssr_data_encoded)
            if decoded_ssr_params:
                try:
                    parts = decoded_ssr_params.split(':')
                    if len(parts) >= 5: # 至少 server:port:protocol:method:obfs
                        address = parts[0]
                        port = int(parts[1])
                        # ssr_protocol = parts[2] # SSR 协议类型
                        encryption = parts[3]
                        obfs = parts[4]
                        if len(parts) >= 6:
                            password_and_params = parts[5]
                            # 密码部分可能也进行了 Base64 编码，且后面可能跟有 URL 参数
                            password_base64_part = password_and_params.split('/')[0]
                            password = decode_base64_url(password_base64_part) if password_base64_part else None
                except (ValueError, IndexError) as e:
                    logger.debug(f"SSR numerical/index error '{e}': '{decoded_ssr_params[:100]}' for {original_link[:100]}...")
                except Exception as e:
                    logger.debug(f"SSR unexpected error parsing '{e}': '{decoded_ssr_params[:100]}' in {original_link[:100]}...")
            else:
                logger.debug(f"SSR base64 decode failed for link: {original_link[:100]}...")

        elif protocol == "hysteria2":
            # Hysteria2: password@address:port?params#name
            # 优化：组合 netloc 和 path，然后手动分割，避免 urllib.parse 误判
            full_auth_addr_port_str = parsed_url.netloc + parsed_url.path

            if '@' in full_auth_addr_port_str:
                password, addr_port_str = full_auth_addr_port_str.split('@', 1)
            else:
                addr_port_str = full_auth_addr_port_str
                logger.debug(f"Hysteria2 link missing password: {original_link[:100]}...")

            if ':' in addr_port_str:
                address, port_str = addr_port_str.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"Hysteria2 invalid port '{port_str}' in {original_link[:100]}...")
                    port = None
            else: # 如果没有端口，则整个是地址
                 address = addr_port_str
                 logger.debug(f"Hysteria2 link missing port: {original_link[:100]}...")
            
            obfs = query_params.get('obfs', [None])[0]

        # --- 最终判断：如果至少解析出了协议、地址和有效端口，则认为初步解析成功 ---
        # 端口必须是整数且大于0小于65536
        if protocol and address and port is not None and 0 < port <= 65535:
            return ParsedNode(
                protocol=protocol,
                address=address,
                port=port,
                user_id=user_id,
                password=password,
                encryption=encryption,
                name=name,
                remark=remark,
                network=network,
                tls=tls,
                sni=sni,
                obfs=obfs,
                raw_link=original_link # 保存原始完整的链接，以便最终输出
            )
        else:
            # 如果 essential info 缺失或端口无效，则跳过
            logger.debug(f"Failed to extract essential info (protocol/addr/valid_port) for '{original_link[:100]}...'")
            return None

    except Exception as e:
        # 捕获更宽泛的异常，但这里通常是更深层次的逻辑错误或非常规的格式。
        logger.error(f"Critical error parsing node '{original_link[:100]}...': {e}", exc_info=False)
        return None

# --- 主逻辑函数 ---
def main():
    logger.info(f"Starting node processing. Downloading from: {NODE_URLS}")
    
    # 确保输出目录存在
    output_dir = os.path.dirname(OUTPUT_FILE)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        except OSError as e:
            logger.critical(f"Failed to create directory {output_dir}: {e}. Exiting.", exc_info=True)
            return # 无法创建目录则退出

    # 使用集合存储节点唯一键，用于高效去重
    unique_nodes_keys = set()
    # 使用列表存储最终要写入文件的原始链接字符串
    processed_output_links = []

    raw_lines_total = 0 # 统计从所有源下载到的总行数
    parsed_nodes_count = 0
    duplicates_skipped_count = 0
    malformed_or_unrecognized_count = 0

    # 循环遍历所有节点源 URL
    for url in NODE_URLS:
        logger.info(f"Downloading from: {url}")
        try:
            # 使用 stream=True 进行流式下载，避免一次性加载大文件到内存
            response = requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status() # 对非 200 状态码抛出异常
            logger.info(f"Successfully downloaded from {url} (streaming).")

            # 逐行处理下载的内容，进一步减少内存占用
            for line_bytes in response.iter_lines(chunk_size=8192):
                if not line_bytes:
                    continue # 跳过空字节行

                raw_lines_total += 1 # 统计原始行数
                try:
                    # 将字节行解码为 UTF-8 字符串，并去除首尾空白
                    # errors='ignore' 处理编码错误，防止中断
                    node_entry = line_bytes.decode('utf-8', errors='ignore').strip()
                    if not node_entry:
                        continue # 跳过解码后的空行

                    final_processed_node_string = node_entry

                    # 优化：快速检查整行是否可能是 Base64 编码的，如果是，则尝试解码。
                    # 长度限制 (>15) 可避免对短字符串进行不必要的 Base64 解码尝试，提高效率。
                    if len(node_entry) > 15 and re.fullmatch(r'^[a-zA-Z0-9+/=\-_]+$', node_entry):
                        decoded_full_line = decode_base64_url(node_entry)
                        if decoded_full_line:
                            final_processed_node_string = decoded_full_line
                        else:
                            # 如果看起来像 Base64 但解码失败，就继续尝试将原始行作为节点处理。
                            logger.debug(f"Line looks like Base64 but decode failed, processing original: '{node_entry[:50]}...'")
                            pass # 保持 final_processed_node_string 为原始 node_entry

                    # 调用 parse_node 进行初步解析和信息提取
                    parsed_info = parse_node(final_processed_node_string)

                    if parsed_info:
                        # 生成唯一键进行去重。包含协议、地址、端口以及其他重要参数，确保精准去重。
                        node_key_elements = [
                            parsed_info.protocol,
                            parsed_info.address,
                            str(parsed_info.port),
                        ]
                        if parsed_info.user_id: node_key_elements.append(parsed_info.user_id)
                        if parsed_info.password: node_key_elements.append(parsed_info.password)
                        if parsed_info.encryption: node_key_elements.append(parsed_info.encryption)
                        if parsed_info.obfs: node_key_elements.append(parsed_info.obfs)
                        if parsed_info.network: node_key_elements.append(parsed_info.network)
                        if parsed_info.tls: node_key_elements.append(parsed_info.tls)
                        if parsed_info.sni: node_key_elements.append(parsed_info.sni)

                        # 使用 set 进行去重，这是处理大量数据的最高效方式。
                        # filter(None, ...) 用于去除列表中可能存在的 None 值，确保键的干净。
                        node_unique_key = "|".join(filter(None, node_key_elements))

                        if node_unique_key not in unique_nodes_keys:
                            unique_nodes_keys.add(node_unique_key)
                            processed_output_links.append(parsed_info.raw_link) # 保存原始完整的链接
                            parsed_nodes_count += 1
                            # logger.debug(f"Added node: {parsed_info.raw_link[:100]}...") # 调试时启用，可提供详细添加日志
                        else:
                            duplicates_skipped_count += 1
                            logger.debug(f"Skipping duplicate node: '{parsed_info.raw_link[:100]}...'") # 调试时启用，可提供详细跳过日志
                    else:
                        # 如果 parse_node 返回 None，说明节点无法识别或格式错误。
                        malformed_or_unrecognized_count += 1
                        # logger.debug(f"Skipping malformed/unrecognized: '{final_processed_node_string[:100]}...'") # 调试时启用

                except Exception as e:
                    # 捕获处理单行时可能发生的任何其他异常，确保脚本不会中断。
                    logger.error(f"Error processing raw line '{node_entry[:100]}...': {e}", exc_info=False)
                    malformed_or_unrecognized_count += 1
                    continue

        except requests.exceptions.RequestException as e:
            # 捕获网络请求相关错误（如连接失败、超时、HTTP 状态码错误）。
            logger.error(f"Network error downloading from {url}: {e}", exc_info=False)
        except Exception as e:
            # 捕获下载过程中可能发生的任何其他未预料的关键错误。
            logger.critical(f"An unexpected critical error occurred during processing from {url}: {e}", exc_info=True)
            
    # 对最终去重后的链接进行排序，以便于 Git diff 和保持文件内容的稳定性。
    processed_output_links.sort()

    try:
        # 将处理后的唯一节点链接写入输出文件
        with open(OUTPUT_FILE, "w", encoding='utf-8') as f:
            for link in processed_output_links:
                f.write(link + "\n")
        logger.info(f"Successfully processed and saved {parsed_nodes_count} unique and recognized nodes to {OUTPUT_FILE}")
        logger.info(f"--- Processing Summary ---")
        logger.info(f"Total raw lines processed (all sources): {raw_lines_total}")
        logger.info(f"Unique & Parsed Nodes Saved: {parsed_nodes_count}")
        logger.info(f"Duplicates Skipped: {duplicates_skipped_count}")
        logger.info(f"Malformed/Unrecognized Nodes Skipped: {malformed_or_unrecognized_count}")
    except IOError as e:
        # 捕获文件写入错误。
        logger.critical(f"Error writing to output file {OUTPUT_FILE}: {e}", exc_info=True)

if __name__ == "__main__":
    main()
