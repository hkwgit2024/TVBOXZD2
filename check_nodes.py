import requests
import base64
import re
import os
import urllib.parse
import json
import logging
from collections import namedtuple

# --- 配置日志 ---
# 设置日志级别为 INFO，这意味着 INFO、WARNING、ERROR、CRITICAL 级别的消息都会被记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 常量定义 ---
NODE_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt"
OUTPUT_FILE = "data/sub.txt"

# 定义一个具名元组来标准化解析后的节点信息
# 并非所有字段都适用于所有协议，未解析到的字段将为 None
ParsedNode = namedtuple(
    'ParsedNode',
    ['protocol', 'address', 'port', 'user_id', 'password', 'encryption', 'name', 'remark', 'network', 'tls', 'sni', 'raw_link']
)

# --- 辅助函数：Base64 解码 ---
def decode_base64_url(data: str) -> str | None:
    """
    解码 URL-safe Base64 字符串，处理填充并增强容错性。
    此函数现在尝试更健壮地处理非标准 Base64 字符串。
    """
    data = data.strip()
    if not data:
        return None

    # 尝试去除可能的多余URL编码或特殊字符
    data = data.replace(' ', '').replace('\n', '').replace('\r', '')

    try:
        # 添加或移除填充
        # base64.urlsafe_b64decode 会自动处理一些不带填充的情况，但为了健壮性手动处理
        missing_padding = len(data) % 4
        if missing_padding == 2:
            data += '=='
        elif missing_padding == 3:
            data += '='
        elif missing_padding == 1: # 这种情况通常是无效的Base64，但我们尝试处理
            logger.debug(f"Possibly invalid Base64 padding (len % 4 == 1): {data[:50]}...")
            return None # 暂时认为这是无效的，避免后续错误

        decoded_bytes = base64.urlsafe_b64decode(data)
        return decoded_bytes.decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        logger.debug(f"Base64 decode error for '{data[:100]}...': {e}")
        return None
    except Exception as e:
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
    protocol, address, port, user_id, password, encryption, name, remark, network, tls, sni = (None,) * 11

    try:
        # 使用 urllib.parse.urlparse 解析 URL
        parsed_url = urllib.parse.urlparse(original_link)
        protocol = parsed_url.scheme.lower()
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query) # 解析查询参数
        fragment = parsed_url.fragment # 解析 URL 片段 (通常是节点名称)

        # 优先使用 URL 片段作为名称
        if fragment:
            name = urllib.parse.unquote(fragment) # 解码名称

        # 处理不同协议的逻辑
        if protocol == "vmess":
            # VMess: base64(json_config)
            decoded_json_str = decode_base64_url(parsed_url.netloc + path) # VMess链接的主体是base64编码
            if decoded_json_str:
                try:
                    vmess_config = json.loads(decoded_json_str)
                    address = vmess_config.get('add')
                    port = vmess_config.get('port')
                    user_id = vmess_config.get('id')
                    encryption = vmess_config.get('scy') # scy for security
                    network = vmess_config.get('net')
                    tls = 'tls' if vmess_config.get('tls') == 'tls' else None
                    sni = vmess_config.get('host') # host is often SNI/hostname for WS/HTTP
                    name = name or vmess_config.get('ps') # ps for remark/name
                    remark = vmess_config.get('ps')
                except json.JSONDecodeError:
                    logger.debug(f"VMess JSON decode error: {decoded_json_str[:100]}... for link {original_link[:100]}...")
            else:
                logger.debug(f"VMess base64 decode failed for link: {original_link[:100]}...")

        elif protocol == "vless":
            # VLESS: uuid@address:port?params#name
            # netloc 包含 uuid@address:port
            auth_addr_port = parsed_url.netloc
            if '@' in auth_addr_port:
                user_id, addr_port = auth_addr_port.split('@', 1)
            else:
                addr_port = auth_addr_port # 某些VLESS可能没有直接的UUID在netloc
                logger.debug(f"VLESS link missing UUID in netloc: {original_link[:100]}...")

            if ':' in addr_port:
                address, port_str = addr_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"VLESS invalid port: {port_str} in {original_link[:100]}...")
                    port = None

            # 解析 VLESS 的查询参数
            network = query.get('type', [None])[0] # network type
            tls = query.get('security', [None])[0] # security type (tls, reality)
            sni = query.get('sni', [None])[0] # SNI for TLS/Reality

        elif protocol == "trojan":
            # Trojan: password@address:port?params#name
            auth_addr_port = parsed_url.netloc
            if '@' in auth_addr_port:
                password, addr_port = auth_addr_port.split('@', 1)
            else:
                addr_port = auth_addr_port # 某些Trojan可能没有密码在netloc
                logger.debug(f"Trojan link missing password in netloc: {original_link[:100]}...")

            if ':' in addr_port:
                address, port_str = addr_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"Trojan invalid port: {port_str} in {original_link[:100]}...")
                    port = None
            
            # 解析Trojan的查询参数
            tls = query.get('security', [None])[0] # usually 'tls'
            sni = query.get('sni', [None])[0]


        elif protocol == "ss":
            # SS: base64(method:password)@address:port#name
            # 或者 method:password@address:port#name (旧格式或不带base64)
            # urllib.parse.urlparse 会把 'method:password@' 放在 netloc
            auth_part_raw = parsed_url.netloc

            # 尝试解码auth部分
            decoded_auth_part = decode_base64_url(auth_part_raw)
            auth_info = decoded_auth_part if decoded_auth_part else auth_part_raw

            if ':' in auth_info:
                encryption, password = auth_info.split(':', 1)
            else:
                logger.debug(f"SS auth info malformed: {auth_info} in {original_link[:100]}...")

            # address:port 在 path 中，需要去除 /
            addr_port_part = path.lstrip('/')
            if ':' in addr_port_part:
                address, port_str = addr_port_part.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"SS invalid port: {port_str} in {original_link[:100]}...")
                    port = None
            else:
                address = addr_port_part # Fallback if no port specified (unlikely but possible)
                logger.debug(f"SS link missing port: {original_link[:100]}...")

        elif protocol == "ssr":
            # SSR: base64(server:port:protocol:method:obfs:password_base64/?params)
            # SSR 链接通常整个 "host/path" 部分都是 Base64 编码的
            decoded_ssr_params = decode_base64_url(parsed_url.netloc + path)
            if decoded_ssr_params:
                try:
                    parts = decoded_ssr_params.split(':')
                    if len(parts) >= 5: # 至少 server:port:protocol:method:obfs
                        address = parts[0]
                        port = int(parts[1])
                        # ssr_protocol = parts[2] # SSR 协议类型
                        encryption = parts[3]
                        # obfs = parts[4] # SSR 混淆类型
                        if len(parts) >= 6:
                            # 密码通常是最后一个参数，并且可能带有 URL 查询参数
                            password_and_params = parts[5]
                            password = decode_base64_url(password_and_params.split('/')[0]) # 密码也需要Base64解码
                except ValueError:
                    logger.debug(f"SSR numerical conversion error: {decoded_ssr_params[:100]} for {original_link[:100]}...")
                except Exception:
                    logger.debug(f"SSR param decode/parse error for: {decoded_ssr_params[:100]} in {original_link[:100]}...")
            else:
                logger.debug(f"SSR base64 decode failed for link: {original_link[:100]}...")

        elif protocol == "hysteria2":
            # Hysteria2: password@address:port?params#name
            # netloc 包含 password@address:port
            auth_addr_port = parsed_url.netloc
            if '@' in auth_addr_port:
                password, addr_port = auth_addr_port.split('@', 1)
            else:
                addr_port = auth_addr_port
                logger.debug(f"Hysteria2 link missing password in netloc: {original_link[:100]}...")

            if ':' in addr_port:
                address, port_str = addr_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"Hysteria2 invalid port: {port_str} in {original_link[:100]}...")
                    port = None
            
            # Hysteria2 的查询参数，如 obfs
            # obfs = query.get('obfs', [None])[0]

        # 如果至少解析出了协议、地址和端口，则认为初步解析成功
        if protocol and address and port is not None:
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
                raw_link=original_link # 保存原始链接以便输出
            )
        else:
            logger.debug(f"Failed to extract essential info (addr/port) for {protocol} from: {original_link[:100]}...")
            return None

    except Exception as e:
        logger.error(f"Critical error parsing node '{original_link[:100]}...': {e}", exc_info=False) # exc_info=True 会打印完整堆栈，这里为了简洁设为False
        return None

# --- 主逻辑函数 ---
def main():
    logger.info(f"Starting node processing. Downloading from: {NODE_URL}")
    
    # 确保输出目录存在
    output_dir = os.path.dirname(OUTPUT_FILE)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        except OSError as e:
            logger.error(f"Failed to create directory {output_dir}: {e}")
            return # 无法创建目录则退出

    # 使用集合存储节点唯一键，用于高效去重
    unique_nodes_keys = set()
    # 使用列表存储最终要写入文件的原始链接字符串
    processed_output_links = []

    raw_nodes_count = 0
    parsed_nodes_count = 0
    duplicates_skipped_count = 0
    malformed_or_unrecognized_count = 0

    try:
        # 使用 stream=True 和 iter_lines() 逐行处理，优化内存
        logger.info(f"Attempting to download nodes from {NODE_URL}...")
        response = requests.get(NODE_URL, stream=True, timeout=60) # 增加超时时间
        response.raise_for_status() # 对非200状态码抛出异常
        logger.info("Node list downloaded successfully (streaming).")

        for line_bytes in response.iter_lines(chunk_size=8192):
            if line_bytes:
                raw_nodes_count += 1
                try:
                    # 解码每一行，处理可能存在的非UTF-8字符
                    node_entry = line_bytes.decode('utf-8', errors='ignore').strip()
                    if not node_entry:
                        continue # 跳过空行

                    final_processed_node_string = node_entry

                    # 检查整行是否可能是Base64编码的，如果是，则尝试解码
                    # 订阅链接中常见一整行为一个base64编码的节点
                    if re.fullmatch(r'^[a-zA-Z0-9+/=-]+$', node_entry) and len(node_entry) > 10: # 长度限制避免误判
                        decoded_full_line = decode_base64_url(node_entry)
                        if decoded_full_line:
                            final_processed_node_string = decoded_full_line
                            logger.debug(f"Decoded full line as Base64: {node_entry[:50]} -> {decoded_full_line[:50]}")
                        else:
                            logger.debug(f"Failed to decode full line Base64: {node_entry[:50]}...")
                            # 如果解码失败，继续尝试将原始行作为节点处理

                    # 调用 parse_node 进行初步解析和信息提取
                    parsed_info = parse_node(final_processed_node_string)

                    if parsed_info:
                        # 生成唯一键进行去重。
                        # 对于代理节点，协议、地址、端口是核心标识。
                        # 用户ID/密码/加密方式也应加入，以区分同一服务器的不同用户。
                        node_key_elements = [
                            parsed_info.protocol,
                            parsed_info.address,
                            str(parsed_info.port), # 端口转为字符串
                        ]
                        if parsed_info.user_id:
                            node_key_elements.append(parsed_info.user_id)
                        if parsed_info.password:
                            node_key_elements.append(parsed_info.password)
                        if parsed_info.encryption: # 加密方式有时也区分节点
                            node_key_elements.append(parsed_info.encryption)

                        node_unique_key = "|".join(filter(None, node_key_elements)) # 过滤掉None值

                        if node_unique_key not in unique_nodes_keys:
                            unique_nodes_keys.add(node_unique_key)
                            processed_output_links.append(parsed_info.raw_link) # 保存原始完整的链接
                            parsed_nodes_count += 1
                        else:
                            duplicates_skipped_count += 1
                            logger.debug(f"Skipping duplicate node: {parsed_info.raw_link[:100]}...")
                    else:
                        malformed_or_unrecognized_count += 1
                        logger.debug(f"Skipping malformed/unrecognized node: {final_processed_node_string[:100]}...")

                except Exception as e:
                    logger.error(f"Error processing line '{node_entry[:100]}...': {e}")
                    malformed_or_unrecognized_count += 1
                    continue

    except requests.exceptions.RequestException as e:
        logger.critical(f"Network error during download: {e}. Please check NODE_URL or network connectivity.", exc_info=True)
        return
    except Exception as e:
        logger.critical(f"An unexpected critical error occurred during node download/processing: {e}", exc_info=True)
        return

    # 排序处理后的链接，保持输出文件的内容稳定，便于Git diff
    processed_output_links.sort()

    try:
        with open(OUTPUT_FILE, "w", encoding='utf-8') as f:
            for link in processed_output_links:
                f.write(link + "\n")
        logger.info(f"Successfully processed and saved {parsed_nodes_count} unique and recognized nodes to {OUTPUT_FILE}")
        logger.info(f"--- Processing Summary ---")
        logger.info(f"Total raw lines downloaded: {raw_nodes_count}")
        logger.info(f"Unique & Parsed Nodes Saved: {parsed_nodes_count}")
        logger.info(f"Duplicates Skipped: {duplicates_skipped_count}")
        logger.info(f"Malformed/Unrecognized Nodes Skipped: {malformed_or_unrecognized_count}")
    except IOError as e:
        logger.critical(f"Error writing to output file {OUTPUT_FILE}: {e}", exc_info=True)

if __name__ == "__main__":
    main()
