import requests
import base64
import re
import os
import urllib.parse
import json
import logging
from collections import namedtuple

# --- 配置日志 ---
# 默认设置为 INFO 级别，以减少 GitHub Actions 中的日志量，提高运行效率。
# 如果需要详细调试，可以临时改为 logging.DEBUG。
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 常量定义 ---
# 所有的节点源 URL 列表
NODE_URLS = [
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
]
OUTPUT_FILE = "data/sub.txt"
DOWNLOAD_TIMEOUT = 60 # 下载超时时间，单位秒

# 定义一个具名元组来标准化解析后的节点信息
ParsedNode = namedtuple(
    'ParsedNode',
    ['protocol', 'address', 'port', 'user_id', 'password', 'encryption', 'name', 'remark', 'network', 'tls', 'sni', 'obfs', 'raw_link']
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

    # 预过滤，快速排除明显不符合 Base64 字符集的字符串
    if not re.fullmatch(r'^[a-zA-Z0-9+/=-]+$', data):
        logger.debug(f"Quick filter: Data contains non-Base64 chars '{data[:50]}...'")
        return None

    # 尝试去除可能的多余URL编码或特殊字符
    data = data.replace(' ', '').replace('\n', '').replace('\r', '')

    try:
        # 添加或移除填充
        missing_padding = len(data) % 4
        if missing_padding == 2:
            data += '=='
        elif missing_padding == 3:
            data += '='
        elif missing_padding == 1: # 这种情况通常是无效的Base64
            logger.debug(f"Base64 padding issue (len % 4 == 1) for '{data[:50]}...'")
            return None

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
    protocol, address, port, user_id, password, encryption, name, remark, network, tls, sni, obfs = (None,) * 12

    try:
        # 使用 urllib.parse.urlparse 解析 URL
        parsed_url = urllib.parse.urlparse(original_link)
        protocol = parsed_url.scheme.lower()
        
        # 快速过滤掉明显无效的协议
        supported_protocols = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2'}
        if protocol not in supported_protocols:
            logger.debug(f"Unsupported protocol '{protocol}' for link: {original_link[:100]}...")
            return None

        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query) # 解析查询参数
        fragment = parsed_url.fragment # 解析 URL 片段 (通常是节点名称)

        # 优先使用 URL 片段作为名称
        if fragment:
            name = urllib.parse.unquote(fragment) # 解码名称

        # --- 各协议解析逻辑 ---
        if protocol == "vmess":
            # VMess: base64(json_config)
            # parsed_url.netloc + path 是 Base64 编码的 JSON 字符串
            vmess_data_encoded = parsed_url.netloc + path.lstrip('/')
            decoded_json_str = decode_base64_url(vmess_data_encoded)
            if decoded_json_str:
                try:
                    vmess_config = json.loads(decoded_json_str)
                    address = vmess_config.get('add')
                    port = vmess_config.get('port')
                    user_id = vmess_config.get('id')
                    encryption = vmess_config.get('scy')
                    network = vmess_config.get('net')
                    tls = 'tls' if vmess_config.get('tls') == 'tls' else None
                    sni = vmess_config.get('host')
                    name = name or vmess_config.get('ps')
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
                addr_port = auth_addr_port # VLESS可能没有直接的UUID在netloc
                logger.debug(f"VLESS link missing UUID in netloc: {original_link[:100]}...")

            if ':' in addr_port:
                address, port_str = addr_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"VLESS invalid port: {port_str} in {original_link[:100]}...")
                    port = None

            network = query.get('type', [None])[0]
            tls = query.get('security', [None])[0]
            sni = query.get('sni', [None])[0]
            
        elif protocol == "trojan":
            # Trojan: password@address:port?params#name
            # netloc 包含 password@address:port
            auth_addr_port = parsed_url.netloc
            if '@' in auth_addr_port:
                password, addr_port = auth_addr_port.split('@', 1)
            else:
                addr_port = auth_addr_port
                logger.debug(f"Trojan link missing password in netloc: {original_link[:100]}...")

            if ':' in addr_port:
                address, port_str = addr_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.debug(f"Trojan invalid port: {port_str} in {original_link[:100]}...")
                    port = None
            
            tls = query.get('security', [None])[0]
            sni = query.get('sni', [None])[0]

        elif protocol == "ss":
            # SS: base64(method:password)@address:port#name OR method:password@address:port#name
            # urllib.parse.urlparse 把 'method:password@' 或 'method:password' 放在 netloc
            auth_part_raw = parsed_url.netloc

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
                address = addr_port_part # Fallback if no port specified (unlikely)
                logger.debug(f"SS link missing port: {original_link[:100]}...")

        elif protocol == "ssr":
            # SSR: base64(server:port:protocol:method:obfs:password_base64/?params)
            # SSR 链接通常整个 "host/path" 部分都是 Base64 编码的
            ssr_data_encoded = parsed_url.netloc + path.lstrip('/')
            decoded_ssr_params = decode_base64_url(ssr_data_encoded)
            if decoded_ssr_params:
                try:
                    parts = decoded_ssr_params.split(':')
                    if len(parts) >= 5: # 至少 server:port:protocol:method:obfs
                        address = parts[0]
                        port = int(parts[1])
                        # ssr_protocol = parts[2]
                        encryption = parts[3]
                        obfs = parts[4]
                        if len(parts) >= 6:
                            # 密码通常是最后一个参数，并且可能带有 URL 查询参数
                            password_and_params = parts[5]
                            password = decode_base64_url(password_and_params.split('/')[0]) # 密码也可能Base64解码
                except (ValueError, IndexError):
                    logger.debug(f"SSR param parse error: {decoded_ssr_params[:100]} for {original_link[:100]}...")
                except Exception:
                    logger.debug(f"SSR unexpected error parsing: {decoded_ssr_params[:100]} in {original_link[:100]}...")
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
            obfs = query.get('obfs', [None])[0]
        
        # --- 如果至少解析出了协议、地址和端口，则认为初步解析成功 ---
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
                obfs=obfs,
                raw_link=original_link # 保存原始链接以便输出
            )
        else:
            logger.debug(f"Failed to extract essential info (addr/port) for {protocol} from: {original_link[:100]}...")
            return None

    except Exception as e:
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
            logger.critical(f"Failed to create directory {output_dir}: {e}")
            return # 无法创建目录则退出

    # 使用集合存储节点唯一键，用于高效去重
    unique_nodes_keys = set()
    # 使用列表存储最终要写入文件的原始链接字符串
    processed_output_links = []

    raw_lines_total = 0 # 统计从所有源下载到的总行数
    parsed_nodes_count = 0
    duplicates_skipped_count = 0
    malformed_or_unrecognized_count = 0

    for url in NODE_URLS:
        logger.info(f"Downloading from: {url}")
        try:
            response = requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status()
            logger.info(f"Successfully downloaded from {url} (streaming).")

            for line_bytes in response.iter_lines(chunk_size=8192):
                if line_bytes:
                    raw_lines_total += 1
                    try:
                        node_entry = line_bytes.decode('utf-8', errors='ignore').strip()
                        if not node_entry:
                            continue # 跳过空行

                        final_processed_node_string = node_entry

                        # 优化：快速检查是否可能是 Base64 编码的完整节点行
                        # 避免对所有行都尝试 Base64 解码，只对看起来像 Base64 的行进行。
                        # 长度限制避免误判短字符串
                        if len(node_entry) > 15 and re.fullmatch(r'^[a-zA-Z0-9+/=-]+$', node_entry):
                            decoded_full_line = decode_base64_url(node_entry)
                            if decoded_full_line:
                                final_processed_node_string = decoded_full_line
                            else:
                                # 如果Base64解码失败，但原字符串可能也是一个URL，继续尝试处理原字符串
                                logger.debug(f"Line looks like Base64 but decode failed, processing original: {node_entry[:50]}...")
                                pass # 继续使用 original_link

                        # 调用 parse_node 进行初步解析和信息提取
                        parsed_info = parse_node(final_processed_node_string)

                        if parsed_info:
                            # 生成唯一键进行去重。
                            # 协议、地址、端口是核心标识。用户ID/密码/加密方式/混淆方式也应加入。
                            node_key_elements = [
                                parsed_info.protocol,
                                parsed_info.address,
                                str(parsed_info.port),
                            ]
                            if parsed_info.user_id: node_key_elements.append(parsed_info.user_id)
                            if parsed_info.password: node_key_elements.append(parsed_info.password)
                            if parsed_info.encryption: node_key_elements.append(parsed_info.encryption)
                            if parsed_info.obfs: node_key_elements.append(parsed_info.obfs) # 增加obfs
                            if parsed_info.network: node_key_elements.append(parsed_info.network) # 增加network
                            if parsed_info.tls: node_key_elements.append(parsed_info.tls) # 增加tls
                            if parsed_info.sni: node_key_elements.append(parsed_info.sni) # 增加sni

                            node_unique_key = "|".join(filter(None, node_key_elements)) # 过滤掉None值

                            if node_unique_key not in unique_nodes_keys:
                                unique_nodes_keys.add(node_unique_key)
                                processed_output_links.append(parsed_info.raw_link) # 保存原始完整的链接
                                parsed_nodes_count += 1
                                # logger.debug(f"Added node: {parsed_info.raw_link[:100]}...") # 调试时启用
                            else:
                                duplicates_skipped_count += 1
                                logger.debug(f"Skipping duplicate node: {parsed_info.raw_link[:100]}...")
                        else:
                            malformed_or_unrecognized_count += 1
                            # logger.debug(f"Skipping malformed/unrecognized: {final_processed_node_string[:100]}...") # 调试时启用

                    except Exception as e:
                        logger.error(f"Error processing line '{node_entry[:100]}...': {e}")
                        malformed_or_unrecognized_count += 1
                        continue

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error downloading from {url}: {e}")
        except Exception as e:
            logger.critical(f"An unexpected critical error occurred during processing from {url}: {e}", exc_info=True)
            
    # 排序处理后的链接，保持输出文件的内容稳定，便于Git diff
    processed_output_links.sort()

    try:
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
        logger.critical(f"Error writing to output file {OUTPUT_FILE}: {e}", exc_info=True)

if __name__ == "__main__":
    main()
