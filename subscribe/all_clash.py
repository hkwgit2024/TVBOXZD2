# -*- coding: utf-8 -*-
import os
import requests
import socket
import subprocess
import time
import base64
import logging
import yaml
import hashlib
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import argparse
import socks  # 需要安装 pysocks: pip install pysocks

# --- 配置日志 ---
logging.basicConfig(filename='error.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- 请求头 ---
headers = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/91.0.4472.124 Safari/537.36'
    ),
    'Accept-Encoding': 'gzip, deflate'
}

# --- 命令行参数 ---
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持节点连通性测试和协议级测试")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功节点数量")
parser.add_argument('--timeout', type=int, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.txt', help="输出文件路径")
parser.add_argument('--max_size', type=int, default=100*1024*1024, help="单个文件最大大小（字节，100MB）")
parser.add_argument('--max_total_size', type=int, default=1*1024*1024*1024, help="总输出大小限制（字节，1GB）")
parser.add_argument('--test_timeout', type=float, default=2.0, help="节点测试超时时间（秒）")
parser.add_argument('--max_test_workers', type=int, default=8, help="节点测试的最大并发数")
parser.add_argument('--enable_protocol_test', action='store_true', help="启用协议级测试（Shadowsocks 和 Trojan）")
args = parser.parse_args()

MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
MAX_FILE_SIZE = args.max_size
TOTAL_SIZE_LIMIT = args.max_total_size
TEST_TIMEOUT = args.test_timeout
MAX_TEST_WORKERS = args.max_test_workers
ENABLE_PROTOCOL_TEST = args.enable_protocol_test

# --- 辅助函数 ---
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def get_url_list(source_url):
    print(f"正在从源获取URL列表: {source_url}")
    try:
        response = requests.get(source_url, headers=headers, timeout=60)
        response.raise_for_status()
        raw_urls = response.text.splitlines()
        valid_urls = [url.strip() for url in raw_urls if is_valid_url(url.strip())]
        print(f"从 {source_url} 获取到 {len(valid_urls)} 个有效URL")
        return valid_urls
    except Exception as e:
        print(f"获取URL列表失败 ({source_url}): {e}")
        logging.error(f"Failed to get URL list from {source_url}: {e}")
        return []

def ping_node(server, timeout=TEST_TIMEOUT):
    try:
        cmd = ['ping', '-n' if os.name == 'nt' else '-c', '2', server]
        subprocess.run(cmd, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        logging.info(f"Ping successful for {server}")
        return True
    except subprocess.CalledProcessError:
        logging.warning(f"Ping failed for {server}")
        return False
    except Exception as e:
        logging.error(f"Ping error for {server}: {e}")
        return False

def test_node_connectivity(server, port, timeout=TEST_TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, int(port)))
        sock.close()
        logging.info(f"Node {server}:{port} is reachable (TCP)")
        return True
    except Exception as e:
        logging.error(f"Node {server}:{port} connection failed (TCP): {e}")
        return False

def test_proxy_node(node_line, timeout=TEST_TIMEOUT):
    if not ENABLE_PROTOCOL_TEST:
        return True  # 如果未启用协议级测试，直接返回 True
    try:
        if node_line.startswith('ss://'):
            # 解析 Shadowsocks 节点
            _, rest = node_line.split('://', 1)
            user_info, host_port = rest.split('@', 1)
            method, password = user_info.split(':', 1)
            server, port = host_port.split('#', 1)[0].split(':', 1)
            socks.set_default_proxy(socks.SOCKS5, server, int(port), username=method, password=password)
            socket.socket = socks.socksocket
            response = requests.get('https://api.ipify.org', timeout=timeout)
            logging.info(f"Node {server}:{port} is working (Shadowsocks). External IP: {response.text}")
            return True
        elif node_line.startswith('trojan://'):
            # 解析 Trojan 节点（仅示例，实际需 Trojan 客户端支持）
            _, rest = node_line.split('://', 1)
            password, host_port = rest.split('@', 1)
            server, port = host_port.split('#', 1)[0].split(':', 1)
            # Trojan 测试需要专用客户端（如 trojan-go），此处仅模拟 TCP 测试
            logging.warning(f"Trojan protocol test not fully implemented, falling back to TCP test for {server}:{port}")
            return test_node_connectivity(server, port, timeout)
        else:
            logging.warning(f"Protocol test not supported for {node_line}")
            return True  # 对不支持的协议跳过协议级测试
    except Exception as e:
        logging.error(f"Proxy test failed for {node_line}: {e}")
        return False
    finally:
        socket.socket = socket._socket.socket  # 重置 socket 以避免影响后续请求

def test_node_async(node_line):
    try:
        node_key = get_node_key(node_line)
        if node_key[0] in ['ss', 'vless', 'trojan', 'hysteria2', 'ssr']:
            server, port = node_key[-2], node_key[-1]
            if ping_node(server) and test_node_connectivity(server, port):
                if test_proxy_node(node_line):
                    return node_line
        logging.warning(f"Skipping node with unsupported key format or failed test: {node_line}")
        return None
    except Exception as e:
        logging.error(f"Error testing node {node_line}: {e}")
        return None

def get_node_key(node_line):
    node_line = node_line.strip()
    fallback_key = ('fallback_hash', hashlib.sha256(node_line.encode('utf-8')).hexdigest())
    try:
        if '://' not in node_line:
            return fallback_key
        protocol_part, rest = node_line.split('://', 1)
        protocol = protocol_part.lower()
        rest_no_fragment = rest.split('#', 1)[0]  # 移除 # 后的名称

        if protocol == 'vmess':
            try:
                encoded_json = rest_no_fragment
                missing_padding = len(encoded_json) % 4
                if missing_padding:
                    encoded_json += '=' * (4 - missing_padding)
                decoded_json_str = base64.b64decode(encoded_json).decode('utf-8')
                config = json.loads(decoded_json_str)
                uuid = config.get('id')
                server_address = str(config.get('add', '')).lower().rstrip('.')
                port = str(config.get('port', ''))
                if uuid and server_address and port:
                    return ('vmess', uuid, server_address, port)
            except Exception:
                return fallback_key

        elif protocol == 'ssr':
            try:
                decoded_ssr = base64.urlsafe_b64decode(rest_no_fragment + '=' * (4 - len(rest_no_fragment) % 4)).decode('utf-8')
                parts = decoded_ssr.split(':')
                if len(parts) >= 6:
                    server_host = parts[0].lower().rstrip('.')
                    server_port = parts[1]
                    password = parts[5].split('/')[0]
                    return ('ssr', password, server_host, server_port)
                return fallback_key
            except Exception:
                return fallback_key

        elif protocol in ['ss', 'vless', 'trojan', 'hysteria2']:
            user_info = ""
            host_spec_part = rest_no_fragment
            if '@' in rest_no_fragment:
                user_info, host_spec_part = rest_no_fragment.split('@', 1)
            server_host = ""
            server_port = ""
            if '?' in host_spec_part:
                host_spec_part, _ = host_spec_part.split('?', 1)
            last_colon_idx = host_spec_part.rfind(':')
            if last_colon_idx != -1 and host_spec_part[last_colon_idx:].lstrip(':').isdigit():
                server_port = host_spec_part[last_colon_idx+1:]
                server_host = host_spec_part[:last_colon_idx].lower().rstrip('.')
                if server_host.startswith('[') and server_host.endswith(']'):
                    server_host = server_host[1:-1]
            else:
                server_host = host_spec_part.lower().rstrip('.')
            identifier = user_info

            if protocol == 'ss':
                if ':' in identifier:
                    method, password = identifier.split(':', 1)
                    if server_host and server_port:
                        return (protocol, method, password, server_host, server_port)
                return fallback_key
            elif protocol in ['vless', 'trojan', 'hysteria2']:
                uuid_or_password = identifier
                if uuid_or_password and server_host and server_port:
                    return (protocol, uuid_or_password, server_host, server_port)
                return fallback_key
        else:
            logging.warning(f"Unsupported protocol {protocol} in node: {node_line}")
            return fallback_key
    except Exception as e:
        logging.debug(f"Failed to get node key for {node_line}: {e}")
        return fallback_key

def fetch_url(url):
    attempts = 3
    for attempt in range(1, attempts + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.text.strip()
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt} failed for {url}: {e}")
            if attempt == attempts:
                logging.error(f"Failed to fetch {url} after {attempts} attempts")
                raise
            time.sleep(2 ** attempt)  # Exponential backoff: 2, 4, 8 seconds

def process_url(url):
    try:
        head_resp = requests.head(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        head_resp.raise_for_status()
        content_type = head_resp.headers.get('Content-Type', '')
        content_length = int(head_resp.headers.get('Content-Length', 0))
        
        if 'text' not in content_type.lower() and 'application/x-yaml' not in content_type.lower() and 'application/json' not in content_type.lower():
            logging.warning(f"Skipping {url}: Invalid Content-Type: {content_type}")
            return None, url, False
        if content_length > 10 * 1024 * 1024:
            logging.warning(f"Skipping {url}: Content too large ({content_length} bytes)")
            return None, url, False
        
        text_content = fetch_url(url)
        decoded_content = None
        is_base64_decoded = False
        
        try:
            decoded_content = base64.b64decode(text_content).decode('utf-8')
            is_base64_decoded = True
        except (base64.binascii.Error, UnicodeDecodeError):
            pass

        content_to_parse = decoded_content if is_base64_decoded else text_content

        try:
            yaml_config = yaml.safe_load(content_to_parse)
            if isinstance(yaml_config, dict) and 'proxies' in yaml_config and isinstance(yaml_config['proxies'], list):
                proxy_nodes = []
                for proxy in yaml_config['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy and 'server' in proxy and 'port' in proxy:
                        proxy_nodes.append(str(proxy))
                    else:
                        logging.warning(f"Skipping invalid proxy in Clash config from {url}: {proxy}")
                if proxy_nodes:
                    return content_to_parse, url, True
                else:
                    logging.warning(f"Clash config found but no valid proxies extracted from {url}.")
                    return None, url, False
            else:
                if len(text_content) > 50 and any(text_content.startswith(p) for p in ["ss://", "vmess://", "vless://", "trojan://", "hysteria2://"]):
                    return content_to_parse, url, True
                else:
                    logging.warning(f"Content is too short or not a recognized format: {url}")
                    return None, url, False
        except yaml.YAMLError:
            if len(text_content) > 50 and any(text_content.startswith(p) for p in ["ss://", "vmess://", "vless://", "trojan://", "hysteria2://"]):
                return content_to_parse, url, True
            else:
                logging.warning(f"Direct text content is too short or not recognized: {url}")
                return None, url, False
        except Exception as e:
            logging.error(f"Error during content parsing for {url}: {e}")
            return None, url, False
    except requests.exceptions.Timeout:
        logging.error(f"Request timed out: {url}")
        return None, url, False
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for {url}: {e}")
        return None, url, False
    except Exception as e:
        logging.error(f"Unhandled error processing {url}: {e}")
        return None, url, False

# --- 主程序逻辑 ---
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")
if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。请设置环境变量并重试。")
    logging.critical("Environment variable 'URL_SOURCE' not set. Exiting.")
    exit(1)

url_sources = [URL_SOURCE]
all_raw_urls = []
for source in url_sources:
    raw_urls = get_url_list(source)
    all_raw_urls.extend(raw_urls)

unique_urls = list(sorted(list({url.strip() for url in all_raw_urls if url.strip()})))
print(f"合并后唯一URL数量：{len(unique_urls)}")

output_dir = os.path.dirname(OUTPUT_FILE)
os.makedirs(output_dir, exist_ok=True)

successful_urls = []
failed_urls = []
seen_node_keys = set()
success_count = 0
file_index = 1
current_file_size = 0
total_size = 0
base_output_file = os.path.splitext(OUTPUT_FILE)[0]
extension = os.path.splitext(OUTPUT_FILE)[1]

def open_new_output_file(index):
    file_path = f"{base_output_file}_{index}{extension}"
    logging.info(f"Opening new output file: {file_path}")
    return open(file_path, 'w', encoding='utf-8')

out_file = None
try:
    out_file = open_new_output_file(file_index)
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_url = {executor.submit(process_url, url): url for url in unique_urls}
        for future in tqdm(as_completed(future_to_url), total=len(unique_urls), desc="处理URL"):
            result_content, original_url, success = future.result()
            if result_content and success_count < MAX_SUCCESS:
                nodes = result_content.strip().splitlines()
                nodes = [node.strip() for node in nodes if node.strip()]
                if not nodes:
                    logging.warning(f"No valid nodes found in {original_url}")
                    failed_urls.append(original_url)
                    continue
                # 过滤过期节点
                nodes = [node for node in nodes if not any(keyword in node for keyword in ['过期', '续费', 'expired'])]
                # 异步测试节点连通性
                with ThreadPoolExecutor(max_workers=MAX_TEST_WORKERS) as test_executor:
                    valid_nodes = list(test_executor.map(test_node_async, nodes))
                    valid_nodes = [n for n in valid_nodes if n]
                
                current_batch_unique_nodes = []
                for node_line in valid_nodes:
                    node_key = get_node_key(node_line)
                    if node_key in seen_node_keys:
                        logging.debug(f"Duplicate node skipped: {node_line} (key: {node_key})")
                        continue
                    seen_node_keys.add(node_key)
                    current_batch_unique_nodes.append(node_line)
                    success_count += 1
                    logging.info(f"Added valid node: {node_line}")
                    if success_count >= MAX_SUCCESS:
                        break
                
                if current_batch_unique_nodes:
                    content_to_write = '\n'.join(current_batch_unique_nodes)
                    result_bytes = (content_to_write + '\n').encode('utf-8')
                    if total_size + len(result_bytes) > TOTAL_SIZE_LIMIT:
                        logging.warning(f"Reached total size limit ({TOTAL_SIZE_LIMIT / (1024*1024):.2f} MB). Stopping write operations.")
                        if out_file and not out_file.closed:
                            out_file.close()
                        break
                    if current_file_size + len(result_bytes) > MAX_FILE_SIZE:
                        logging.info(f"Current file {out_file.name} reached max size. Switching to new file.")
                        if out_file and not out_file.closed:
                            out_file.close()
                        file_index += 1
                        current_file_size = 0
                        out_file = open_new_output_file(file_index)
                    out_file.write(content_to_write + '\n')
                    current_file_size += len(result_bytes)
                    total_size += len(result_bytes)
                    successful_urls.append(original_url)
                    logging.info(f"Processed {original_url}: {len(nodes)} nodes found, {len(current_batch_unique_nodes)} unique and valid nodes added")
                else:
                    logging.warning(f"No valid nodes after testing for {original_url}")
                    failed_urls.append(original_url)
            else:
                if not result_content and not success:
                    failed_urls.append(original_url)
            if success_count >= MAX_SUCCESS:
                logging.info(f"Reached MAX_SUCCESS ({MAX_SUCCESS}) unique nodes. Terminating further URL processing.")
                break
finally:
    if out_file and not out_file.closed:
        out_file.close()
        logging.info(f"Closed final output file: {out_file.name}")

with open(os.path.join(output_dir, 'successful_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(successful_urls))
print(f"成功URL记录至：{os.path.join(output_dir, 'successful_urls.txt')}")

with open(os.path.join(output_dir, 'failed_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(failed_urls))
print(f"失败URL记录至：{os.path.join(output_dir, 'failed_urls.txt')}")

print("\n" + "=" * 50)
print("最终结果：")
print(f"处理URL总数：{len(unique_urls)}")
print(f"成功获取并去重节点数：{success_count}")
print(f"输出文件数量：{file_index}")
print(f"总输出大小：{total_size / (1024*1024):.2f} MB")
if len(unique_urls) > 0:
    print(f"成功处理URL率：{len(successful_urls)/len(unique_urls):.1%}")
print(f"结果文件已保存至：{base_output_file}_[1-{file_index}]{extension}")
print("=" * 50)
