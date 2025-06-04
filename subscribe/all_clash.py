# -*- coding: utf-8 -*-
import os
import requests
from urllib.parse import urlparse
import base64
import logging
import yaml
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import argparse
from tenacity import retry, stop_after_attempt, wait_exponential

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
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功节点数量")
parser.add_argument('--timeout', type=int, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.txt', help="输出文件路径")
parser.add_argument('--max_size', type=int, default=100*1024*1024, help="单个文件最大大小（字节，100MB）")
parser.add_argument('--max_total_size', type=int, default=1*1024*1024*1024, help="总输出大小限制（字节，1GB）")
args = parser.parse_args()

MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
MAX_FILE_SIZE = args.max_size
TOTAL_SIZE_LIMIT = args.max_total_size

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

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def fetch_url(url):
    resp = requests.get(url, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.text.strip()

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
                return text_content, url, True
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
                current_batch_unique_nodes = []
                for node_line in nodes:
                    node_line = node_line.strip()
                    if not node_line:
                        continue
                    if any(keyword in node_line for keyword in ['过期', '续费', 'expired']):
                        logging.warning(f"Skipping expired node: {node_line}")
                        continue
                    node_key = get_node_key(node_line)
                    if node_key in seen_node_keys:
                        logging.debug(f"Duplicate node skipped: {node_line} (key: {node_key})")
                        continue
                    seen_node_keys.add(node_key)
                    current_batch_unique_nodes.append(node_line)
                    success_count += 1
                    logging.info(f"Added unique node: {node_line}")
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
                    logging.info(f"Processed {original_url}: {len(nodes)} nodes found, {len(current_batch_unique_nodes)} unique nodes added")
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
