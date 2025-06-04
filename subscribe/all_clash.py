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

# --- 配置日志 ---
logging.basicConfig(filename='error.log', level=logging.INFO,
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
parser.add_argument('--max_size', type=int, default=1024*1024*1024, help="单个文件最大大小（字节）")
parser.add_argument('--max_total_size', type=int, default=10*1024*1024*1024, help="总输出大小限制（字节）")
args = parser.parse_args()

MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
MAX_FILE_SIZE = args.max_size
TOTAL_SIZE_LIMIT = args.max_total_size

# --- 辅助函数 ---
def is_valid_url(url):
    """验证URL格式是否合法"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def get_url_list(source_url):
    """从单个源URL获取URL列表"""
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
    """
    为代理节点字符串生成一个唯一的键，用于去重。
    键的组成部分: (协议, 标识符, 小写的服务器主机名, 端口)
    如果解析失败，则返回内容的SHA256哈希值作为后备。
    """
    node_line = node_line.strip()
    # 如果无法解析，使用其内容的SHA256哈希值作为后备键
    fallback_key = ('fallback_hash', hashlib.sha256(node_line.encode('utf-8')).hexdigest())

    try:
        if '://' not in node_line:
            return fallback_key

        protocol_part, rest = node_line.split('://', 1)
        protocol = protocol_part.lower()

        # 移除URL片段（#后面的部分，通常是名称）
        if '#' in rest:
            rest_no_fragment, _ = rest.split('#', 1)
        else:
            rest_no_fragment = rest
            
        # 处理vmess
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
                return fallback_key # 解析失败，使用哈希值

        # 处理ss, vless, trojan, hysteria2
        elif protocol in ['ss', 'vless', 'trojan', 'hysteria2']:
            user_info = ""
            host_spec_part = rest_no_fragment

            if '@' in rest_no_fragment:
                user_info, host_spec_part = rest_no_fragment.split('@', 1)

            server_host = ""
            server_port = ""
            
            # 移除查询参数
            if '?' in host_spec_part:
                host_spec_part, _ = host_spec_part.split('?', 1)

            last_colon_idx = host_spec_part.rfind(':')
            if last_colon_idx != -1 and host_spec_part[last_colon_idx:].lstrip(':').isdigit():
                # 确保冒号后确实是端口号
                potential_host = host_spec_part[:last_colon_idx]
                potential_port = host_spec_part[last_colon_idx+1:]
                
                server_port = potential_port
                server_host = potential_host
                # 处理IPv6地址，移除方括号
                if server_host.startswith('[') and server_host.endswith(']'):
                    server_host = server_host[1:-1]
                server_host = server_host.lower().rstrip('.')
            else:
                server_host = host_spec_part.lower().rstrip('.')
                # 如果没有端口，port为空，但在这种情况下，去重键的有效性会降低

            identifier = user_info # 使用user_info作为通用标识符

            if protocol == 'ss':
                # SS协议的user_info是 method:password
                if ':' in identifier:
                    method, password = identifier.split(':', 1)
                    if server_host and server_port: # 确保主机和端口存在
                        return (protocol, method, password, server_host, server_port)
                return fallback_key
            
            elif protocol in ['vless', 'trojan', 'hysteria2']:
                # 这些协议的user_info通常是UUID或密码
                uuid_or_password = identifier
                if uuid_or_password and server_host and server_port: # 确保标识符、主机和端口存在
                    return (protocol, uuid_or_password, server_host, server_port)
                return fallback_key
                
    except Exception as e:
        # logging.debug(f"Failed to get node key for {node_line}: {e}") # 可选：记录更详细的解析失败信息
        return fallback_key # 解析失败，使用哈希值
    
    return fallback_key # 如果没有匹配的协议或解析不完全，使用哈希值

def process_url(url):
    """
    处理单个URL，获取内容并验证其是否为有效的Clash配置或代理节点列表。
    成功则返回解码后的内容(字符串形式)，失败则返回None。
    """
    try:
        # 1. 发送HEAD请求检查内容类型和大小
        head_resp = requests.head(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        head_resp.raise_for_status()
        content_type = head_resp.headers.get('Content-Type', '')
        content_length = int(head_resp.headers.get('Content-Length', 0))
        
        if 'text' not in content_type.lower() and 'application/x-yaml' not in content_type.lower() and 'application/json' not in content_type.lower():
            logging.warning(f"Skipping {url}: Invalid Content-Type: {content_type}")
            return None, url, False
        if content_length > 10 * 1024 * 1024: # 10MB
            logging.warning(f"Skipping {url}: Content too large ({content_length} bytes)")
            return None, url, False
        
        # 2. 下载完整内容
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        text_content = resp.text.strip()
        
        # 3. 尝试解析内容
        decoded_content = None
        is_base64_decoded = False
        
        # 尝试 Base64 解码
        try:
            decoded_content = base64.b64decode(text_content).decode('utf-8')
            is_base64_decoded = True
        except (base64.binascii.Error, UnicodeDecodeError):
            pass # 不是有效的Base64编码，继续尝试直接作为文本处理

        content_to_parse = decoded_content if is_base64_decoded else text_content

        # 4. 尝试 YAML 解析和 Clash 配置验证
        try:
            yaml_config = yaml.safe_load(content_to_parse)

            # 检查是否为有效的Clash配置结构
            if isinstance(yaml_config, dict) and 'proxies' in yaml_config and isinstance(yaml_config['proxies'], list):
                # 如果是Clash配置，提取其代理节点
                # 这里假设Clash配置中的proxies列表是需要提取的节点
                proxy_nodes = []
                for proxy in yaml_config['proxies']:
                    # 检查代理节点是否包含关键字段，可以根据需要调整验证逻辑
                    if isinstance(proxy, dict) and 'type' in proxy and 'server' in proxy and 'port' in proxy:
                        # 尝试将代理节点转换为标准格式（如 Base64 编码的 VMess 或直接的 SS/VLESS/Trojan 链接）
                        # 这部分逻辑会比较复杂，目前直接使用字典表示，可能需要进一步转换成URL字符串
                        # 简单起见，这里直接返回 YAML 内容，去重逻辑将在主循环中处理每行
                        proxy_nodes.append(str(proxy)) # 将字典转换为字符串，后续get_node_key需要处理
                    else:
                        logging.warning(f"Skipping invalid proxy in Clash config from {url}: {proxy}")
                
                # 如果提取到了有效代理节点，则认为该URL有效
                if proxy_nodes:
                    # 返回原始YAML内容，因为去重是针对每一行的
                    return content_to_parse, url, True
                else:
                    logging.warning(f"Clash config found but no valid proxies extracted from {url}.")
                    return None, url, False
            else:
                # 如果不是Clash配置，尝试作为纯节点列表处理
                # 这里只验证长度，并假设每一行都是一个独立的代理节点
                if len(text_content) > 50: # 认为节点列表至少有一定长度
                    # 对于非Clash配置，如果不是Base64编码，直接返回原文
                    # 如果是Base64解码，但不是Clash配置，可能也是节点列表
                    return content_to_parse, url, True
                else:
                    logging.warning(f"Content is too short or not a recognized format (YAML/Base64 nodes): {url}")
                    return None, url, False
        except yaml.YAMLError:
            # YAML解析失败，尝试作为纯节点列表处理
            if len(text_content) > 50: # 认为节点列表至少有一定长度
                 # 简单检查是否包含常见协议头，作为额外验证
                if any(text_content.startswith(p) for p in ["ss://", "vmess://", "vless://", "trojan://", "hysteria2://"]):
                    return text_content, url, True
                else:
                    logging.warning(f"Direct text content not a valid YAML or recognized node format: {url}")
                    return None, url, False
            else:
                logging.warning(f"Direct text content is too short: {url}")
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

# 从环境变量中读取 URL_SOURCE 并调试
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")
if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。请设置环境变量并重试。")
    logging.critical("Environment variable 'URL_SOURCE' not set. Exiting.")
    exit(1)

# URL 来源列表
url_sources = [URL_SOURCE]

# 获取所有URL来源的URL列表
all_raw_urls = []
for source in url_sources:
    raw_urls = get_url_list(source)
    all_raw_urls.extend(raw_urls)

# 去重并验证URL格式
unique_urls = list(sorted(list({url.strip() for url in all_raw_urls if url.strip()})))
print(f"合并后唯一URL数量：{len(unique_urls)}")

# 确保输出目录存在
output_dir = os.path.dirname(OUTPUT_FILE)
os.makedirs(output_dir, exist_ok=True)

# 初始化成功和失败URL列表
successful_urls = []
failed_urls = []
seen_node_keys = set() # 用于存储已去重节点的键

# 处理URL内容并写入文件
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

out_file = None # 初始化文件句柄

try:
    out_file = open_new_output_file(file_index)

    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(process_url, url): url for url in unique_urls}
        
        # 使用tqdm显示进度条
        for future in tqdm(as_completed(future_to_url), total=len(unique_urls), desc="处理URL"):
            result_content, original_url, success = future.result()

            if result_content and success_count < MAX_SUCCESS:
                # 无论 content_type 是 Clash YAML 还是纯节点列表，都按行处理
                nodes = result_content.strip().splitlines()
                current_batch_unique_nodes = [] # 存储当前URL中去重后的节点

                for node_line in nodes:
                    node_line = node_line.strip()
                    if not node_line:
                        continue # 跳过空行

                    node_key = get_node_key(node_line)
                    if node_key not in seen_node_keys:
                        seen_node_keys.add(node_key)
                        current_batch_unique_nodes.append(node_line)
                        success_count += 1
                        if success_count >= MAX_SUCCESS:
                            # 达到目标节点数量，立即停止处理当前URL的剩余节点
                            break 
                
                if current_batch_unique_nodes:
                    content_to_write = '\n'.join(current_batch_unique_nodes)
                    result_bytes = (content_to_write + '\n').encode('utf-8')

                    # 检查总大小限制
                    if total_size + len(result_bytes) > TOTAL_SIZE_LIMIT:
                        logging.warning(f"Reached total size limit ({TOTAL_SIZE_LIMIT / (1024*1024):.2f} MB). Stopping write operations.")
                        # 关闭当前文件
                        if out_file and not out_file.closed:
                            out_file.close()
                        break # 跳出 URL 处理循环

                    # 检查单个文件大小限制
                    if current_file_size + len(result_bytes) > MAX_FILE_SIZE:
                        logging.info(f"Current file {out_file.name} reached max size. Switching to new file.")
                        # 关闭当前文件，打开新文件
                        if out_file and not out_file.closed:
                            out_file.close()
                        file_index += 1
                        current_file_size = 0
                        out_file = open_new_output_file(file_index)

                    out_file.write(content_to_write + '\n')
                    current_file_size += len(result_bytes)
                    total_size += len(result_bytes)
                    successful_urls.append(original_url) # 记录成功处理的URL
            else:
                # 只有当明确失败（result_content为None且success为False）才加入failed_urls
                # 或者因为达到MAX_SUCCESS而跳过处理的URL不加入failed_urls
                if not result_content and not success:
                    failed_urls.append(original_url)
            
            # 再次检查是否达到MAX_SUCCESS，如果已达到则中断整个处理过程
            if success_count >= MAX_SUCCESS:
                logging.info(f"Reached MAX_SUCCESS ({MAX_SUCCESS}) unique nodes. Terminating further URL processing.")
                break # 跳出 as_completed 循环

finally:
    # 确保在脚本结束时关闭所有文件句柄
    if out_file and not out_file.closed:
        out_file.close()
        logging.info(f"Closed final output file: {out_file.name}")

# --- 记录成功和失败的URL ---
with open(os.path.join(output_dir, 'successful_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(successful_urls))
print(f"成功URL记录至：{os.path.join(output_dir, 'successful_urls.txt')}")

with open(os.path.join(output_dir, 'failed_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(failed_urls))
print(f"失败URL记录至：{os.path.join(output_dir, 'failed_urls.txt')}")

# --- 最终结果报告 ---
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
