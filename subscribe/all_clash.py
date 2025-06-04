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

# 配置日志
logging.basicConfig(filename='error.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 请求头
headers = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/91.0.4472.124 Safari/537.36'
    ),
    'Accept-Encoding': 'gzip, deflate'
}

# 命令行参数
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
        return []

def get_node_key(node_line):
    """
    为代理节点字符串生成一个唯一的键，用于去重。
    键的组成部分: (协议, 标识符, 小写的服务器主机名, 端口)
    如果解析失败，则返回原始 node_line 作为后备。
    """
    node_line = node_line.strip()
    original_node_for_fallback = node_line

    try:
        if '://' not in node_line:
            return original_node_for_fallback

        protocol_part, rest = node_line.split('://', 1)
        protocol = protocol_part.lower()

        if '#' in rest:
            rest_no_fragment, _ = rest.split('#', 1)
        else:
            rest_no_fragment = rest
        
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
                return original_node_for_fallback

        elif protocol in ['ss', 'vless', 'hysteria2']:
            if '@' not in rest_no_fragment:
                return original_node_for_fallback

            auth_part, host_spec_part = rest_no_fragment.split('@', 1)

            if '?' in host_spec_part:
                host_and_port_part, _ = host_spec_part.split('?', 1)
            else:
                host_and_port_part = host_spec_part
            
            server_host = ""
            server_port = ""

            last_colon_idx = host_and_port_part.rfind(':')
            if last_colon_idx != -1:
                potential_host = host_and_port_part[:last_colon_idx]
                potential_port = host_and_port_part[last_colon_idx+1:]
                if potential_port.isdigit():
                    server_port = potential_port
                    server_host = potential_host
                    if server_host.startswith('[') and server_host.endswith(']'):
                        server_host = server_host[1:-1]
                    server_host = server_host.lower().rstrip('.')
                else:
                    server_host = host_and_port_part.lower().rstrip('.')
                    server_port = ""
            else:
                server_host = host_and_port_part.lower().rstrip('.')
                server_port = ""

            identifier = auth_part
            
            if protocol == 'ss':
                if ':' in identifier:
                    method, password = identifier.split(':', 1)
                    if server_host and server_port:
                        return (protocol, method, password, server_host, server_port)
                return original_node_for_fallback
            
            elif protocol in ['vless', 'hysteria2']:
                uuid = identifier
                if uuid and server_host and server_port:
                    return (protocol, uuid, server_host, server_port)
                return original_node_for_fallback
        
    except Exception:
        return original_node_for_fallback

def process_url(url):
    """
    处理单个URL，获取内容。
    成功则返回解码后的内容(字符串形式，可能包含多行)，失败则返回None。
    """
    try:
        # 检查响应头
        head_resp = requests.head(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        head_resp.raise_for_status()
        content_type = head_resp.headers.get('Content-Type', '')
        content_length = int(head_resp.headers.get('Content-Length', 0))
        
        if 'text' not in content_type.lower() or content_length > 10 * 1024 * 1024:
            logging.error(f"无效内容类型或过大: {url} - Content-Type: {content_type}, Size: {content_length}")
            return None, url, False
        
        # 下载完整内容
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        text_content = resp.text.strip()
        
        # 基本过滤
        if len(text_content) < 10 or any(x in text_content for x in ["DOMAIN", "port", "proxies"]):
            return None, url, False
        
        # 验证Clash配置
        try:
            decoded_content = base64.b64decode(text_content).decode('utf-8')
            yaml.safe_load(decoded_content)
            if not any(k in decoded_content for k in ["server", "password", "type"]):
                return None, url, False
            return decoded_content, url, True
        except base64.binascii.Error:
            if len(text_content) >= 10 and not any(x in text_content for x in ["DOMAIN", "port", "proxies"]):
                try:
                    yaml.safe_load(text_content)
                    if any(k in text_content for k in ["server", "password", "type"]):
                        return text_content, url, True
                except Exception:
                    pass
            return None, url, False
        except UnicodeDecodeError:
            return None, url, False
    except requests.exceptions.Timeout:
        logging.error(f"请求超时: {url}")
        return None, url, False
    except requests.exceptions.RequestException as e:
        logging.error(f"请求失败: {url} - {e}")
        return None, url, False
    except Exception as e:
        logging.error(f"处理失败: {url} - {e}")
        return None, url, False

# 从环境变量中读取 URL_SOURCE 并调试
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")
if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。请设置环境变量并重试。")
    exit(1)

# URL 来源列表
url_sources = [URL_SOURCE]

# 获取所有URL来源的URL列表
all_raw_urls = []
for source in url_sources:
    raw_urls = get_url_list(source)
    all_raw_urls.extend(raw_urls)

# 去重并验证URL格式
unique_urls = list({url.strip() for url in all_raw_urls if url.strip()})
print(f"合并后唯一URL数量：{len(unique_urls)}")

# 确保输出目录存在
output_dir = os.path.dirname(OUTPUT_FILE)
os.makedirs(output_dir, exist_ok=True)

# 初始化成功和失败URL列表
successful_urls = []
failed_urls = []
seen_node_keys = set()

# 处理URL内容
success_count = 0
file_index = 1
current_file_size = 0
total_size = 0
base_output_file = os.path.splitext(OUTPUT_FILE)[0]
extension = os.path.splitext(OUTPUT_FILE)[1]
out_file = open(f"{base_output_file}_{file_index}{extension}", 'w', encoding='utf-8')

with ThreadPoolExecutor(max_workers=16) as executor:
    future_to_url = {executor.submit(process_url, url): url for url in unique_urls}
    for future in tqdm(as_completed(future_to_url), total=len(unique_urls), desc="处理URL"):
        result, url, success = future.result()
        if result and success_count < MAX_SUCCESS:
            # 处理多行节点并去重
            nodes = result.strip().splitlines()
            unique_nodes = []
            for node in nodes:
                node = node.strip()
                if not node:
                    continue
                node_key = get_node_key(node)
                if node_key not in seen_node_keys:
                    seen_node_keys.add(node_key)
                    unique_nodes.append(node)
                    success_count += 1
                    if success_count >= MAX_SUCCESS:
                        break
            
            if unique_nodes:
                content = '\n'.join(unique_nodes)
                result_bytes = (content + '\n').encode('utf-8')
                if total_size + len(result_bytes) > TOTAL_SIZE_LIMIT:
                    logging.warning("达到总大小限制，停止写入")
                    break
                if current_file_size + len(result_bytes) > MAX_FILE_SIZE:
                    out_file.close()
                    file_index += 1
                    current_file_size = 0
                    out_file = open(f"{base_output_file}_{file_index}{extension}", 'w', encoding='utf-8')
                out_file.write(content + '\n')
                current_file_size += len(result_bytes)
                total_size += len(result_bytes)
                successful_urls.append(url)
        if success:
            successful_urls.append(url)
        else:
            failed_urls.append(url)
        if success_count >= MAX_SUCCESS:
            break

out_file.close()

# 记录成功和失败的URL
with open(os.path.join(output_dir, 'successful_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(successful_urls))
with open(os.path.join(output_dir, 'failed_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(failed_urls))

# 最终结果报告
print("\n" + "=" * 50)
print("最终结果：")
print(f"处理URL总数：{len(unique_urls)}")
print(f"成功获取节点数：{success_count}")
print(f"输出文件数量：{file_index}")
print(f"总输出大小：{total_size / (1024*1024):.2f} MB")
if len(unique_urls) > 0:
    print(f"有效URL率：{len(successful_urls)/len(unique_urls):.1%}")
print(f"结果文件已保存至：{base_output_file}_[1-{file_index}]{extension}")
print(f"成功URL记录至：{os.path.join(output_dir, 'successful_urls.txt')}")
print(f"失败URL记录至：{os.path.join(output_dir, 'failed_urls.txt')}")
