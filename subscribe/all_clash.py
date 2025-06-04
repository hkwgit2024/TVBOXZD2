# -*- coding: utf-8 -*-
import os
import requests
from urllib.parse import urlparse
import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import argparse
import re
import yaml
import json
import csv # 导入csv库

# 配置日志
logging.basicConfig(filename='error.log', level=logging.ERROR,
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

# 命令行参数解析
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源和节点解析")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功数量")
parser.add_argument('--timeout', type=int, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.txt', help="输出文件路径")
args = parser.parse_args()

# 全局变量，从命令行参数或默认值获取
MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
TEMP_MERGED_FILE = 'temp_merged_nodes.txt' # 临时合并节点文件
STATISTICS_FILE = 'data/url_statistics.csv' # URL获取统计CSV文件
SUCCESS_URLS_FILE = 'data/successful_urls.txt' # 成功获取节点或解析成功的URL列表文件
FAILED_URLS_FILE = 'data/failed_urls.txt' # 获取失败或解析失败的URL列表文件

def is_valid_url(url):
    """验证URL格式是否合法，仅接受 http 或 https 方案"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def get_url_list_from_remote(url_source):
    """从给定的公开网址获取 URL 列表"""
    try:
        response = requests.get(url_source, headers=headers, timeout=10)
        response.raise_for_status() # 对HTTP错误状态码抛出异常
        text_content = response.text.strip()
        raw_urls = [line.strip() for line in text_content.splitlines() if line.strip()]
        print(f"从 {url_source} 获取到 {len(raw_urls)} 个URL")
        return raw_urls
    except Exception as e:
        logging.error(f"获取URL列表失败: {url_source} - {e}")
        return []

def parse_content_to_nodes(content):
    """
    从文本内容中解析出各种类型的节点。
    支持 Base64 解码、Clash YAML 格式的proxies，以及多种节点协议的直接链接。
    """
    if not content:
        return []

    found_nodes = set()
    processed_content = content

    # 1. 尝试 Base64 解码
    try:
        decoded_bytes = base64.b64decode(content)
        processed_content = decoded_bytes.decode('utf-8')
        logging.info("内容成功 Base64 解码。")
    except Exception:
        # 如果不是有效的Base64，就用原始内容
        pass

    # 2. 尝试 YAML 解析 (主要用于 Clash 配置)
    try:
        # 使用 safe_load 防止任意代码执行
        parsed_data = yaml.safe_load(processed_content)
        if isinstance(parsed_data, dict) and 'proxies' in parsed_data and isinstance(parsed_data['proxies'], list):
            # 这是一个 Clash 配置的 proxies 部分
            for proxy_entry in parsed_data['proxies']:
                if isinstance(proxy_entry, dict):
                    # 将代理字典转换为一个稳定的字符串表示形式，方便去重
                    # 使用 JSON dumps 可以保证字典键的顺序，使得去重更可靠
                    node_str_representation = json.dumps(proxy_entry, sort_keys=True, ensure_ascii=False) # ensure_ascii=False for Chinese chars
                    found_nodes.add(node_str_representation)
                # 兼容直接包含节点字符串的情况，即使在 YAML 格式中也可能出现
                elif isinstance(proxy_entry, str) and (
                    proxy_entry.startswith("vmess://") or 
                    proxy_entry.startswith("trojan://") or 
                    proxy_entry.startswith("ss://") or 
                    proxy_entry.startswith("ssr://") or
                    proxy_entry.startswith("vless://") or
                    proxy_entry.startswith("hy://") or 
                    proxy_entry.startswith("hy2://") or 
                    proxy_entry.startswith("hysteria://") or 
                    proxy_entry.startswith("hysteria2://")
                ):
                    found_nodes.add(proxy_entry.strip())
            logging.info("内容成功解析为 Clash YAML。")
        elif isinstance(parsed_data, list):
            # 有些订阅可能直接返回一个节点列表（YAML格式）
            for item in parsed_data:
                if isinstance(item, str):
                    found_nodes.add(item.strip())
            logging.info("内容成功解析为 YAML 列表。")
    except yaml.YAMLError:
        # 不是有效的 YAML 格式，忽略此错误，继续尝试正则表达式
        pass
    except Exception as e:
        logging.error(f"YAML 解析失败: {e}")
        pass

    # 3. 通过正则表达式提取节点（处理明文、非标准格式等）
    # 仅匹配节点协议前缀，不再包含 http:// 或 https://，因为它们现在被视为订阅URL而不是节点本身
    node_pattern = re.compile(
        r'(vmess://\S+|'
        r'trojan://\S+|'
        r'ss://\S+|'
        r'ssr://\S+|'
        r'vless://\S+|'
        r'hy://\S+|'
        r'hy2://\S+|'
        r'hysteria://\S+|'
        r'hysteria2://\S+)'
    )
    
    # 尝试在原始内容和解码后的内容中都查找
    matches = node_pattern.findall(content)
    for match in matches:
        found_nodes.add(match.strip())
    
    if content != processed_content: # 如果成功解码了，也要在解码后的内容中查找
        matches_decoded = node_pattern.findall(processed_content)
        for match in matches_decoded:
            found_nodes.add(match.strip())

    return list(found_nodes) # 返回列表

def fetch_and_parse_url(url):
    """
    获取URL内容并解析出节点。
    返回一个元组：(节点列表, 是否成功, 错误信息(如果失败))
    """
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status() # 对HTTP错误状态码抛出异常
        content = resp.text.strip()
        
        if len(content) < 10: # 简单过滤一些过短的无效内容
            logging.warning(f"获取到内容过短，可能无效: {url}")
            return [], False, "内容过短"
        
        nodes = parse_content_to_nodes(content)
        return nodes, True, None # 成功获取并解析
    except requests.exceptions.Timeout:
        logging.error(f"请求超时: {url}")
        return [], False, "请求超时"
    except requests.exceptions.RequestException as e:
        logging.error(f"请求失败: {url} - {e}")
        return [], False, f"请求失败: {e}"
    except Exception as e:
        logging.error(f"处理URL异常: {url} - {e}")
        return [], False, f"未知异常: {e}"

def write_statistics_to_csv(statistics_data, filename):
    """将统计数据写入CSV文件"""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量', '状态', '错误信息']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in statistics_data:
            writer.writerow(row)
    print(f"统计数据已保存至：{filename}")

def write_urls_to_file(urls, filename):
    """将URL列表写入文件"""
    with open(filename, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(url + '\n')
    print(f"URL列表已保存至：{filename}")

# --- 主程序流程 ---

# 从环境变量中读取 URL_SOURCE
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")

# 如果 URL_SOURCE 未设置，则退出脚本
if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。无法获取订阅链接。")
    exit(1)

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
os.makedirs(os.path.dirname(STATISTICS_FILE), exist_ok=True) # 确保统计文件目录也存在

# 获取原始的URL列表（包含可能不是HTTP/HTTPS的条目）
raw_urls_from_source = get_url_list_from_remote(URL_SOURCE)

# 用于存储需要进行 HTTP 请求的订阅 URL
urls_to_fetch = set()
# 用于存储从 URL_SOURCE 中直接解析出的节点字符串（非 HTTP/HTTPS URL）
# 这些不会进行 HTTP 请求，而是直接解析并合并
direct_parsed_nodes_from_source = set()

# 存储所有URL的统计信息，包括成功和失败的 HTTP 请求以及直接解析的结果
url_statistics = []
# 存储成功获取节点或直接解析成功的原始 URL/字符串
successful_urls = []
# 存储获取失败或直接解析失败的原始 URL/字符串
failed_urls = []

# 预处理 raw_urls_from_source，分离出真正需要请求的URL和直接解析的节点字符串
print("\n--- 预处理原始URL/字符串列表 ---")
for entry in raw_urls_from_source:
    if is_valid_url(entry):
        urls_to_fetch.add(entry)
    else:
        # 如果不是有效的HTTP/HTTPS URL，尝试将其作为内容直接解析为节点
        # 这处理了 URL_SOURCE 中直接包含节点字符串的情况
        print(f"发现非HTTP/HTTPS条目，尝试直接解析: {entry[:80]}...")
        parsed_nodes = parse_content_to_nodes(entry)
        if parsed_nodes:
            for node in parsed_nodes:
                direct_parsed_nodes_from_source.add(node)
            # 记录为成功解析，不触发HTTP请求
            stat_entry = {'URL': entry, '节点数量': len(parsed_nodes), '状态': '直接解析成功', '错误信息': ''}
            url_statistics.append(stat_entry)
            successful_urls.append(entry)
        else:
            # 既不是有效URL也无法解析出节点
            stat_entry = {'URL': entry, '节点数量': 0, '状态': '直接解析失败', '错误信息': '非URL且无法解析为节点'}
            url_statistics.append(stat_entry)
            failed_urls.append(entry)

# 阶段一：并行获取并解析所有 HTTP/HTTPS 订阅链接，合并节点到临时文件
print("\n--- 阶段一：获取并合并所有订阅链接中的节点 ---")
temp_merged_nodes_set = set() # 用于阶段一的去重

# 首先添加那些从 URL_SOURCE 直接解析出来的节点
for node in direct_parsed_nodes_from_source:
    temp_merged_nodes_set.add(node)

total_urls_to_process_via_http = len(urls_to_fetch)

if total_urls_to_process_via_http > 0:
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls_to_fetch}
        for future in tqdm(as_completed(future_to_url), total=total_urls_to_process_via_http, desc="通过HTTP/HTTPS请求并解析节点"):
            url = future_to_url[future]
            nodes, success, error_message = future.result()

            # 记录统计信息
            stat_entry = {'URL': url, '节点数量': len(nodes), '状态': '成功' if success else '失败', '错误信息': error_message if error_message else ''}
            url_statistics.append(stat_entry)

            if success:
                successful_urls.append(url)
                for node in nodes:
                    temp_merged_nodes_set.add(node) # 添加到集合进行去重
            else:
                failed_urls.append(url)

# 将阶段一收集到的节点写入临时文件
with open(TEMP_MERGED_FILE, 'w', encoding='utf-8') as temp_file:
    for node in temp_merged_nodes_set:
        temp_file.write(node.strip() + '\n')

# 写入统计数据和URL列表文件
write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE)

print(f"\n阶段一完成。从所有订阅链接和直接解析的字符串中合并到 {len(temp_merged_nodes_set)} 个唯一节点，已保存至 {TEMP_MERGED_FILE}")

# 阶段二：从聚合的节点文件中再次进行去重后输出保存
print("\n--- 阶段二：最终去重并保存节点 ---")
final_unique_nodes = set()
try:
    with open(TEMP_MERGED_FILE, 'r', encoding='utf-8') as temp_file:
        for line in temp_file:
            stripped_line = line.strip()
            if stripped_line:
                final_unique_nodes.add(stripped_line)
except FileNotFoundError:
    print(f"警告：未找到临时文件 {TEMP_MERGED_FILE}，可能阶段一没有成功获取到任何节点。")
except Exception as e:
    logging.error(f"读取临时文件 {TEMP_MERGED_FILE} 失败: {e}")

success_count = 0
with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
    for node in sorted(list(final_unique_nodes)): # 排序后写入，方便查看和比较
        if success_count < MAX_SUCCESS:
            out_file.write(node + '\n')
            success_count += 1
        else:
            break

# 清理临时文件
if os.path.exists(TEMP_MERGED_FILE):
    os.remove(TEMP_MERGED_FILE)
    print(f"已删除临时文件：{TEMP_MERGED_FILE}")

# 最终结果报告
print("\n" + "=" * 50)
print("最终结果：")
print(f"原始来源总条目数：{len(raw_urls_from_source)}")
print(f"其中需要HTTP/HTTPS请求的订阅链接数：{len(urls_to_fetch)}")
print(f"其中直接解析的非URL字符串数：{len(raw_urls_from_source) - len(urls_to_fetch)}")
print(f"成功处理的URL/字符串总数：{len(successful_urls)}")
print(f"失败的URL/字符串总数：{len(failed_urls)}")
print(f"初步聚合的唯一节点数：{len(temp_merged_nodes_set)}")
print(f"最终去重并成功保存的节点数：{success_count}")
if len(temp_merged_nodes_set) > 0:
    print(f"最终有效内容率（相对于初步聚合）：{success_count/len(temp_merged_nodes_set):.1%}")
if success_count < MAX_SUCCESS:
    print("警告：未能达到目标数量，原始列表可能有效URL/节点不足，或部分URL获取失败。")
print(f"结果文件已保存至：{OUTPUT_FILE}")
print(f"统计数据已保存至：{STATISTICS_FILE}")
print(f"成功URL列表已保存至：{SUCCESS_URLS_FILE}")
print(f"失败URL列表已保存至：{FAILED_URLS_FILE}")
print("=" * 50)
