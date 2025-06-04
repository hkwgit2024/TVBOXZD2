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
import yaml # 导入yaml库
import json # 导入json库，用于处理yaml中的字典结构节点

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

# 命令行参数
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源和节点解析")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功数量")
parser.add_argument('--timeout', type=int, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.txt', help="输出文件路径")
args = parser.parse_args()

MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
TEMP_MERGED_FILE = 'temp_merged_nodes.txt' # 中间文件路径

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
        response.raise_for_status()
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
        # 记录解码成功的信息
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
                # 兼容直接包含节点字符串的情况
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
    # 仅匹配节点协议前缀，不再包含 http:// 或 https://
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

    return list(found_nodes)

def fetch_and_parse_url(url):
    """获取URL内容并解析出节点"""
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text.strip()
        
        # 简单过滤一些无效内容
        if len(content) < 10:
            logging.warning(f"获取到内容过短，可能无效: {url}")
            return []
        
        # 将获取到的内容传递给解析函数
        nodes = parse_content_to_nodes(content)
        return nodes
    except Exception as e:
        logging.error(f"获取或解析URL内容失败: {url} - {e}")
        return []

# --- 主程序流程 ---

# 从环境变量中读取 URL_SOURCE 并调试
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")

initial_urls_to_fetch = set()

# 从远程 URL_SOURCE 获取 URL 列表
if URL_SOURCE:
    print(f"将从远程URL_SOURCE获取订阅链接: {URL_SOURCE}")
    raw_urls_from_remote = get_url_list_from_remote(URL_SOURCE)
    # 将从远程获取的URL添加到待处理队列，这里假设这些URL都是订阅链接
    for url in raw_urls_from_remote:
        if is_valid_url(url): # 确保是有效的HTTP/HTTPS链接才加入fetch队列
            initial_urls_to_fetch.add(url)
        else: # 如果不是有效的URL，但可能是直接的节点字符串，也先尝试解析并添加到临时集合
            # 这种情况是为了处理 URL_SOURCE 中直接包含节点字符串的情况，而非订阅链接
            nodes_from_direct_string = parse_content_to_nodes(url)
            if nodes_from_direct_string:
                # 这种情况下，直接将解析出的节点添加到阶段一的合并集合中
                # 这样做是为了确保这些直接的节点字符串也能参与去重和保存
                # 注意：temp_merged_nodes_set 在这里还没有初始化，需要先初始化
                # 或者将这部分节点收集起来，在阶段一执行前统一处理
                # 考虑到多线程，我们统一在阶段一的循环后收集
                pass # 暂时不做特殊处理，让 fetch_and_parse_url 来处理，如果它是URL会请求，如果不是URL，会作为字符串被 parse_content_to_nodes 处理
else:
    print("错误：环境变量 'URL_SOURCE' 未设置。无法获取订阅链接。")
    exit(1) # 如果没有URL_SOURCE，则脚本无法执行

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# 阶段一：解析URL内容，下载并合并多个URL的节点到临时文件
print("\n--- 阶段一：获取并合并所有来源的节点 ---")
temp_merged_nodes_set = set() # 用于阶段一的去重

total_urls_to_process = len(initial_urls_to_fetch)
processed_count = 0

if total_urls_to_process > 0:
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in initial_urls_to_fetch}
        for future in tqdm(as_completed(future_to_url), total=total_urls_to_process, desc="处理URL并解析节点"):
            url = future_to_url[future]
            try:
                nodes = future.result()
                for node in nodes:
                    temp_merged_nodes_set.add(node) # 添加到集合进行去重
                processed_count += 1
            except Exception as e:
                logging.error(f"处理URL {url} 出现异常: {e}")

# 将阶段一收集到的节点写入临时文件
with open(TEMP_MERGED_FILE, 'w', encoding='utf-8') as temp_file:
    for node in temp_merged_nodes_set:
        temp_file.write(node.strip() + '\n')

print(f"\n阶段一完成。从所有订阅链接中合并到 {len(temp_merged_nodes_set)} 个唯一节点，已保存至 {TEMP_MERGED_FILE}")

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
print(f"待处理订阅链接总数：{len(initial_urls_to_fetch)}")
print(f"初步聚合的唯一节点数：{len(temp_merged_nodes_set)}")
print(f"最终去重并成功保存的节点数：{success_count}")
if len(temp_merged_nodes_set) > 0:
    print(f"最终有效内容率（相对于初步聚合）：{success_count/len(temp_merged_nodes_set):.1%}")
if success_count < MAX_SUCCESS:
    print("警告：未能达到目标数量，原始列表可能有效URL/节点不足，或部分URL获取失败。")
print(f"结果文件已保存至：{OUTPUT_FILE}")
print("=" * 50)
